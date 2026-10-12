use super::*;

impl Authority {
    pub fn market_initialize(&self) -> Result<()> {
        let catalog: Value = serde_json::from_str(CATALOG).map_err(|_| "catalog schema")?;
        if catalog["schema"] != "flybrain-market-catalog-v1" || catalog["projects"].as_array().map(Vec::len) != Some(10)
            || catalog["products"].as_array().map(Vec::len) != Some(5) { return Err("catalog inventory".into()); }
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        sql(tx.execute_batch(include_str!("../../config/market-v1.sql")))?;
        for spec in catalog["projects"].as_array().unwrap() {
            let slug = text(spec, "slug")?;
            let pid = id("brain-project-v1", &json!({"slug":slug}))?;
            let spec_root = id("brain-project-spec-v1", spec)?;
            let old: Option<String> = sql(tx.query_row("SELECT spec_root FROM brain_projects WHERE id=?", [&pid], |r| r.get(0)).optional())?;
            if old.as_ref().is_some_and(|root| root != &spec_root) { return Err("CONFLICT: project definition needs an explicit version migration".into()); }
            sql(tx.execute("INSERT OR IGNORE INTO brain_projects(id,slug,code,spec_root,spec,status,created_at) VALUES(?,?,?,?,?,'proposed',?)",
                params![pid,slug,spec["code"].as_str().ok_or("code")?,spec_root,spec.to_string(),now()]))?;
        }
        for product in catalog["products"].as_array().unwrap() {
            let slug = text(product, "slug")?;
            let mid = id("market-model-id-v1", &json!({"slug":slug}))?;
            sql(tx.execute("INSERT OR IGNORE INTO market_products VALUES(?,?,?)", params![mid,slug,product.to_string()]))?;
            for sku in product["serviceSkus"].as_array().ok_or("sku inventory")? {
                let sku = sku.as_str().ok_or("sku")?;
                let template = catalog["priceTemplates"].as_array().unwrap().iter().find(|p| p["skuId"] == sku).ok_or("price inventory")?;
                decimal(template, "amountAtoms")?;
                sql(tx.execute("INSERT OR IGNORE INTO service_skus VALUES(?,?,?)", params![sku,mid,template.to_string()]))?;
                let policy = id("market-price-template-v1", template)?;
                sql(tx.execute("INSERT OR IGNORE INTO price_policies VALUES(?,?,NULL,?,'draft',?)", params![policy,sku,template.to_string(),now()]))?;
            }
        }
        sql(tx.commit())
    }

    pub fn market_public(&self, path: &str, q: &ListQuery) -> Result<Value> {
        if q.limit.unwrap_or(20) == 0 || q.limit.unwrap_or(20) > 50 || q.cursor.len() > 64 || q.status.len() > 40
            || q.category.len() > 40 || q.hardware.len() > 40 { return Err("INVALID_INPUT: bounded market query".into()); }
        let db = self.lock()?;
        let parts: Vec<_> = path.trim_matches('/').split('/').collect();
        match parts.as_slice() {
            ["health"] => Ok(json!({"status":"available","catalogSchemaVersion":1,"asOf":now(),"asset":"NOT_CONFIGURED","modelsReleased":sql(db.query_row("SELECT COUNT(*) FROM model_versions WHERE status='released'",[],|r|r.get::<_,u64>(0)))?,"paidSuccessfulRequests":sql(db.query_row("SELECT COUNT(*) FROM service_jobs WHERE status='completed' AND settlement_status='finalized'",[],|r|r.get::<_,u64>(0)))?,"operatorScope":"controlled service nodes; signed receipts are not execution proofs"})),
            ["projects"] => {
                let mut stmt = sql(db.prepare("SELECT id,slug,spec,status FROM brain_projects WHERE id>? ORDER BY id LIMIT 100"))?;
                let rows = sql(stmt.query_map([&q.cursor], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?))))?
                    .collect::<rusqlite::Result<Vec<_>>>().map_err(|_| "market read")?;
                let mut projects = Vec::new();
                let mut next = None;
                for (pid,slug,spec,status) in rows {
                    let mut spec = parse(spec)?;
                    if !q.status.is_empty() && status != q.status { continue; }
                    if !q.category.is_empty() && spec["category"] != q.category { continue; }
                    if !q.hardware.is_empty() && !spec["hardware"].as_array().unwrap().iter().any(|v| v == &q.hardware) { continue; }
                    if projects.len() == q.limit.unwrap_or(20) { break; }
                    spec["projectId"] = json!(pid); spec["slug"] = json!(slug); spec["projectStatus"] = json!(status);
                    spec["generationCount"] = json!(sql(db.query_row("SELECT COUNT(*) FROM project_generations WHERE project_id=?",[&pid],|r|r.get::<_,u64>(0)))?);
                    spec["currentActivity"] = json!({"freshExecutions":sql(db.query_row("SELECT COUNT(*) FROM work_assignments a JOIN work_packages w ON w.id=a.work_id JOIN project_generations g ON g.id=w.generation_id WHERE g.project_id=? AND a.status='running' AND a.lease_until>?",params![pid,now()],|r|r.get::<_,u64>(0)))?,"asOf":now()});
                    next = Some(pid); projects.push(spec);
                }
                Ok(json!({"projects":projects,"nextCursor":if projects.len()==q.limit.unwrap_or(20){next}else{None},"asOf":now(),"knownZeroFields":"initial definitions create no execution, customer or financial facts"}))
            },
            ["projects", project] => {
                let (pid, spec, status):(String,String,String) = sql(db.query_row("SELECT id,spec,status FROM brain_projects WHERE id=? OR slug=? OR code=?", params![project,project,project],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?.ok_or("NOT_FOUND: project")?;
                let mut spec = parse(spec)?; spec["projectId"] = json!(pid); spec["projectStatus"] = json!(status); spec["asOf"] = json!(now()); Ok(spec)
            },
            ["projects", project, "generations"] => {
                let pid:String = sql(db.query_row("SELECT id FROM brain_projects WHERE id=? OR slug=? OR code=?",params![project,project,project],|r|r.get(0)).optional())?.ok_or("NOT_FOUND: project")?;
                let mut stmt = sql(db.prepare("SELECT id,manifest,status,budget_atoms,reserved_atoms,accepted_atoms,paid_atoms FROM project_generations WHERE project_id=? AND id>? ORDER BY id LIMIT ?"))?;
                let items = sql(stmt.query_map(params![pid,q.cursor,q.limit.unwrap_or(20)],|r|Ok(json!({"generationId":r.get::<_,String>(0)?,"manifest":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"status":r.get::<_,String>(2)?,"budgetAtoms":r.get::<_,String>(3)?,"reservedAtoms":r.get::<_,String>(4)?,"acceptedAtoms":r.get::<_,String>(5)?,"paidAtoms":r.get::<_,String>(6)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|_|"market read")?;
                Ok(json!({"generations":items,"asOf":now()}))
            },
            ["projects", project, "activity"] => {
                let pid:String=sql(db.query_row("SELECT id FROM brain_projects WHERE id=? OR slug=? OR code=?",params![project,project,project],|r|r.get(0)).optional())?.ok_or("NOT_FOUND: project")?;
                let cursor=if q.cursor.is_empty(){0}else{q.cursor.parse::<u64>().map_err(|_|"INVALID_INPUT: event cursor")?};
                let mut stmt=sql(db.prepare("SELECT id,kind,object_id,public_data,created_at FROM market_public_events WHERE id>? AND (object_id=? OR object_id IN (SELECT id FROM project_generations WHERE project_id=?) OR object_id IN (SELECT w.id FROM work_packages w JOIN project_generations g ON g.id=w.generation_id WHERE g.project_id=?) OR object_id IN (SELECT id FROM model_versions WHERE project_id=?)) ORDER BY id LIMIT ?"))?;
                let events=sql(stmt.query_map(params![cursor,pid,pid,pid,pid,q.limit.unwrap_or(20)],|r|Ok(json!({"eventId":r.get::<_,u64>(0)?,"kind":r.get::<_,String>(1)?,"objectId":r.get::<_,String>(2)?,"data":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null),"createdAt":r.get::<_,u64>(4)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|_|"market read")?;
                Ok(json!({"events":events,"asOf":now(),"scope":"public work progress; private inputs excluded"}))
            },
            ["models"] => {
                let mut stmt=sql(db.prepare("SELECT id,manifest,status FROM model_versions WHERE id>? AND status IN ('released','deprecated') ORDER BY id LIMIT ?"))?;
                let models=sql(stmt.query_map(params![q.cursor,q.limit.unwrap_or(20)],|r|Ok(json!({"versionId":r.get::<_,String>(0)?,"manifest":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"releaseStatus":r.get::<_,String>(2)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|_|"market read")?;
                let mut stmt=sql(db.prepare("SELECT id,definition FROM market_products ORDER BY slug"))?;
                let upcoming=sql(stmt.query_map([],|r|Ok(json!({"modelId":r.get::<_,String>(0)?,"definition":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"releaseStatus":"not_released","deployment":"unconfigured"}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|_|"market read")?;
                Ok(json!({"models":models,"upcoming":upcoming,"asOf":now(),"commercialTraffic":"only finalized fulfilled service receipts"}))
            },
            ["models", version] => {
                let (manifest,status):(String,String)=sql(db.query_row("SELECT manifest,status FROM model_versions WHERE id=?",[version],|r|Ok((r.get(0)?,r.get(1)?))).optional())?.ok_or("NOT_FOUND: model version")?;
                Ok(json!({"versionId":version,"manifest":parse(manifest)?,"releaseStatus":status,"asOf":now()}))
            },
            ["prices"] => {
                let mut stmt=sql(db.prepare("SELECT id,policy,state FROM price_policies ORDER BY sku_id,id"))?;
                let prices=sql(stmt.query_map([],|r|Ok(json!({"policyId":r.get::<_,String>(0)?,"policy":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"state":r.get::<_,String>(2)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|_|"market read")?;
                Ok(json!({"prices":prices,"asOf":now()}))
            },
            _ => Err("NOT_FOUND: market route".into())
        }
    }
}
