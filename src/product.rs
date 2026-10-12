//! Product API in the existing authority and SQLite/WAL. Private candidates are
//! never a public file source. Public packages require a signed publication.
use super::*;
use crate::product_identity as science;
use axum::{
    body::Body,
    extract::{ConnectInfo, Extension},
    http::{header, HeaderValue},
};
use std::{io::Read, net::SocketAddr};
pub const PRODUCT: &str = include_str!("../web/data/product-manifest-v1.json");
pub const POLICY: &str = include_str!("../web/data/economic-policy-v2.json");
const SERVICE_STATES: [&str; 8] = [
    "received",
    "scoping",
    "proposal",
    "quote-confirmation",
    "budget-required",
    "executing",
    "delivered",
    "closed",
];
fn clean(v: &Value, key: &str, min: usize, max: usize) -> Result<String> {
    let s = text(v, key)?;
    if s.chars().count() < min || s.chars().count() > max || s.contains('\0') {
        return Err(format!("INVALID_INPUT: {key}"));
    }
    Ok(s)
}
fn file_name(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 80
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || s.starts_with('.')
        || s.contains("..")
    {
        return Err("INVALID_INPUT: file name".into());
    }
    Ok(())
}
fn public_json(path: &std::path::Path, allowed: &[&str]) -> Result<Value> {
    if fs::metadata(path)
        .map_err(|_| "NOT_FOUND: public metadata")?
        .len()
        > 1024 * 1024
    {
        return Err("INVALID_INPUT: public metadata size".into());
    }
    let v: Value =
        serde_json::from_slice(&fs::read(path).map_err(|_| "DAMAGED_ARTIFACT: public metadata")?)
            .map_err(|_| "INVALID_INPUT: public JSON")?;
    let obj = v.as_object().ok_or("INVALID_INPUT: public object")?;
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err("AUTHORIZATION: public metadata whitelist".into());
    }
    fn inspect(v: &Value) -> Result<()> {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    if [
                        "salt",
                        "secret",
                        "privatekey",
                        "password",
                        "contact",
                        "accesstoken",
                        "privatepath",
                    ]
                    .contains(&k.to_ascii_lowercase().as_str())
                    {
                        return Err("AUTHORIZATION: private field in publication".into());
                    }
                    inspect(x)?;
                }
            }
            Value::Array(a) => {
                for x in a {
                    inspect(x)?;
                }
            }
            Value::String(s)
                if [
                    "/var/lib/flypow",
                    "/etc/flypow",
                    "/workspace/",
                    "PRIVATE KEY",
                ]
                .iter()
                .any(|p| s.contains(p)) =>
            {
                return Err("AUTHORIZATION: private path in publication".into())
            }
            _ => (),
        }
        Ok(())
    }
    inspect(&v)?;
    Ok(v)
}
pub(super) fn digest_file(p: &std::path::Path) -> Result<(String, u64)> {
    let mut f = fs::File::open(p).map_err(|_| "DAMAGED_ARTIFACT: public file unavailable")?;
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    let mut len = 0;
    loop {
        let n = f
            .read(&mut b)
            .map_err(|_| "DAMAGED_ARTIFACT: public read")?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
        len += n as u64;
    }
    Ok((p::hex(&h.finalize()), len))
}
pub(super) fn source_key(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let ip = peer.map(|p| p.ip());
    let source = if ip.is_some_and(|i| i.is_loopback()) {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .map(|i| i.to_string())
            .unwrap_or_else(|| ip.unwrap().to_string())
    } else {
        ip.map(|i| i.to_string()).unwrap_or("internal-test".into())
    };
    hash(source.as_bytes())
}
impl Authority {
    pub fn product_initialize(&self) -> Result<()> {
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        sql(tx.execute_batch(include_str!("../config/product-v1.sql")))?;sql(tx.execute_batch(include_str!("../config/explorer-source-v1.sql")))?;
        let old_books={let mut q=sql(tx.prepare("SELECT asset,state FROM economic_books"))?;let rows=sql(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;rows};
        for (asset,state) in old_books {let mut book:flypow_economic_core::Book=serde_json::from_str(&state).map_err(|_|"legacy book")?;if book.normalize_legacy_payment_keys().map_err(|e|format!("MIGRATION_REQUIRED: {e}"))?{let next=serde_json::to_string(&book).map_err(|_|"book")?;sql(tx.execute("INSERT OR IGNORE INTO economic_book_migrations VALUES(?,?,?,?,?)",params![asset,hash(state.as_bytes()),hash(next.as_bytes()),book.payments.len(),now()]))?;sql(tx.execute("UPDATE economic_books SET state=? WHERE asset=?",params![next,asset]))?;}}
        let winners = {
            let mut q=sql(tx.prepare("SELECT round_id,claim_id,json_extract(winner_json,'$.confirmedAt') FROM round_winners ORDER BY round_id"))?;
            let rows = sql(q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            }))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
            rows
        };
        for (rid, cid, at) in winners {
            self.product_capture_tx(&tx, &rid, &cid, at)?;
        }
        let old_votes={let mut q=sql(tx.prepare("SELECT v.vote_json FROM verification_votes v LEFT JOIN public_verification_declarations p ON p.claim_id=v.claim_id AND p.verifier_id=v.verifier_id WHERE p.claim_id IS NULL"))?;let rows=sql(q.query_map([],|r|r.get::<_,String>(0)))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;rows};
        for vote in old_votes {let vote:SignedRequest=serde_json::from_str(&vote).map_err(|_|"source vote")?;self.public_vote_tx(&tx,&vote,now(),true)?;}
        let published={let mut q=sql(tx.prepare("SELECT id,task_id,summary FROM public_results"))?;let rows=sql(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;rows};
        for(rid,gid,summary)in published{let g:GoalSpec=serde_json::from_str(&sql(tx.query_row("SELECT spec_json FROM goal_specs WHERE goal_id=?",[gid],|r|r.get::<_,String>(0)))?).map_err(|_|"goal")?;let input:p::CandidateInput=serde_json::from_value(parse(summary)?["input"].clone()).map_err(|_|"input")?;Self::index_result_neurons_tx(&tx,&rid,&g,&input)?;}
        sql(tx.commit())?;
        drop(db);self.migrate_public_objects()?;self.backfill_public_response_roles()?;Ok(())
    }
    pub(super) fn product_capture_tx(
        &self,
        db: &Connection,
        rid: &str,
        cid: &str,
        at: u64,
    ) -> Result<()> {
        self.product_capture_kind_tx(db,rid,cid,at,"discovery")
    }
    fn product_capture_kind_tx(&self,db:&Connection,rid:&str,cid:&str,at:u64,kind:&str)->Result<()> {
        let (actor,manifest):(String,String)=sql(db.query_row("SELECT miner_id,manifest_json FROM candidate_claims JOIN candidate_reveals USING(claim_id) WHERE claim_id=?",[cid],|r|Ok((r.get(0)?,r.get(1)?))))?;
        let m: CandidateManifest = serde_json::from_str(&manifest).map_err(|e| e.to_string())?;
        let r = Self::round(db, rid)?;
        let g: GoalSpec = serde_json::from_value(r["goal"].clone()).map_err(|e| e.to_string())?;
        let mut ids = Vec::new();
        for t in &m.trials {
            let (id, v) = science::simulation(&g, &m.input, &t.seed_hex)?;
            sql(db.execute(
                "INSERT OR IGNORE INTO science_simulations VALUES(?,?)",
                params![id, v.to_string()],
            ))?;
            ids.push(id);
        }
        let (readout, v) = science::readout(&g, &ids)?;
        sql(db.execute(
            "INSERT OR IGNORE INTO science_readouts VALUES(?,?)",
            params![readout, v.to_string()],
        ))?;
        let task = science::task(&g)?;
        let c = science::contribution(&actor, kind, &readout, &task, "unbudgeted", cid)?;
        sql(db.execute(
            "INSERT OR IGNORE INTO science_contributions VALUES(?,?,?,?,?,?,?)",
            params![c, actor, kind, task, readout, cid, at],
        ))?;
        let policy = id("verification-policy", &r["pre"]["verificationPolicy"])?;
        let acceptance = id(
            "acceptance-v1",
            &json!({"contributionId":c,"policy":policy,"judgement":"protocol-full-replay","evidence":m.goal_result_root,"issuer":self.authority_id}),
        )?;
        sql(db.execute(
            "INSERT OR IGNORE INTO science_acceptances VALUES(?,?,?,?,?,?,?)",
            params![
                acceptance,
                c,
                policy,
                "protocol-full-replay",
                m.goal_result_root,
                self.authority_id,
                at
            ],
        ))?;
        Ok(())
    }
    pub fn product_manifest(&self) -> Result<Value> {
        let db = self.lock()?;
        let public: u64 =
            sql(db.query_row("SELECT COUNT(*) FROM public_results", [], |r| r.get(0)))?;
        let simulations: u64 =
            sql(db.query_row("SELECT COUNT(*) FROM science_simulations", [], |r| r.get(0)))?;
        Ok(
            json!({"product":serde_json::from_str::<Value>(PRODUCT).unwrap(),"economicPolicy":serde_json::from_str::<Value>(POLICY).unwrap(),"deployment":{"networkId":self.config.network_id,"authorityId":self.authority_id,"operators":1,"verificationIdentities":3,"quorum":2,"externalValidation":"observations-required","payments":"asset-identity-and-published-funded-plan-required"},"metrics":{"publicResults":{"value":public,"unit":"distinct-public-readouts","at":now()},"indexedSimulations":{"value":simulations,"unit":"distinct-scientific-identities","scope":"authority-records-not-global-network","at":now()},"externalRevenue":null,"operatingCosts":"not-yet-collected"}}),
        )
    }
    pub fn product_tasks(&self, q: &ProductQuery) -> Result<Value> {
        let db = self.lock()?;
        let mut s=sql(db.prepare("SELECT goal_id,spec_json,calibration_json FROM goal_specs WHERE goal_id>? ORDER BY goal_id LIMIT ?"))?;
        let rows = sql(s.query_map(params![q.after, q.limit.min(50).max(1)], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        }))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for (gid, g, c) in rows {
            let goal: GoalSpec = serde_json::from_str(&g).map_err(|e| e.to_string())?;
            let task = science::task(&goal)?;
            let state: Option<String> = sql(db
                .query_row(
                    "SELECT state FROM goal_plan_progress WHERE campaign_id=? AND goal_id=?",
                    params![self.config.campaign_id, gid],
                    |r| r.get(0),
                )
                .optional())?;
            let cal = parse(c)?;
            out.push(json!({"id":gid,"scientificTaskId":task,"title":{"zh":"双窗口选择性刺激响应搜索","en":"Two-window selective stimulus response search"},"goal":goal,"state":state.unwrap_or("REGISTERED".into()),"legalInputCount":goal.inputs().len(),"calibration":{"hash":goal.calibration_hash,"sampleCount":cal["samples"].as_array().map(Vec::len),"levels":cal["levels"],"source":"complete-event-model-calibration-not-external-biology"},"budgetPlan":null,"publicationPolicy":"private-candidates-explicit-publication-required","customer":null,"purpose":{"zh":"公共模型内响应比较；评估指定下游集合与局部 O32 约束","en":"Public model response comparison for specified downstream sets and local O32 constraints"}}));
        }
        Ok(
            json!({"items":out,"nextCursor":out.last().map(|x|x["id"].clone()),"sort":"goal-id-ascending","economicPolicy":serde_json::from_str::<Value>(POLICY).unwrap()["policyId"]}),
        )
    }
    pub fn product_task(&self, gid: &str) -> Result<Value> {
        root(gid)?;
        let db = self.lock()?;
        let s: String = sql(db
            .query_row(
                "SELECT spec_json FROM goal_specs WHERE goal_id=?",
                [gid],
                |r| r.get(0),
            )
            .optional())?
        .ok_or("NOT_FOUND: task")?;
        let previous: Option<String> = sql(db.query_row(
            "SELECT MAX(goal_id) FROM goal_specs WHERE goal_id<?",
            [gid],
            |r| r.get(0),
        ))?;
        drop(db);
        let q = ProductQuery {
            after: previous.unwrap_or_default(),
            limit: 1,
            ..Default::default()
        };
        let tasks = self.product_tasks(&q)?;
        let mut found = tasks["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == gid)
            .cloned()
            .ok_or("NOT_FOUND: task")?;
        found["goal"] = parse(s)?;
        let results = self.product_results(&ProductQuery {
            task: gid.into(),
            ..Default::default()
        })?;
        found["results"] = results;
        Ok(found)
    }
    pub fn product_results(&self, q: &ProductQuery) -> Result<Value> {
        let db = self.lock()?;
        let mut stmt=sql(db.prepare("SELECT sequence,summary FROM public_results WHERE (?=0 OR sequence<?) AND (?='' OR task_id=?) AND (?='' OR model_root=?) AND (?='' OR input_body=?) AND (?='' OR result_type=?) AND (?='' OR evidence_level=?) AND published_at>=? AND (?='' OR EXISTS(SELECT 1 FROM result_neurons n WHERE n.result_id=public_results.id AND n.body_id=? AND (?='' OR n.role=?))) ORDER BY sequence DESC LIMIT ?"))?;
        let rows = sql(stmt.query_map(
            params![
                q.before,
                q.before,
                q.task,
                q.task,
                q.model,
                q.model,
                q.input,
                q.input,
                q.kind,
                q.kind,
                q.evidence,
                q.evidence,
                q.since,q.related,q.related,q.role,q.role,
                q.limit.max(1).min(50)
            ],
            |r| Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?)),
        ))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
        let mut out = rows.iter().map(|(_,v)|parse(v.clone())).collect::<Result<Vec<_>>>()?;
        if !q.related.is_empty(){for result in &mut out {let mut roles=sql(db.prepare("SELECT role FROM result_neurons WHERE result_id=? AND body_id=? ORDER BY role"))?;result["relatedRoles"]=json!(sql(roles.query_map(params![result["id"].as_str().unwrap(),q.related],|r|r.get::<_,String>(0)))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?);result["responseRoleScope"]=json!("actual-response means a spike in the stimulated B lane of complete published events; target membership and causal increase are separate");}}

        Ok(
            json!({"items":out,"nextCursor":rows.last().map(|(n,_)|n),"sort":"publication-sequence-descending","scope":"explicitly-published-readouts"}),
        )
    }
    pub fn product_result(&self, rid: &str) -> Result<Value> {
        root(rid)?;
        let db = self.lock()?;
        let s: String = sql(db
            .query_row(
                "SELECT summary FROM public_results WHERE id=?",
                [rid],
                |r| r.get(0),
            )
            .optional())?
        .ok_or("NOT_FOUND: published result")?;
        let mut v = parse(s)?;
        let mut stmt=sql(db.prepare("SELECT name,sha256,bytes,mime FROM public_result_files WHERE result_id=? ORDER BY name"))?;
        let rows = sql(stmt.query_map([rid], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, String>(3)?,
            ))
        }))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
        let expires = now() + 3600;
        let mut files = Vec::new();
        for (name, sha, bytes, mime) in rows {
            let bind =
                json!({"resultId":rid,"name":name,"sha256":sha,"bytes":bytes,"expires":expires});
            let signature = self.sign("public-download-v1", &bind)?;
            files.push(json!({"name":name,"sha256":sha,"bytes":bytes,"mime":mime,"expires":expires,"url":format!("/api/results/{rid}/files/{name}?expires={expires}&signature={signature}")}));
        }
        v["files"] = json!(files);
        Ok(v)
    }
    pub fn publish_product_package(&self, r: &SignedRequest, at: u64) -> Result<Value> {
        r.authenticate("product-operation")?;
        if !self.config.admin_keys.contains(&r.public_key) {
            return Err("AUTHORIZATION: operator required".into());
        }
        if r.payload["operation"] != "publish-result" {
            return Err("INVALID_INPUT: publication operation".into());
        }
        let package = text(&r.payload, "packageId")?;
        root(&package)?;
        {
            let db = self.lock()?;
            if let Some(v) = Self::cached(&db, r)? {
                return Ok(v);
            }
        }
        let staging = self.data.join("public-staging").join(&package);
        let actual = staging
            .canonicalize()
            .map_err(|_| "NOT_FOUND: staging package")?;
        if actual
            != self
                .data
                .canonicalize()
                .map_err(|_| "storage unavailable")?
                .join("public-staging")
                .join(&package)
        {
            return Err("AUTHORIZATION: staging path".into());
        }
        let meta = public_json(
            &staging.join("publication.json"),
            &[
                "schema",
                "publicationPolicy",
                "license",
                "goalId",
                "input",
                "requiredBackgrounds",
                "trials",
                "files","roundId","claimId","publicationAuthorization","customerConsentId",
            ],
        )?;
        if id("public-package-v1", &meta)? != package {
            return Err("DAMAGED_ARTIFACT: publication identity".into());
        }
        let publication_type=match (meta["schema"].as_str(),meta["publicationPolicy"].as_str()) {
            (Some("flybrain-public-calibration-package-v1"),Some("public-calibration-v1"))=>"calibration-case",
            (Some("flybrain-public-protocol-package-v1"),Some("public-winner-v1"))=>"public-winner",
            (Some("flybrain-public-protocol-package-v1"),Some("public-verified-candidate-v1"))=>"verified-candidate",
            (Some("flybrain-public-protocol-package-v1"),Some("public-service-result-v1"))=>"service-result",
            _=>return Err("AUTHORIZATION: versioned publication policy".into())};
        if meta["license"] != "CC-BY-4.0" {
            return Err("AUTHORIZATION: explicit public calibration policy required".into());
        }
        let gid = text(&meta, "goalId")?;
        root(&gid)?;
        let goal: GoalSpec = {
            let db = self.lock()?;
            let g: String = sql(db.query_row(
                "SELECT spec_json FROM goal_specs WHERE goal_id=?",
                [&gid],
                |r| r.get(0),
            ))?;
            serde_json::from_str(&g).map_err(|e| e.to_string())?
        };
        let input: p::CandidateInput = serde_json::from_value(meta["input"].clone())
            .map_err(|_| "INVALID_INPUT: canonical input")?;
        goal.validate_input(&input)?;
        let trials = meta["trials"].as_array().ok_or("INVALID_INPUT: trials")?;
        let required = num(&meta, "requiredBackgrounds")? as usize;
        if ![2, 4, 8, 16].contains(&required) || trials.len() != required {
            return Err("INVALID_INPUT: complete published backgrounds".into());
        }
        let mut simulations = Vec::new();
        let mut trial_summaries = Vec::new();
        for (j, t) in trials.iter().enumerate() {
            let name = text(t, "file")?;
            if name != format!("trial-{j}.bin") {
                return Err("INVALID_INPUT: trial file".into());
            }
            let path = staging.join(&name);
            if path.canonicalize().map_err(|_| "NOT_FOUND: trial")? != actual.join(&name) {
                return Err("AUTHORIZATION: file symlink".into());
            }
            if fs::metadata(&path).map_err(|_| "NOT_FOUND: trial")?.len() > goal.max_trial_bytes {
                return Err("INVALID_INPUT: oversized trial".into());
            }
            let bytes = fs::read(&path).map_err(|_| "DAMAGED_ARTIFACT: trial")?;
            if hash(&bytes) != t["sha256"] {
                return Err("DAMAGED_ARTIFACT: publication checksum".into());
            }
            let metrics = p::evaluate(&goal, &input, &bytes)?;
            let response: std::collections::BTreeSet<_> =
                goal.response_set.iter().map(|n| n.model_index).collect();
            let baseline_count = u32::from_le_bytes(bytes[472..476].try_into().unwrap()) as usize;
            let mut paired = vec![[0u64; 2]; goal.windows.len()];
            for (i, event) in bytes[480..].chunks_exact(8).enumerate() {
                let step = u32::from_le_bytes(event[..4].try_into().unwrap());
                let neuron = u32::from_le_bytes(event[4..].try_into().unwrap());
                if response.contains(&neuron) {
                    for (j, w) in goal.windows.iter().enumerate() {
                        if step >= input.end_step + w.start_offset
                            && step < input.end_step + w.end_offset
                        {
                            paired[j][usize::from(i >= baseline_count)] += 1;
                        }
                    }
                }
            }
            let seed = text(t, "seedHex")?;
            let (sid, descriptor) = science::simulation(&goal, &input, &seed)?;
            simulations.push((sid.clone(), descriptor));
            trial_summaries.push(json!({"simulationId":sid,"seedHex":seed,"metrics":metrics,"pairedTargetCounts":paired,"bytes":bytes.len(),"sha256":hash(&bytes)}));
        }
        let (rid, readout) = science::readout(
            &goal,
            &simulations.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
        )?;
        let mut publication_link=Value::Null;
        if publication_type!="calibration-case" {
            let cid=text(&meta,"claimId")?;let round_id=text(&meta,"roundId")?;root(&cid)?;root(&round_id)?;
            let mut locked=self.lock()?;let db=sql(locked.transaction_with_behavior(TransactionBehavior::Immediate))?;let(source,status,miner):(String,String,String)=sql(db.query_row("SELECT manifest_json,status,miner_id FROM candidate_reveals JOIN candidate_claims USING(claim_id) WHERE claim_id=? AND round_id=?",params![cid,round_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))))?;
            let source:CandidateManifest=serde_json::from_str(&source).map_err(|_|"source manifest")?;
            if status!="VALID"||source.input!=input||source.goal_id!=gid||source.trials.len()!=required||source.trials.iter().zip(trial_summaries.iter()).any(|(s,t)|s.result_root!=t["sha256"]||s.seed_hex!=t["seedHex"]) {return Err("AUTHORIZATION: published protocol source mismatch".into());}
            if publication_type=="public-winner"&&sql(db.query_row("SELECT COUNT(*) FROM round_winners WHERE claim_id=?",[&cid],|r|r.get::<_,u64>(0)))?!=1{return Err("AUTHORIZATION: published winner source".into());}
            let permission=&meta["publicationAuthorization"];let message=json!({"claimId":cid,"roundId":round_id,"goalResultRoot":source.goal_result_root,"publicationPolicy":meta["publicationPolicy"],"license":meta["license"]});
            if permission["publicKey"]!=miner||permission["message"]!=message {return Err("AUTHORIZATION: contributor disclosure consent".into());}
            let key=VerifyingKey::from_bytes(&p::unhex(&miner)?.try_into().map_err(|_|"key")?).map_err(|_|"key")?;
            key.verify_strict(&p::unhex(&id("public-disclosure-v1",&message)?)?,&Signature::from_slice(&p::unhex(&text(permission,"signature")?)?).map_err(|_|"signature")?).map_err(|_|"BAD_SIGNATURE: publication authorization")?;
            if publication_type=="service-result" {
                let consent=text(&meta,"customerConsentId")?;root(&consent)?;
                let mut q=sql(db.prepare("SELECT d.request_id,d.manifest_root FROM private_deliveries d JOIN private_delivery_events e ON d.request_id=e.request_id AND d.manifest_root=e.manifest_root WHERE e.kind='approve-publication' AND json_extract(d.manifest,'$.readoutId')=?"))?;
                let rows=sql(q.query_map([&rid],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
                if !rows.iter().any(|(sid,root)|id("customer-publication-consent-v1",&json!({"requestId":sid,"manifestRoot":root,"scope":"versioned-public-scientific-package-only"})).is_ok_and(|h|h==consent)){return Err("AUTHORIZATION: explicit customer consent".into());}
            }
            let winner=sql(db.query_row("SELECT COUNT(*) FROM round_winners WHERE claim_id=?",[&cid],|r|r.get::<_,u64>(0)))?==1;
            self.product_capture_kind_tx(&db,&round_id,&cid,at,if winner{"discovery"}else{"verified-candidate"})?;
            let (contribution,acceptance):(String,String)=sql(db.query_row("SELECT c.id,a.id FROM science_contributions c JOIN science_acceptances a ON c.id=a.contribution_id WHERE c.authorization=? AND c.readout_id=?",params![cid,rid],|r|Ok((r.get(0)?,r.get(1)?))))?;
            publication_link=json!({"roundId":round_id,"claimId":cid,"contributionId":contribution,"acceptanceId":acceptance});
            sql(db.commit())?;
        }
        let task = science::task(&goal)?;
        let allow = [
            "goal.json",
            "input.json",
            "publication.json",
            "reproduction.json",
            "reproduce.py",
            "target_trial",
            "target_trial.rs",
            "graph.bin",
            "model.bin",
            "README.txt",
            "native-replay.json",
            "numpy-replay.json",
        ];
        let mut files = Vec::new();
        let list = meta["files"].as_array().ok_or("INVALID_INPUT: files")?;
        if list.len() > 32 {
            return Err("INVALID_INPUT: file bound".into());
        }
        for f in list {
            let name = text(f, "name")?;
            file_name(&name)?;
            if files.iter().any(|(n, _, _, _)| n == &name) {
                return Err("INVALID_INPUT: duplicate public file".into());
            }
            if !allow.contains(&name.as_str())
                && !((0..required).any(|j| name == format!("trial-{j}.bin")))
            {
                return Err("AUTHORIZATION: public file whitelist".into());
            }
            let path = staging.join(&name);
            if path.canonicalize().map_err(|_| "NOT_FOUND: public file")? != actual.join(&name) {
                return Err("AUTHORIZATION: public file symlink".into());
            }
            if name.ends_with(".json")
                && fs::metadata(&path)
                    .map_err(|_| "NOT_FOUND: metadata")?
                    .len()
                    > 1024 * 1024
            {
                return Err("INVALID_INPUT: metadata size".into());
            }
            let (sha, bytes) = digest_file(&path)?;
            if sha != f["sha256"] || bytes != num(f, "bytes")? {
                return Err("DAMAGED_ARTIFACT: public file checksum".into());
            }
            let mime = if name.ends_with(".json") {
                "application/json"
            } else if name.ends_with(".txt") || name.ends_with(".rs") || name.ends_with(".py") {
                "text/plain; charset=utf-8"
            } else {
                "application/octet-stream"
            };
            files.push((name, sha, bytes, mime));
        }
        for name in [
            "goal.json",
            "input.json",
            "reproduction.json",
            "reproduce.py",
            "graph.bin",
            "model.bin",
            "native-replay.json",
            "target_trial",
        ] {
            if !files.iter().any(|(n, _, _, _)| n == name) {
                return Err("INVALID_INPUT: incomplete reproduction package".into());
            }
        }
        for j in 0..required {
            if !files
                .iter()
                .any(|(n, _, _, _)| n == &format!("trial-{j}.bin"))
            {
                return Err("INVALID_INPUT: missing complete events".into());
            }
        }
        let reproduction = public_json(
            &staging.join("reproduction.json"),
            &[
                "schema",
                "modelRoots",
                "goalId",
                "input",
                "trials",
                "files",
                "command",
                "environment",
                "source",
            ],
        )?;
        if reproduction["goalId"] != meta["goalId"]
            || reproduction["input"] != value(&input)
            || reproduction["trials"] != meta["trials"]
            || reproduction["schema"] != "flybrain-reproduction-v1"
            || reproduction["command"] != "python3 reproduce.py"
        {
            return Err("INVALID_INPUT: reproduction bindings".into());
        }
        for (k, v) in reproduction["modelRoots"]
            .as_object()
            .ok_or("INVALID_INPUT: model roots")?
        {
            if value(&goal).get(k) != Some(v) {
                return Err("INVALID_INPUT: reproduction roots".into());
            }
        }
        let expected_files: Vec<_> = list
            .iter()
            .filter(|f| f["name"] != "reproduction.json")
            .cloned()
            .collect();
        if reproduction["files"] != json!(expected_files) {
            return Err("INVALID_INPUT: reproduction files".into());
        }
        if serde_json::from_slice::<Value>(
            &fs::read(staging.join("goal.json")).map_err(|_| "missing goal")?,
        )
        .map_err(|_| "goal JSON")?
            != value(&goal)
            || serde_json::from_slice::<Value>(
                &fs::read(staging.join("input.json")).map_err(|_| "missing input")?,
            )
            .map_err(|_| "input JSON")?
                != value(&input)
        {
            return Err("INVALID_INPUT: frozen science files").map_err(String::from);
        }
        let native: Value = serde_json::from_slice(
            &fs::read(staging.join("native-replay.json")).map_err(|_| "missing native report")?,
        )
        .map_err(|_| "native report JSON")?;
        let reports = native.as_array().ok_or("native replay array")?;
        if reports.len() != required
            || reports.iter().zip(trial_summaries.iter()).any(|(r, t)| {
                r["replayVerified"] != true
                    || r["resultRoot"] != t["sha256"]
                    || r["seedHex"] != t["seedHex"]
                    || r["metrics"] != t["metrics"]
                    || r.as_object().is_none_or(|o| {
                        o.keys().any(|k| {
                            ![
                                "schema",
                                "bytes",
                                "elapsedMs",
                                "metrics",
                                "neuronUpdates",
                                "replayVerified",
                                "resultRoot",
                                "seedHex",
                                "steps",
                                "synapticAdditions",
                            ]
                            .contains(&k.as_str())
                        })
                    })
            })
        {
            return Err("INVALID_INPUT: native replay evidence".into());
        }
        let graph = files.iter().find(|(n, _, _, _)| n == "graph.bin").unwrap();
        let model = files.iter().find(|(n, _, _, _)| n == "model.bin").unwrap();
        if graph.1 != goal.graph_root || model.1 != goal.model_data_root {
            return Err("DAMAGED_ARTIFACT: frozen model".into());
        }
        let passed = trial_summaries
            .iter()
            .all(|t| t["metrics"]["passed"] == true);
        let summary = json!({"id":rid,"title":{"zh":format!("神经元 {} 的配对刺激响应",input.stimulated_body_id),"en":format!("Paired stimulus response of neuron {}",input.stimulated_body_id)},"taskId":gid,"scientificTaskId":task,"modelRoot":goal.model_root,"parameterVersion":goal.parameter_version,"sourceRoot":goal.source_root,"graphRoot":goal.graph_root,"parameterProfileHash":goal.parameter_profile_hash,"input":input,"trials":trial_summaries,"requiredBackgrounds":required,"steps":goal.steps,"timeStepUs":goal.time_step_us,"windows":goal.windows,"resultType":if publication_type=="calibration-case"{if passed{"complete-passed"}else{"complete-not-passed"}}else{publication_type},"publicationType":publication_type,"protocolLinks":publication_link,"evidenceLevel":"full-model-replayed","trust":{"operators":1,"independentInstitutions":0,"externalObservation":false,"protocolRoundWinner":publication_type=="public-winner","scope":if publication_type=="calibration-case"{"public-calibration-case-new-native-replay"}else{"authorized-protocol-replay-result"}},"readoutId":rid,"simulationIds":simulations.iter().map(|x|&x.0).collect::<Vec<_>>(),"publicationPolicy":meta["publicationPolicy"],"license":"CC-BY-4.0","attribution":"MaleCNS source dataset contributors; flybrain model outputs and reproduction materials; source-specific licensing applies","economicPolicy":if publication_type=="calibration-case"{"unbudgeted-calibration-no-economic-right"}else{"scientific-publication-does-not-create-an-economic-right"},"publishedAt":at});
        let destination = self.data.join("public-results").join(&rid);
        fs::create_dir_all(&destination).map_err(|_| "storage: public package")?;
        for (name, sha, bytes, _) in &files {
            let to = destination.join(name);
            if to.exists() {
                if digest_file(&to)? != (sha.clone(), *bytes) {
                    return Err("CONFLICT: immutable public file".into());
                }
            } else {
                self.install_public_object(&staging.join(name),&to,sha,*bytes)?;
            }
        }
        // Replace explicitly-public staging copies with links to the same
        // immutable public objects; private permission domains are not touched.
        for(name,sha,bytes,_)in &files {self.install_public_object(&staging.join(name),&staging.join(name),sha,*bytes)?;}
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        for (sid, v) in simulations {
            sql(tx.execute(
                "INSERT OR IGNORE INTO science_simulations VALUES(?,?)",
                params![sid, v.to_string()],
            ))?;
        }
        sql(tx.execute(
            "INSERT OR IGNORE INTO science_readouts VALUES(?,?)",
            params![rid, readout.to_string()],
        ))?;
        sql(tx.execute("INSERT OR IGNORE INTO public_results(id,task_id,model_root,input_body,result_type,evidence_level,summary,publication_policy,published_at) VALUES(?,?,?,?,?,?,?,?,?)",params![rid,gid,goal.model_root,input.stimulated_body_id,summary["resultType"].as_str(),"full-model-replayed",summary.to_string(),meta["publicationPolicy"].as_str(),at]))?;
        Self::index_result_neurons_tx(&tx,&rid,&goal,&input)?;
        let statement=self.signed("public-result-statement-v1",json!({"resultId":rid,"packageId":package,"publicationPolicy":meta["publicationPolicy"],"publicationType":publication_type,"protocolLinks":publication_link,"publishedAt":at}))?;
        sql(tx.execute("INSERT OR IGNORE INTO publication_links VALUES(?,?,?,?,?,?,?)",params![rid,publication_type,publication_link["roundId"].as_str(),publication_link["claimId"].as_str(),publication_link["contributionId"].as_str(),publication_link["acceptanceId"].as_str(),statement.to_string()]))?;
        for (name, sha, bytes, mime) in files {
            sql(tx.execute(
                "INSERT OR IGNORE INTO public_result_files VALUES(?,?,?,?,?)",
                params![rid, name, sha, bytes, mime],
            ))?;
        }
        sql(tx.execute("INSERT INTO product_audit(kind,actor,payload,created_at) VALUES('PUBLICATION',?,?,?)",params![r.public_key,json!({"resultId":rid,"packageId":package,"publicationPolicy":meta["publicationPolicy"]}).to_string(),at]))?;
        let receipt = json!({"resultId":rid,"published":true,"economicRight":false});
        Self::remember(&tx, r, &receipt)?;sql(tx.commit())?;drop(db);self.backfill_public_response_roles()?;Ok(receipt)
    }
    pub fn service_session(&self, source: &str, at: u64) -> Result<Value> {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).map_err(|_| "service entropy unavailable")?;
        let token = p::hex(&b);
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let bucket = at / 3600;
        let count: u64 = sql(tx
            .query_row(
                "SELECT count FROM service_limits WHERE source_hash=? AND bucket=?",
                params![source, bucket],
                |r| r.get(0),
            )
            .optional())?
        .unwrap_or(0);
        if count >= 30 {
            return Err("RATE_LIMIT: request session".into());
        }
        sql(tx.execute("INSERT INTO service_limits VALUES(?,?,1) ON CONFLICT(source_hash,bucket) DO UPDATE SET count=count+1",params![source,bucket]))?;
        sql(tx.execute("DELETE FROM service_sessions WHERE expires<?", [at]))?;
        sql(tx.execute(
            "DELETE FROM service_limits WHERE bucket<?",
            [bucket.saturating_sub(48)],
        ))?;
        sql(tx.execute(
            "INSERT INTO service_sessions VALUES(?,?,?,0)",
            params![hash(token.as_bytes()), source, at + 1800],
        ))?;
        sql(tx.commit())?;
        Ok(json!({"csrfToken":token,"expires":at+1800}))
    }
    pub fn service_create(&self, v: &Value, source: &str, at: u64) -> Result<Value> {
        let request = clean(v, "requestId", 8, 128)?;
        let access = text(v, "accessToken")?;
        root(&access)?;
        let fields = &v["fields"];
        let problem = clean(fields, "problem", 10, 4000)?;
        let contact = clean(fields, "contact", 5, 160)?;
        let name = clean(fields, "name", 1, 120)?;
        let kind = clean(fields, "taskType", 1, 40)?;
        if ![
            "stimulus-search",
            "response-comparison",
            "public-sponsorship",
            "results-delivery",
            "privacy-request",
        ]
        .contains(&kind.as_str())
        {
            return Err("INVALID_INPUT: taskType".into());
        }
        let deadline = clean(fields, "deadline", 0, 100)?;
        let budget = clean(fields, "budget", 0, 120)?;
        let publication = clean(fields, "publication", 1, 32)?;
        if !["public", "restricted-review", "discuss"].contains(&publication.as_str()) {
            return Err("INVALID_INPUT: publication preference".into());
        }
        if fields["termsAccepted"] != true {
            return Err("INVALID_INPUT: terms acceptance required".into());
        }
        let f = json!({"problem":problem,"contact":contact,"name":name,"taskType":kind,"deadline":deadline,"budget":budget,"publication":publication,"termsAccepted":true});
        let request_hash = id(
            "service-request-v1",
            &json!({"fields":f,"requestId":request,"accessHash":hash(access.as_bytes())}),
        )?;
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if let Some((sid, h)) = sql(tx
            .query_row(
                "SELECT id,request_hash FROM service_requests WHERE request_id=?",
                [&request],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional())?
        {
            if h != request_hash {
                return Err("CONFLICT: idempotency payload".into());
            }
            return Ok(json!({"ticketId":sid,"status":"received","saved":true,"duplicate":true}));
        }
        let csrf = text(v, "csrfToken")?;
        root(&csrf)?;
        let session: Option<(String, u64, bool)> = sql(tx
            .query_row(
                "SELECT source_hash,expires,used FROM service_sessions WHERE token_hash=?",
                [hash(csrf.as_bytes())],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional())?;
        if !session.is_some_and(|(s, e, u)| s == source && e >= at && !u) {
            return Err("AUTHORIZATION: expired request session".into());
        }
        let recent: u64 = sql(tx.query_row(
            "SELECT COUNT(*) FROM service_requests WHERE created_at>?",
            [at.saturating_sub(3600)],
            |r| r.get(0),
        ))?;
        if recent >= 1000 {
            return Err("RATE_LIMIT: service intake capacity".into());
        }
        let sid = format!("FR-{}-{}", at, &random_suffix()?[..8]);
        sql(tx.execute(
            "INSERT INTO service_requests VALUES(?,?,?,?,?,'received',?,?)",
            params![
                sid,
                request,
                request_hash,
                hash(access.as_bytes()),
                f.to_string(),
                at,
                at
            ],
        ))?;
        sql(tx.execute(
            "UPDATE service_sessions SET used=1 WHERE token_hash=?",
            [hash(csrf.as_bytes())],
        ))?;
        sql(tx.execute("INSERT INTO service_events(request_id,actor,status,basis,created_at) VALUES(?,'requester','received','saved-successfully',?)",params![sid,at]))?;
        sql(tx.commit())?;
        Ok(
            json!({"ticketId":sid,"status":"received","saved":true,"duplicate":false,"orderConfirmed":false,"incomeRecorded":false}),
        )
    }
    pub fn service_lookup(&self, v: &Value) -> Result<Value> {
        let token = text(v, "accessToken")?;
        let sid=if v["ticketId"].is_string(){clean(v,"ticketId",8,80)?}else{let request=clean(v,"requestId",8,128)?;let db=self.lock()?;sql(db.query_row("SELECT id FROM service_requests WHERE request_id=? AND access_hash=?",params![request,hash(token.as_bytes())],|r|r.get::<_,String>(0)).optional())?.ok_or("AUTHORIZATION: pending receipt required")?};
        root(&token)?;
        let db = self.lock()?;
        let row:Option<(String,String,u64,u64)>=sql(db.query_row("SELECT fields,status,created_at,updated_at FROM service_requests WHERE id=? AND access_hash=?",params![sid,hash(token.as_bytes())],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional())?;
        let Some((f, status, at, updated)) = row else {
            return Err("AUTHORIZATION: ticket receipt required".into());
        };
        let mut stmt=sql(db.prepare("SELECT status,basis,created_at FROM service_events WHERE request_id=? ORDER BY sequence"))?;
        let events=sql(stmt.query_map([&sid],|r|Ok(json!({"status":r.get::<_,String>(0)?,"basis":r.get::<_,String>(1)?,"at":r.get::<_,u64>(2)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
        let quotes = {
            let mut q=sql(db.prepare("SELECT id,asset,amount_atoms,expires,terms,confirmed_by FROM economic_quotes WHERE request_id=? ORDER BY created_at DESC,rowid DESC"))?;
            let rows=sql(q.query_map([&sid],|r|Ok(json!({"id":r.get::<_,String>(0)?,"asset":r.get::<_,String>(1)?,"amountAtoms":r.get::<_,String>(2)?,"expires":r.get::<_,u64>(3)?,"terms":r.get::<_,String>(4)?,"confirmed":r.get::<_,Option<String>>(5)?.is_some()}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
            rows
        };
        let mut quotes=quotes;for(i,q)in quotes.iter_mut().enumerate(){q["current"]=json!(i==0);q["superseded"]=json!(i>0);q["actionable"]=json!(i==0&&q["confirmed"]==false&&q["expires"].as_u64().is_some_and(|n|n>now()));}
        let delivery:Option<(String,String,String)>=sql(db.query_row("SELECT manifest,manifest_root,signature FROM private_deliveries WHERE request_id=?",[&sid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?;
        let mut delivery_events=Vec::new();let mut q=sql(db.prepare("SELECT kind,manifest_root,created_at FROM private_delivery_events WHERE request_id=? ORDER BY sequence"))?;for row in sql(q.query_map([&sid],|r|Ok(json!({"kind":r.get::<_,String>(0)?,"manifestRoot":r.get::<_,String>(1)?,"at":r.get::<_,u64>(2)?}))))?{delivery_events.push(sql(row)?);}
        Ok(
            json!({"delivery":delivery.map(|(m,root,sig)|Ok::<_,String>(json!({"manifest":parse(m)?,"manifestRoot":root,"signature":sig,"available":"receipt-authorized-download","events":delivery_events}))).transpose()?,"ticketId":sid,"fields":parse(f)?,"quotes":quotes,"status":status,"createdAt":at,"updatedAt":updated,"events":events}),
        )
    }
    pub fn product_operation(&self, r: &SignedRequest, at: u64) -> Result<Value> {
        r.authenticate("product-operation")?;
        if !self.config.admin_keys.contains(&r.public_key) {
            return Err("AUTHORIZATION: operator required".into());
        }
        let op = text(&r.payload, "operation")?;
        if op == "publish-result" {
            return self.publish_product_package(r, at);
        }
        if op=="register-evidence-manifest" {
            let mut manifest=r.payload["manifest"].clone();
            let config:Value=serde_json::from_slice(&fs::read(self.data.join("private/economic-settlement-config.json")).map_err(|_|"NOT_CONFIGURED: audited evidence chain identity")?).map_err(|_|"config")?;
            if config["enabled"]!=true||manifest["genesisHash"]!=config["genesisHash"]||manifest["programId"]!=config["programId"]||manifest["policyHash"]!=config["policyHash"]{return Err("NOT_CONFIGURED: frozen evidence chain/policy binding".into());}
            let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
            if let Some(private)=r.payload["privateEvidence"].as_array(){if private.len()>16{return Err("INVALID_INPUT: private evidence bound".into());}let mut commitments=Vec::new();for payload in private{if canonical(payload)?.len()>8192{return Err("INVALID_INPUT: private evidence size".into());}let mut salt=[0u8;32];getrandom::fill(&mut salt).map_err(|_|"private commitment entropy")?;let binding=json!({"saltHex":p::hex(&salt),"payload":payload});let commitment=id("randomized-private-evidence-v1",&binding)?;sql(tx.execute("INSERT INTO private_evidence_commitments VALUES(?,?,?)",params![commitment,binding.to_string(),at]))?;commitments.push(json!({"schema":"randomized-sha256-commitment-v1","root":commitment}));}manifest["privateCommitments"]=json!(commitments);}
            let root=crate::evidence_manifest::digest(&manifest)?;
            for commitment in manifest["privateCommitments"].as_array().unwrap(){if sql(tx.query_row("SELECT COUNT(*) FROM private_evidence_commitments WHERE root=?",[commitment["root"].as_str().unwrap()],|r|r.get::<_,u64>(0)))?!=1{return Err("AUTHORIZATION: registered randomized private commitment required".into());}}

            if ["discovery","coverage","readout"].contains(&manifest["kind"].as_str().unwrap_or("")) {
                let(cid,acceptance,readout)=(text(&manifest,"contributionId")?,text(&manifest,"acceptanceId")?,text(&manifest,"readoutId")?);
                let count:u64=sql(tx.query_row("SELECT COUNT(*) FROM science_contributions c JOIN science_acceptances a ON c.id=a.contribution_id WHERE c.id=? AND a.id=? AND c.readout_id=?",params![cid,acceptance,readout],|r|r.get(0)))?;
                if count!=1{return Err("AUTHORIZATION: manifest science source".into());}
                let gid=text(&manifest,"goalId")?;let goal:GoalSpec=serde_json::from_str(&sql(tx.query_row("SELECT spec_json FROM goal_specs WHERE goal_id=?",[&gid],|r|r.get::<_,String>(0)))?).map_err(|_|"goal")?;
                let task_id:String=sql(tx.query_row("SELECT task_id FROM science_contributions WHERE id=?",[&cid],|r|r.get(0)))?;
                if task_id!=science::task(&goal)?||manifest["modelRoot"]!=goal.model_root||manifest["graphRoot"]!=goal.graph_root||manifest["parameterProfileHash"]!=goal.parameter_profile_hash||manifest["evaluatorVersion"]!=goal.evaluator_version{return Err("AUTHORIZATION: original scientific model/task binding".into());}
                if manifest["kind"]=="discovery"{let claim=text(&manifest,"claimId")?;let round=text(&manifest,"roundId")?;if sql(tx.query_row("SELECT COUNT(*) FROM round_winners w JOIN science_contributions c ON c.authorization=w.claim_id WHERE w.claim_id=? AND w.round_id=? AND c.id=?",params![claim,round,cid],|r|r.get::<_,u64>(0)))?!=1{return Err("AUTHORIZATION: discovery winner source".into());}}
            }else{
                let order=&r.payload["workOrder"];if order["schema"]!="flybrain-authorized-economic-work-order-v1"||order["kind"]!=manifest["kind"]||order["economicTaskId"]!=manifest["economicTaskId"]||order["unitId"]!=manifest["unitId"]||order["policyHash"]!=manifest["policyHash"]||id("authorized-economic-work-order-v1",order)?!=manifest["authorizationId"]{return Err("AUTHORIZATION: authorized verification/community work order".into());}
            }
            let book:flypow_economic_core::Book=serde_json::from_str(&sql(tx.query_row("SELECT state FROM economic_books WHERE asset=?",[text(&config,"asset")?],|r|r.get::<_,String>(0)))?).map_err(|_|"book")?;
            if !book.slots.values().any(|s|s.genesis_hash==manifest["genesisHash"]&&s.program_id==manifest["programId"]&&s.economic_task==manifest["economicTaskId"]&&s.kind==manifest["kind"]&&s.unit_id==manifest["unitId"]&&s.contribution==manifest["contributionId"]&&!s.released){return Err("AUTHORIZATION: reserved immutable EconomicSlotKey/contribution required".into());}
            let signature=self.sign("public-evidence-manifest-v1",&manifest)?;
            sql(tx.execute("INSERT OR IGNORE INTO evidence_manifests VALUES(?,?,?,?)",params![root,manifest.to_string(),signature,at]))?;
            sql(tx.commit())?;return Ok(json!({"evidenceManifestRoot":root,"manifest":manifest,"signature":signature,"scientificVerification":"separate authorized full replay","privateMaterials":"commitments only"}));
        }
        if op == "record-operating-entry" {
            return self.record_operating_entry(r, at);
        }
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if op == "list-requests" {
            let before = r.payload["before"].as_u64().unwrap_or(u64::MAX);
            let before_id = r.payload["beforeId"].as_str().unwrap_or("~");
            let mut q=sql(tx.prepare("SELECT id,fields,status,created_at,updated_at FROM service_requests WHERE created_at<? OR (created_at=? AND id<?) ORDER BY created_at DESC,id DESC LIMIT 50"))?;
            let rows=sql(q.query_map(params![before.min(i64::MAX as u64),before.min(i64::MAX as u64),before_id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"fields":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"status":r.get::<_,String>(2)?,"createdAt":r.get::<_,u64>(3)?,"updatedAt":r.get::<_,u64>(4)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
            return Ok(
                json!({"items":rows,"nextCursor":rows.last().map(|r|json!({"before":r["createdAt"],"beforeId":r["id"]})),"private":true}),
            );
        }
        if let Some(v) = Self::cached(&tx, r)? {
            return Ok(v);
        }
        let sid = clean(&r.payload, "ticketId", 8, 80)?;
        if op == "quote-request" {
            let current: String = sql(tx.query_row(
                "SELECT status FROM service_requests WHERE id=?",
                [&sid],
                |r| r.get(0),
            ))?;
            if ["executing", "delivered", "closed"].contains(&current.as_str()) {
                return Err("CONFLICT: quote lifecycle".into());
            }
            let _: String = sql(tx.query_row(
                "SELECT id FROM service_requests WHERE id=?",
                [&sid],
                |r| r.get(0),
            ))?;
            let asset = clean(&r.payload, "asset", 1, 128)?;
            let amount = text(&r.payload, "amountAtoms")?;
            let n = amount
                .parse::<u64>()
                .map_err(|_| "INVALID_INPUT: quote atoms")?;
            let expires = num(&r.payload, "expires")?;
            let terms = clean(&r.payload, "terms", 20, 4000)?;
            if n == 0 || n.to_string() != amount || expires <= at || expires > at + 30 * 86400 {
                return Err("INVALID_INPUT: quote bounds".into());
            }
            let qid = id(
                "service-quote-v1",
                &json!({"ticketId":sid,"asset":asset,"amountAtoms":amount,"terms":terms,"expires":expires,"operator":r.public_key}),
            )?;
            sql(tx.execute("INSERT OR IGNORE INTO economic_quotes(id,request_id,asset,amount_atoms,expires,terms,created_at) VALUES(?,?,?,?,?,?,?)",params![qid,sid,asset,amount,expires,terms,at]))?;
            sql(tx.execute(
                "UPDATE service_requests SET status='quote-confirmation',updated_at=? WHERE id=?",
                params![at, sid],
            ))?;
            sql(tx.execute("INSERT INTO service_events(request_id,actor,status,basis,created_at) VALUES(?,?,'quote-confirmation','quote-saved-budget-not-received',?)",params![sid,r.public_key,at]))?;
            let out = json!({"quoteId":qid,"saved":true,"paid":false});
            Self::remember(&tx, r, &out)?;
            sql(tx.commit())?;
            return Ok(out);
        }
        if op == "assign-request" || op == "deliver-request" {
            let mut configuration: Value = serde_json::from_slice(
                &fs::read(self.data.join("private/economic-settlement-config.json"))
                    .map_err(|_| "CONDITIONS_REQUIRED: audited asset required")?,
            )
            .map_err(|_| "CONDITIONS_REQUIRED: settlement identity")?;
            if configuration["enabled"] != true
                || configuration["networkId"] != self.config.network_id
                || configuration["authorityId"] != self.authority_id
            {
                return Err("CONDITIONS_REQUIRED: settlement identity".into());
            }
            let basis = clean(&r.payload, "basis", 1, 1200)?;
            let current: String = sql(tx.query_row(
                "SELECT status FROM service_requests WHERE id=?",
                [&sid],
                |r| r.get(0),
            ))?;
            if (op == "assign-request" && current != "budget-required")
                || (op == "deliver-request" && current != "executing")
            {
                return Err("CONFLICT: service lifecycle".into());
            }
            if op == "assign-request" {
                let asset = text(&r.payload, "asset")?;
                let stage_id = text(&r.payload, "stageId")?;
                let slot_id = text(&r.payload, "slotId")?;
                let gid = text(&r.payload, "goalId")?;
                root(&gid)?;
                if configuration["asset"] != asset {
                    return Err("INVALID_INPUT: service asset".into());
                }
                let (quote_id,quote_asset,amount):(String,String,String)=sql(tx.query_row("SELECT id,asset,amount_atoms FROM economic_quotes WHERE request_id=? AND confirmed_by IS NOT NULL ORDER BY created_at DESC,rowid DESC LIMIT 1",[&sid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?.ok_or("CONDITIONS_REQUIRED: confirmed quote")?;
                let science_task: GoalSpec = serde_json::from_str(&sql(tx.query_row(
                    "SELECT spec_json FROM goal_specs WHERE goal_id=?",
                    [&gid],
                    |r| r.get::<_, String>(0),
                ))?)
                .map_err(|_| "INVALID_INPUT: registered task")?;
                let encoded: String = sql(tx.query_row(
                    "SELECT state FROM economic_books WHERE asset=?",
                    [&asset],
                    |r| r.get(0),
                ))?;
                let book: flypow_economic_core::Book =
                    serde_json::from_str(&encoded).map_err(|_| "storage: book")?;
                book.reconcile()
                    .map_err(|_| "CONDITIONS_REQUIRED: budget reconciliation")?;
                let slot = book
                    .slots
                    .get(&slot_id)
                    .ok_or("CONDITIONS_REQUIRED: funded task slot")?;
                let stage = book
                    .stages
                    .get(&stage_id)
                    .ok_or("CONDITIONS_REQUIRED: funded stage")?;
                if slot.stage != stage_id
                    || slot.released
                    || stage.closed
                    || stage.deadline <= at
                    || slot.economic_task != science::task(&science_task)?
                    || quote_asset != asset
                    || slot.amount.0 < amount.parse::<u64>().map_err(|_| "amount")?
                {
                    return Err("CONDITIONS_REQUIRED: quote/task/budget binding".into());
                }
                sql(tx.execute(
                    "INSERT INTO service_task_bindings VALUES(?,?,?,?,?,?,?)",
                    params![sid, asset, stage_id, slot_id, gid, quote_id, at],
                ))?;
                configuration["newStatus"] = json!("executing");
            } else {
                let cid = text(&r.payload, "contributionId")?;
                root(&cid)?;
                let (asset,stage_id,slot_id,gid):(String,String,String,String)=sql(tx.query_row("SELECT asset,stage_id,slot_id,goal_id FROM service_task_bindings WHERE request_id=?",[&sid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))))?;
                let encoded: String = sql(tx.query_row(
                    "SELECT state FROM economic_books WHERE asset=?",
                    [&asset],
                    |r| r.get(0),
                ))?;
                let book: flypow_economic_core::Book =
                    serde_json::from_str(&encoded).map_err(|_| "storage: book")?;
                let slot = book
                    .slots
                    .get(&slot_id)
                    .ok_or("CONDITIONS_REQUIRED: task slot")?;
                if !slot.accepted || slot.stage != stage_id || slot.contribution != cid {
                    return Err("CONDITIONS_REQUIRED: confirmed task contribution".into());
                }
                let task: GoalSpec = serde_json::from_str(&sql(tx.query_row(
                    "SELECT spec_json FROM goal_specs WHERE goal_id=?",
                    [gid],
                    |r| r.get::<_, String>(0),
                ))?)
                .map_err(|_| "task")?;
                let readout:String=sql(tx.query_row("SELECT readout_id FROM science_contributions c JOIN science_acceptances a ON c.id=a.contribution_id WHERE c.id=? AND c.task_id=? AND a.judgement='protocol-full-replay'",params![cid,science::task(&task)?],|r|r.get(0)))?;
                self.freeze_delivery_tx(&tx,&sid,&readout,&cid,&r.payload["deliveryManifest"],at)?;
                sql(tx.execute(
                    "INSERT INTO service_deliveries VALUES(?,?,?,?)",
                    params![sid, readout, cid, at],
                ))?;
                configuration["newStatus"] = json!("delivered");
            }
            let state = text(&configuration, "newStatus")?;
            sql(tx.execute(
                "UPDATE service_requests SET status=?,updated_at=? WHERE id=? AND status!='closed'",
                params![state, at, sid],
            ))?;
            sql(tx.execute("INSERT INTO service_events(request_id,actor,status,basis,created_at) VALUES(?,?,?,?,?)",params![sid,r.public_key,state,basis,at]))?;
            let receipt =
                json!({"ticketId":sid,"status":state,"saved":true,"incomeRecognized":false});
            Self::remember(&tx, r, &receipt)?;
            sql(tx.commit())?;
            return Ok(receipt);
        }
        let prior: String = sql(tx
            .query_row(
                "SELECT status FROM service_requests WHERE id=?",
                [&sid],
                |r| r.get(0),
            )
            .optional())?
        .ok_or("NOT_FOUND: ticket")?;
        let basis = clean(&r.payload, "basis", 1, 1200)?;
        let state = clean(&r.payload, "status", 1, 40)?;
        if op == "redact-request" {
            sql(tx.execute(
                "UPDATE service_requests SET fields='{}',status='closed',updated_at=? WHERE id=?",
                params![at, sid],
            ))?;
        } else if op == "update-request" {
            if !SERVICE_STATES.contains(&state.as_str())
                || [
                    "executing",
                    "delivered",
                    "quote-confirmation",
                    "budget-required",
                ]
                .contains(&state.as_str())
            {
                return Err(
                    "CONDITIONS_REQUIRED: funded authorized task and delivery receipt".into(),
                );
            }
            let old = SERVICE_STATES
                .iter()
                .position(|s| *s == prior)
                .ok_or("invalid request state")?;
            let new = SERVICE_STATES.iter().position(|s| *s == state).unwrap();
            if new < old {
                return Err("CONFLICT: request state transition".into());
            }
            sql(tx.execute(
                "UPDATE service_requests SET status=?,updated_at=? WHERE id=?",
                params![state, at, sid],
            ))?;
        } else {
            return Err("INVALID_INPUT: operation".into());
        }
        sql(tx.execute("INSERT INTO service_events(request_id,actor,status,basis,created_at) VALUES(?,?,?,?,?)",params![sid,r.public_key,if op=="redact-request"{"closed"}else{&state},basis,at]))?;
        let out = json!({"ticketId":sid,"status":if op=="redact-request"{"closed"}else{&state},"saved":true});
        Self::remember(&tx, r, &out)?;
        sql(tx.commit())?;
        Ok(out)
    }
    pub fn product_records(&self, r: &SignedRequest) -> Result<Value> {
        r.authenticate("product-records")?;
        let db = self.lock()?;
        let limit=r.payload["limit"].as_u64().unwrap_or(20).clamp(1,50);
        let cursor=r.payload["contributionCursor"].as_str().unwrap_or("");
        let (before_time,before_id)=if cursor.is_empty(){(i64::MAX,"~".to_string())}else{let decoded=String::from_utf8(p::unhex(cursor)?).map_err(|_|"INVALID_INPUT: contribution cursor")?;let(time,id)=decoded.split_once(':').ok_or("INVALID_INPUT: cursor")?;root(id)?;(time.parse::<i64>().map_err(|_|"INVALID_INPUT: cursor time")?,id.to_string())};
        let mut stmt=sql(db.prepare(
            "SELECT c.id,c.kind,c.task_id,c.readout_id,c.created_at,a.id,
                    t.goal_id,q.round_id,json_extract(v.manifest_json,'$.candidateId'),p.id
             FROM science_contributions c
             LEFT JOIN science_acceptances a ON a.contribution_id=c.id
             LEFT JOIN candidate_claims q ON q.claim_id=c.authorization AND q.miner_id=c.actor
             LEFT JOIN target_rounds t ON t.round_id=q.round_id
             LEFT JOIN candidate_reveals v ON v.claim_id=q.claim_id
             LEFT JOIN public_results p ON p.id=c.readout_id
             WHERE c.actor=? AND (c.created_at<? OR (c.created_at=? AND c.id<?)) ORDER BY c.created_at DESC,c.id DESC LIMIT ?"
        ))?;
        let mut rows=sql(stmt.query_map(params![r.public_key,before_time,before_time,before_id,limit+1],|r|Ok(json!({"contributionId":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"taskId":r.get::<_,String>(2)?,"readoutId":r.get::<_,String>(3)?,"createdAt":r.get::<_,u64>(4)?,"acceptanceId":r.get::<_,Option<String>>(5)?,"goalId":r.get::<_,Option<String>>(6)?,"roundId":r.get::<_,Option<String>>(7)?,"candidateId":r.get::<_,Option<String>>(8)?,"publicResultId":r.get::<_,Option<String>>(9)?,"economicState":"plan-publication-required","confirmedAtoms":null,"availableAtoms":null,"paidAtoms":null}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
        let has_more=rows.len()>limit as usize;rows.truncate(limit as usize);
        let contribution_cursor=if has_more {rows.last().map(|c|p::hex(format!("{}:{}",c["createdAt"],c["contributionId"].as_str().unwrap()).as_bytes()))}else{None};
        let count:u64=sql(db.query_row("SELECT COUNT(*) FROM science_contributions WHERE actor=?",[&r.public_key],|r|r.get(0)))?;
        let mut query = sql(db.prepare("SELECT asset,state FROM economic_books ORDER BY asset"))?;
        let encoded =
            sql(query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| e.to_string())?;
        let mut rights = Vec::new();let mut totals=Vec::new();
        for (asset, state) in encoded {
            let book: flypow_economic_core::Book =
                serde_json::from_str(&state).map_err(|_| "storage: economic book")?;
            book.reconcile()
                .map_err(|_| "CONDITIONS_REQUIRED: book reconciliation")?;
            let mut confirmed=0u128;let mut available=0u128;let mut inflight=0u128;let mut paid=0u128;
            for (slot_id, slot) in &book.slots {
                let owned:u64=sql(db.query_row("SELECT COUNT(*) FROM science_contributions WHERE id=? AND actor=?",params![slot.contribution,r.public_key],|r|r.get(0)))?;
                if owned==1 {
                    if slot.accepted{confirmed+=slot.amount.0 as u128;available+=(slot.amount.0-slot.paid.0-slot.inflight.0) as u128;}
                    inflight+=slot.inflight.0 as u128;paid+=slot.paid.0 as u128;
                    for c in rows.iter_mut().filter(|c|c["contributionId"]==slot.contribution) {c["economicState"]=json!(if slot.released{"released"}else if !slot.accepted{"pending-acceptance"}else if slot.paid.0==slot.amount.0{"paid"}else{"confirmed"});}

                    rights.push(json!({"slotId":slot_id,"unitId":slot.unit_id,"genesisHash":slot.genesis_hash,"programId":slot.program_id,"slotPda":slot.slot_pda,"state":if slot.released{"released"}else if !slot.accepted{"pending-acceptance"}else if slot.paid.0==slot.amount.0{"paid"}else{"confirmed"},"asset":asset,"stageId":slot.stage,"taskId":slot.economic_task,"contributionId":slot.contribution,"beneficiary":slot.beneficiary,"confirmedAtoms":if slot.accepted {Some(slot.amount.0.to_string())}else{None},"availableAtoms":if slot.accepted {Some((slot.amount.0-slot.paid.0-slot.inflight.0).to_string())}else{None},"inflightAtoms":slot.inflight.0.to_string(),"paidAtoms":slot.paid.0.to_string(),"stage":book.stages.get(&slot.stage),"payments":book.payments.iter().filter(|(_,p)|p.slot==*slot_id).map(|(id,p)|json!({"paymentId":id,"payment":p})).collect::<Vec<_>>() }));
                }
            }
            totals.push(json!({"asset":asset,"confirmedAtoms":confirmed.to_string(),"availableAtoms":available.to_string(),"inflightAtoms":inflight.to_string(),"paidAtoms":paid.to_string(),"scope":"complete authorized history, independent of contribution page"}));
        }
        rights.sort_by_key(|r|format!("{}:{}",r["asset"].as_str().unwrap(),r["slotId"].as_str().unwrap()));
        let rights_cursor=r.payload["rightsCursor"].as_str().unwrap_or("");
        let rights_after=String::from_utf8(p::unhex(rights_cursor)?).map_err(|_|"INVALID_INPUT: rights cursor")?;
        rights.retain(|r|format!("{}:{}",r["asset"].as_str().unwrap(),r["slotId"].as_str().unwrap())>rights_after);
        let rights_more=rights.len()>limit as usize;rights.truncate(limit as usize);
        let next_rights=if rights_more{rights.last().map(|r|p::hex(format!("{}:{}",r["asset"].as_str().unwrap(),r["slotId"].as_str().unwrap()).as_bytes()))}else{None};
        Ok(
            json!({"contributionCount":count.to_string(),"contributionNextCursor":contribution_cursor,"contributionHasMore":has_more,"rightsNextCursor":next_rights,"rightsHasMore":rights_more,"totals":totals,"rights":rights,"contributions":rows,"economicPolicy":serde_json::from_str::<Value>(POLICY).unwrap(),"assetBalance":null,"walletBindings":self.wallet_bindings(&db,&r.public_key)?}),
        )
    }
    fn wallet_bindings(&self, db: &Connection, miner: &str) -> Result<Vec<Value>> {
        let mut q=sql(db.prepare("SELECT id,wallet,chain,policy,created_at FROM wallet_bindings WHERE miner=? ORDER BY created_at DESC"))?;
        let result=sql(q.query_map([miner],|r|Ok(json!({"id":r.get::<_,String>(0)?,"wallet":r.get::<_,String>(1)?,"chain":r.get::<_,String>(2)?,"policy":r.get::<_,String>(3)?,"createdAt":r.get::<_,u64>(4)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;
        Ok(result)
    }
    pub fn bind_product_wallet(&self, r: &SignedRequest, at: u64) -> Result<Value> {
        r.authenticate("product-wallet-binding")?;
        let wallet = text(&r.payload, "walletHex")?;
        root(&wallet)?;
        let chain = clean(&r.payload, "chain", 1, 128)?;
        let policy = clean(&r.payload, "policy", 1, 128)?;
        if policy != "flybrain-global-supply-v2-20261011" || !chain.starts_with("solana:") {
            return Err("INVALID_INPUT: chain/policy binding".into());
        }
        let produced = num(&r.payload, "producedAt")?;
        if produced > at + 30 || at > produced + 600 {
            return Err("DEADLINE: wallet binding proof".into());
        }
        let binding = json!({"miner":r.public_key,"walletHex":wallet,"chain":chain,"policy":policy,"producedAt":produced});
        let proof = text(&r.payload, "walletSignature")?;
        let key = VerifyingKey::from_bytes(&p::unhex(&wallet)?.try_into().map_err(|_| "key")?)
            .map_err(|_| "BAD_SIGNATURE: wallet")?;
        key.verify_strict(
            &p::unhex(&id("wallet-binding-v1", &binding)?)?,
            &Signature::from_slice(&p::unhex(&proof)?)
                .map_err(|_| "BAD_SIGNATURE: wallet proof")?,
        )
        .map_err(|_| "BAD_SIGNATURE: wallet ownership")?;
        let bid = id("wallet-binding-v1", &binding)?;
        let db = self.lock()?;
        sql(db.execute(
            "INSERT OR IGNORE INTO wallet_bindings VALUES(?,?,?,?,?,?,?)",
            params![
                bid,
                r.public_key,
                wallet,
                chain,
                policy,
                serde_json::to_string(r).unwrap(),
                at
            ],
        ))?;
        Ok(
            json!({"bindingId":bid,"walletHex":wallet,"chain":chain,"historicalBeneficiariesChanged":false,"economicRight":false}),
        )
    }
    pub fn service_confirm_quote(&self, v: &Value, at: u64) -> Result<Value> {
        self.service_lookup(v)?;
        let sid = text(v, "ticketId")?;
        let qid = text(v, "quoteId")?;
        root(&qid)?;
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let expires: u64 = sql(tx
            .query_row(
                "SELECT expires FROM economic_quotes WHERE id=? AND request_id=?",
                params![qid, sid],
                |r| r.get(0),
            )
            .optional())?
        .ok_or("NOT_FOUND: quote")?;
        if expires < at {
            return Err("DEADLINE: quote expired".into());
        }
        let current: String = sql(tx.query_row(
            "SELECT status FROM service_requests WHERE id=?",
            [&sid],
            |r| r.get(0),
        ))?;
        let latest:String=sql(tx.query_row("SELECT id FROM economic_quotes WHERE request_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1",[&sid],|r|r.get(0)))?;
        if latest != qid || !["quote-confirmation", "budget-required"].contains(&current.as_str()) {
            return Err("CONFLICT: quote lifecycle".into());
        }
        let changed = sql(tx.execute(
            "UPDATE economic_quotes SET confirmed_by=? WHERE id=? AND confirmed_by IS NULL",
            params![hash(text(v, "accessToken")?.as_bytes()), qid],
        ))?;
        if changed == 1 {
            sql(tx.execute(
                "UPDATE service_requests SET status='budget-required',updated_at=? WHERE id=?",
                params![at, sid],
            ))?;
            sql(tx.execute("INSERT INTO service_events(request_id,actor,status,basis,created_at) VALUES(?,'requester','budget-required','quote-confirmed-no-payment-asserted',?)",params![sid,at]))?;
        }
        sql(tx.commit())?;
        Ok(json!({"quoteId":qid,"confirmed":true,"paid":false,"orderFunded":false}))
    }
    pub fn product_housekeeping(&self, at: u64) -> Result<()> {
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let threshold = at.saturating_sub(365 * 86400);
        sql(tx.execute("UPDATE service_requests SET fields='{}',status='closed',updated_at=? WHERE created_at<? AND fields!='{}'",params![at,threshold]))?;
        sql(tx.commit())?;
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductQuery {
    #[serde(default)]pub related:String,
    #[serde(default)]pub role:String,
    #[serde(default)]
    pub before: u64,
    #[serde(default)]
    pub after: String,
    #[serde(default = "page_size")]
    pub limit: u32,
    #[serde(default)]
    pub task: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub input: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub since: u64,
}
fn page_size() -> u32 {
    20
}
impl Default for ProductQuery {
    fn default() -> Self {
        Self {
            related:String::new(),role:String::new(),
            before: 0,
            after: String::new(),
            limit: page_size(),
            task: String::new(),
            model: String::new(),
            input: String::new(),
            kind: String::new(),
            evidence: String::new(),
            since: 0,
        }
    }
}
struct ProductError(String);
impl IntoResponse for ProductError {
    fn into_response(self) -> Response {
        let code = self.0.split(':').next().unwrap_or("UNAVAILABLE");
        let status = match code {
            "AUTHORIZATION" | "BAD_SIGNATURE" => StatusCode::FORBIDDEN,
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "CONFLICT" => StatusCode::CONFLICT,
            "RATE_LIMIT" => StatusCode::TOO_MANY_REQUESTS,
            "DAMAGED_ARTIFACT" => StatusCode::SERVICE_UNAVAILABLE,
            "DEADLINE" => StatusCode::GONE,
            "INVALID_INPUT" | "CONDITIONS_REQUIRED" => StatusCode::BAD_REQUEST,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status,Json(json!({"error":code,"retryable":status==StatusCode::SERVICE_UNAVAILABLE||status==StatusCode::TOO_MANY_REQUESTS}))).into_response()
    }
}
async fn product_block<T: Send + 'static>(
    a: Arc<Authority>,
    f: impl FnOnce(&Authority) -> Result<T> + Send + 'static,
) -> std::result::Result<T, ProductError> {
    tokio::task::spawn_blocking(move || f(&a))
        .await
        .map_err(|_| ProductError("UNAVAILABLE".into()))?
        .map_err(ProductError)
}
async fn manifest(
    State(a): State<Arc<Authority>>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, Authority::product_manifest)
        .await
        .map(Json)
}
async fn tasks(
    State(a): State<Arc<Authority>>,
    Query(q): Query<ProductQuery>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.product_tasks(&q))
        .await
        .map(Json)
}
async fn task(
    State(a): State<Arc<Authority>>,
    Path(id): Path<String>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.product_task(&id))
        .await
        .map(Json)
}
async fn results(
    State(a): State<Arc<Authority>>,
    Query(q): Query<ProductQuery>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.product_results(&q))
        .await
        .map(Json)
}
async fn result(
    State(a): State<Arc<Authority>>,
    Path(id): Path<String>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.product_result(&id))
        .await
        .map(Json)
}
async fn service_session(
    State(a): State<Arc<Authority>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> std::result::Result<Json<Value>, ProductError> {
    let source = source_key(&headers, peer.map(|p| p.0 .0));
    product_block(a, move |a| a.service_session(&source, now()))
        .await
        .map(Json)
}
async fn service_create(
    State(a): State<Arc<Authority>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(v): Json<Value>,
) -> std::result::Result<Json<Value>, ProductError> {
    let source = source_key(&headers, peer.map(|p| p.0 .0));
    product_block(a, move |a| a.service_create(&v, &source, now()))
        .await
        .map(Json)
}
async fn service_lookup(
    State(a): State<Arc<Authority>>,
    Json(v): Json<Value>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.service_lookup(&v))
        .await
        .map(Json)
}
async fn confirm_quote(
    State(a): State<Arc<Authority>>,
    Json(v): Json<Value>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.service_confirm_quote(&v, now()))
        .await
        .map(Json)
}
async fn operation(
    State(a): State<Arc<Authority>>,
    Json(r): Json<SignedRequest>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.product_operation(&r, now()))
        .await
        .map(Json)
}
async fn records(
    State(a): State<Arc<Authority>>,
    Json(r): Json<SignedRequest>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.product_records(&r))
        .await
        .map(Json)
}
async fn binding(
    State(a): State<Arc<Authority>>,
    Json(r): Json<SignedRequest>,
) -> std::result::Result<Json<Value>, ProductError> {
    product_block(a, move |a| a.bind_product_wallet(&r, now()))
        .await
        .map(Json)
}
#[derive(Deserialize)]
struct Download {
    expires: u64,
    signature: String,
}
async fn download(
    State(a): State<Arc<Authority>>,
    Path((rid, name)): Path<(String, String)>,
    Query(q): Query<Download>,
    headers: HeaderMap,
) -> std::result::Result<Response, ProductError> {
    let meta=product_block(a.clone(),move|a|{root(&rid)?;file_name(&name)?;if q.expires<now()||q.expires>now()+3600{return Err("DEADLINE: download link expired".into());}let db=a.lock()?;let(sha,bytes,mime):(String,u64,String)=sql(db.query_row("SELECT sha256,bytes,mime FROM public_result_files JOIN public_results ON public_results.id=result_id WHERE result_id=? AND name=?",params![rid,name],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?.ok_or("NOT_FOUND: published file")?;drop(db);let bind=json!({"resultId":rid,"name":name,"sha256":sha,"bytes":bytes,"expires":q.expires});if a.sign("public-download-v1",&bind)?!=q.signature{return Err("AUTHORIZATION: download signature".into());}let path=a.data.join("public-results").join(&rid).join(&name);a.cached_public_digest(&path,&sha,bytes)?;Ok((path,name,sha,bytes,mime))}).await?;
    let (path, name, sha, total, mime) = meta;
    let (mut start, mut end) = (0, total.saturating_sub(1));
    let mut status = StatusCode::OK;
    if let Some(range) = headers.get(header::RANGE) {
        let s = range
            .to_str()
            .map_err(|_| ProductError("INVALID_INPUT".into()))?;
        let Some((from, to)) = s.strip_prefix("bytes=").and_then(|s| s.split_once('-')) else {
            return Err(ProductError("INVALID_INPUT: range".into()));
        };
        if from.is_empty() {
            let suffix = to
                .parse::<u64>()
                .map_err(|_| ProductError("INVALID_INPUT".into()))?;
            if suffix == 0 {
                return Ok(StatusCode::RANGE_NOT_SATISFIABLE.into_response());
            }
            start = total.saturating_sub(suffix);
        } else {
            start = from
                .parse::<u64>()
                .map_err(|_| ProductError("INVALID_INPUT".into()))?;
            if !to.is_empty() {
                end = to
                    .parse::<u64>()
                    .map_err(|_| ProductError("INVALID_INPUT".into()))?
                    .min(end);
            }
        }
        if start > end || start >= total {
            return Ok((
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, format!("bytes */{total}"))],
            )
                .into_response());
        }
        status = StatusCode::PARTIAL_CONTENT;
    }
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| ProductError("DAMAGED_ARTIFACT".into()))?;
    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(|_| ProductError("DAMAGED_ARTIFACT".into()))?;
    let len = end - start + 1;
    let stream = futures_util::stream::try_unfold((file, len), |(mut f, remaining)| async move {
        if remaining == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        let mut b = vec![0u8; remaining.min(65536) as usize];
        let n = f.read(&mut b).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "public file truncated",
            ));
        }
        b.truncate(n);
        Ok(Some((Bytes::from(b), (f, remaining - n as u64))))
    });
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    let h = response.headers_mut();
    for (k, v) in [
        (header::CONTENT_TYPE, mime),
        (header::CONTENT_LENGTH, len.to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        ),
        (header::ACCEPT_RANGES, "bytes".into()),
        (header::ETAG, format!("\"{sha}\"")),
    ] {
        h.insert(
            k,
            HeaderValue::from_str(&v).map_err(|_| ProductError("UNAVAILABLE".into()))?,
        );
    }
    h.insert("x-content-sha256", HeaderValue::from_str(&sha).unwrap());
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if status == StatusCode::PARTIAL_CONTENT {
        h.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).unwrap(),
        );
    }
    Ok(response)
}
pub(super) fn routes() -> Router<Arc<Authority>> {
    Router::new()
        .route("/api/product/manifest", get(manifest))
        .route("/api/tasks", get(tasks))
        .route("/api/tasks/{id}", get(task))
        .route("/api/results", get(results))
        .route("/api/results/{id}", get(result))
        .route("/api/results/{id}/files/{name}", get(download))
        .route("/api/service-requests/session", get(service_session))
        .route("/api/service-requests", post(service_create))
        .route("/api/service-requests/lookup", post(service_lookup))
        .route("/api/service-requests/confirm-quote", post(confirm_quote))
        .route("/api/operations", post(operation))
        .route("/api/my-records", post(records))
        .route("/api/wallet-bindings", post(binding))
        .layer(DefaultBodyLimit::max(32768))
}
