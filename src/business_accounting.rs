//! Evidence-backed operating records; distinct assets are never silently priced.
use super::*;
use std::collections::BTreeMap;
impl Authority {
    pub fn record_operating_entry(&self, r: &SignedRequest, at: u64) -> Result<Value> {
        r.authenticate("product-operation")?;
        if !self.config.admin_keys.contains(&r.public_key) {
            return Err("AUTHORIZATION: accounting operator".into());
        }
        let v = &r.payload;
        let kind = text(v, "kind")?;
        if ![
            "external-revenue",
            "sponsorship-task",
            "sponsorship-grant",
            "miner-settlement",
            "verification-cost",
            "storage-transfer",
            "retry-cost",
            "delivery-support",
            "fixed-cost",
            "research-cost",
            "fly-subsidy",
            "customer-advance",
            "refundable-deposit",
            "refund-liability",
            "refund-paid",
        ]
        .contains(&kind.as_str())
        {
            return Err("INVALID_INPUT: operating category".into());
        }
        let amount = text(v, "amountAtoms")?;
        let n = amount.parse::<u64>().map_err(|_| "INVALID_INPUT: amount")?;
        if n.to_string() != amount {
            return Err("INVALID_INPUT: canonical atoms".into());
        }
        let asset = text(v, "asset")?;
        let business = text(v, "businessId")?;
        let source = text(v, "source")?;
        if [asset.as_str(), business.as_str(), source.as_str()]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || s.contains('\0'))
        {
            return Err("INVALID_INPUT: operating evidence".into());
        }
        let task = v["taskId"].as_str().unwrap_or("");
        let stage = v["stageId"].as_str().unwrap_or("");
        if (kind == "fly-subsidy" || asset == "FLY")
            && ["external-revenue", "sponsorship-task", "sponsorship-grant"]
                .contains(&kind.as_str())
        {
            return Err("INVALID_INPUT: token subsidy is not external revenue".into());
        }
        let entry = id(
            "operating-entry-v1",
            &json!({"businessId":business,"asset":asset,"kind":kind,"amountAtoms":amount,"taskId":task,"stageId":stage,"source":source}),
        )?;
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if let Some(prior) = sql(tx
            .query_row(
                "SELECT id FROM operating_entries WHERE business_id=?",
                [&business],
                |r| r.get::<_, String>(0),
            )
            .optional())?
        {
            if prior != entry {
                return Err("CONFLICT: one source cannot be recognized twice".into());
            }
            return Ok(json!({"entryId":entry,"duplicate":true}));
        }
        if kind == "external-revenue" {
            let ticket = text(v, "ticketId")?;
            let delivered: bool = sql(tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM service_deliveries WHERE request_id=?)",
                [ticket],
                |r| r.get(0),
            ))?;
            if !delivered {
                return Err("CONDITIONS_REQUIRED: delivered service and receipt evidence".into());
            }
        }
        sql(tx.execute(
            "INSERT INTO operating_entries VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![
                entry,
                business,
                task,
                stage,
                asset,
                amount,
                kind,
                source,
                r.public_key,
                at
            ],
        ))?;
        sql(tx.execute("INSERT INTO product_audit(kind,actor,payload,created_at) VALUES('OPERATING_ENTRY',?,?,?)",params![r.public_key,json!({"entryId":entry,"kind":kind}).to_string(),at]))?;
        sql(tx.commit())?;
        Ok(json!({"entryId":entry,"saved":true,"price":null}))
    }
    pub fn operating_summary(
        &self,
        task: &str,
        stage: &str,
        since: u64,
        until: u64,
    ) -> Result<Value> {
        let db = self.lock()?;
        let mut q=sql(db.prepare("SELECT asset,kind,amount_atoms FROM operating_entries WHERE (?='' OR task_id=?) AND (?='' OR stage_id=?) AND created_at>=? AND created_at<=? ORDER BY id"))?;
        let rows = sql(q.query_map(
            params![task, task, stage, stage, since, until.min(i64::MAX as u64)],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        ))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
        let mut totals: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for (asset, kind, amount) in rows {
            let n = amount
                .parse::<u64>()
                .map_err(|_| "storage: operating amount")?;
            let entry = totals.entry(asset).or_default().entry(kind).or_default();
            *entry = entry
                .checked_add(n)
                .ok_or("INVALID_INPUT: operating sum overflow")?;
        }
        let assets:Vec<Value>=totals.into_iter().map(|(asset,by_kind)|{
            let expenses=["miner-settlement","verification-cost","storage-transfer","retry-cost","delivery-support"];
            let covered=expenses.iter().all(|k|by_kind.contains_key(*k)) && (by_kind.contains_key("external-revenue")||by_kind.contains_key("sponsorship-task"));
            let margin=if covered {let income=i128::from(*by_kind.get("external-revenue").unwrap_or(&0))+i128::from(*by_kind.get("sponsorship-task").unwrap_or(&0));Some((income-expenses.iter().map(|k|i128::from(by_kind[*k])).sum::<i128>()).to_string())}else{None};
            let period=margin.as_ref().and_then(|m| if by_kind.contains_key("fixed-cost")&&by_kind.contains_key("research-cost"){Some((m.parse::<i128>().unwrap()+i128::from(*by_kind.get("sponsorship-grant").unwrap_or(&0))-i128::from(by_kind["fixed-cost"])-i128::from(by_kind["research-cost"])).to_string())}else{None});
            json!({"asset":asset,"categories":by_kind.into_iter().map(|(k,v)|(k,v.to_string())).collect::<BTreeMap<_,_>>(),"taskContributionMarginAtoms":margin,"periodOperatingResultAtoms":period,"costCoverageComplete":covered,"reportingCurrencyValuation":null,"price":null})
        }).collect();
        Ok(
            json!({"assets":assets,"taskId":task,"stageId":stage,"since":since,"until":until,"at":now(),"scope":"operator-recorded-evidence-in-original-assets","status":if assets.is_empty(){"not-collected"}else{"recorded"},"price":null,"customerCount":null,"fundingAndRevenueDistinct":true}),
        )
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperatingQuery {
    #[serde(default)]
    task: String,
    #[serde(default)]
    stage: String,
    #[serde(default)]
    since: u64,
    #[serde(default = "maximum")]
    until: u64,
}
fn maximum() -> u64 {
    i64::MAX as u64
}
async fn summary(
    State(a): State<Arc<Authority>>,
    Query(q): Query<OperatingQuery>,
) -> std::result::Result<Json<Value>, ApiError> {
    blocking(a, move |a| {
        a.operating_summary(&q.task, &q.stage, q.since, q.until)
    })
    .await
    .map(Json)
}
pub(super) fn routes() -> Router<Arc<Authority>> {
    Router::new().route("/api/economy/operations", get(summary))
}
