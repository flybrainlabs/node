//! Three-book settlement adapter. Two admitted chain observers attest finalized
//! facts; this does not replace the on-chain budget or payment-consumption check.
use super::*;
use flypow_economic_core::{Book, Slot, Stage};
fn clean(v: &Value, key: &str, min: usize, max: usize) -> Result<String> {
    let s = text(v, key)?;
    if s.len() < min || s.len() > max || s.contains('\0') {
        return Err("INVALID_INPUT: field length".into());
    }
    Ok(s)
}
fn apply_fact(book: &mut Book, fact: &Value, initial: bool) -> Result<()> {
    let book_asset = book.asset.clone();
    let fact_transaction = text(fact, "transaction")?;
    let kind = text(fact, "kind")?;
    let data = &fact["data"];
    let decimal = |key: &str| -> Result<u64> {
        let s = text(data, key)?;
        let n = s
            .parse::<u64>()
            .map_err(|_| "INVALID_INPUT: checked atoms")?;
        if s != n.to_string() {
            return Err("INVALID_INPUT: canonical atoms".into());
        }
        Ok(n)
    };
    book.atomic(|b| match kind.as_str() {
        "global-issued" => {
            if !initial {
                Err("duplicate global issuance")
            } else {
                Ok(())
            }
        }
        "stage-opened" => {
            let stage: Stage =
                serde_json::from_value(data["stage"].clone()).map_err(|_| "stage encoding")?;
            b.open_stage(data["stageId"].as_str().ok_or("stage id")?.into(), stage)
        }
        "slot-reserved" => {
            let slot: Slot =
                serde_json::from_value(data["slot"].clone()).map_err(|_| "slot encoding")?;
            b.reserve_slot(data["slotId"].as_str().ok_or("slot id")?.into(), slot)
        }
        "right-confirmed" => b.accept(
            data["slotId"].as_str().ok_or("slot")?,
            data["contributionId"].as_str().ok_or("contribution")?,
        ),
        "payment-submitted" => {
            let payment=data["paymentId"].as_str().ok_or("payment")?;let slot=data["slotId"].as_str().ok_or("slot")?;
            b.begin_payment(payment.into(),slot,data["beneficiary"].as_str().ok_or("recipient")?,&book_asset,decimal("amountAtoms").map_err(|_|"amount")?,fact_transaction.clone())?;
            let key=b.payment_key_for_slot(slot,payment)?;
            b.payments.get_mut(&key).ok_or("payment")?.consumption_pda=data["consumptionPda"].as_str().unwrap_or("").into();Ok(())
        },
        "payment-finalized" => {
            if data["consumptionVerified"] != true {
                return Err("on-chain payment consumption required");
            }
            if let Some(slot)=data["slotId"].as_str(){b.resolve_payment(slot,data["paymentId"].as_str().ok_or("payment")?,true,false)}else{b.resolve(data["paymentId"].as_str().ok_or("payment")?, true, false)}
        }
        "payment-proven-unexecuted" => {
            if data["transactionExpired"] != true || data["consumptionAbsent"] != true {
                return Err("definitive non-execution required");
            }
            if data["finalizedExpiredRecheck"]!=true || data["reliableHistory"]!=true {return Err("reliable finalized post-expiry evidence required");}
            if let Some(slot)=data["slotId"].as_str(){b.resolve_payment(slot,data["paymentId"].as_str().ok_or("payment")?,false,true)}else{b.resolve(data["paymentId"].as_str().ok_or("payment")?, false, true)}
        }
        "slot-released" => b.release_unaccepted(data["slotId"].as_str().ok_or("slot")?),
        "stage-cancelled" => b
            .close_stage(data["stageId"].as_str().ok_or("stage")?)
            .map(|_| ()),
        "refund-finalized" => b.refund(
            data["stageId"].as_str().ok_or("stage")?,
            data["beneficiary"].as_str().ok_or("recipient")?,
            decimal("amountAtoms").map_err(|_| "amount")?,
        ),
        _ => Err("unsupported financial transition"),
    })
    .map_err(|e| format!("INVALID_INPUT: {e}"))?;
    Ok(())
}
impl Authority {
    pub fn economic_operation(&self, r: &SignedRequest, at: u64) -> Result<Value> {
        r.authenticate("economic-operation")?;
        if !self.config.admin_keys.contains(&r.public_key) {
            return Err("AUTHORIZATION: economic operator".into());
        }
        // No deployment flag or marketing text activates assets. An operator must
        // install an audited identity configuration after real chain inspection.
        let config_path = self.data.join("private/economic-settlement-config.json");
        let config: Value = serde_json::from_slice(
            &fs::read(config_path).map_err(|_| "CONDITIONS_REQUIRED: settlement asset identity")?,
        )
        .map_err(|_| "INVALID_INPUT: settlement config")?;
        if config["schema"] != "flybrain-economic-settlement-v2"
            || config["enabled"] != true
            || config["networkId"] != self.config.network_id
            || config["authorityId"] != self.authority_id
            || config["finality"] != "finalized"
        {
            return Err("CONDITIONS_REQUIRED: audited settlement configuration".into());
        }
        let fact = &r.payload["fact"];
        let asset = text(fact, "asset")?;
        if asset != text(&config, "asset")?
            || fact["networkId"] != self.config.network_id
            || fact["programId"] != config["programId"]
            || fact["genesisHash"] != config["genesisHash"]
            || fact["mint"] != config["mint"]
            || fact["finality"] != "finalized"
        {
            return Err("INVALID_INPUT: chain/asset/finality".into());
        }
        let event = text(fact, "eventId")?;
        root(&event)?;
        let kind = text(fact, "kind")?;
        let business = clean(fact, "businessKey", 1, 256)?;
        let _transaction = clean(fact, "transaction", 16, 128)?;
        let observation=&r.payload["observation"];
        let v2=observation.is_object();
        let produced=if v2{num(observation,"observedAt")?}else{num(fact,"observedAt")?};
        let message=p::unhex(&if v2{id("economic-chain-observation-v2",&json!({"fact":fact,"observation":observation}))?}else{id("economic-chain-fact-v1",fact)?})?;
        // Asset paths without an actual audited customer escrow cannot ingest
        // a customer refund as a completed payment.
        if kind=="refund-finalized" {return Err("CONDITIONS_REQUIRED: no audited customer refund escrow implementation".into());}
        let locator=&fact["sourceLocator"];
        if v2 && (fact["policyHash"]!=config["policyHash"] || locator["genesisHash"]!=config["genesisHash"] || locator["signature"]!=fact["transaction"] || !locator["instructionPath"].is_array() || !locator["eventOrdinal"].is_u64() || observation["commitment"]!="finalized" || !observation["contextSlot"].is_string()) {return Err("INVALID_INPUT: frozen chain source/observation".into());}
        if v2&&kind=="right-confirmed" {
            let envelope=&r.payload["evidenceManifest"];let root=crate::evidence_manifest::digest(envelope)?;
            if fact["data"]["evidence"]!=root||fact["data"]["contributionId"]!=envelope["contributionId"]||envelope["genesisHash"]!=config["genesisHash"]||envelope["programId"]!=config["programId"]||envelope["policyHash"]!=config["policyHash"]{return Err("INVALID_INPUT: chain evidence envelope binding".into());}
            let db=self.lock()?;if sql(db.query_row("SELECT COUNT(*) FROM evidence_manifests WHERE root=? AND manifest=?",params![root,envelope.to_string()],|r|r.get::<_,u64>(0)))?!=1{return Err("AUTHORIZATION: registered complete public evidence envelope".into());}
        }
        let source_key=if v2{Some(id("economic-source-location-v1",locator)?)}else{None};
        let mut immutable=fact.clone();immutable.as_object_mut().ok_or("INVALID_INPUT: fact object")?.remove("observedAt");immutable.as_object_mut().unwrap().remove("eventId");
        let immutable_root=id("economic-immutable-operation-v1",&immutable)?;
        let mut business_fact=immutable.clone();business_fact.as_object_mut().unwrap().remove("transaction");business_fact.as_object_mut().unwrap().remove("sourceLocator");
        let business_root=id("economic-business-operation-v1",&business_fact)?;
        let natural=match kind.as_str(){
            "global-issued"=>json!([fact["genesisHash"],fact["programId"],fact["mint"],"issue"]),
            "stage-opened"|"stage-cancelled"=>json!([fact["genesisHash"],fact["programId"],kind,fact["data"]["stageId"]]),
            "slot-reserved"|"right-confirmed"|"slot-released"=>json!([fact["genesisHash"],fact["programId"],kind,fact["data"]["slotId"]]),
            "payment-submitted"|"payment-finalized"|"payment-proven-unexecuted"=>json!([fact["genesisHash"],fact["programId"],kind,fact["data"]["slotId"],fact["data"]["paymentId"]]),
            _=>return Err("INVALID_INPUT: unsupported financial transition".into())};
        let operation_key=id("economic-operation-key-v1",&natural)?;
        if v2 && kind=="slot-reserved" {let slot:Slot=serde_json::from_value(fact["data"]["slot"].clone()).map_err(|_|"INVALID_INPUT: slot encoding")?;if slot.genesis_hash!=text(&config,"genesisHash")? || slot.program_id!=text(&config,"programId")? || slot.slot_pda!=text(&fact["data"],"slotId")? {return Err("INVALID_INPUT: EconomicSlotKey/PDA binding".into());}}
        let witnesses = r.payload["witnesses"]
            .as_array()
            .ok_or("BAD_SIGNATURE: chain witnesses")?;
        let mut keys = std::collections::BTreeSet::new();
        for w in witnesses {
            let k = text(w, "publicKey")?;
            if !self.config.verifier_keys.contains(&k) || !keys.insert(k.clone()) {
                return Err("AUTHORIZATION: distinct admitted chain witnesses".into());
            }
            let pk = VerifyingKey::from_bytes(&p::unhex(&k)?.try_into().map_err(|_| "key")?)
                .map_err(|_| "key")?;
            pk.verify_strict(
                &message,
                &Signature::from_slice(&p::unhex(&text(w, "signature")?)?)
                    .map_err(|_| "BAD_SIGNATURE: witness")?,
            )
            .map_err(|_| "BAD_SIGNATURE: witness")?;
        }
        if keys.len() < 2 {
            return Err("BAD_SIGNATURE: chain observer quorum".into());
        }
        let mut db = self.lock()?;
        let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if let Some(v) = Self::cached(&tx, r)? {
            return Ok(v);
        }
        // Replaying the same committed transport returns its receipt above.
        // Adding an observation, including a duplicate business operation,
        // requires fresh admitted signatures and retains the original fact ID.
        if produced > at + 30 || at > produced + 600 {
            return Err("DEADLINE: chain attestation".into());
        }
        let prior: Option<(String, String)> = sql(tx
            .query_row(
                "SELECT state,root FROM economic_books WHERE asset=?",
                [&asset],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional())?;
        let observation_id=id("economic-observation-envelope-v1",&value(r))?;
        let policy=json!({"version":"two-admitted-observers-v1","keys":self.config.verifier_keys,"quorum":2});
        sql(tx.execute("INSERT OR IGNORE INTO economic_observations VALUES(?,?,?,?,?,?,?)",params![observation_id,event,serde_json::to_string(r).map_err(|_|"observation envelope")?,policy.to_string(),p::hex(&message),produced,at]))?;
        if let Some((existing,old_root))=sql(tx.query_row("SELECT event_id,immutable_root FROM economic_business_operations WHERE operation_key=?",[&operation_key],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional())? {
            if old_root!=business_root{return Err("CONFLICT: immutable natural business operation".into());}
            sql(tx.commit())?;return Ok(json!({"eventId":existing,"duplicate":true,"observationId":observation_id}));
        }
        if let Some(source)=&source_key {if let Some((existing,old_root))=sql(tx.query_row("SELECT event_id,immutable_root FROM economic_source_locations WHERE source_key=?",[source],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional())? {if old_root!=immutable_root{return Err("CONFLICT: immutable chain instruction".into());}sql(tx.commit())?;return Ok(json!({"eventId":existing,"duplicate":true,"observationId":observation_id}));}}
        if let Some(existing) = sql(tx
            .query_row(
                "SELECT payload FROM economic_events WHERE event_id=?",
                [&event],
                |row| row.get::<_, String>(0),
            )
            .optional())?
        {
            if parse(existing)? != *fact {
                return Err("CONFLICT: immutable financial event".into());
            }
            sql(tx.commit())?;return Ok(json!({"eventId":event,"duplicate":true,"observationId":observation_id}));
        }
        let (mut book, prior_root) = if let Some((s, h)) = prior {
            (
                serde_json::from_str::<Book>(&s).map_err(|_| "storage: book")?,
                h,
            )
        } else {
            if kind != "global-issued"
                || fact["supplyAtoms"] != flypow_economic_core::CAP.to_string()
                || fact["mintAuthorityRevoked"] != true
                || fact["vaultAtoms"] != json!(flypow_economic_core::POOLS.map(|n| n.to_string()))
            {
                return Err("CONDITIONS_REQUIRED: atomic global issuance proof".into());
            }
            (
                Book::new(asset.clone(), flypow_economic_core::POOLS),
                "0".repeat(64),
            )
        };
        if let Err(e)=apply_fact(&mut book,fact,prior_root=="0".repeat(64)) {sql(tx.execute("INSERT OR REPLACE INTO economic_quarantine VALUES(?,?,?,?)",params![event,e,r.payload.to_string(),at]))?;sql(tx.commit())?;return Err(e);}
        sql(tx.execute("INSERT INTO economic_business_operations VALUES(?,?,?)",params![operation_key,event,business_root]))?;
        if let Some(source)=source_key {sql(tx.execute("INSERT INTO economic_source_locations VALUES(?,?,?)",params![source,event,immutable_root]))?;}
        sql(tx.execute("DELETE FROM economic_quarantine WHERE event_id=?",[&event]))?;
        let root = id(
            "economic-event-chain-v1",
            &json!({"priorRoot":prior_root,"fact":fact}),
        )?;
        sql(tx.execute("INSERT INTO economic_events(event_id,business_key,asset,kind,payload,prior_root,root,created_at) VALUES(?,?,?,?,?,?,?,?)",params![event,business,asset,kind,fact.to_string(),prior_root,root,at]))?;
        sql(tx.execute("INSERT INTO economic_books VALUES(?,?,?) ON CONFLICT(asset) DO UPDATE SET state=excluded.state,root=excluded.root",params![asset,serde_json::to_string(&book).unwrap(),root]))?;
        sql(tx.execute(
            "INSERT INTO economic_outbox(event_id,payload) VALUES(?,?)",
            params![
                event,
                json!({"eventId":event,"asset":asset,"root":root}).to_string()
            ],
        ))?;
        let result = json!({"eventId":event,"root":root,"committed":true});
        Self::remember(&tx, r, &result)?;
        sql(tx.commit())?;
        Ok(result)
    }
    pub fn economic_reconcile(&self) -> Result<Value> {
        let db = self.lock()?;
        let mut q = sql(db.prepare("SELECT asset,state,root FROM economic_books ORDER BY asset"))?;
        let rows = sql(q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        }))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
        let mut reports = Vec::new();
        for (asset, state, root) in rows {
            let mut book: Book = serde_json::from_str(&state).map_err(|_| "storage: economic book")?;book.normalize_legacy_payment_keys().map_err(|_|"legacy payment identity")?;
            let mut stmt=sql(db.prepare("SELECT payload,prior_root,root FROM economic_events WHERE asset=? ORDER BY sequence"))?;
            let events = sql(stmt.query_map([&asset], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            }))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
            let mut previous = "0".repeat(64);
            let mut chain = true;
            let mut replay = Book::new(asset.clone(), flypow_economic_core::POOLS);
            for (f, p, h) in events {
                let fact = parse(f)?;
                let initial = previous == "0".repeat(64);
                if initial
                    && (fact["kind"] != "global-issued"
                        || fact["supplyAtoms"] != flypow_economic_core::CAP.to_string()
                        || fact["vaultAtoms"]
                            != json!(flypow_economic_core::POOLS.map(|n| n.to_string())))
                {
                    chain = false;
                }
                if apply_fact(&mut replay, &fact, initial).is_err() {
                    chain = false;
                }
                if p != previous
                    || id(
                        "economic-event-chain-v1",
                        &json!({"priorRoot":p,"fact":fact}),
                    )? != h
                {
                    chain = false;
                }
                previous = h;
            }
            let chain_report:Option<String>=sql(db.query_row("SELECT report FROM chain_reconciliations WHERE asset=? AND created_at>=? ORDER BY created_at DESC LIMIT 1",params![asset,now().saturating_sub(600)],|r|r.get(0)).optional())?;
            let chain_observation=chain_report.map(parse).transpose()?.map(|v|v["result"].clone());
            let chain_matches=chain_observation.as_ref().is_some_and(|v|v["bookRoot"]==root&&v["chainStateReconciled"]==true);
            reports.push(json!({"asset":asset,"localLedgerReconciled":book.reconcile().is_ok()&&chain&&previous==root&&serde_json::to_value(&book).unwrap()==serde_json::to_value(&replay).unwrap(),"chainStateReconciled":chain_matches,"chainObservation":chain_observation,"scientificVerification":"separate-evidence-required","chainState":"no-current-consistent-RPC-watermark","liabilitiesConserve":book.reconcile().is_ok(),"eventChainValid":chain&&previous==root,"snapshotMatchesReplay":serde_json::to_value(&book).unwrap()==serde_json::to_value(&replay).unwrap(),"vaults":book.vaults,"price":null,"profitValuation":"price-and-confirmed-external-revenue-required"}));
        }
        Ok(
            json!({"books":reports,"status":if reports.is_empty(){"no-settled-assets"}else if reports.iter().all(|r|r["liabilitiesConserve"]==true&&r["eventChainValid"]==true&&r["snapshotMatchesReplay"]==true){"reconciled"}else{"requires-reconciliation"},"at":now(),"externalIncome":null,"sponsorship":null,"costs":null,"price":null,"outbox":"durable-committed-events"}),
        )
    }
}
async fn ingest(
    State(a): State<Arc<Authority>>,
    Json(r): Json<SignedRequest>,
) -> std::result::Result<Json<Value>, ApiError> {
    blocking(a, move |a| a.economic_operation(&r, now()))
        .await
        .map(Json)
}
async fn reconcile(State(a): State<Arc<Authority>>) -> std::result::Result<Json<Value>, ApiError> {
    blocking(a, Authority::economic_reconcile).await.map(Json)
}
pub(super) fn routes() -> Router<Arc<Authority>> {
    Router::new()
        .route("/api/economy/ingest", post(ingest))
        .route("/api/economy/reconcile", get(reconcile))
}
