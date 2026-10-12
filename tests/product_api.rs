//! Isolated fault tests, never write the public deployment or real asset books.
use ed25519_dalek::{Signer, SigningKey};
use flypow::target_authority::*;
use flypow_target_protocol as p;
use serde_json::{json, Value};
use sha2::Digest;
use std::{path::PathBuf, sync::Arc};
fn request(k: &SigningKey, action: &str, payload: Value, name: &str) -> SignedRequest {
    let mut r = SignedRequest {
        public_key: p::hex(k.verifying_key().as_bytes()),
        action: action.into(),
        request_id: name.into(),
        round_id: "".into(),
        payload,
        signature: String::new(),
    };
    r.signature = p::hex(
        &k.sign(&p::unhex(&p::id("authority-action", &r.unsigned()).unwrap()).unwrap())
            .to_bytes(),
    );
    r
}
fn open(dir: &std::path::Path) -> Arc<Authority> {
    let keys = (1..=4)
        .map(|i| p::hex(SigningKey::from_bytes(&[i; 32]).verifying_key().as_bytes()))
        .collect::<Vec<_>>();
    Authority::open(
        dir.into(),
        AuthorityConfig {
            schema: "flypow-target-authority-config-v2".into(),
            network_id: "isolated-product-api-fixture".into(),
            campaign_id: "fixture".into(),
            goal_paths: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("web/data/target-mining-v2/product-group-1-20261011/goal.json")],
            verifier_keys: keys[..3].to_vec(),
            admin_keys: vec![keys[3].clone()],
            allowed_origins: vec!["https://flybrain.work".into()],
            tau_seconds: 300,
            search_seconds: 120,
            reveal_seconds: 60,
            verification_seconds: 1200,
            max_queue: 8,
            per_identity_claims: 2,
            max_private_bytes: 512 * 1024 * 1024,
            family_paths: vec![],
        },
    )
    .unwrap()
}
#[test]
fn service_durable_idempotent_private_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(dir.path());
    let session = a.service_session("client", 1000).unwrap();
    let v = json!({"requestId":"business-request-123","accessToken":"ab".repeat(32),"csrfToken":session["csrfToken"],"fields":{"problem":"A real typed client request; <script> is inert text","contact":"private@example.invalid","name":"API fixture","taskType":"response-comparison","deadline":"","budget":"","publication":"discuss","termsAccepted":true}});
    let r = a.service_create(&v, "client", 1001).unwrap();
    assert_eq!(r["saved"], true);
    assert_eq!(
        a.service_create(&v, "client", 1002).unwrap()["duplicate"],
        true
    );
    let mut changed = v.clone();
    changed["fields"]["budget"] = json!("changed");
    assert!(a.service_create(&changed, "client", 1003).is_err());
    let lookup = json!({"ticketId":r["ticketId"],"accessToken":v["accessToken"]});
    assert!(a
        .service_lookup(&json!({"ticketId":r["ticketId"],"accessToken":"00".repeat(32)}))
        .is_err());
    let key = SigningKey::from_bytes(&[4; 32]);
    let op = request(
        &key,
        "product-operation",
        json!({"operation":"update-request","ticketId":r["ticketId"],"status":"scoping","basis":"scope review by authorized operator"}),
        "operator-update-1",
    );
    a.product_operation(&op, 1004).unwrap();
    assert!(a
        .product_operation(
            &request(
                &SigningKey::from_bytes(&[5; 32]),
                "product-operation",
                json!({"operation":"list-requests"}),
                "operator-forged"
            ),
            1004
        )
        .is_err());
    assert!(!a
        .product_manifest()
        .unwrap()
        .to_string()
        .contains("private@example"));
    drop(a);
    let a = open(dir.path());
    assert_eq!(a.service_lookup(&lookup).unwrap()["status"], "scoping");
    assert_eq!(
        a.service_lookup(&lookup).unwrap()["events"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(a.product_operation(&request(&key,"product-operation",json!({"operation":"update-request","ticketId":r["ticketId"],"status":"delivered","basis":"cannot assert unperformed delivery"}),"unfunded-delivery"),1005).is_err());
    a.product_housekeeping(1000 + 366 * 86400).unwrap();
    assert_eq!(a.service_lookup(&lookup).unwrap()["fields"], json!({}));
}
#[test]
fn csrf_rate_limits_and_input_bounds() {
    let d = tempfile::tempdir().unwrap();
    let a = open(d.path());
    for _ in 0..30 {
        a.service_session("source", 1000).unwrap();
    }
    assert!(a
        .service_session("source", 1000)
        .unwrap_err()
        .contains("RATE_LIMIT"));
    a.service_session("other", 1000).unwrap();
    let v = json!({"requestId":"request-invalid","accessToken":"00".repeat(32),"csrfToken":"00".repeat(32),"fields":{"problem":"valid length question","name":"name","contact":"user@example.invalid","taskType":"arbitrary-script","deadline":"","budget":"","publication":"public","termsAccepted":true}});
    assert!(a.service_create(&v, "other", 1001).is_err());
}
#[test]
fn wallet_requires_both_signatures_no_retroactive_rights() {
    let d = tempfile::tempdir().unwrap();
    let a = open(d.path());
    let miner = SigningKey::from_bytes(&[5; 32]);
    let wallet = SigningKey::from_bytes(&[6; 32]);
    let binding = json!({"miner":p::hex(miner.verifying_key().as_bytes()),"walletHex":p::hex(wallet.verifying_key().as_bytes()),"chain":"solana:address-ownership-only","policy":"flybrain-global-supply-v2-20261011","producedAt":1000});
    let mut v = binding.clone();
    v.as_object_mut().unwrap().remove("miner");
    v["walletSignature"] = json!(p::hex(
        &wallet
            .sign(&p::unhex(&p::id("wallet-binding-v1", &binding).unwrap()).unwrap())
            .to_bytes()
    ));
    let r = request(
        &miner,
        "product-wallet-binding",
        v.clone(),
        "bind-wallet-proof",
    );
    assert_eq!(
        a.bind_product_wallet(&r, 1001).unwrap()["historicalBeneficiariesChanged"],
        false
    );
    v["walletHex"] = json!("ab".repeat(32));
    assert!(a
        .bind_product_wallet(
            &request(&miner, "product-wallet-binding", v, "wrong-wallet-proof"),
            1001
        )
        .is_err());
    assert!(a.bind_product_wallet(&r, 2000).is_err());
}
#[tokio::test]
async fn http_boundary_rejects_origins_private_files_and_large_forms() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let d = tempfile::tempdir().unwrap();
    let a = open(d.path());
    let app = router(a);
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/product/manifest")
                .header("origin", "https://evil.invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/results/{}/files/private.key?expires=1000&signature=x",
                    "ab".repeat(32)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!r.status().is_success());
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/service-requests")
                .header("content-type", "application/json")
                .body(Body::from("x".repeat(40000)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), 413);
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/operations")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!r.status().is_success());
    let body = to_bytes(r.into_body(), 65536).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("private@example"));
}

#[test]
fn quotes_require_owner_and_never_assert_payment() {
    let d = tempfile::tempdir().unwrap();
    let a = open(d.path());
    let admin = SigningKey::from_bytes(&[4; 32]);
    let session = a.service_session("quote-client", 1000).unwrap();
    let v = json!({"requestId":"quote-request-fixture","accessToken":"ab".repeat(32),"csrfToken":session["csrfToken"],"fields":{"problem":"Compare two approved response windows","contact":"unit-test@example.invalid","name":"Isolated quote test","taskType":"response-comparison","deadline":"","budget":"","publication":"discuss","termsAccepted":true}});
    let ticket = a.service_create(&v, "quote-client", 1000).unwrap()["ticketId"].clone();
    let quote=a.product_operation(&request(&admin,"product-operation",json!({"operation":"quote-request","ticketId":ticket,"asset":"isolated-asset","amountAtoms":"9007199254740993","expires":2000,"terms":"Isolated fixture terms: scoped replay, no payment, delivery only after funded budget"}),"quote-fixture-op"),1001).unwrap();
    let stale = json!({"ticketId":ticket,"accessToken":v["accessToken"],"quoteId":quote["quoteId"]});
    // Same-second edits must follow persisted insertion order, not hash order.
    let revised=a.product_operation(&request(&admin,"product-operation",json!({"operation":"quote-request","ticketId":ticket,"asset":"isolated-asset","amountAtoms":"9007199254740994","expires":2000,"terms":"Revised isolated fixture terms: no payment, delivery only after funded budget"}),"revised-quote-fixture-op"),1001).unwrap();
    assert_ne!(quote["quoteId"],revised["quoteId"]);
    assert!(a.service_confirm_quote(&stale,1002).is_err());
    assert_eq!(a.service_lookup(&stale).unwrap()["quotes"][0]["id"],revised["quoteId"]);
    let proof =
        json!({"ticketId":ticket,"accessToken":v["accessToken"],"quoteId":revised["quoteId"]});
    let mut forged = proof.clone();
    forged["accessToken"] = json!("00".repeat(32));
    assert!(a.service_confirm_quote(&forged, 1002).is_err());
    assert_eq!(
        a.service_confirm_quote(&proof, 1002).unwrap()["paid"],
        false
    );
    a.service_confirm_quote(&proof, 1003).unwrap();
    assert_eq!(
        a.service_lookup(&proof).unwrap()["status"],
        "budget-required"
    );
    assert!(a.service_confirm_quote(&proof, 2001).is_err());
    drop(a);
    let a = open(d.path());
    assert_eq!(
        a.service_lookup(&proof).unwrap()["quotes"][0]["confirmed"],
        true
    );
    assert!(a.product_operation(&request(&admin,"product-operation",json!({"operation":"assign-request","ticketId":ticket,"basis":"No audited funded budget exists"}),"unfunded-fixture"),1004).is_err());
}

#[test]
fn economic_ingest_is_quorum_gated_replayable_and_durable() {
    use std::fs;
    let d = tempfile::tempdir().unwrap();
    let a = open(d.path());
    let admin = SigningKey::from_bytes(&[4; 32]);
    let asset = "solana:isolated:mint:8";
    let config = json!({"schema":"flybrain-economic-settlement-v2","enabled":true,"networkId":a.config.network_id,"authorityId":a.authority_id,"finality":"finalized","asset":asset,"programId":"isolated-local-program","genesisHash":"isolated-genesis","mint":"isolated-mint"});
    fs::write(
        d.path().join("private/economic-settlement-config.json"),
        config.to_string(),
    )
    .unwrap();
    let fact = json!({"networkId":a.config.network_id,"asset":asset,"programId":config["programId"],"genesisHash":config["genesisHash"],"mint":config["mint"],"finality":"finalized","observedAt":1000,"eventId":"aa".repeat(32),"kind":"global-issued","businessKey":"one-global-supply","transaction":"isolated-fixture-transaction","supplyAtoms":flypow_economic_core::CAP.to_string(),"mintAuthorityRevoked":true,"vaultAtoms":flypow_economic_core::POOLS.map(|n|n.to_string()),"data":{}});
    let message = p::unhex(&p::id("economic-chain-fact-v1", &fact).unwrap()).unwrap();
    let ws:Vec<_>=(1..=2).map(|i|{let k=SigningKey::from_bytes(&[i;32]);json!({"publicKey":p::hex(k.verifying_key().as_bytes()),"signature":p::hex(&k.sign(&message).to_bytes())})}).collect();
    let r = request(
        &admin,
        "economic-operation",
        json!({"fact":fact,"witnesses":ws}),
        "economic-fixture-issuance",
    );
    let mut bad = r.payload.clone();
    bad["witnesses"] = json!([ws[0].clone()]);
    assert!(a
        .economic_operation(
            &request(&admin, "economic-operation", bad, "no-quorum-fixture"),
            1001
        )
        .is_err());
    assert_eq!(a.economic_operation(&r, 1001).unwrap()["committed"], true);
    a.economic_operation(&r, 1002).unwrap();
    assert_eq!(
        a.economic_reconcile().unwrap()["books"][0]["snapshotMatchesReplay"],
        true
    );
    drop(a);
    let a = open(d.path());
    assert_eq!(a.economic_reconcile().unwrap()["status"], "reconciled");
    assert_eq!(
        a.economic_operation(
            &request(
                &admin,
                "economic-operation",
                r.payload.clone(),
                "different-transport-id"
            ),
            1002
        )
        .unwrap()["duplicate"],
        true
    );
}

#[test]
fn original_assets_unknown_costs_and_unique_source_accounting() {
    let d = tempfile::tempdir().unwrap();
    let a = open(d.path());
    let admin = SigningKey::from_bytes(&[4; 32]);
    for (asset, amount, index) in [("USD:2", "31183324300000000", 1), ("EUR:2", "18", 2)] {
        let v = json!({"operation":"record-operating-entry","asset":asset,"businessId":format!("isolated-receipt-{index}"),"source":"isolated unit fixture, not external revenue","kind":"verification-cost","amountAtoms":amount,"taskId":"fixture-task"});
        a.product_operation(
            &request(
                &admin,
                "product-operation",
                v.clone(),
                &format!("operating-cost-{index}"),
            ),
            1000,
        )
        .unwrap();
        let mut duplicate = v;
        duplicate["kind"] = json!("sponsorship-grant");
        assert!(a
            .product_operation(
                &request(
                    &admin,
                    "product-operation",
                    duplicate,
                    &format!("double-recognition-{index}")
                ),
                1001
            )
            .is_err());
    }
    let report = a.operating_summary("fixture-task", "", 0, 2000).unwrap();
    assert_eq!(report["assets"].as_array().unwrap().len(), 2);
    assert_eq!(report["assets"][0]["price"], Value::Null);
    assert_eq!(
        report["assets"][0]["taskContributionMarginAtoms"],
        Value::Null
    );
    assert!(!report.to_string().contains("isolated-receipt"));
}

#[tokio::test]
#[ignore = "explicit retained full-model public reproduction package required"]
async fn full_public_package_download_access_and_damage_boundaries(){
 use axum::{body::{Body,to_bytes},http::Request};use tower::ServiceExt;use std::fs;
 let package=PathBuf::from(std::env::var("FLYPOW_PUBLIC_PACKAGE").expect("retained public package path"));
 let meta:Value=serde_json::from_slice(&fs::read(package.join("publication.json")).unwrap()).unwrap();let pid=p::id("public-package-v1",&meta).unwrap();
 let d=tempfile::tempdir_in(package.parent().unwrap()).unwrap();let a=open(d.path());let staging=d.path().join("public-staging").join(&pid);fs::create_dir_all(&staging).unwrap();
 for f in fs::read_dir(&package).unwrap(){let f=f.unwrap();if f.file_type().unwrap().is_file(){fs::hard_link(f.path(),staging.join(f.file_name())).unwrap();}}
 let admin=SigningKey::from_bytes(&[4;32]);let op=request(&admin,"product-operation",json!({"operation":"publish-result","packageId":pid}),"publish-retained-full-package");
 let result=a.publish_product_package(&op,now()).unwrap();let rid=result["resultId"].as_str().unwrap();let detail=a.product_result(rid).unwrap();assert_eq!(detail["trust"]["externalObservation"],false);assert_eq!(detail["trials"][0]["pairedTargetCounts"],json!([[0,55],[0,125]]));
 let file=detail["files"].as_array().unwrap().iter().find(|f|f["name"]=="README.txt").unwrap();let url=file["url"].as_str().unwrap();let app=router(a.clone());
 let response=app.clone().oneshot(Request::builder().uri(url).header("range","bytes=0-31").body(Body::empty()).unwrap()).await.unwrap();assert_eq!(response.status(),206);assert_eq!(to_bytes(response.into_body(),64).await.unwrap().len(),32);
 let invalid=app.clone().oneshot(Request::builder().uri(format!("{url}a")).body(Body::empty()).unwrap()).await.unwrap();assert_eq!(invalid.status(),403);
 let expired=app.clone().oneshot(Request::builder().uri(format!("/api/results/{rid}/files/README.txt?expires=1&signature=invalid")).body(Body::empty()).unwrap()).await.unwrap();assert_eq!(expired.status(),410);
 let destination=d.path().join("public-results").join(rid).join("README.txt");fs::write(&destination,b"isolated corrupted fixture").unwrap();let damaged=app.clone().oneshot(Request::builder().uri(url).body(Body::empty()).unwrap()).await.unwrap();assert_eq!(damaged.status(),503);fs::copy(package.join("README.txt"),destination).unwrap();a.audit_public_objects().unwrap();
 let ok=app.oneshot(Request::builder().uri(url).body(Body::empty()).unwrap()).await.unwrap();assert_eq!(ok.status(),200);assert_eq!(to_bytes(ok.into_body(),65536).await.unwrap().len(),file["bytes"].as_u64().unwrap() as usize);
 a.publish_product_package(&op,now()).unwrap();assert_eq!(a.product_manifest().unwrap()["metrics"]["publicResults"]["value"],1);
}

#[test]
fn thousand_contributions_do_not_hide_earliest_right_and_summaries_are_global(){
 use flypow_economic_core::{Book,Slot,Stage,Atoms};
 let dir=tempfile::tempdir().unwrap();let a=open(dir.path());let actor=p::hex(SigningKey::from_bytes(&[5;32]).verifying_key().as_bytes());
 let conn=rusqlite::Connection::open(dir.path().join("target-v2.sqlite")).unwrap();
 for i in 0..1000 {conn.execute("INSERT INTO science_contributions VALUES(?,?,'discovery',?,?,?,?)",rusqlite::params![format!("{:064x}",i+1),actor,"a".repeat(64),"b".repeat(64),format!("{:064x}",1001+i),i]).unwrap();}
 let mut b=Book::new("isolated-history-asset".into(),[100,0,0]);b.open_stage("stage".into(),Stage{policy:"p".into(),asset:b.asset.clone(),pool:0,budget:Atoms(100),remaining:Atoms(100),refund_remaining:Atoms(0),deadline:9000,closed:false,refund_recipient:"global-pool".into()}).unwrap();
 b.reserve_slot("oldest-slot".into(),Slot{genesis_hash:String::new(),program_id:String::new(),unit_id:String::new(),slot_pda:String::new(),stage:"stage".into(),economic_task:"oldest-task".into(),kind:"discovery".into(),beneficiary:"frozen-wallet".into(),amount:Atoms(10),contribution:format!("{:064x}",1),accepted:false,released:false,paid:Atoms(0),inflight:Atoms(0)}).unwrap();b.accept("oldest-slot",&format!("{:064x}",1)).unwrap();conn.execute("INSERT INTO economic_books VALUES(?,?,?)",rusqlite::params![b.asset,serde_json::to_string(&b).unwrap(),"c".repeat(64)]).unwrap();drop(conn);
 let key=SigningKey::from_bytes(&[5;32]);let first=a.product_records(&request(&key,"product-records",json!({}),"thousand-history-page")).unwrap();assert_eq!(first["contributionCount"],"1000");assert_eq!(first["rights"][0]["slotId"],"oldest-slot");assert_eq!(first["totals"][0]["availableAtoms"],"10");
 let mut count=first["contributions"].as_array().unwrap().len();let mut page=first;
 while page["contributionHasMore"]==true{page=a.product_records(&request(&key,"product-records",json!({"contributionCursor":page["contributionNextCursor"]}),"thousand-history-next")).unwrap();count+=page["contributions"].as_array().unwrap().len();assert_eq!(page["totals"][0]["availableAtoms"],"10");}
 assert_eq!(count,1000);assert_eq!(page["contributions"].as_array().unwrap().last().unwrap()["contributionId"],format!("{:064x}",1));
 let foreign=a.product_records(&request(&SigningKey::from_bytes(&[6;32]),"product-records",json!({}),"foreign-history-page")).unwrap();assert!(foreign["rights"].as_array().unwrap().is_empty());
}

#[test]
fn immutable_financial_identity_survives_late_observation_and_event_id_change(){
 use std::fs;
 let d=tempfile::tempdir().unwrap();let a=open(d.path());let admin=SigningKey::from_bytes(&[4;32]);
 let config=json!({"schema":"flybrain-economic-settlement-v2","enabled":true,"networkId":a.config.network_id,"authorityId":a.authority_id,"finality":"finalized","asset":"isolated-observation-asset","programId":"isolated-local-program","genesisHash":"isolated-genesis","mint":"isolated-mint","policyHash":"b".repeat(64)});
 fs::write(d.path().join("private/economic-settlement-config.json"),config.to_string()).unwrap();
 let fact=json!({"networkId":a.config.network_id,"asset":config["asset"],"programId":config["programId"],"genesisHash":config["genesisHash"],"mint":config["mint"],"policyHash":config["policyHash"],"finality":"finalized","eventId":"aa".repeat(32),"kind":"global-issued","businessKey":"isolated-supply","transaction":"isolated-fixture-transaction","sourceLocator":{"genesisHash":config["genesisHash"],"signature":"isolated-fixture-transaction","instructionPath":[0],"eventOrdinal":0},"supplyAtoms":flypow_economic_core::CAP.to_string(),"mintAuthorityRevoked":true,"vaultAtoms":flypow_economic_core::POOLS.map(|n|n.to_string()),"data":{}});
 let payload=|f:&Value,at:u64|{let o=json!({"observedAt":at,"commitment":"finalized","contextSlot":"100"});let m=p::unhex(&p::id("economic-chain-observation-v2",&json!({"fact":f,"observation":o})).unwrap()).unwrap();let ws=(1..=2).map(|i|{let k=SigningKey::from_bytes(&[i;32]);json!({"publicKey":p::hex(k.verifying_key().as_bytes()),"signature":p::hex(&k.sign(&m).to_bytes())})}).collect::<Vec<_>>();json!({"fact":f,"observation":o,"witnesses":ws})};
 a.economic_operation(&request(&admin,"economic-operation",payload(&fact,1000),"first-observation"),1001).unwrap();
 assert!(a.economic_operation(&request(&admin,"economic-operation",payload(&fact,1000),"stale-transport"),2000).is_err());
 assert_eq!(a.economic_operation(&request(&admin,"economic-operation",payload(&fact,2000),"fresh-same-business"),2001).unwrap()["duplicate"],true);
 let mut changed=fact.clone();changed["eventId"]=json!("cc".repeat(32));
 assert_eq!(a.economic_operation(&request(&admin,"economic-operation",payload(&changed,2000),"changed-caller-event-id"),2001).unwrap()["duplicate"],true);
 drop(a);let a=open(d.path());assert_eq!(a.economic_reconcile().unwrap()["books"][0]["localLedgerReconciled"],true);
 let db=rusqlite::Connection::open(d.path().join("target-v2.sqlite")).unwrap();assert_eq!(db.query_row("SELECT COUNT(*) FROM economic_events",[],|r|r.get::<_,u64>(0)).unwrap(),1);
 let envelopes=db.prepare("SELECT envelope FROM economic_observations").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();assert_eq!(envelopes.len(),3);for e in envelopes{let r:SignedRequest=serde_json::from_str(&e).unwrap();assert_eq!(r.payload["witnesses"].as_array().unwrap().len(),2);}
}

#[tokio::test]
async fn private_delivery_requires_receipt_and_keeps_frozen_root_on_retry(){
 use axum::{body::{Body,to_bytes},http::Request};use tower::ServiceExt;use std::fs;
 let d=tempfile::tempdir().unwrap();let a=open(d.path());let session=a.service_session("isolated-delivery",1000).unwrap();
 let v=json!({"requestId":"isolated-delivery-request","accessToken":"ab".repeat(32),"csrfToken":session["csrfToken"],"fields":{"problem":"Private actual delivery file boundary","contact":"delivery@example.invalid","name":"fixture","taskType":"response-comparison","deadline":"","budget":"","publication":"restricted-review","termsAccepted":true}});
 let created=a.service_create(&v,"isolated-delivery",1001).unwrap();let sid=created["ticketId"].as_str().unwrap();let root="c".repeat(64);
 let file=d.path().join("private/deliveries").join(sid).join("result.bin");fs::create_dir_all(file.parent().unwrap()).unwrap();fs::write(&file,b"isolated private delivery bytes").unwrap();let sha=p::hex(&sha2::Sha256::digest(fs::read(&file).unwrap()));
 let manifest=json!({"schema":"flybrain-private-delivery-v1","files":[{"name":"result.bin","sha256":sha,"bytes":31}]});
 let db=rusqlite::Connection::open(d.path().join("target-v2.sqlite")).unwrap();db.execute("INSERT INTO private_deliveries VALUES(?,?,?,?,?)",rusqlite::params![sid,manifest.to_string(),root,"isolated-fixture",1002]).unwrap();drop(db);
 let app=router(a.clone());let req=|payload:Value,path:&str|Request::builder().method("POST").uri(path).header("content-type","application/json").header("origin","https://flybrain.work").body(Body::from(payload.to_string())).unwrap();
 let good=json!({"ticketId":sid,"accessToken":v["accessToken"],"name":"result.bin"});
 let bad=json!({"ticketId":sid,"accessToken":"00".repeat(32),"name":"result.bin"});let denied=app.clone().oneshot(req(bad,"/api/service-requests/delivery-file")).await.unwrap();assert!(!denied.status().is_success());
 let response=app.clone().oneshot(req(good.clone(),"/api/service-requests/delivery-file")).await.unwrap();let status=response.status();let headers=response.headers().clone();let body=to_bytes(response.into_body(),2048).await.unwrap();assert_eq!(status,200,"{}",String::from_utf8_lossy(&body));assert_eq!(headers["cache-control"],"private, no-store");assert_eq!(&body[..],b"isolated private delivery bytes");
 let action=json!({"ticketId":sid,"accessToken":v["accessToken"],"manifestRoot":root,"action":"received"});a.delivery_action(&action,1003).unwrap();a.delivery_action(&action,1004).unwrap();
 let mut altered=action.clone();altered["manifestRoot"]=json!("d".repeat(64));assert!(a.delivery_action(&altered,1005).is_err());
 let db=rusqlite::Connection::open(d.path().join("target-v2.sqlite")).unwrap();assert_eq!(db.query_row("SELECT COUNT(*) FROM private_delivery_events WHERE kind='received'",[],|r|r.get::<_,u64>(0)).unwrap(),1);drop(db);
 fs::write(&file,b"tampered").unwrap();let damaged=app.oneshot(req(good,"/api/service-requests/delivery-file")).await.unwrap();assert_eq!(damaged.status(),503);
}
