use super::*;
use crate::CanonicalSynapse;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use std::io::Write;
use tower::ServiceExt;

fn fixture() -> (tempfile::TempDir, Arc<LoadedRuntime>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synapses.bin");
    let mut file = File::create(&path).unwrap();
    for i in 0..20_u32 {
        file.write_all(
            &CanonicalSynapse {
                body_pre: (i % 4 + 1) as u64,
                body_post: ((i + 1) % 4 + 1) as u64,
                x_pre: i,
                y_pre: i + 1,
                z_pre: i + 2,
                x_post: i + 3,
                y_post: i + 4,
                z_post: i + 5,
            }
            .consensus_bytes(),
        )
        .unwrap();
    }
    drop(file);
    let dataset = CanonicalDataset::inspect(path).unwrap();
    let epoch_seed = [3; 32];
    let miner_key = [4; 32];
    let index = CompactIndex::build(
        &dataset,
        epoch_seed,
        miner_key,
        &dir.path().join("index.bin"),
        |_| {},
    )
    .unwrap();
    assert_eq!(
        encode_hex(&index.artifact_root()),
        "f7212e810f6300f40a0aaf63ccadbbeb5278d2cb90d61be1b4a5c66186e35648"
    );
    (
        dir,
        Arc::new(LoadedRuntime {
            dataset,
            index,
            epoch_seed,
            miner_key,
            manifest: json!({}),
            load_seconds: 0.0,
        }),
    )
}

#[test]
fn verification_recomputes_and_rejects_mutated_fields() {
    let (_dir, rt) = fixture();
    let block = BlockTemplate::new([0; 32], message_root("known message"), 0, 1_789_344_000, 0);
    let ctx = DatasetFlyPowContext::new(
        block.clone(),
        &rt.dataset,
        &rt.index,
        rt.epoch_seed,
        rt.miner_key,
    )
    .unwrap();
    let proof = Proof::from_work(
        &rt,
        &block,
        "known message",
        ctx.challenge(),
        ctx.hash_nonce(7).unwrap(),
    );
    let good = verify_proof(&rt, proof.clone()).unwrap();
    assert!(good.valid);
    assert_eq!(good.checks.len(), 11);
    let mut mutations = Vec::new();
    let mut p = proof.clone();
    p.nonce = "8".into();
    mutations.push(p);
    let mut p = proof.clone();
    p.work_hash = "00".repeat(32);
    mutations.push(p);
    let mut p = proof.clone();
    p.dataset_root = "00".repeat(32);
    mutations.push(p);
    let mut p = proof.clone();
    p.artifact_root = "00".repeat(32);
    mutations.push(p);
    let mut p = proof.clone();
    p.message = "edited message".into();
    mutations.push(p);
    let mut p = proof.clone();
    p.winners.pop();
    mutations.push(p);
    let mut p = proof.clone();
    p.access_rounds = 1;
    mutations.push(p);
    let mut p = proof.clone();
    p.template.difficulty_bits = 1;
    mutations.push(p);
    let mut p = proof.clone();
    p.access_trace = "00".repeat(32);
    mutations.push(p);
    let mut p = proof.clone();
    p.epoch_seed = "00".repeat(32);
    mutations.push(p);
    for p in mutations {
        assert!(!verify_proof(&rt, p).unwrap().valid);
    }
    let mut bad = proof;
    bad.nonce = "18446744073709551616".into();
    assert!(verify_proof(&rt, bad).is_err());
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    origin: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1:8787");
    if let Some(origin) = origin {
        builder = builder.header("Origin", origin);
    }
    let request = if let Some(body) = body {
        builder
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)})),
    )
}

#[tokio::test]
async fn http_mining_verification_limits_and_origin_checks() {
    let (dir, rt) = fixture();
    let state = WebState::new(dir.path().into(), 8787);
    let app = router(state.clone());
    let request =
        json!({"message":"api test","difficulty_bits":0,"max_attempts":1,"start_nonce":"0"});
    assert_eq!(
        call(&app, "POST", "/api/mine", Some(request.clone()), None)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    *state.runtime.write().unwrap() = Some(rt);
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/mine",
            Some(request.clone()),
            Some("https://example.com")
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut invalid = request.clone();
    invalid["max_attempts"] = json!(200_001);
    assert_eq!(
        call(&app, "POST", "/api/mine", Some(invalid), None).await.0,
        StatusCode::BAD_REQUEST
    );
    let guard = state.mining_slot.clone().acquire_owned().await.unwrap();
    assert_eq!(
        call(&app, "POST", "/api/mine", Some(request.clone()), None)
            .await
            .0,
        StatusCode::CONFLICT
    );
    drop(guard);
    let (status, job) = call(&app, "POST", "/api/mine", Some(request), None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let path = format!("/api/jobs/{}", job["id"].as_str().unwrap());
    let found = tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let (_, job) = call(&app, "GET", &path, None, None).await;
            if job["status"] != "running" {
                break job;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(found["status"], "found");
    let (status, result) = call(
        &app,
        "POST",
        "/api/verify",
        Some(found["proof"].clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["valid"], true);
    assert_eq!(
        call(&app, "GET", "/api/synapses/20", None, None).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut bad = found["proof"].clone();
    bad["unexpected"] = json!(true);
    assert_eq!(
        call(&app, "POST", "/api/verify", Some(bad), None).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let index = state
        .runtime
        .read()
        .unwrap()
        .as_ref()
        .unwrap()
        .index
        .first_body_id();
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/api/fingerprints/{index}"),
            None,
            None
        )
        .await
        .1["winners"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
}

use std::fs::File;

#[tokio::test]
async fn signed_wallet_mining_binds_owner_and_validator_attests_real_work() {
    use ed25519_dalek::{Signer, SigningKey};
    fn signed_request(state: &WebState, k: &SigningKey, action: &str, payload: Value) -> Value {
        let public = k.verifying_key().to_bytes();
        let address = crate::network::address_from_public_key(&public);
        let now = unix_now();
        let mut a = SignedAction {
            public_key: encode_hex(&public),
            nonce: state.network.account(&address, now).unwrap()["nonce"]
                .as_str()
                .unwrap()
                .into(),
            expires_at: now + 180,
            action: action.into(),
            payload: payload.to_string(),
            signature: String::new(),
        };
        a.signature = encode_hex(
            &k.sign(&crate::network::signing_message(&state.network.id, &a))
                .to_bytes(),
        );
        serde_json::to_value(a).unwrap()
    }
    async fn mine_for(app: &Router, state: &WebState, key: &SigningKey, message: &str) -> Value {
        let (_, ticket) = call(
            app,
            "POST",
            "/api/network/action",
            Some(signed_request(
                state,
                key,
                "mine",
                json!({"message":message}),
            )),
            None,
        )
        .await;
        assert_eq!(ticket["ok"], true);
        // This test covers signed ownership and attestation, not the probability
        // of winning a legacy hash search within a wall-clock timeout. Select a
        // valid nonce from the exact signed challenge first; the HTTP job still
        // computes and the ledger still independently checks the actual work.
        let start_nonce = {
            let binding: NetworkBinding =
                serde_json::from_value(ticket["result"]["binding"].clone()).unwrap();
            let loaded = state.runtime.read().unwrap();
            let rt = loaded.as_ref().unwrap();
            let template = BlockTemplate::new(
                decode_hash(&binding.previous_hash).unwrap(),
                bound_merkle(message, &binding),
                binding.height,
                binding.timestamp,
                NETWORK_DIFFICULTY_BITS,
            );
            let context = DatasetFlyPowContext::new(
                template,
                &rt.dataset,
                &rt.index,
                rt.epoch_seed,
                rt.miner_key,
            )
            .unwrap();
            (0..10000)
                .find(|nonce| {
                    meets_difficulty(
                        &context.hash_nonce(*nonce).unwrap().hash,
                        NETWORK_DIFFICULTY_BITS,
                    )
                })
                .expect("bounded legacy test challenge must have a valid nonce")
        };
        let(status,job)=call(app,"POST","/api/mine",Some(json!({"message":message,"difficulty_bits":NETWORK_DIFFICULTY_BITS,"max_attempts":1,"start_nonce":start_nonce.to_string(),"ticket":ticket["result"]["ticket"]})),None).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let path = format!("/api/jobs/{}", job["id"].as_str().unwrap());
        tokio::time::timeout(Duration::from_secs(35), async {
            loop {
                let (_, job) = call(app, "GET", &path, None, None).await;
                if job["status"] == "found" {
                    let hash = job["proof"]["work_hash"].as_str().unwrap();
                    if state.network.candidate_proof(hash).is_ok() {
                        break job["proof"].clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }
    let (dir, rt) = fixture();
    let state = WebState::new(dir.path().into(), 8787);
    *state.runtime.write().unwrap() = Some(rt);
    let app = router(state.clone());
    let validator = SigningKey::from_bytes(&[90; 32]);
    let miner = SigningKey::from_bytes(&[91; 32]);
    for key in [&validator, &miner] {
        let (status, result) = call(
            &app,
            "POST",
            "/api/network/action",
            Some(signed_request(
                &state,
                key,
                "register",
                json!({"referrer":""}),
            )),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["ok"], true);
    }
    mine_for(&app, &state, &validator, "validator qualification").await;
    for action in ["bootstrap", "stake"] {
        let (status, result) = call(
            &app,
            "POST",
            "/api/network/action",
            Some(signed_request(&state, &validator, action, json!({}))),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
    }
    let proof = mine_for(&app, &state, &miner, "signed miner").await;
    assert_eq!(
        proof["binding"]["owner"],
        crate::network::address_from_public_key(&miner.verifying_key().to_bytes())
    );
    let (_, verified) = call(&app, "POST", "/api/verify", Some(proof.clone()), None).await;
    assert_eq!(verified["valid"], true);
    let hash = proof["work_hash"].as_str().unwrap();
    let candidate_path = format!("/api/network/candidates/{hash}");
    let (status, candidate) = call(&app, "GET", &candidate_path, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(candidate["status"], "pending");
    assert_eq!(candidate["quorum"], 1);
    let (status, result) = call(
        &app,
        "POST",
        "/api/network/action",
        Some(signed_request(
            &state,
            &validator,
            "attest",
            json!({"candidate":hash,"work_hash":hash}),
        )),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    state.network.tick(unix_now() + 61).unwrap();
    assert_eq!(state.network.status(unix_now() + 61).unwrap()["height"], 1);
    let (_, candidate) = call(&app, "GET", &candidate_path, None, None).await;
    assert_eq!(candidate["status"], "finalized");
    assert_eq!(candidate["votes"], 1);
}

#[tokio::test]
async fn native_pages_and_persistent_candidate_explorer() {
    let (directory, runtime) = fixture();
    let state = WebState::new(directory.path().into(), 8787);
    let template = BlockTemplate::new(
        [0; 32],
        message_root("archive fixture"),
        0,
        1_789_344_000,
        0,
    );
    let context = DatasetFlyPowContext::new(
        template.clone(),
        &runtime.dataset,
        &runtime.index,
        runtime.epoch_seed,
        runtime.miner_key,
    )
    .unwrap();
    let proof = Proof::from_work(
        &runtime,
        &template,
        "archive fixture",
        context.challenge(),
        context.hash_nonce(7).unwrap(),
    );
    let hash = proof.work_hash.clone();
    let record = LocalBlock {
        proof,
        attempts: 8,
        elapsed_ms: 12.0,
        nonces_per_second: 666.0,
    };
    save_local_block(&state, record.clone()).unwrap();
    save_local_block(&state, record).unwrap();
    assert_eq!(state.blocks.read().unwrap().len(), 1);
    let restarted = WebState::new(directory.path().into(), 8787);
    assert_eq!(restarted.blocks.read().unwrap().len(), 1);
    *restarted.runtime.write().unwrap() = Some(runtime);
    let app = router(restarted);
    for route in [
        "/",
        "/mining",
        "/atlas",
        "/wallet",
        "/validators",
        "/community",
        "/economics",
        "/explorer",
        "/roadmap",
        "/whitepaper",
        "/blog",
        "/blog/full-connectome",
        "/blog/flyhash-and-pow",
        "/blog/compact-index",
    ] {
        let (status, body) = call(&app, "GET", route, None, None).await;
        assert_eq!(status, StatusCode::OK, "{route}");
        let html = body["text"].as_str().unwrap();
        assert!(html.contains("Main navigation"));
        assert!(!html.contains("{{"), "unresolved page template: {route}");
    }
    let (_, list) = call(&app, "GET", "/api/blocks", None, None).await;
    for (path, expected) in [
        (
            "/whitepaper.md",
            "Verifiable computation and finite-budget settlement V2",
        ),
        ("/whitepaper.md?lang=zh", "Flybrain: verifiable computation and finite settlement budgets V2"),
    ] {
        let (status, body) = call(&app, "GET", path, None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["text"].as_str().unwrap().contains(expected));
    }
    let (status, candidate) = call(
        &app,
        "GET",
        &format!("/api/network/candidates/{hash}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(candidate["status"], "legacy");
    assert_eq!(list["total"], 1);
    assert_eq!(list["entries"][0]["hash"], hash);
    let (_, filtered) = call(
        &app,
        "GET",
        &format!("/api/blocks?q={}", &hash[..8]),
        None,
        None,
    )
    .await;
    assert_eq!(filtered["matched"], 1);
    let (_, empty) = call(&app, "GET", "/api/blocks?q=not-a-match", None, None).await;
    assert_eq!(empty["matched"], 0);
    let (_, detail) = call(&app, "GET", &format!("/api/blocks/{hash}"), None, None).await;
    assert_eq!(detail["record"], 1);
    let (_, checked) = call(
        &app,
        "POST",
        "/api/verify",
        Some(detail["block"]["proof"].clone()),
        None,
    )
    .await;
    assert_eq!(checked["valid"], true);
    assert_eq!(
        call(&app, "GET", "/blog/missing", None, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "GET", "/assets/%2e%2e/Cargo.toml", None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}
