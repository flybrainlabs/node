//! Local HTTP workbench. All computations share one fully scanned dataset and
//! one locally generated index. A proof is checked against that trusted runtime.
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::{
    BlockTemplate, CanonicalDataset, DatasetFlyPowContext, Hash256,
    block::HEADER_VERSION,
    compact_index::CompactIndex,
    dataset::{OFFICIAL_DATASET_PAGE, OFFICIAL_SOURCE_MD5_HEX, OFFICIAL_SOURCE_SIZE},
    decode_hash,
    economics::NETWORK_DIFFICULTY_BITS,
    encode_hex,
    hash::hash_parts,
    network::{Network, NetworkBinding, SignedAction, bound_merkle},
    pow::{DATASET_ACCESS_ROUNDS, DatasetNonceWork, leading_zero_bits, meets_difficulty},
    useful::{FingerprintLookup, derive_sketch_seed},
};

const PROTOCOL: &str = "flypow-local-web-v1";
const MAX_ATTEMPTS: u64 = 200_000;
const MAX_DIFFICULTY: u16 = 20;
const MAX_JOB_SECONDS: u64 = 30;

#[derive(Clone, Serialize)]
struct LoadProgress {
    stage: String,
    message: String,
    completed: u64,
    total: u64,
    bodies: usize,
}

pub struct LoadedRuntime {
    dataset: CanonicalDataset,
    index: CompactIndex,
    epoch_seed: Hash256,
    miner_key: Hash256,
    manifest: Value,
    load_seconds: f64,
}

pub struct WebState {
    data_dir: PathBuf,
    progress: RwLock<LoadProgress>,
    runtime: RwLock<Option<Arc<LoadedRuntime>>>,
    jobs: Mutex<BTreeMap<u64, Arc<Job>>>,
    sequence: AtomicU64,
    mining_slot: Arc<Semaphore>,
    verification_slots: Arc<Semaphore>,
    port: u16,
    blocks: RwLock<Vec<LocalBlock>>,
    network: Arc<Network>,
}

impl WebState {
    pub fn new(data_dir: PathBuf, port: u16) -> Arc<Self> {
        let blocks = load_local_blocks(&data_dir);
        let network = Arc::new(
            Network::open(&data_dir.join("runtime/network.sqlite"), unix_now())
                .expect("open persistent testnet ledger"),
        );
        Arc::new(Self {
            data_dir,
            progress: RwLock::new(LoadProgress {
                stage: "waiting".into(),
                message: "等待官方数据下载与转换".into(),
                completed: 0,
                total: 0,
                bodies: 0,
            }),
            runtime: RwLock::new(None),
            jobs: Mutex::new(BTreeMap::new()),
            sequence: AtomicU64::new(1),
            mining_slot: Arc::new(Semaphore::new(1)),
            verification_slots: Arc::new(Semaphore::new(2)),
            port,
            blocks: RwLock::new(blocks),
            network,
        })
    }

    fn progress(&self, stage: &str, message: &str, completed: u64, total: u64, bodies: usize) {
        *self.progress.write().unwrap() = LoadProgress {
            stage: stage.into(),
            message: message.into(),
            completed,
            total,
            bodies,
        };
    }

    fn loaded(&self) -> Result<Arc<LoadedRuntime>, ApiError> {
        self.runtime.read().unwrap().clone().ok_or_else(|| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "数据尚未装载完成，请等待进度显示就绪".into(),
            )
        })
    }

    pub fn start_loader(self: &Arc<Self>) {
        let network = self.network.clone();
        std::thread::spawn(move || {
            loop {
                if let Err(error) = network.tick(unix_now()) {
                    eprintln!("Network settlement: {error}");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        let state = self.clone();
        std::thread::spawn(move || {
            let manifest_path = state.data_dir.join("prepared/malecns-v1.synapses.bin.json");
            while !manifest_path.exists() {
                std::thread::sleep(Duration::from_secs(2));
            }
            if let Err(error) = load_runtime(&state, &manifest_path) {
                eprintln!("Dataset initialization failed: {error}");
                state.progress("error", &format!("数据装载失败：{error}"), 0, 0, 0);
            }
        });
    }
}

fn load_runtime(state: &WebState, manifest_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let manifest: Value = serde_json::from_slice(&fs::read(manifest_path)?)?;
    if manifest["official_source_verified"] != true
        || manifest["source"]["md5"] != OFFICIAL_SOURCE_MD5_HEX
        || manifest["source"]["bytes"] != OFFICIAL_SOURCE_SIZE
        || manifest["format"] != "flypow-canonical-synapses-v1"
        || manifest["record_bytes"] != 40
        || manifest["chunk_records"] != 4096
    {
        return Err("规范化文件不是经官方源校验的受支持版本".into());
    }
    let root = decode_hash(
        manifest["canonical_merkle_root"]
            .as_str()
            .ok_or("缺少数据根")?,
    )?;
    state.progress(
        "loading",
        "全量扫描规范化突触数据，复核 Python 与 Rust 的数据根",
        0,
        0,
        0,
    );
    let dataset = CanonicalDataset::open_verified(
        state.data_dir.join("prepared/malecns-v1.synapses.bin"),
        root,
    )?;
    if manifest["record_count"] != dataset.record_count()
        || manifest["canonical_bytes"] != dataset.byte_len()
    {
        return Err("规范化记录数或长度与清单不匹配".into());
    }
    let epoch_seed = hash_parts(b"FlyPoW/local-web-epoch/v1", &[&root]);
    let miner_key = hash_parts(b"FlyPoW/local-web-demo-key/v1", &[&root]);
    let index_path = state.data_dir.join("prepared/web-v1.compact.bin");
    let receipt_path = state.data_dir.join("prepared/web-v1.compact.receipt.json");
    let index = if index_path.exists() && receipt_path.exists() {
        state.progress(
            "index_loading",
            "校验并装载本机已生成的 FlyHash 索引",
            0,
            0,
            0,
        );
        let receipt: Value = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        let expected_artifact = decode_hash(
            receipt["artifact_root"]
                .as_str()
                .ok_or("索引收据缺少 root")?,
        )?;
        let index = CompactIndex::open_verified(
            &index_path,
            root,
            derive_sketch_seed(root, epoch_seed, miner_key),
            expected_artifact,
            |p| {
                state.progress(
                    p.phase,
                    "复核压缩索引中的所有神经片段指纹",
                    p.completed,
                    p.total,
                    p.bodies,
                )
            },
        )?;
        if receipt["dataset_root"] != encode_hex(&root)
            || receipt["artifact_root"] != encode_hex(&index.artifact_root())
        {
            return Err("本地索引与首次构建收据不匹配".into());
        }
        index
    } else {
        let index = CompactIndex::build(&dataset, epoch_seed, miner_key, &index_path, |p| {
            let message = if p.phase == "partitioning" {
                "全量遍历突触，按 body ID 分块准备连接草图"
            } else {
                "为所有 body ID 生成 FlyHash 稀疏指纹"
            };
            state.progress(p.phase, message, p.completed, p.total, p.bodies);
            eprintln!(
                "{} {}/{} bodies={}",
                p.phase, p.completed, p.total, p.bodies
            );
        })?;
        state.progress("index_saving", "保存全量索引与构建收据", 0, 0, index.len());
        fs::write(
            &receipt_path,
            serde_json::to_vec_pretty(
                &json!({"dataset_root": encode_hex(&root), "artifact_root": encode_hex(&index.artifact_root()), "bodies": index.len(), "epoch_seed": encode_hex(&epoch_seed), "miner_key": encode_hex(&miner_key)}),
            )?,
        )?;
        index
    };
    let records = dataset.record_count();
    let bodies = index.len();
    *state.runtime.write().unwrap() = Some(Arc::new(LoadedRuntime {
        dataset,
        index,
        epoch_seed,
        miner_key,
        manifest,
        load_seconds: started.elapsed().as_secs_f64(),
    }));
    state.progress(
        "ready",
        "全量数据与 FlyHash 索引已装载，可以开始验证",
        records,
        records,
        bodies,
    );
    eprintln!("Ready: {records} synaptic partner rows, {bodies} body IDs");
    Ok(())
}

#[derive(Debug)]
struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
fn bad(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}
fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
fn parse_hash(text: &str) -> Result<Hash256, ApiError> {
    decode_hash(text).map_err(|e| bad(e.to_string()))
}

// Binding only loopback and checking Host/Origin prevents another website from
// using this unauthenticated local workbench as a compute endpoint.
fn local_request(headers: &HeaderMap, port: u16) -> Result<(), ApiError> {
    let hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if !headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|host| hosts.iter().any(|h| h == host))
    {
        return Err(ApiError(StatusCode::FORBIDDEN, "仅允许本机访问".into()));
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.to_str().map_err(|_| bad("Origin 无效"))?;
        if !hosts.iter().any(|host| origin == format!("http://{host}")) {
            return Err(ApiError(StatusCode::FORBIDDEN, "拒绝跨站计算请求".into()));
        }
    }
    Ok(())
}

pub fn router(state: Arc<WebState>) -> Router {
    let csp = research_csp();
    Router::new()
        .merge(crate::site::routes())
        .route(
            "/app.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/app.css"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/favicon.svg",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "image/svg+xml")],
                    include_str!("../web/favicon.svg"),
                )
            }),
        )
        .route("/api/status", get(status))
        .route("/api/mine", post(start_mining))
        .route("/api/jobs/{id}", get(job_status))
        .route("/api/jobs/{id}/cancel", post(cancel_job))
        .route("/api/verify", post(verify))
        .route("/api/synapses/{index}", get(synapse))
        .route("/api/fingerprints/{body_id}", get(fingerprint))
        .route("/api/blocks", get(list_blocks))
        .route("/api/blocks/{hash}", get(block_detail))
        .route("/api/network", get(network_status))
        .route("/api/network/action", post(network_action))
        .route("/api/network/accounts/{address}", get(network_account))
        .route("/api/network/community", get(network_community))
        .route("/api/network/validators", get(network_validators))
        .route("/api/network/chain", get(network_chain))
        .route(
            "/api/network/candidates/{hash}",
            get(network_candidate_state),
        )
        .route(
            "/api/network/candidates/{hash}/verify",
            post(recompute_candidate),
        )
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(axum::middleware::from_fn(
            move |request, next: axum::middleware::Next| {
                let csp = csp.clone();
                async move {
                    let mut response = next.run(request).await;
                    let headers = response.headers_mut();
                    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
                    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
                    headers.insert(header::CONTENT_SECURITY_POLICY, csp);
                    response
                }
            },
        ))
        .with_state(state)
}

// The browser checks genesis, program and frozen catalog separately. This policy only
// grants explicitly configured development origins; malformed configuration fails closed.
fn research_csp() -> axum::http::HeaderValue {
    let mut origins =
        std::collections::BTreeSet::from(["https://storage.googleapis.com".to_string()]);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("web/data/chain-config.json");
    let config: Value = fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    if config["enabled"].as_bool() == Some(true) {
        let network = config["network"].as_str().unwrap_or("");
        let mut endpoints = vec![
            config["rpc"].as_str().unwrap_or(""),
            config["wss"].as_str().unwrap_or(""),
        ];
        let archives = config["archives"]
            .as_array()
            .expect("Archives must be configured");
        assert!(archives.len() <= 4, "Archive origin bound");
        endpoints.extend(archives.iter().map(|a| a.as_str().expect("Archive URL")));
        for (i, value) in endpoints.iter().enumerate() {
            assert!(!value.contains('#'), "Endpoint fragment not allowed");
            let uri: axum::http::Uri = value.parse().expect("Development endpoint URI");
            let scheme = uri.scheme_str().expect("Endpoint scheme");
            let host = uri.host().expect("Endpoint host");
            let authority = uri.authority().expect("Endpoint authority");
            assert!(
                !authority.as_str().contains('@'),
                "Endpoint credentials not allowed"
            );
            let allowed = if network == "localnet" {
                ["127.0.0.1", "localhost", "[::1]", "::1"].contains(&host)
                    && if i == 1 {
                        ["ws", "wss"].contains(&scheme)
                    } else {
                        ["http", "https"].contains(&scheme)
                    }
            } else if network == "devnet" {
                if i < 2 {
                    value.trim_end_matches('/')
                        == [
                            "https://api.devnet.solana.com",
                            "wss://api.devnet.solana.com",
                        ][i]
                } else {
                    scheme == "https"
                }
            } else {
                false
            };
            assert!(
                allowed,
                "Only explicit localnet/devnet endpoints are supported"
            );
            origins.insert(format!("{scheme}://{authority}"));
        }
    }
    format!("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' {}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",origins.into_iter().collect::<Vec<_>>().join(" ")).parse().unwrap()
}

async fn status(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    local_request(&headers, state.port)?;
    let progress = state.progress.read().unwrap().clone();
    let mut progress_value = serde_json::to_value(&progress).map_err(internal)?;
    if progress.stage == "waiting" {
        if let Ok(bytes) = fs::read(state.data_dir.join("runtime/prepare.json"))
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        {
            progress_value = value;
        }
        if progress_value["stage"] == "downloading" {
            #[cfg(unix)]
            if let Ok(meta) = fs::metadata(
                state
                    .data_dir
                    .join("raw/syn-partners-male-cns-v1.0-minconf-0.5.feather"),
            ) {
                use std::os::unix::fs::MetadataExt;
                progress_value["completed"] =
                    json!((meta.blocks() * 512).min(OFFICIAL_SOURCE_SIZE));
                progress_value["total"] = json!(OFFICIAL_SOURCE_SIZE);
                progress_value["approximate"] = json!(true);
            }
        }
    }
    let runtime = state.runtime.read().unwrap();
    let data = runtime.as_ref().map(|rt| json!({
        "record_count": rt.dataset.record_count(), "canonical_bytes": rt.dataset.byte_len(),
        "body_count": rt.index.len(), "chunk_count": rt.dataset.chunk_count(),
        "dataset_root": encode_hex(&rt.dataset.merkle_root()), "artifact_root": encode_hex(&rt.index.artifact_root()),
        "epoch_seed": encode_hex(&rt.epoch_seed), "miner_key": encode_hex(&rt.miner_key),
        "source_sha256": rt.manifest["source"]["sha256"], "load_seconds": rt.load_seconds,
        "example_body_id": rt.index.first_body_id().to_string(),
        "index_bytes": rt.index.byte_len(), "unique_codes": rt.index.unique_codes(),
        "index_validated_by": "local_full_computation"
    }));
    Ok(Json(
        json!({"protocol": PROTOCOL, "ready": runtime.is_some(), "progress": progress_value,
        "data": data, "source": {"name": "MaleCNS v1.0", "page": OFFICIAL_DATASET_PAGE, "bytes": OFFICIAL_SOURCE_SIZE, "license": "CC-BY 4.0"},
        "limits": {"max_attempts": MAX_ATTEMPTS, "max_difficulty_bits": MAX_DIFFICULTY, "job_seconds": MAX_JOB_SECONDS, "access_rounds": DATASET_ACCESS_ROUNDS}}),
    ))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MineRequest {
    message: String,
    difficulty_bits: u16,
    max_attempts: u64,
    #[serde(default = "zero_nonce")]
    start_nonce: String,
    #[serde(default)]
    ticket: Option<String>,
}
fn zero_nonce() -> String {
    "0".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    protocol: String,
    dataset_root: String,
    artifact_root: String,
    epoch_seed: String,
    miner_key: String,
    message: String,
    template: ProofTemplate,
    nonce: String,
    challenge: String,
    work_hash: String,
    access_trace: String,
    flyhash_digest: String,
    winners: Vec<u32>,
    access_rounds: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<NetworkBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofTemplate {
    version: u32,
    previous_hash: String,
    merkle_root: String,
    height: String,
    timestamp: String,
    difficulty_bits: u16,
}

impl ProofTemplate {
    fn block(&self) -> Result<BlockTemplate, ApiError> {
        Ok(BlockTemplate {
            version: self.version,
            previous_hash: parse_hash(&self.previous_hash)?,
            merkle_root: parse_hash(&self.merkle_root)?,
            height: self
                .height
                .parse()
                .map_err(|_| bad("height 必须为 u64 十进制字符串"))?,
            timestamp: self
                .timestamp
                .parse()
                .map_err(|_| bad("timestamp 必须为 u64 十进制字符串"))?,
            difficulty_bits: self.difficulty_bits,
        })
    }
}
fn message_root(message: &str) -> Hash256 {
    hash_parts(b"FlyPoW/web-message/v1", &[message.as_bytes()])
}

impl Proof {
    fn from_work(
        rt: &LoadedRuntime,
        block: &BlockTemplate,
        message: &str,
        challenge: Hash256,
        work: DatasetNonceWork,
    ) -> Self {
        Self {
            protocol: PROTOCOL.into(),
            dataset_root: encode_hex(&rt.dataset.merkle_root()),
            artifact_root: encode_hex(&rt.index.artifact_root()),
            epoch_seed: encode_hex(&rt.epoch_seed),
            miner_key: encode_hex(&rt.miner_key),
            message: message.into(),
            template: ProofTemplate {
                version: block.version,
                previous_hash: encode_hex(&block.previous_hash),
                merkle_root: encode_hex(&block.merkle_root),
                height: block.height.to_string(),
                timestamp: block.timestamp.to_string(),
                difficulty_bits: block.difficulty_bits,
            },
            nonce: work.nonce.to_string(),
            challenge: encode_hex(&challenge),
            work_hash: encode_hex(&work.hash),
            access_trace: encode_hex(&work.access_trace),
            flyhash_digest: encode_hex(&work.flyhash.code_digest),
            winners: work.flyhash.winners,
            access_rounds: DATASET_ACCESS_ROUNDS,
            binding: None,
        }
    }
}

#[derive(Clone, Serialize)]
struct JobView {
    id: String,
    status: String,
    attempts: u64,
    max_attempts: u64,
    elapsed_ms: f64,
    nonces_per_second: f64,
    proof: Option<Proof>,
    error: Option<String>,
}
struct Job {
    view: Mutex<JobView>,
    cancelled: AtomicBool,
}

fn legacy_write_guard() -> Result<(), ApiError> {
    if cfg!(test) || std::env::var("FLYPOW_ENABLE_LEGACY_WRITES").as_deref() == Ok("1") {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::GONE,
            "Legacy FlyHash ledger writes are disabled; the new browser research experiment has no rewards".into(),
        ))
    }
}

async fn start_mining(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(request): Json<MineRequest>,
) -> Result<(StatusCode, Json<JobView>), ApiError> {
    local_request(&headers, state.port)?;
    legacy_write_guard()?;
    if request.message.len() > 1024 {
        return Err(bad("消息不能超过 1024 字节"));
    }
    if request.difficulty_bits > MAX_DIFFICULTY {
        return Err(bad("网页实验难度范围为 0–20 bit"));
    }
    if request.max_attempts == 0 || request.max_attempts > MAX_ATTEMPTS {
        return Err(bad("尝试次数范围为 1–200000"));
    }
    let start_nonce = request
        .start_nonce
        .parse::<u64>()
        .map_err(|_| bad("nonce 必须为 u64 十进制字符串"))?;
    if start_nonce.checked_add(request.max_attempts - 1).is_none() {
        return Err(bad("nonce 搜索范围溢出"));
    }
    let runtime = state.loaded()?;
    let permit = state.mining_slot.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::CONFLICT,
            "已有试挖任务正在运行，可先取消该任务".into(),
        )
    })?;
    let binding = if let Some(ticket) = &request.ticket {
        if request.difficulty_bits != NETWORK_DIFFICULTY_BITS {
            return Err(bad("Use the network difficulty for wallet mining"));
        }
        Some(
            state
                .network
                .consume_ticket(ticket, &request.message, unix_now())
                .map_err(bad)?,
        )
    } else {
        None
    };
    let id = state.sequence.fetch_add(1, Ordering::Relaxed);
    let view = JobView {
        id: id.to_string(),
        status: "running".into(),
        attempts: 0,
        max_attempts: request.max_attempts,
        elapsed_ms: 0.0,
        nonces_per_second: 0.0,
        proof: None,
        error: None,
    };
    let job = Arc::new(Job {
        view: Mutex::new(view.clone()),
        cancelled: AtomicBool::new(false),
    });
    {
        let mut jobs = state.jobs.lock().unwrap();
        while jobs.len() >= 16 {
            jobs.pop_first();
        }
        jobs.insert(id, job.clone());
    }
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if let Err(error) = mine_job(&runtime, &request, start_nonce, &job, binding) {
            let mut view = job.view.lock().unwrap();
            view.status = "error".into();
            view.error = Some(error.to_string());
        } else {
            let result = job.view.lock().unwrap().clone();
            if let Some(proof) = &result.proof
                && let Some(binding) = &proof.binding
                && let Err(error) = state.network.accept_proof(
                    binding,
                    &serde_json::to_value(proof).unwrap(),
                    &proof.work_hash,
                    unix_now(),
                )
            {
                job.view.lock().unwrap().error = Some(format!(
                    "Proof generated; ledger submission failed: {error}"
                ));
            }
            if let Some(proof) = result.proof
                && let Err(error) = save_local_block(
                    &state,
                    LocalBlock {
                        proof,
                        attempts: result.attempts,
                        elapsed_ms: result.elapsed_ms,
                        nonces_per_second: result.nonces_per_second,
                    },
                )
            {
                job.view.lock().unwrap().error =
                    Some(format!("证明已生成，但记录保存失败：{error}"));
            }
        }
    });
    Ok((StatusCode::ACCEPTED, Json(view)))
}

fn mine_job(
    rt: &LoadedRuntime,
    request: &MineRequest,
    start_nonce: u64,
    job: &Job,
    binding: Option<NetworkBinding>,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let block = if let Some(b) = &binding {
        BlockTemplate::new(
            decode_hash(&b.previous_hash)?,
            bound_merkle(&request.message, b),
            b.height,
            b.timestamp,
            NETWORK_DIFFICULTY_BITS,
        )
    } else {
        BlockTemplate::new(
            [0; 32],
            message_root(&request.message),
            0,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            request.difficulty_bits,
        )
    };
    let context = DatasetFlyPowContext::new(
        block.clone(),
        &rt.dataset,
        &rt.index,
        rt.epoch_seed,
        rt.miner_key,
    )?;
    let mut attempts = 0;
    let mut status = "not_found";
    let mut proof = None;
    for offset in 0..request.max_attempts {
        if job.cancelled.load(Ordering::Relaxed) {
            status = "cancelled";
            break;
        }
        if started.elapsed() >= Duration::from_secs(MAX_JOB_SECONDS) {
            status = "timed_out";
            break;
        }
        let work = context.hash_nonce(start_nonce + offset)?;
        attempts += 1;
        if meets_difficulty(&work.hash, request.difficulty_bits) {
            proof = Some(Proof::from_work(
                rt,
                &block,
                &request.message,
                context.challenge(),
                work,
            ));
            proof.as_mut().unwrap().binding = binding.clone();
            status = "found";
            break;
        }
        if attempts % 64 == 0 {
            let mut view = job.view.lock().unwrap();
            view.attempts = attempts;
            view.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            view.nonces_per_second =
                attempts as f64 / started.elapsed().as_secs_f64().max(0.000_001);
        }
    }
    let mut view = job.view.lock().unwrap();
    view.attempts = attempts;
    view.status = status.into();
    view.proof = proof;
    view.elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    view.nonces_per_second = attempts as f64 / started.elapsed().as_secs_f64().max(0.000_001);
    Ok(())
}

async fn job_status(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<u64>,
) -> Result<Json<JobView>, ApiError> {
    local_request(&headers, state.port)?;
    let jobs = state.jobs.lock().unwrap();
    let job = jobs
        .get(&id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "任务不存在或已过期".into()))?;
    Ok(Json(job.view.lock().unwrap().clone()))
}
async fn cancel_job(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<u64>,
) -> Result<Json<Value>, ApiError> {
    local_request(&headers, state.port)?;
    let jobs = state.jobs.lock().unwrap();
    let job = jobs
        .get(&id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "任务不存在或已过期".into()))?;
    job.cancelled.store(true, Ordering::Relaxed);
    Ok(Json(json!({"cancellation_requested": true})))
}

#[derive(Serialize)]
struct Check {
    name: &'static str,
    valid: bool,
}
#[derive(Serialize)]
struct Verification {
    valid: bool,
    checks: Vec<Check>,
    actual_hash: Option<String>,
    leading_zero_bits: Option<u16>,
    elapsed_ms: f64,
}

fn verify_proof(rt: &LoadedRuntime, proof: Proof) -> Result<Verification, ApiError> {
    let started = Instant::now();
    if proof.message.len() > 1024 || proof.winners.len() > 2000 {
        return Err(bad("证明内容超过限制"));
    }
    let mut checks = vec![
        Check {
            name: "协议版本",
            valid: proof.protocol == PROTOCOL,
        },
        Check {
            name: "全量数据根",
            valid: proof.dataset_root == encode_hex(&rt.dataset.merkle_root()),
        },
        Check {
            name: "本机完整构建的索引根",
            valid: proof.artifact_root == encode_hex(&rt.index.artifact_root()),
        },
        Check {
            name: "Epoch 与矿工标识",
            valid: proof.epoch_seed == encode_hex(&rt.epoch_seed)
                && proof.miner_key == encode_hex(&rt.miner_key),
        },
        Check {
            name: "访问轮数",
            valid: proof.access_rounds == DATASET_ACCESS_ROUNDS,
        },
    ];
    if checks.iter().any(|c| !c.valid) {
        return Ok(Verification {
            valid: false,
            checks,
            actual_hash: None,
            leading_zero_bits: None,
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        });
    }
    let block = proof.template.block()?;
    let nonce = proof.nonce.parse::<u64>().map_err(|_| bad("nonce 无效"))?;
    if block.difficulty_bits > MAX_DIFFICULTY {
        return Err(bad("网页实验难度范围为 0–20 bit"));
    }
    checks.push(Check {
        name: "区块消息与实验模板",
        valid: block.version == HEADER_VERSION
            && if let Some(binding) = &proof.binding {
                block.height == binding.height
                    && block.timestamp == binding.timestamp
                    && proof.message == binding.message
                    && block.difficulty_bits == NETWORK_DIFFICULTY_BITS
                    && encode_hex(&block.previous_hash) == binding.previous_hash
                    && block.merkle_root == bound_merkle(&proof.message, binding)
                    && crate::network::valid_address(&binding.owner)
            } else {
                block.height == 0
                    && block.previous_hash == [0; 32]
                    && block.merkle_root == message_root(&proof.message)
            },
    });
    let context = DatasetFlyPowContext::new(
        block.clone(),
        &rt.dataset,
        &rt.index,
        rt.epoch_seed,
        rt.miner_key,
    )
    .map_err(internal)?;
    let work = context.hash_nonce(nonce).map_err(internal)?;
    checks.push(Check {
        name: "区块挑战",
        valid: proof.challenge == encode_hex(&context.challenge()),
    });
    checks.push(Check {
        name: "256 次突触访问轨迹",
        valid: proof.access_trace == encode_hex(&work.access_trace),
    });
    checks.push(Check {
        name: "FlyHash 摘要与全部 100 个 winner",
        valid: proof.flyhash_digest == encode_hex(&work.flyhash.code_digest)
            && proof.winners == work.flyhash.winners,
    });
    checks.push(Check {
        name: "工作哈希",
        valid: proof.work_hash == encode_hex(&work.hash),
    });
    checks.push(Check {
        name: "PoW 难度",
        valid: meets_difficulty(&work.hash, block.difficulty_bits),
    });
    Ok(Verification {
        valid: checks.iter().all(|c| c.valid),
        checks,
        actual_hash: Some(encode_hex(&work.hash)),
        leading_zero_bits: Some(leading_zero_bits(&work.hash)),
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
    })
}

async fn verify(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(proof): Json<Proof>,
) -> Result<Json<Verification>, ApiError> {
    local_request(&headers, state.port)?;
    let rt = state.loaded()?;
    let permit = state
        .verification_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "验证任务繁忙，请稍后重试".into(),
            )
        })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_proof(&rt, proof).map(Json)
    })
    .await
    .map_err(internal)?
}

async fn synapse(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RoutePath(index): RoutePath<u64>,
) -> Result<Json<Value>, ApiError> {
    local_request(&headers, state.port)?;
    let rt = state.loaded()?;
    let s = rt.dataset.record(index).map_err(|e| bad(e.to_string()))?;
    Ok(Json(
        json!({"index": index.to_string(), "body_pre": s.body_pre.to_string(), "body_post": s.body_post.to_string(), "pre": [s.x_pre, s.y_pre, s.z_pre], "post": [s.x_post, s.y_post, s.z_post], "coordinate_unit": "8 nm voxel"}),
    ))
}
async fn fingerprint(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RoutePath(body): RoutePath<u64>,
) -> Result<Json<Value>, ApiError> {
    local_request(&headers, state.port)?;
    let rt = state.loaded()?;
    let fp = rt
        .index
        .fingerprint(body)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "找不到该 body ID".into()))?;
    Ok(Json(
        json!({"body_id": fp.body_id.to_string(), "winners": fp.winners, "leaf_hash": encode_hex(&fp.leaf_hash)}),
    ))
}

#[derive(Clone, Serialize, Deserialize)]
struct LocalBlock {
    proof: Proof,
    attempts: u64,
    elapsed_ms: f64,
    nonces_per_second: f64,
}

fn load_local_blocks(data_dir: &Path) -> Vec<LocalBlock> {
    let mut blocks = Vec::new();
    if let Ok(entries) = fs::read_dir(data_dir.join("runtime/blocks")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            if let Ok(meta) = entry.metadata()
                && meta.len() <= 32 * 1024
                && let Ok(bytes) = fs::read(&path)
                && let Ok(block) = serde_json::from_slice::<LocalBlock>(&bytes)
                && path.file_stem().and_then(|x| x.to_str()) == Some(block.proof.work_hash.as_str())
                && decode_hash(&block.proof.work_hash).is_ok()
            {
                blocks.push(block);
            }
        }
    }
    blocks.sort_by(|a, b| {
        a.proof
            .template
            .timestamp
            .cmp(&b.proof.template.timestamp)
            .then_with(|| a.proof.work_hash.cmp(&b.proof.work_hash))
    });
    blocks.dedup_by(|a, b| a.proof.work_hash == b.proof.work_hash);
    blocks
}

fn save_local_block(state: &WebState, block: LocalBlock) -> Result<(), Box<dyn std::error::Error>> {
    let mut blocks = state.blocks.write().unwrap();
    if blocks
        .iter()
        .any(|b| b.proof.work_hash == block.proof.work_hash)
    {
        return Ok(());
    }
    let directory = state.data_dir.join("runtime/blocks");
    fs::create_dir_all(&directory)?;
    let hash = &block.proof.work_hash;
    decode_hash(hash)?;
    let partial = directory.join(format!("{hash}.partial"));
    let destination = directory.join(format!("{hash}.json"));
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    file.write_all(&serde_json::to_vec_pretty(&block)?)?;
    file.sync_all()?;
    fs::rename(partial, destination)?;
    blocks.push(block);
    Ok(())
}

#[derive(Default, Deserialize)]
struct BlocksQuery {
    q: Option<String>,
    page: Option<usize>,
}

async fn list_blocks(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(query): Query<BlocksQuery>,
) -> Result<Json<Value>, ApiError> {
    local_request(&headers, state.port)?;
    let query_text = query.q.unwrap_or_default().trim().to_ascii_lowercase();
    if query_text.len() > 128 {
        return Err(bad("查询不能超过 128 个字符"));
    }
    let blocks = state.blocks.read().unwrap();
    let matching = blocks
        .iter()
        .enumerate()
        .rev()
        .filter(|(i, b)| {
            query_text.is_empty()
                || b.proof.work_hash.starts_with(&query_text)
                || (i + 1).to_string() == query_text
                || b.proof.nonce == query_text
        })
        .collect::<Vec<_>>();
    let pages = matching.len().div_ceil(12).max(1);
    let page = query.page.unwrap_or(1).clamp(1, pages);
    let entries = matching.iter().skip((page-1)*12).take(12).map(|(i,b)|json!({
        "record":i+1,"hash":b.proof.work_hash,"nonce":b.proof.nonce,"timestamp":b.proof.template.timestamp,
        "difficulty_bits":b.proof.template.difficulty_bits,"attempts":b.attempts,"elapsed_ms":b.elapsed_ms,"message":b.proof.message
    })).collect::<Vec<_>>();
    Ok(Json(
        json!({"mode":"local_candidates","total":blocks.len(),"matched":matching.len(),"page":page,"pages":pages,"entries":entries,
        "total_attempts":blocks.iter().map(|b|b.attempts).sum::<u64>(),"latest_timestamp":blocks.last().map(|b|&b.proof.template.timestamp)}),
    ))
}

async fn block_detail(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    RoutePath(hash): RoutePath<String>,
) -> Result<Json<Value>, ApiError> {
    local_request(&headers, state.port)?;
    parse_hash(&hash)?;
    let blocks = state.blocks.read().unwrap();
    let (i, block) = blocks
        .iter()
        .enumerate()
        .find(|(_, b)| b.proof.work_hash == hash)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "未找到该本地候选区块".into()))?;
    Ok(Json(
        json!({"record":i+1,"block":block,"mode":"local_candidates"}),
    ))
}

pub async fn serve(data_dir: PathBuf, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    let state = WebState::new(data_dir, port);
    state.start_loader();
    eprintln!("FlyPoW Web listening at http://{address}");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
#[path = "web_tests.rs"]
mod tests;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn network_candidate_state(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
    RoutePath(hash): RoutePath<String>,
) -> Result<Json<Value>, ApiError> {
    local_request(&h, s.port)?;
    parse_hash(&hash)?;
    s.network.candidate_state(&hash).map(Json).map_err(internal)
}
async fn network_status(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    local_request(&h, s.port)?;
    s.network.status(unix_now()).map(Json).map_err(internal)
}
async fn network_account(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
    RoutePath(a): RoutePath<String>,
) -> Result<Json<Value>, ApiError> {
    local_request(&h, s.port)?;
    s.network.account(&a, unix_now()).map(Json).map_err(bad)
}
async fn network_community(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    local_request(&h, s.port)?;
    s.network.community(unix_now()).map(Json).map_err(internal)
}
async fn network_validators(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    local_request(&h, s.port)?;
    s.network.validators().map(Json).map_err(internal)
}
async fn network_chain(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    local_request(&h, s.port)?;
    s.network.chain().map(Json).map_err(internal)
}
async fn recompute_candidate(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
    RoutePath(hash): RoutePath<String>,
) -> Result<Json<Verification>, ApiError> {
    local_request(&h, s.port)?;
    parse_hash(&hash)?;
    let rt = s.loaded()?;
    let proof: Proof =
        serde_json::from_value(s.network.candidate_proof(&hash).map_err(bad)?).map_err(internal)?;
    let permit = s
        .verification_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "Verification workers are busy".into(),
            )
        })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_proof(&rt, proof).map(Json)
    })
    .await
    .map_err(internal)?
}
async fn network_action(
    State(s): State<Arc<WebState>>,
    h: HeaderMap,
    Json(action): Json<SignedAction>,
) -> Result<Json<Value>, ApiError> {
    local_request(&h, s.port)?;
    legacy_write_guard()?;
    if action.action == "attest" {
        let payload: Value =
            serde_json::from_str(&action.payload).map_err(|e| bad(e.to_string()))?;
        let hash = payload["candidate"]
            .as_str()
            .ok_or_else(|| bad("Missing candidate hash"))?;
        parse_hash(hash)?;
        let proof: Proof = serde_json::from_value(s.network.candidate_proof(hash).map_err(bad)?)
            .map_err(internal)?;
        let rt = s.loaded()?;
        let net = s.network.clone();
        let permit = s
            .verification_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Verification workers are busy".into(),
                )
            })?;
        return tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = verify_proof(&rt, proof)?;
            if !result.valid {
                return Err(bad("Candidate computation is invalid"));
            }
            net.attest(&action, result.actual_hash.as_deref().unwrap(), unix_now())
                .map(Json)
                .map_err(bad)
        })
        .await
        .map_err(internal)?;
    }
    s.network
        .execute(&action, unix_now())
        .map(Json)
        .map_err(bad)
}
