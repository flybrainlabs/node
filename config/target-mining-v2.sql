-- Independent V2 development adjudication. Never touches legacy rounds or V1 PDAs.
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
-- Additive observational schema. Never used by difficulty, validity or rewards.
CREATE TABLE IF NOT EXISTS work_sessions (miner_id TEXT NOT NULL,session_id TEXT NOT NULL,campaign_id TEXT NOT NULL,round_id TEXT NOT NULL,sequence INTEGER NOT NULL,produced_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,phase TEXT NOT NULL,neurons TEXT NOT NULL,synapses TEXT NOT NULL,request_hash TEXT NOT NULL,PRIMARY KEY(miner_id,session_id));
CREATE TABLE IF NOT EXISTS work_samples (sample_id INTEGER PRIMARY KEY AUTOINCREMENT,miner_id TEXT NOT NULL,session_id TEXT NOT NULL,from_at INTEGER NOT NULL,to_at INTEGER NOT NULL,neurons TEXT NOT NULL,synapses TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS work_samples_window ON work_samples(to_at);
CREATE TABLE IF NOT EXISTS target_campaigns (campaign_id TEXT PRIMARY KEY, config_json TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS goal_specs (goal_id TEXT PRIMARY KEY, spec_json TEXT NOT NULL, calibration_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS goal_plan_progress (campaign_id TEXT NOT NULL, plan_index INTEGER NOT NULL, goal_id TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING', winner_round TEXT, PRIMARY KEY(campaign_id,plan_index), UNIQUE(campaign_id,goal_id));
CREATE TABLE IF NOT EXISTS difficulty_snapshots (campaign_id TEXT PRIMARY KEY, controller_json TEXT NOT NULL, policy_hash TEXT NOT NULL, version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS target_rounds (round_id TEXT PRIMARY KEY,campaign_id TEXT NOT NULL, sequence INTEGER NOT NULL, goal_id TEXT NOT NULL, descriptor_json TEXT NOT NULL, status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, opened_at INTEGER NOT NULL, claim_deadline INTEGER NOT NULL, reveal_deadline INTEGER NOT NULL, verification_deadline INTEGER NOT NULL, UNIQUE(campaign_id,sequence));
CREATE UNIQUE INDEX IF NOT EXISTS target_one_active ON target_rounds(campaign_id) WHERE status IN ('OPEN','VERIFYING');
CREATE TABLE IF NOT EXISTS candidate_inputs (candidate_id TEXT PRIMARY KEY, round_id TEXT NOT NULL,input_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS candidate_claims (claim_id TEXT PRIMARY KEY,round_id TEXT NOT NULL,miner_id TEXT NOT NULL,commitment TEXT NOT NULL,claim_sequence INTEGER NOT NULL,received_at INTEGER NOT NULL,reveal_deadline INTEGER NOT NULL,verification_deadline INTEGER NOT NULL,status TEXT NOT NULL,receipt_json TEXT NOT NULL,UNIQUE(round_id,claim_sequence),UNIQUE(round_id,miner_id,commitment));
CREATE TABLE IF NOT EXISTS request_receipts (miner_id TEXT NOT NULL,request_id TEXT NOT NULL,request_hash TEXT NOT NULL,response_json TEXT NOT NULL,PRIMARY KEY(miner_id,request_id));
CREATE TABLE IF NOT EXISTS candidate_reveals (claim_id TEXT PRIMARY KEY,manifest_json TEXT NOT NULL,manifest_hash TEXT NOT NULL,salt TEXT NOT NULL,revealed_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS candidate_artifacts (upload_id TEXT PRIMARY KEY,claim_id TEXT NOT NULL,miner_id TEXT NOT NULL,trial_index INTEGER NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'UPLOADING',UNIQUE(claim_id,trial_index));
CREATE TABLE IF NOT EXISTS artifact_chunks (upload_id TEXT NOT NULL,chunk_index INTEGER NOT NULL,bytes INTEGER NOT NULL,sha256 TEXT NOT NULL,PRIMARY KEY(upload_id,chunk_index));
CREATE TABLE IF NOT EXISTS verification_jobs (job_id TEXT PRIMARY KEY,claim_id TEXT NOT NULL,verifier_id TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING',lease_until INTEGER NOT NULL DEFAULT 0,fencing_token INTEGER NOT NULL DEFAULT 0,UNIQUE(claim_id,verifier_id));
CREATE TABLE IF NOT EXISTS verification_votes (claim_id TEXT NOT NULL,verifier_id TEXT NOT NULL,valid INTEGER NOT NULL,vote_json TEXT NOT NULL,received_at INTEGER NOT NULL,PRIMARY KEY(claim_id,verifier_id));
CREATE TABLE IF NOT EXISTS round_winners (round_id TEXT PRIMARY KEY,claim_id TEXT NOT NULL UNIQUE,winner_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS protocol_events (event_sequence INTEGER PRIMARY KEY AUTOINCREMENT,round_id TEXT,kind TEXT NOT NULL,payload_json TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS protocol_outbox (event_sequence INTEGER PRIMARY KEY REFERENCES protocol_events(event_sequence),published_at INTEGER);
CREATE TABLE IF NOT EXISTS difficulty_observations (round_id TEXT PRIMARY KEY,candidate_id TEXT UNIQUE,discovery_ms INTEGER,verification_ms INTEGER,healthy INTEGER NOT NULL,observation_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS target_sessions (miner_id TEXT NOT NULL,session_id TEXT NOT NULL,round_id TEXT,phase TEXT NOT NULL,last_seen INTEGER NOT NULL,PRIMARY KEY(miner_id,session_id));
CREATE TABLE IF NOT EXISTS target_audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT NOT NULL,payload_json TEXT NOT NULL,at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS target_future_policies (campaign_id TEXT NOT NULL, revision INTEGER NOT NULL, policy_hash TEXT NOT NULL UNIQUE, policy_json TEXT NOT NULL, request_json TEXT NOT NULL, published_at INTEGER NOT NULL, PRIMARY KEY(campaign_id,revision));

CREATE TABLE IF NOT EXISTS target_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_at INTEGER NOT NULL);
INSERT OR IGNORE INTO target_clock VALUES(1,0);

CREATE TABLE IF NOT EXISTS comparable_difficulty_families (family_id TEXT PRIMARY KEY, descriptor_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS goal_difficulty_families (goal_id TEXT PRIMARY KEY, family_id TEXT NOT NULL REFERENCES comparable_difficulty_families(family_id));
CREATE TABLE IF NOT EXISTS difficulty_family_controllers (campaign_id TEXT NOT NULL, family_id TEXT NOT NULL, controller_json TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(campaign_id,family_id));
CREATE TABLE IF NOT EXISTS goal_plan_revisions (campaign_id TEXT NOT NULL,revision INTEGER NOT NULL,plan_hash TEXT NOT NULL UNIQUE,descriptor_json TEXT NOT NULL,request_json TEXT NOT NULL,published_at INTEGER NOT NULL,PRIMARY KEY(campaign_id,revision));
CREATE TABLE IF NOT EXISTS verifier_presence (verifier_id TEXT PRIMARY KEY,last_seen INTEGER NOT NULL,phase TEXT NOT NULL,model_json TEXT NOT NULL DEFAULT '{}');
