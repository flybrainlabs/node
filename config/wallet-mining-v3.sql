-- Additive wallet/financial state in the existing authority SQLite/WAL.
CREATE TABLE IF NOT EXISTS mining_v3_challenges(
 nonce TEXT PRIMARY KEY,wallet TEXT NOT NULL,origin TEXT NOT NULL,
 message TEXT NOT NULL,input_json TEXT NOT NULL,created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,used_at INTEGER
);
CREATE INDEX IF NOT EXISTS mining_v3_challenge_wallet ON mining_v3_challenges(wallet,created_at);
CREATE TABLE IF NOT EXISTS mining_v3_sessions(
 token_hash TEXT PRIMARY KEY,csrf_hash TEXT NOT NULL,wallet TEXT NOT NULL,
 origin TEXT NOT NULL,expires_at INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS mining_v3_grant_requests(
 id TEXT PRIMARY KEY,wallet TEXT NOT NULL,action TEXT NOT NULL,
 grant_address TEXT NOT NULL,message_hash TEXT NOT NULL,signature TEXT,
 last_valid_height INTEGER NOT NULL,created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mining_v3_participation(
 wallet TEXT NOT NULL,round_id TEXT NOT NULL,scientific_identity TEXT NOT NULL,
 original_grant TEXT NOT NULL,started_at INTEGER NOT NULL,
 PRIMARY KEY(wallet,round_id,scientific_identity)
);
CREATE TABLE IF NOT EXISTS mining_v3_candidates(
 claim_id TEXT PRIMARY KEY,wallet TEXT NOT NULL,round_id TEXT NOT NULL,
 candidate_id TEXT NOT NULL,scientific_identity TEXT NOT NULL,
 unit_address TEXT NOT NULL,intent_address TEXT NOT NULL,staging_address TEXT NOT NULL,
 original_grant TEXT NOT NULL,intent_hash TEXT NOT NULL,intent_json TEXT NOT NULL,
 session_signature TEXT NOT NULL,manifest_json TEXT NOT NULL,
 state TEXT NOT NULL,reason TEXT,prepared_bytes TEXT,
 result_address TEXT NOT NULL,reward_atoms TEXT NOT NULL,rent_lamports TEXT,
 settlement_signature TEXT,finalized_json TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,
 lease_owner TEXT NOT NULL DEFAULT '',lease_until INTEGER NOT NULL DEFAULT 0,
 intent_registered INTEGER NOT NULL DEFAULT 0,
 UNIQUE(wallet,round_id,candidate_id)
);
CREATE INDEX IF NOT EXISTS mining_v3_candidate_history ON mining_v3_candidates(wallet,created_at DESC,claim_id);
CREATE TABLE IF NOT EXISTS mining_v3_transactions(
 operation_key TEXT PRIMARY KEY,claim_id TEXT NOT NULL,step TEXT NOT NULL,
 signed_bytes TEXT NOT NULL,signature TEXT NOT NULL,blockhash TEXT NOT NULL,
 last_valid_height INTEGER NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,observed_slot TEXT,error_code TEXT
);
CREATE TABLE IF NOT EXISTS mining_v3_audit(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,wallet TEXT,
 claim_id TEXT,public_json TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mining_v3_transport_leases(
 operation_scope TEXT PRIMARY KEY,owner TEXT NOT NULL,expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mining_v3_attempts(
 wallet TEXT NOT NULL,round_id TEXT NOT NULL,candidate_id TEXT NOT NULL,
 scientific_identity TEXT NOT NULL,original_grant TEXT NOT NULL,
 state TEXT NOT NULL,started_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,
 PRIMARY KEY(wallet,round_id,candidate_id)
);
CREATE TABLE IF NOT EXISTS mining_v3_funded_goals(
 goal_id TEXT PRIMARY KEY,economic_task TEXT NOT NULL UNIQUE,program TEXT NOT NULL,
 policy TEXT NOT NULL,stage TEXT NOT NULL,unit_address TEXT NOT NULL UNIQUE,
 reward_atoms TEXT NOT NULL,enabled INTEGER NOT NULL
);
