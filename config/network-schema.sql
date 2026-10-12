PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accounts(
 address TEXT PRIMARY KEY, public_key TEXT NOT NULL UNIQUE, nonce INTEGER NOT NULL DEFAULT 0,
 balance INTEGER NOT NULL DEFAULT 0 CHECK(balance>=0),
 stake INTEGER NOT NULL DEFAULT 0 CHECK(stake>=0),
 locked_liquid INTEGER NOT NULL DEFAULT 0 CHECK(locked_liquid>=0),
 locked_stake INTEGER NOT NULL DEFAULT 0 CHECK(locked_stake>=0),
 grant_unlock INTEGER NOT NULL DEFAULT 0, unbond_at INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 0, referrer TEXT, qualified INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS journal(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>=0), time INTEGER NOT NULL, reference TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_journal_sender ON journal(sender,id);
CREATE INDEX IF NOT EXISTS idx_journal_recipient ON journal(recipient,id);
CREATE TABLE IF NOT EXISTS points(id INTEGER PRIMARY KEY, address TEXT NOT NULL REFERENCES accounts(address),kind TEXT NOT NULL,source TEXT NOT NULL,week INTEGER NOT NULL,day INTEGER NOT NULL,amount INTEGER NOT NULL,time INTEGER NOT NULL,UNIQUE(address,kind,source));
CREATE INDEX IF NOT EXISTS idx_points_week_address ON points(week,address);
CREATE INDEX IF NOT EXISTS idx_points_day_kind ON points(address,kind,day);
CREATE TABLE IF NOT EXISTS awards(address TEXT PRIMARY KEY REFERENCES accounts(address),kind TEXT NOT NULL,week INTEGER NOT NULL,rank INTEGER NOT NULL,amount INTEGER NOT NULL,claimed INTEGER NOT NULL DEFAULT 0,time INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rounds(week INTEGER PRIMARY KEY,settled_at INTEGER NOT NULL,winners INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tickets(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES accounts(address),binding TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS candidates(hash TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES accounts(address),ticket TEXT NOT NULL UNIQUE,proof TEXT NOT NULL,committee TEXT NOT NULL,quorum INTEGER NOT NULL,height INTEGER NOT NULL,previous_hash TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_candidates_status_height ON candidates(status,height);
CREATE TABLE IF NOT EXISTS computations(hash TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES accounts(address),time INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_computations_owner ON computations(owner);
CREATE TABLE IF NOT EXISTS votes(candidate TEXT NOT NULL REFERENCES candidates(hash),address TEXT NOT NULL REFERENCES accounts(address),signature TEXT NOT NULL,time INTEGER NOT NULL,PRIMARY KEY(candidate,address));
CREATE TABLE IF NOT EXISTS chain(height INTEGER PRIMARY KEY,hash TEXT NOT NULL UNIQUE,previous_hash TEXT NOT NULL,owner TEXT NOT NULL,reward INTEGER NOT NULL,miner_reward INTEGER NOT NULL,validator_reward INTEGER NOT NULL,validators TEXT NOT NULL,finalized_at INTEGER NOT NULL);
PRAGMA optimize;

