-- Additive community state; existing wallet, mining and settlement tables stay intact.
CREATE TABLE IF NOT EXISTS social_schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,sha256 TEXT NOT NULL,applied_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS social_tasks(
 task_key TEXT PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL,
 reward_points INTEGER NOT NULL CHECK(reward_points BETWEEN 1 AND 1000000),
 category TEXT NOT NULL,verification_type TEXT NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
 repeatable INTEGER NOT NULL DEFAULT 0 CHECK(repeatable=0),revision INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS community_profiles(
 wallet TEXT PRIMARY KEY,total_points INTEGER NOT NULL DEFAULT 0 CHECK(total_points BETWEEN 0 AND 1000000000000),
 completed_tasks INTEGER NOT NULL DEFAULT 0,reached_at INTEGER NOT NULL,
 review_status TEXT NOT NULL DEFAULT 'normal' CHECK(review_status IN('normal','needs_review')),
 show_x INTEGER NOT NULL DEFAULT 0 CHECK(show_x IN(0,1))
);
CREATE INDEX IF NOT EXISTS community_profile_ranking ON community_profiles(review_status,total_points DESC,reached_at,wallet);
CREATE TABLE IF NOT EXISTS social_x_challenges(
 id TEXT PRIMARY KEY,wallet TEXT NOT NULL,session_identifier TEXT NOT NULL,challenge_hash TEXT NOT NULL UNIQUE,
 public_code TEXT NOT NULL,status TEXT NOT NULL,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
 task_revision INTEGER NOT NULL,reward_points INTEGER NOT NULL,
 consumed_at INTEGER,submitted_post_id TEXT,submitted_post_url TEXT,attempt_count INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0,result_code TEXT,evidence_json TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS social_x_one_active_challenge ON social_x_challenges(wallet) WHERE status IN('issued','verifying','needs_review');
CREATE INDEX IF NOT EXISTS social_x_challenge_owner ON social_x_challenges(wallet,issued_at DESC);
CREATE TABLE IF NOT EXISTS social_x_bindings(
 id TEXT PRIMARY KEY,wallet TEXT NOT NULL UNIQUE,x_user_id TEXT UNIQUE,
 username TEXT NOT NULL,username_normalized TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,
 verification_level TEXT NOT NULL,verification_method TEXT NOT NULL,verified_post_id TEXT NOT NULL UNIQUE,
 verified_post_url TEXT NOT NULL,verified_at INTEGER NOT NULL,status TEXT NOT NULL,
 challenge_id TEXT NOT NULL REFERENCES social_x_challenges(id)
);
CREATE TABLE IF NOT EXISTS social_task_completions(
 id TEXT PRIMARY KEY,task_key TEXT NOT NULL REFERENCES social_tasks(task_key),wallet TEXT NOT NULL,
 evidence_id TEXT NOT NULL,evidence_url TEXT NOT NULL,verification_status TEXT NOT NULL,
 points_awarded INTEGER NOT NULL,task_revision INTEGER NOT NULL,completed_at INTEGER NOT NULL,
 UNIQUE(wallet,task_key),UNIQUE(task_key,evidence_id)
);
CREATE TABLE IF NOT EXISTS community_points_ledger(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,wallet TEXT NOT NULL,points_delta INTEGER NOT NULL CHECK(points_delta<>0),
 source_type TEXT NOT NULL,source_id TEXT NOT NULL,task_key TEXT,idempotency_key TEXT NOT NULL UNIQUE,
 public_description TEXT NOT NULL,private_reason TEXT NOT NULL,actor TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS community_points_owner ON community_points_ledger(wallet,sequence DESC);
CREATE TRIGGER IF NOT EXISTS community_points_immutable_update BEFORE UPDATE ON community_points_ledger BEGIN SELECT RAISE(ABORT,'immutable points ledger');END;
CREATE TRIGGER IF NOT EXISTS community_points_immutable_delete BEFORE DELETE ON community_points_ledger BEGIN SELECT RAISE(ABORT,'immutable points ledger');END;
CREATE TRIGGER IF NOT EXISTS community_points_summary AFTER INSERT ON community_points_ledger BEGIN
 INSERT INTO community_profiles(wallet,total_points,reached_at) VALUES(NEW.wallet,0,NEW.created_at) ON CONFLICT(wallet) DO NOTHING;
 UPDATE community_profiles SET total_points=total_points+NEW.points_delta,reached_at=NEW.created_at WHERE wallet=NEW.wallet;
END;
CREATE TRIGGER IF NOT EXISTS community_completion_summary AFTER INSERT ON social_task_completions BEGIN
 UPDATE community_profiles SET completed_tasks=completed_tasks+1 WHERE wallet=NEW.wallet;
END;
CREATE TRIGGER IF NOT EXISTS community_completion_immutable_update BEFORE UPDATE ON social_task_completions BEGIN SELECT RAISE(ABORT,'immutable completion');END;
CREATE TRIGGER IF NOT EXISTS community_completion_immutable_delete BEFORE DELETE ON social_task_completions BEGIN SELECT RAISE(ABORT,'immutable completion');END;
CREATE TABLE IF NOT EXISTS social_verification_audit(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,challenge_id TEXT,wallet TEXT NOT NULL,
 provider TEXT NOT NULL,result_code TEXT NOT NULL,evidence_json TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS community_admin_audit(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,
 request_id TEXT NOT NULL UNIQUE,reason TEXT NOT NULL,record_json TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS community_audit_immutable_update BEFORE UPDATE ON community_admin_audit BEGIN SELECT RAISE(ABORT,'immutable admin audit');END;
CREATE TRIGGER IF NOT EXISTS community_audit_immutable_delete BEFORE DELETE ON community_admin_audit BEGIN SELECT RAISE(ABORT,'immutable admin audit');END;
CREATE TABLE IF NOT EXISTS community_leaderboard_snapshots(
 id TEXT PRIMARY KEY,created_at INTEGER NOT NULL,cutoff_at INTEGER NOT NULL,rules_version TEXT NOT NULL,
 rules_json TEXT NOT NULL,snapshot_hash TEXT NOT NULL,entry_count INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN('candidate','approved','superseded')),created_by TEXT NOT NULL,
 approved_by TEXT,approved_at INTEGER,request_id TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS community_leaderboard_snapshot_entries(
 snapshot_id TEXT NOT NULL REFERENCES community_leaderboard_snapshots(id),wallet TEXT NOT NULL,
 points INTEGER NOT NULL,rank INTEGER NOT NULL,completed_tasks INTEGER NOT NULL,
 eligibility_status TEXT NOT NULL,PRIMARY KEY(snapshot_id,wallet),UNIQUE(snapshot_id,rank)
);
CREATE TRIGGER IF NOT EXISTS community_snapshot_immutable_update BEFORE UPDATE ON community_leaderboard_snapshot_entries BEGIN SELECT RAISE(ABORT,'immutable snapshot entry');END;
CREATE TRIGGER IF NOT EXISTS community_snapshot_immutable_delete BEFORE DELETE ON community_leaderboard_snapshot_entries BEGIN SELECT RAISE(ABORT,'immutable snapshot entry');END;
CREATE TRIGGER IF NOT EXISTS community_snapshot_metadata_immutable BEFORE UPDATE OF cutoff_at,rules_version,rules_json,snapshot_hash,entry_count,created_by,created_at ON community_leaderboard_snapshots BEGIN SELECT RAISE(ABORT,'immutable snapshot content');END;
CREATE TABLE IF NOT EXISTS community_distribution_rules(
 version TEXT PRIMARY KEY,rules_json TEXT NOT NULL,rules_hash TEXT NOT NULL,
 published INTEGER NOT NULL DEFAULT 0,created_by TEXT NOT NULL,created_at INTEGER NOT NULL,published_at INTEGER
);
CREATE TRIGGER IF NOT EXISTS community_rules_immutable BEFORE UPDATE OF rules_json,rules_hash,version ON community_distribution_rules BEGIN SELECT RAISE(ABORT,'immutable distribution rules');END;
CREATE TABLE IF NOT EXISTS community_airdrop_allocations(
 id TEXT PRIMARY KEY,snapshot_id TEXT NOT NULL REFERENCES community_leaderboard_snapshots(id),
 rules_version TEXT NOT NULL REFERENCES community_distribution_rules(version),budget_atoms TEXT NOT NULL,
 allocation_hash TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('candidate','approved','cancelled')),
 created_by TEXT NOT NULL,created_at INTEGER NOT NULL,approved_by TEXT,approved_at INTEGER,
 request_id TEXT NOT NULL UNIQUE,UNIQUE(snapshot_id,rules_version)
);
CREATE TABLE IF NOT EXISTS community_airdrop_allocation_entries(
 allocation_id TEXT NOT NULL REFERENCES community_airdrop_allocations(id),wallet TEXT NOT NULL,
 points INTEGER NOT NULL,rank INTEGER NOT NULL,amount_atoms TEXT NOT NULL,
 PRIMARY KEY(allocation_id,wallet)
);
CREATE TRIGGER IF NOT EXISTS community_allocation_entries_immutable_update BEFORE UPDATE ON community_airdrop_allocation_entries BEGIN SELECT RAISE(ABORT,'immutable allocation entry');END;
CREATE TRIGGER IF NOT EXISTS community_allocation_entries_immutable_delete BEFORE DELETE ON community_airdrop_allocation_entries BEGIN SELECT RAISE(ABORT,'immutable allocation entry');END;
CREATE TRIGGER IF NOT EXISTS community_allocation_content_immutable BEFORE UPDATE OF snapshot_id,rules_version,budget_atoms,allocation_hash,created_by,created_at ON community_airdrop_allocations BEGIN SELECT RAISE(ABORT,'immutable allocation content');END;
CREATE TABLE IF NOT EXISTS community_budget_ledger(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,allocation_id TEXT NOT NULL REFERENCES community_airdrop_allocations(id),
 atoms_delta TEXT NOT NULL,operation_key TEXT NOT NULL UNIQUE,actor TEXT NOT NULL,created_at INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS community_budget_immutable_update BEFORE UPDATE ON community_budget_ledger BEGIN SELECT RAISE(ABORT,'immutable budget ledger');END;
CREATE TRIGGER IF NOT EXISTS community_budget_immutable_delete BEFORE DELETE ON community_budget_ledger BEGIN SELECT RAISE(ABORT,'immutable budget ledger');END;

CREATE TRIGGER IF NOT EXISTS community_verification_immutable_update BEFORE UPDATE ON social_verification_audit BEGIN SELECT RAISE(ABORT,'immutable verification audit');END;
CREATE TRIGGER IF NOT EXISTS community_verification_immutable_delete BEFORE DELETE ON social_verification_audit BEGIN SELECT RAISE(ABORT,'immutable verification audit');END;
CREATE TRIGGER IF NOT EXISTS community_snapshot_metadata_no_delete BEFORE DELETE ON community_leaderboard_snapshots BEGIN SELECT RAISE(ABORT,'immutable snapshot');END;
CREATE TRIGGER IF NOT EXISTS community_rules_no_delete BEFORE DELETE ON community_distribution_rules BEGIN SELECT RAISE(ABORT,'immutable rules');END;
CREATE TRIGGER IF NOT EXISTS community_allocation_no_delete BEFORE DELETE ON community_airdrop_allocations BEGIN SELECT RAISE(ABORT,'immutable allocation');END;
