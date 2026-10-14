-- Add GitHub identities and encrypted OAuth credentials without rewriting v1/v2.
CREATE TABLE social_github_bindings(
 wallet TEXT PRIMARY KEY,github_user_id TEXT NOT NULL UNIQUE,
 github_login TEXT NOT NULL,avatar_url TEXT NOT NULL,connected_at INTEGER NOT NULL,
 verification_method TEXT NOT NULL,binding_status TEXT NOT NULL CHECK(binding_status IN('active','reauthorization_required')),
 updated_at INTEGER NOT NULL
);
CREATE TRIGGER social_github_identity_immutable BEFORE UPDATE OF wallet,github_user_id,connected_at ON social_github_bindings BEGIN SELECT RAISE(ABORT,'immutable GitHub reward identity');END;
CREATE TRIGGER social_github_binding_no_delete BEFORE DELETE ON social_github_bindings BEGIN SELECT RAISE(ABORT,'immutable GitHub reward identity');END;
CREATE TABLE social_github_credentials(
 wallet TEXT PRIMARY KEY REFERENCES social_github_bindings(wallet),encrypted_credentials TEXT NOT NULL,
 expires_at INTEGER,refresh_expires_at INTEGER,revision INTEGER NOT NULL,updated_at INTEGER NOT NULL
);
CREATE TABLE social_github_oauth_states(
 state_hash TEXT PRIMARY KEY,wallet TEXT NOT NULL,session_identifier TEXT NOT NULL,
 origin TEXT NOT NULL,browser_hash TEXT NOT NULL,encrypted_verifier TEXT,
 issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN('issued','exchanging','authorized','completed','failed','cancelled')),
 consumed_at INTEGER,code_hash TEXT UNIQUE,encrypted_result TEXT,result_code TEXT,task_revision INTEGER NOT NULL,reward_points INTEGER NOT NULL
);
CREATE INDEX social_github_oauth_owner ON social_github_oauth_states(wallet,issued_at DESC);
CREATE UNIQUE INDEX social_github_oauth_code ON social_github_oauth_states(consumed_at,state_hash) WHERE consumed_at IS NOT NULL;
CREATE TRIGGER social_github_oauth_identity_immutable BEFORE UPDATE OF state_hash,wallet,session_identifier,origin,browser_hash,issued_at,expires_at,task_revision,reward_points ON social_github_oauth_states BEGIN SELECT RAISE(ABORT,'immutable OAuth flow identity');END;
CREATE TRIGGER social_github_oauth_terminal BEFORE UPDATE OF status ON social_github_oauth_states WHEN OLD.status IN('completed','failed','cancelled') AND NEW.status<>OLD.status BEGIN SELECT RAISE(ABORT,'consumed OAuth flow');END;
CREATE TRIGGER social_github_oauth_code_immutable BEFORE UPDATE OF code_hash ON social_github_oauth_states WHEN OLD.code_hash IS NOT NULL AND NEW.code_hash IS NOT OLD.code_hash BEGIN SELECT RAISE(ABORT,'consumed OAuth code');END;
CREATE TABLE social_github_verification_audit(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,wallet TEXT NOT NULL,github_user_id TEXT,
 task_key TEXT NOT NULL,result_code TEXT NOT NULL,repository_id TEXT,evidence_hash TEXT,
 created_at INTEGER NOT NULL
);
CREATE INDEX social_github_audit_owner ON social_github_verification_audit(wallet,created_at);
CREATE TRIGGER social_github_audit_immutable_update BEFORE UPDATE ON social_github_verification_audit BEGIN SELECT RAISE(ABORT,'immutable GitHub verification');END;
CREATE TRIGGER social_github_audit_immutable_delete BEFORE DELETE ON social_github_verification_audit BEGIN SELECT RAISE(ABORT,'immutable GitHub verification');END;
CREATE TABLE social_github_task_targets(
 task_key TEXT PRIMARY KEY REFERENCES social_tasks(task_key),owner TEXT NOT NULL,repository TEXT,
 repository_id TEXT UNIQUE,verified_public INTEGER NOT NULL CHECK(verified_public IN(0,1)),
 verified_at INTEGER NOT NULL
);
CREATE TRIGGER social_github_target_immutable BEFORE UPDATE OF task_key,owner,repository,repository_id ON social_github_task_targets BEGIN SELECT RAISE(ABORT,'immutable GitHub task target');END;
CREATE TABLE social_github_verification_locks(
 wallet TEXT NOT NULL,task_key TEXT NOT NULL,lease_until INTEGER NOT NULL,
 retry_at INTEGER NOT NULL DEFAULT 0,result_code TEXT,PRIMARY KEY(wallet,task_key)
);
