-- Add repeatable contributions and first-registration referral attribution.
-- Version 1 receipts, points and allocation tables remain immutable.
CREATE TABLE social_task_repeat_rules(
 task_key TEXT PRIMARY KEY REFERENCES social_tasks(task_key),
 period TEXT NOT NULL CHECK(period='utc_day'),daily_limit INTEGER NOT NULL CHECK(daily_limit BETWEEN 1 AND 3)
);
CREATE TABLE social_repeat_completions(
 id TEXT PRIMARY KEY,task_key TEXT NOT NULL REFERENCES social_tasks(task_key),wallet TEXT NOT NULL,
 period_key TEXT NOT NULL,slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 3),
 evidence_id TEXT NOT NULL UNIQUE,evidence_url TEXT NOT NULL,
 points_awarded INTEGER NOT NULL,task_revision INTEGER NOT NULL,completed_at INTEGER NOT NULL,
 UNIQUE(wallet,task_key,period_key,slot)
);
CREATE INDEX social_repeat_owner ON social_repeat_completions(wallet,task_key,period_key);
CREATE TRIGGER social_repeat_summary AFTER INSERT ON social_repeat_completions BEGIN
 UPDATE community_profiles SET completed_tasks=completed_tasks+1 WHERE wallet=NEW.wallet;
END;
CREATE TRIGGER social_repeat_immutable_update BEFORE UPDATE ON social_repeat_completions BEGIN SELECT RAISE(ABORT,'immutable repeat completion');END;
CREATE TRIGGER social_repeat_immutable_delete BEFORE DELETE ON social_repeat_completions BEGIN SELECT RAISE(ABORT,'immutable repeat completion');END;
CREATE TABLE social_post_uses(
 post_id TEXT PRIMARY KEY,wallet TEXT NOT NULL,purpose TEXT NOT NULL,record_id TEXT NOT NULL UNIQUE
);
INSERT INTO social_post_uses SELECT verified_post_id,wallet,'identity',id FROM social_x_bindings;
CREATE TRIGGER social_post_immutable_update BEFORE UPDATE ON social_post_uses BEGIN SELECT RAISE(ABORT,'immutable post use');END;
CREATE TRIGGER social_post_immutable_delete BEFORE DELETE ON social_post_uses BEGIN SELECT RAISE(ABORT,'immutable post use');END;
CREATE TABLE social_daily_x_challenges(
 id TEXT PRIMARY KEY,wallet TEXT NOT NULL,session_identifier TEXT NOT NULL,challenge_hash TEXT NOT NULL UNIQUE,
 public_code TEXT NOT NULL,status TEXT NOT NULL,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
 task_revision INTEGER NOT NULL,reward_points INTEGER NOT NULL,period_key TEXT NOT NULL,
 consumed_at INTEGER,submitted_post_id TEXT,submitted_post_url TEXT,attempt_count INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0,result_code TEXT,evidence_json TEXT
);
CREATE UNIQUE INDEX social_daily_x_active ON social_daily_x_challenges(wallet) WHERE status IN('issued','verifying','needs_review');
CREATE INDEX social_daily_x_owner ON social_daily_x_challenges(wallet,issued_at DESC);
CREATE TABLE community_registrations(
 wallet TEXT PRIMARY KEY,invite_code TEXT REFERENCES community_invites(code),
 registered_at INTEGER NOT NULL,legacy INTEGER NOT NULL CHECK(legacy IN(0,1))
);
CREATE TABLE community_invites(
 code TEXT PRIMARY KEY,wallet TEXT NOT NULL UNIQUE REFERENCES community_registrations(wallet),created_at INTEGER NOT NULL
);
INSERT INTO community_registrations(wallet,registered_at,legacy)
 SELECT wallet,MIN(registered_at),1 FROM (
  SELECT wallet,reached_at AS registered_at FROM community_profiles
  UNION ALL SELECT wallet,issued_at FROM social_x_challenges
  UNION ALL SELECT wallet,expires_at-28800 FROM mining_v3_sessions
 ) GROUP BY wallet;
CREATE TRIGGER community_registration_immutable_update BEFORE UPDATE ON community_registrations BEGIN SELECT RAISE(ABORT,'immutable registration');END;
CREATE TRIGGER community_registration_immutable_delete BEFORE DELETE ON community_registrations BEGIN SELECT RAISE(ABORT,'immutable registration');END;
CREATE TRIGGER community_invite_immutable_update BEFORE UPDATE ON community_invites BEGIN SELECT RAISE(ABORT,'immutable invite');END;
CREATE TRIGGER community_invite_immutable_delete BEFORE DELETE ON community_invites BEGIN SELECT RAISE(ABORT,'immutable invite');END;
CREATE TABLE community_referral_rewards(
 invitee_wallet TEXT PRIMARY KEY REFERENCES community_registrations(wallet),
 inviter_wallet TEXT NOT NULL REFERENCES community_registrations(wallet),
 completion_id TEXT NOT NULL UNIQUE REFERENCES social_task_completions(id),
 points_awarded INTEGER NOT NULL CHECK(points_awarded=10),created_at INTEGER NOT NULL,
 CHECK(invitee_wallet<>inviter_wallet)
);
CREATE INDEX community_referral_inviter ON community_referral_rewards(inviter_wallet);
CREATE INDEX community_registration_invite ON community_registrations(invite_code);
CREATE TRIGGER community_referral_immutable_update BEFORE UPDATE ON community_referral_rewards BEGIN SELECT RAISE(ABORT,'immutable referral reward');END;
CREATE TRIGGER community_referral_immutable_delete BEFORE DELETE ON community_referral_rewards BEGIN SELECT RAISE(ABORT,'immutable referral reward');END;
UPDATE community_profiles SET show_x=0 WHERE show_x<>0;
UPDATE social_tasks SET reward_points=10,revision=revision+1 WHERE task_key='connect_x_identity_v1';
UPDATE social_x_challenges SET reward_points=10,task_revision=(SELECT revision FROM social_tasks WHERE task_key='connect_x_identity_v1') WHERE consumed_at IS NULL;
