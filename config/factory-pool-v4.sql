-- Dedicated PostgreSQL state. Existing SQLite archives are retained.
CREATE SCHEMA IF NOT EXISTS factory_pool_v4;
CREATE TABLE IF NOT EXISTS factory_pool_v4.jobs (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 200),
  kind text NOT NULL CHECK (kind IN ('catalog','calibrate','replay','payment','input')),
  scope text NOT NULL,
  payload jsonb NOT NULL,
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[a-f0-9]{64}$'),
  state text NOT NULL DEFAULT 'ready' CHECK (state IN ('ready','leased','done','blocked')),
  priority integer NOT NULL DEFAULT 0,
  ready_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_owner text,
  lease_until timestamptz,
  fence bigint NOT NULL DEFAULT 0,
  attempts integer NOT NULL DEFAULT 0,
  result jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS pool_jobs_ready ON factory_pool_v4.jobs(kind,priority DESC,ready_at,created_at) WHERE state IN ('ready','leased');
-- Additive upgrade; frozen payloads, signed bytes and old states are retained.
ALTER TABLE factory_pool_v4.jobs DROP CONSTRAINT IF EXISTS jobs_kind_check;
ALTER TABLE factory_pool_v4.jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('catalog','calibrate','replay','payment','input','keeper'));
ALTER TABLE factory_pool_v4.jobs ADD COLUMN IF NOT EXISTS quarantined boolean NOT NULL DEFAULT false;
ALTER TABLE factory_pool_v4.jobs ADD COLUMN IF NOT EXISTS reconciled_at timestamptz;
CREATE TABLE IF NOT EXISTS factory_pool_v4.transactions (
  id text PRIMARY KEY,
  job_id text NOT NULL REFERENCES factory_pool_v4.jobs(id),
  instruction_hash text NOT NULL,
  signature text NOT NULL UNIQUE,
  raw_base64 text NOT NULL,
  last_valid_height bigint NOT NULL,
  fee_lamports bigint NOT NULL CHECK (fee_lamports BETWEEN 0 AND 20000),
  state text NOT NULL DEFAULT 'signed' CHECK (state IN ('signed','finalized','failed','unknown')),
  receipt jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS factory_pool_v4.science (
  identity text PRIMARY KEY CHECK (identity ~ '^[a-f0-9]{64}$'),
  catalog_id text NOT NULL,
  descriptor_hash text NOT NULL,
  historical boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS factory_pool_v4.replays (
  job_id text PRIMARY KEY REFERENCES factory_pool_v4.jobs(id),
  report_hash text NOT NULL,
  report jsonb NOT NULL,
  wall_ms bigint NOT NULL CHECK (wall_ms>=0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS factory_pool_v4.catalogs (
  id text PRIMARY KEY,
  pool_id text NOT NULL,
  deployment jsonb NOT NULL,
  plan_hash text NOT NULL,
  compiled jsonb NOT NULL,
  state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','registered','retired')),
  registered_at timestamptz
);
CREATE TABLE IF NOT EXISTS factory_pool_v4.manifests (
  pool_id text NOT NULL,
  revision bigint NOT NULL,
  hash text NOT NULL,
  body jsonb NOT NULL,
  PRIMARY KEY(pool_id,revision)
);
ALTER TABLE factory_pool_v4.catalogs ADD COLUMN IF NOT EXISTS serving_state text NOT NULL DEFAULT 'serving' CHECK (serving_state IN ('serving','draining','retired'));
ALTER TABLE factory_pool_v4.catalogs ADD COLUMN IF NOT EXISTS observed_at timestamptz;
ALTER TABLE factory_pool_v4.catalogs ADD COLUMN IF NOT EXISTS released_authorization_atoms numeric(20,0) NOT NULL DEFAULT 0 CHECK (released_authorization_atoms>=0);
CREATE TABLE IF NOT EXISTS factory_pool_v4.demand (
  pool_id text NOT NULL, wallet text NOT NULL, session_id text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(pool_id,wallet,session_id)
);
CREATE INDEX IF NOT EXISTS pool_demand_live ON factory_pool_v4.demand(pool_id,expires_at);
CREATE TABLE IF NOT EXISTS factory_pool_v4.job_costs (
  job_id text PRIMARY KEY REFERENCES factory_pool_v4.jobs(id),
  background_count integer NOT NULL CHECK (background_count BETWEEN 1 AND 64),
  estimate_ms bigint NOT NULL CHECK (estimate_ms>0),
  deadline bigint NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS factory_pool_v4.events (
  sequence bigserial PRIMARY KEY,
  scope text NOT NULL,
  kind text NOT NULL,
  value jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE OR REPLACE FUNCTION factory_pool_v4.immutable_job() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.id,NEW.kind,NEW.scope,NEW.payload,NEW.payload_hash) IS DISTINCT FROM
     (OLD.id,OLD.kind,OLD.scope,OLD.payload,OLD.payload_hash) THEN
    RAISE EXCEPTION 'Frozen job identity changed';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS immutable_job ON factory_pool_v4.jobs;
CREATE TRIGGER immutable_job BEFORE UPDATE ON factory_pool_v4.jobs FOR EACH ROW EXECUTE FUNCTION factory_pool_v4.immutable_job();
CREATE OR REPLACE FUNCTION factory_pool_v4.immutable_transaction() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.id,NEW.job_id,NEW.instruction_hash,NEW.signature,NEW.raw_base64,NEW.last_valid_height,NEW.fee_lamports) IS DISTINCT FROM
     (OLD.id,OLD.job_id,OLD.instruction_hash,OLD.signature,OLD.raw_base64,OLD.last_valid_height,OLD.fee_lamports) THEN
    RAISE EXCEPTION 'Signed transaction changed';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS immutable_transaction ON factory_pool_v4.transactions;
CREATE TRIGGER immutable_transaction BEFORE UPDATE ON factory_pool_v4.transactions FOR EACH ROW EXECUTE FUNCTION factory_pool_v4.immutable_transaction();
