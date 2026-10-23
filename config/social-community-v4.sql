CREATE TABLE project_interests (
  subject_wallet TEXT NOT NULL,
  project_id TEXT NOT NULL,
  interested INTEGER NOT NULL CHECK (interested IN (0,1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(subject_wallet, project_id)
);
CREATE TABLE project_preferences (
  subject_wallet TEXT PRIMARY KEY,
  primary_project_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE project_applications (
  id TEXT PRIMARY KEY,
  subject_wallet TEXT NOT NULL,
  project_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  consent_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('submitted','reviewing','waitlisted','selected','rejected','withdrawn')),
  revision INTEGER NOT NULL CHECK(revision > 0),
  public_note TEXT NOT NULL DEFAULT '',
  internal_note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(subject_wallet, project_id)
);
CREATE INDEX project_applications_filter ON project_applications(project_id,status,updated_at);
CREATE TABLE project_application_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  application_id TEXT NOT NULL REFERENCES project_applications(id),
  actor_wallet TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_status TEXT,
  status TEXT NOT NULL,
  revision INTEGER NOT NULL,
  public_note TEXT NOT NULL DEFAULT '',
  internal_note TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(application_id, revision)
);
CREATE INDEX project_application_events_history ON project_application_events(application_id,sequence);
CREATE TABLE project_request_idempotency (
  actor_wallet TEXT NOT NULL,
  request_id TEXT NOT NULL,
  action TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  response_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(actor_wallet,request_id)
);
CREATE INDEX project_requests_rate ON project_request_idempotency(actor_wallet,created_at);
