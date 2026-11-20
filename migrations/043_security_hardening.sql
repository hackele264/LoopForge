-- Security hardening (SOAR phase 5).
--
-- api_tokens.scopes / project_ids: comma-separated token scopes and project
-- allowlist; empty keeps the legacy full access.
-- audit_events: platform audit log (logins, token changes, API writes,
-- denied requests, connector actions).
--
-- gorm's incremental AutoMigrate creates all of this on start; this script is
-- the manual equivalent. CREATE TABLE is re-runnable; the ALTER TABLE is not
-- (MySQL 8.0 has no ADD COLUMN IF NOT EXISTS), so check
-- information_schema.columns first.

ALTER TABLE api_tokens
  ADD COLUMN scopes VARCHAR(255) NULL,
  ADD COLUMN project_ids TEXT NULL;

CREATE TABLE IF NOT EXISTS audit_events (
  id VARCHAR(64) NOT NULL,
  at DATETIME(3) NULL,
  actor_user_id BIGINT NULL,
  action VARCHAR(160) NULL,
  project_id VARCHAR(128) NULL,
  outcome VARCHAR(16) NULL,
  payload JSON NULL,
  PRIMARY KEY (id),
  KEY idx_audit_events_at (at),
  KEY idx_audit_events_actor_user_id (actor_user_id),
  KEY idx_audit_events_action (action),
  KEY idx_audit_events_project_id (project_id)
);
