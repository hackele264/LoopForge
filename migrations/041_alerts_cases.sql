-- Security alerts and cases (SOAR phase 3).
--
-- alerts: every inbound alert, linked to the case and run it belongs to.
-- cases: investigations numbered per project via case_counters.
-- case_iocs / case_events: indicators and the timeline of each case.
-- case_triggers: SOPs started by case events.
-- runs.case_id links runs to cases; webhook_dedup.case_id lets duplicates
-- join the case their fingerprint opened.
--
-- gorm's incremental AutoMigrate creates all of this on start; this script is
-- the manual equivalent. The CREATE TABLE statements are re-runnable; the two
-- ALTER TABLE statements are not (MySQL 8.0 has no ADD COLUMN IF NOT EXISTS),
-- so check information_schema.columns before running them.

CREATE TABLE IF NOT EXISTS alerts (
  id VARCHAR(64) NOT NULL,
  project_id VARCHAR(128) NULL,
  webhook_id VARCHAR(64) NULL,
  case_id VARCHAR(64) NULL,
  run_id VARCHAR(64) NULL,
  severity VARCHAR(16) NULL,
  fingerprint VARCHAR(64) NULL,
  received_at DATETIME(3) NULL,
  payload JSON NULL,
  PRIMARY KEY (id),
  KEY idx_alerts_project_received (project_id, received_at),
  KEY idx_alerts_webhook_id (webhook_id),
  KEY idx_alerts_case_id (case_id)
);

CREATE TABLE IF NOT EXISTS cases (
  id VARCHAR(64) NOT NULL,
  project_id VARCHAR(128) NULL,
  number BIGINT NULL,
  status VARCHAR(32) NULL,
  severity VARCHAR(16) NULL,
  payload JSON NULL,
  created_at DATETIME(3) NULL,
  updated_at DATETIME(3) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY idx_cases_project_number (project_id, number),
  KEY idx_cases_project_updated (project_id, updated_at),
  KEY idx_cases_status (status)
);

CREATE TABLE IF NOT EXISTS case_counters (
  project_id VARCHAR(128) NOT NULL,
  last_number BIGINT NULL,
  PRIMARY KEY (project_id)
);

CREATE TABLE IF NOT EXISTS case_iocs (
  case_id VARCHAR(64) NOT NULL,
  type VARCHAR(16) NOT NULL,
  value_key VARCHAR(64) NOT NULL,
  value TEXT NULL,
  alert_id VARCHAR(64) NULL,
  first_seen DATETIME(3) NULL,
  PRIMARY KEY (case_id, type, value_key)
);

CREATE TABLE IF NOT EXISTS case_events (
  id VARCHAR(64) NOT NULL,
  case_id VARCHAR(64) NULL,
  created_at DATETIME(3) NULL,
  type VARCHAR(64) NULL,
  actor_user_id BIGINT NULL,
  payload JSON NULL,
  PRIMARY KEY (id),
  KEY idx_case_events_case (case_id, created_at),
  KEY idx_case_events_actor_user_id (actor_user_id)
);

CREATE TABLE IF NOT EXISTS case_triggers (
  id VARCHAR(64) NOT NULL,
  project_id VARCHAR(128) NULL,
  payload JSON NULL,
  created_at DATETIME(3) NULL,
  updated_at DATETIME(3) NULL,
  PRIMARY KEY (id),
  KEY idx_case_triggers_project_id (project_id)
);

ALTER TABLE runs
  ADD COLUMN case_id VARCHAR(64) NULL,
  ADD KEY idx_runs_case (case_id);

ALTER TABLE webhook_dedup
  ADD COLUMN case_id VARCHAR(64) NULL;
