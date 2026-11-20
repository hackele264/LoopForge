-- Inbound webhooks that start SOP runs (SOAR phase 2).
--
-- webhooks holds each definition; payload carries the full JSON including the
-- SHA-256 of the URL secret and the optional HMAC signing secret.
-- webhook_dedup keeps one row per alert fingerprint while its dedup window is
-- open; webhook_deliveries is a bounded per-webhook delivery log.
--
-- gorm's incremental AutoMigrate creates these tables on start; this script
-- is the manual equivalent and is safe to re-run.

CREATE TABLE IF NOT EXISTS webhooks (
  id VARCHAR(64) NOT NULL,
  project_id VARCHAR(128) NULL,
  workflow_id VARCHAR(128) NULL,
  payload JSON NULL,
  created_at DATETIME(3) NULL,
  updated_at DATETIME(3) NULL,
  PRIMARY KEY (id),
  KEY idx_webhooks_project_id (project_id),
  KEY idx_webhooks_workflow_id (workflow_id)
);

CREATE TABLE IF NOT EXISTS webhook_dedup (
  webhook_id VARCHAR(64) NOT NULL,
  fingerprint VARCHAR(64) NOT NULL,
  run_id VARCHAR(64) NULL,
  hits BIGINT NULL,
  first_seen DATETIME(3) NULL,
  last_seen DATETIME(3) NULL,
  expires_at DATETIME(3) NULL,
  PRIMARY KEY (webhook_id, fingerprint),
  KEY idx_webhook_dedup_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id VARCHAR(64) NOT NULL,
  webhook_id VARCHAR(64) NULL,
  received_at DATETIME(3) NULL,
  payload JSON NULL,
  PRIMARY KEY (id),
  KEY idx_webhook_deliveries_hook (webhook_id, received_at)
);
