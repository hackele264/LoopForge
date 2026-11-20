-- Pull alert sources (SOAR: products that cannot push to a webhook).
--
-- alert_sources: one schedule that calls a connector action to list alerts
-- and admits them through a webhook. payload holds the configuration and
-- state what the poller records, in separate columns so neither write
-- overwrites the other. lease_owner/lease_until let one of several API
-- processes poll a source at a time.
--
-- alert_source_seen: alert IDs (SHA-256) a source admitted, so an alert
-- seen again in an overlapping window is not admitted twice.
--
-- gorm's incremental AutoMigrate creates these tables on start; this script
-- is the manual equivalent and is re-runnable.

CREATE TABLE IF NOT EXISTS alert_sources (
  id VARCHAR(64) NOT NULL,
  project_id VARCHAR(128) NULL,
  webhook_id VARCHAR(64) NULL,
  enabled TINYINT(1) NULL,
  next_run_at DATETIME(3) NULL,
  lease_owner VARCHAR(128) NULL,
  lease_until DATETIME(3) NULL,
  payload JSON NULL,
  state JSON NULL,
  created_at DATETIME(3) NULL,
  updated_at DATETIME(3) NULL,
  PRIMARY KEY (id),
  KEY idx_alert_sources_project_id (project_id),
  KEY idx_alert_sources_webhook_id (webhook_id),
  KEY idx_alert_sources_due (enabled, next_run_at)
);

CREATE TABLE IF NOT EXISTS alert_source_seen (
  source_id VARCHAR(64) NOT NULL,
  item_key VARCHAR(64) NOT NULL,
  seen_at DATETIME(3) NULL,
  PRIMARY KEY (source_id, item_key),
  KEY idx_alert_source_seen_seen_at (seen_at)
);
