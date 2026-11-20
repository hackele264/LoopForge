-- Connector connections (SOAR phase 4).
--
-- connections: per-project endpoint, non-secret params and secrets for one
-- connector; action nodes reference a connection by ID. Secrets live in
-- their own JSON column so list queries never read them.
--
-- gorm's incremental AutoMigrate creates this table on start; this script is
-- the manual equivalent and is re-runnable.

CREATE TABLE IF NOT EXISTS connections (
  id VARCHAR(64) NOT NULL,
  project_id VARCHAR(128) NULL,
  connector_id VARCHAR(64) NULL,
  payload JSON NULL,
  secrets JSON NULL,
  created_at DATETIME(3) NULL,
  updated_at DATETIME(3) NULL,
  PRIMARY KEY (id),
  KEY idx_connections_project_id (project_id),
  KEY idx_connections_connector_id (connector_id)
);
