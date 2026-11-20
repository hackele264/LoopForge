-- Configurable per-project run limit.
--
-- projects.run_limit: how many top-level SOP runs the project may hold on
-- platform execution at once; NULL uses the platform default
-- (AGENTFLOW_PROJECT_RUN_LIMIT, or 10). Written only through
-- PUT /api/projects/{id}/run-limit.
--
-- gorm's incremental AutoMigrate adds the column on start; this script is the
-- manual equivalent. It is not re-runnable (MySQL 8.0 has no ADD COLUMN IF
-- NOT EXISTS), so check information_schema.columns first.

ALTER TABLE projects ADD COLUMN run_limit INT NULL;
