-- Conditional workflows and named approvals (SOAR phase 1).
--
-- runs.trigger_payload holds the structured payload that started a run, read
-- by RunIf expressions as `trigger`. run_events.actor_user_id indexes human
-- control events (approve, reject, pass, retry) by who performed them; the
-- full actor also lives in run_events.payload.
--
-- gorm's incremental AutoMigrate adds both columns on start, so this script is
-- only needed where AutoMigrate is disabled. MySQL 8.0 has no
-- ADD COLUMN IF NOT EXISTS: check information_schema.columns first; the
-- script is not re-runnable. Existing rows keep NULL / 0, which read as
-- "no trigger payload" and "no recorded actor".

ALTER TABLE runs
  ADD COLUMN trigger_payload JSON NULL;

ALTER TABLE run_events
  ADD COLUMN actor_user_id BIGINT NOT NULL DEFAULT 0,
  ADD KEY idx_run_events_actor (actor_user_id);
