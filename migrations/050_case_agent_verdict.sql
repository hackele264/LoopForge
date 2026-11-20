-- Agent verdict on cases (phase 6 shadow-mode pilot).
--
-- A playbook's 记录研判结论 action (loopforge.case_set_verdict) stores the
-- triage verdict on the case: agentVerdict (malicious, benign,
-- false_positive, needs_review), agentConfidence, agentRationale,
-- agentVerdictRunId, agentVerdictAt and agentVerdictFirstAt are fields of
-- cases.payload and need no DDL. The two columns below mirror agentVerdict
-- and agentVerdictFirstAt so the pilot report (GET /api/pilot-report) can
-- filter on them.
--
-- gorm's incremental AutoMigrate adds both columns on start, so this script is
-- only needed where AutoMigrate is disabled. MySQL 8.0 has no
-- ADD COLUMN IF NOT EXISTS: check information_schema.columns first; the
-- script is not re-runnable. Existing cases keep '' / NULL ("no verdict").
-- Numbers 047-049 are used by other phase-6 branches.

ALTER TABLE cases
  ADD COLUMN agent_verdict VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN agent_verdict_at DATETIME(3) NULL;
