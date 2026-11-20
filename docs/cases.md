# Alerts and cases

Inbound alerts are stored per project; related alerts are grouped into cases
that carry the investigation: severity, status, indicators (IOCs), a timeline
of every change, and the runs that worked on them. The 告警与案件 page in the
left rail shows the case list, the alert queue and case triggers.

## Alerts

Every webhook delivery that passes its checks stores an alert: the raw
payload, the title (`titleField`), the severity (`severityField`, normalized
to low/medium/high/critical; vendor words like `CRITICAL`, `高危`, `warning`
and CVSS-like numbers are mapped, anything else reads as medium), the
fingerprint and the run it started. A duplicate alert is stored too, marked
`duplicate`, without a run of its own.

## How cases are opened

| Way | Result |
|---|---|
| Webhook `caseMode: per_fingerprint` | A new fingerprint opens a case; duplicates within the dedup window join it. Needs `dedupFields`. |
| Webhook `caseMode: per_alert` | Every alert opens its own case. |
| Webhook without `caseMode` | Alerts stay in the alert queue. |
| 升级为案件 / `POST /api/alerts/{id}/escalate` | Opens a case from an uncased alert, or attaches it to `caseId`. |
| 新建案件 / `POST /api/cases` | Opens a case by hand, optionally with `alertIds`. |

A case opened by a webhook is created before the webhook's SOP starts, so the
run carries the case ID (`executionContext.caseId`) and appears on the case.
Cases are numbered per project (#1, #2, ...); numbers come from a locked
per-project counter, so concurrent creations never collide.

IOCs are extracted from every string in an alert's payload when it joins a
case: IPv4 addresses, URLs, email addresses, MD5/SHA-1/SHA-256 hashes, CVE IDs,
and domains taken from URLs, email addresses and values that are a bare host
name (free text like `invoice.pdf` is not read as a domain). At most 200 per
alert. More can be added by hand (`POST /api/cases/{id}/iocs`).

## Status

`new` → `investigating` → `pending_response` → `closed`. Closing requires a
resolution: `false_positive`, `resolved` or `duplicate`; reopening clears it.
Every change to title, description, severity, status or assignee, every
comment, IOC, alert and run is recorded on the timeline with who did it.
Raising severity to high or critical also records `case.escalated`.

## Case triggers

A trigger starts an SOP when one of these happens on a case of its project:
`case.created`, `case.alert_added`, `case.escalated`, `case.severity_changed`,
`case.status_changed`, optionally only for cases at or above `minSeverity`.
The run executes as the user who created the trigger and is linked to the
case. Its trigger payload is:

```json
{"case": {...}, "event": {"type": "case.escalated"}, "alerts": [...], "iocs": [...], "alert": {...}}
```

`alerts` holds up to 20 alert summaries; `alert` is the alert that caused the
event, when there is one. Node conditions read it as usual, for example
`trigger.case.severity == "critical"`.

To stop a playbook that edits its own case from looping, a trigger does not
start while its previous run for the same case is still active, and starts at
most 20 runs per case. Skipped starts are recorded on the timeline.

A playbook can also be started on a case by hand (对此案件运行 SOP, or
`POST /api/cases/{id}/runs`), as the requesting user.

## Playbook actions

Action nodes of the built-in connector (案件评论, 更新案件, 案件添加 IOC)
change the run's case through the same path as the UI: their changes land on
the timeline attributed to the run and fire case triggers. Every external
connector action a case's run performs is recorded as `case.action`, and
every approval or rejection of one of its steps as `case.approval` with the
person who decided. See
[connectors and action nodes](connectors.md).

## Agents

Alert and case reads and writes are MCP tools (`alerts_*`, `cases_*`,
`case_triggers_list`), so an agent role with platform MCP access can open a
case, add a summary comment, add IOCs or close it with a resolution. Trigger
creation and editing stay in the UI because triggers start runs as their
creator.

## Access

Unlike the rest of the catalog, alerts and cases are not readable by every
signed-in user: reads need project membership of any role (including
viewer), project ownership or platform admin; writes need project write
access (owner, maintainer or member).

## Storage

Tables `alerts`, `cases`, `case_counters`, `case_iocs`, `case_events`,
`case_triggers`, plus `runs.case_id` and `webhook_dedup.case_id`, are created
by gorm's incremental AutoMigrate; `migrations/041_alerts_cases.sql` is the
manual equivalent. `TestCaseStorageOnMySQL` covers case numbering and storage
on MySQL (`AGENTFLOW_WEBHOOK_TEST_DSN`).

## Not covered yet

- No SLA timers or MTTD/MTTR metrics on cases.
- Assignee is a user ID; there is no picker or notification yet.
- Correlation is by webhook fingerprint only; alerts from different webhooks
  are not merged automatically.
- No bulk actions on the alert queue.
