# Security hardening

What protects a LoopForge instance used for security operations, and the
settings that control it. Everything here applies only while login is
required (`AGENTFLOW_AUTH_REQUIRED=true`, the default of the platform
binary and of `compose.yaml`).

## Project read isolation

Runs, issues, alerts, cases and connections belong to a project. Only the
project owner, its members (any role, viewer included) and platform
administrators can read them. Projects without an owner stay shared.

| Data | Rule |
|---|---|
| Run list (`GET /api/runs`) | Runs of projects you cannot read are left out |
| Everything under `/api/runs/{id}` (detail, logs, telemetry, artifacts, workspace, stream, preview) | 403 for non-members |
| Issue list and `/api/issues/{id}` | Same |
| Alerts, cases, connections | Always member-only, whatever the setting below |
| Runs with no project | Readable by every signed-in user, as before |
| Personal workspace runs | Only their owner, as before |

`AGENTFLOW_PROJECT_READ_ISOLATION=false` turns the rule off for runs and
issues and restores the earlier instance-wide reads.

Not covered: workflow definitions, the agent and rule catalog, analytics and
the project list stay readable by every signed-in user, because SOPs and
roles are shared across projects by design.

## API tokens

Personal tokens (个人设置 → 访问密钥, or `POST /api/auth/tokens`) can be
limited when they are created:

| Scope | Allows |
|---|---|
| `read` | Every read; always granted to a scoped token |
| `runs:execute` | Start and control runs, run a playbook on a case |
| `cases:write` | Create and change alerts and cases |
| `approvals:decide` | Approve, reject or pass run steps |
| `config:write` | Every other write: workflows, connections, webhooks, triggers, catalog |
| `admin` | Platform administration; only administrators can grant it |

- A token without scopes keeps its owner's full access, so tokens created
  before scopes existed behave as before. Prefer scoped tokens for
  integrations.
- `projectIds` limits a token to those projects. Its owner must be a member.
  A project-limited token reaches nothing outside its projects and never
  carries platform administration. Without scopes it is read-only.
- The check runs in the authentication middleware on the route, and again
  for each MCP tool call, which is dispatched as its own request.
- Tokens are still managed only from a browser session, and a token cannot
  create or revoke tokens.

For an external system, create a dedicated account, add it to the projects it
needs, and give it a scoped, project-limited token. There is no separate
service-account type yet.

## Approvals that release response actions

An approval node whose success path reaches a response action (isolate a
host, disable an account) accepts only a named person signed in to the
platform:

- service callers and anonymous requests are refused;
- API tokens are refused, even with `approvals:decide`, unless
  `AGENTFLOW_RESPONSE_APPROVAL_ALLOW_TOKEN=true`.

Other approvals follow the existing rules: an approver policy on the node,
and `AGENTFLOW_APPROVAL_REQUIRE_NAMED=true` to require a named user
everywhere. Saving a workflow with a response action that is not behind an
approval on every path is refused (see [connectors](connectors.md)).

## Audit log

平台管理 → 审计日志 (`GET /api/audit`, `GET /api/audit/export?format=csv|json`)
is readable by platform administrators only; a token needs the `admin` scope.
It records:

| Action | When |
|---|---|
| `auth.login`, `auth.login.local`, `auth.login.exchange`, `auth.login.oauth` | Every sign-in attempt, with the attempted user name on failure |
| `auth.register`, `auth.setup`, `auth.logout` | Account creation, first administrator, sign-out |
| `auth.token.create`, `auth.token.revoke` | Token changes, with scopes and projects |
| `api METHOD /route` | Every API write (approvals, configuration, cases, connections...) and every request answered 401 or 403 |
| `connector.action` | Every connector call that used a connection's credentials, with run, node and outcome |

Each entry has the time, the user, whether an API token was used (its ID),
the source address, the project when the request names one, the HTTP status
and success / failure / denied. Request bodies are never stored. Webhook
ingress is not logged here; it has its own delivery log. Audit-log reads and
exports are themselves logged.

Entries are kept for `AGENTFLOW_AUDIT_RETENTION_DAYS` days (default 365;
`0` keeps everything); older ones are deleted at most once an hour. Exports
hold up to 10,000 entries; CSV cells starting with `=`, `+`, `-` or `@` are
prefixed with `'` so spreadsheets do not run them as formulas.

## Hardened deployment

`compose.hardened.yaml` applies the settings above to the Compose stack
(Docker Compose 2.24.4 or later):

```bash
COMPOSE_FILE=compose.yaml:compose.hardened.yaml docker compose --profile platform up -d
```

- The platform runs as `AGENTFLOW_ROLE=api` without the Docker socket and
  without the local Docker sandbox, so the internet-facing container cannot
  start containers on the host. Runs execute on separate workers or
  execution machines ([deployment](deployment.md#workers-and-runners)); until
  one is connected, runs wait.
- Sign-up is off (`AGENTFLOW_ALLOW_SIGNUP=false`); create accounts with
  `loopforge-account`.
- Read isolation and named approvals are on.

Also:

- Serve the site over HTTPS and set `AGENTFLOW_SECURE_COOKIES=true`.
- Keep `LOOPFORGE_BIND` on an internal address; do not expose the platform
  to the internet without a reverse proxy that you control.
- The default `compose.yaml` keeps the Docker socket and open sign-up so a
  first install works on one machine; it is meant for trusted networks.

## Settings

| Variable | Default | Effect |
|---|---|---|
| `AGENTFLOW_PROJECT_READ_ISOLATION` | `true` | Member-only reads of runs and issues |
| `AGENTFLOW_APPROVAL_REQUIRE_NAMED` | `false` | Every approval needs a named user |
| `AGENTFLOW_RESPONSE_APPROVAL_ALLOW_TOKEN` | `false` | Let API tokens approve gates before response actions |
| `AGENTFLOW_AUDIT_RETENTION_DAYS` | `365` | Audit log retention; `0` keeps everything |
| `AGENTFLOW_ALLOW_SIGNUP` | `true` | Self-service sign-up after the first administrator |

## Storage

`audit_events` and the `api_tokens.scopes` / `api_tokens.project_ids` columns
are created by gorm's incremental AutoMigrate;
`migrations/043_security_hardening.sql` is the manual equivalent.

## Not covered yet

- Two-person approval and timed escalation of approvals.
- A service-account type distinct from user accounts.
- Encryption at rest for connection secrets and other stored credentials.
- Multi-factor sign-in.
