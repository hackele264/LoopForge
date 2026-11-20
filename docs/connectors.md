# Connectors and action nodes

An action node calls a security product (threat intelligence, EDR,
identity provider, chat bot) or changes LoopForge's own case. It runs in the
platform process: no sandbox, no execution machine, so it starts in
milliseconds. Its result is the node's structured output, readable by later
conditions and inputs as `nodes.<id>.data`.

## Building blocks

| Piece | What it is | Where |
|---|---|---|
| Connector | A vendor template: endpoint, authentication, actions | Shipped in `internal/connector/templates/`, or added by the deployment |
| Action | One operation of a connector, with typed inputs and output fields | Inside the connector |
| Connection | A project's endpoint and credentials for one connector | 告警与案件 → 连接, or `/api/connections` |
| Action node | A workflow node of type `action` naming connector, action, connection and inputs | Flow designer → 动作 |

Actions come in three categories:

- **情报富化 (enrichment)**: read-only lookups.
- **响应处置 (response)**: change something outside LoopForge, such as
  isolating a host or disabling an account. A response action must come
  after an approval node on every path that reaches it; an approval's error
  edge (a rejection) does not count. Saving a workflow that breaks this is
  refused, and the engine checks again before the action runs.
- **通用 (utility)**: notifications and LoopForge's own case actions.

## Shipped connectors

| Connector | Actions | Authentication |
|---|---|---|
| LoopForge 内置动作 | 提取 IOC, 案件评论, 更新案件, 案件添加 IOC | none |
| VirusTotal | IP / 域名 / URL / 文件哈希信誉 | `x-apikey` header |
| AbuseIPDB | IP 滥用检查 | `Key` header |
| urlscan.io | 提交扫描, 查询结果, 搜索 | `API-Key` header |
| AlienVault OTX | IP / 域名 / 哈希情报 | `X-OTX-API-KEY` header |
| Shodan | 主机信息, 账户额度 | `key` query parameter |
| GreyNoise | IP 社区情报 | `key` header (optional) |
| 微步在线 ThreatBook | IP 信誉 | `apikey` query parameter |
| Microsoft Defender for Endpoint | 查找终端, 终端详情, **隔离**, **解除隔离** | OAuth 2.0 client credentials |
| Microsoft Entra ID | 查询用户, **禁用账号**, **启用账号**, **吊销会话** | OAuth 2.0 client credentials |
| CrowdStrike Falcon | 查找终端, **网络隔离**, **解除隔离** | OAuth 2.0 client credentials |
| 企业微信群机器人 | 发送文本 / Markdown | `key` query parameter |
| 钉钉群机器人 | 发送 Markdown | `access_token` query parameter |

Bold actions are response actions. The templates were written for LoopForge
from each vendor's public API documentation; check permissions and regional
endpoints against your tenant before relying on them.

## Connections

A connection belongs to one project and one connector. It holds:

- **服务地址**: overrides the connector's default endpoint (regional clouds,
  on-premise products).
- **参数**: non-secret settings such as the Entra tenant ID.
- **凭据**: write-only. The API returns only the names of the secrets that
  are set; an empty field on edit keeps the stored value.

Project members of any role may list connections; owners, maintainers and
members may create, edit, test and delete them. 测试 runs the connector's
read-only test action and shows the outcome without the response body.

An action node may only use a connection of its run's project. Secrets never
enter a template, a node configuration or a log line: authentication is
applied after the request is built, and secret values are replaced with
`[redacted]` in any error message. Requests never follow a redirect to
another host, so header credentials cannot leak through one. Secrets are
stored in the database without encryption, like the platform's other
credentials; restrict database access accordingly.

## Inputs and outputs

Input values are templates. Text outside `{{ }}` is literal; each
`{{ expression }}` uses the [condition language](conditional-workflows.md)
over `trigger`, `nodes` and `run` (`run.caseId`, `run.projectId`). A value
that is exactly one `{{ expression }}` keeps its type, so a list stays a
list. Inputs are converted to the declared type (string, number, boolean,
list, object), defaults fill empty ones, and a missing required input fails
the node.

Functions available in conditions and templates:

| Function | Result |
|---|---|
| `iocs(value)` | Every indicator in any value as `{type, value}` objects |
| `iocs(value, "url")` | The values of one type: ipv4, domain, url, email, md5, sha1, sha256, cve |
| `first(list)` | The first element, or null |
| `join(list, sep)` / `split(text, sep)` | Join or split text |
| `coalesce(a, b, ...)` | The first value that is not null or empty |
| `str(value)` | The value as text |
| `base64url(text)` | URL-safe Base64 without padding |
| `len`, `lower`, `upper`, `contains`, `startsWith`, `endsWith`, `exists` | As in conditions |

Every action's output has `status` (the HTTP status) and its declared output
fields, for example `nodes.vt.data.malicious`. Actions without output fields
also keep the response `body`. An output larger than 128 KiB drops the body
and sets `bodyTruncated`.

## Case audit

When the run belongs to a case, every external action, successful or not,
is recorded on the case timeline as `case.action` with the connector,
action, connection, run and node, and every approval or rejection of one of
the run's steps as `case.approval` with the person who decided and their
note. A response action on a case therefore shows who approved it and what
it did, next to each other. The built-in case actions change the case
through the same path as the UI, so a playbook that raises severity fires
`case.escalated` triggers, and its comments and changes appear on the
timeline attributed to the run.

## Example: phishing playbook

A mail gateway webhook with `caseMode: per_fingerprint` opens a case and
starts this SOP:

```
提取 IOC ─▶ VirusTotal URL ─▶ 人工门禁 ─▶ Entra 吊销会话 ─▶ 关闭案件
          (loopforge.extract_iocs)  (runIf: nodes.vt.data.malicious > 0)
```

| Node | Type | Configuration |
|---|---|---|
| `extract` | action | `loopforge.extract_iocs`, value `{{ trigger }}` |
| `vt` | action | `virustotal.url_report`, url `{{ first(nodes.extract.data.url) }}` |
| `approve` | approval | runIf `nodes.vt.data.malicious > 0` |
| `revoke` | action | `entra.revoke_sessions`, user `{{ trigger.alert.recipient }}` |
| `close` | action | `loopforge.case_update`, status `closed`, resolution `resolved` |

A clean URL skips the approval and everything after it. Add an Agent node
between `vt` and `approve` to have the triage reasoning recorded with
`submit_output`, and branch on its verdict instead of the raw count.
`TestActionNodesRunPhishingPlaybook` in `internal/engine` runs the same
shape against a fake vendor.

## Adding connectors

Set `AGENTFLOW_CONNECTOR_DIR` to a directory of `*.yaml` templates; they are
loaded at start next to the shipped ones and may not reuse a shipped ID. A
template that fails validation is logged and the whole directory is ignored.

```yaml
id: example_ti            # lower case, digits, _
title: Example TI
description: 查询 IP 信誉
baseUrl: https://api.example.test
auth:
  type: header            # none | header | bearer | basic | query | oauth2_client_credentials
  name: X-Api-Key
  secret: api_key
params:                   # non-secret settings, readable as params.<name>
  - {name: region, label: 区域, default: global}
secrets:
  - {name: api_key, label: API Key, required: true}
testAction: ip            # read-only action used by 测试
testInputs: {ip: 8.8.8.8}
actions:
  - id: ip
    title: IP 信誉
    category: enrichment  # enrichment | response | utility
    inputs:
      - {name: ip, label: IP 地址, type: string, required: true}
    request:
      method: GET         # GET | POST | PUT | PATCH | DELETE
      path: /v1/ip/{{ inputs.ip }}    # expression parts are path-escaped
      query: {region: "{{ params.region }}"}
      headers: {}
      body: null          # JSON body; strings inside are templates
      form: {}            # or form-encoded fields
    success: [200, 404]   # default: any 2xx
    failIf: response.body.error != null
    timeoutSeconds: 30
    output:
      score: response.body.score
      found: response.status == 200
```

Templates may read `inputs` and `params`; output and `failIf` expressions
read `response` (`status`, `headers`, `body`) and `inputs`. OAuth token
URLs may be absolute or relative to the connection's address; tokens are
cached per connection until a minute before they expire.

## Storage

Table `connections` is created by gorm's incremental AutoMigrate;
`migrations/042_connections.sql` is the manual equivalent.

## Not covered yet

- No per-connection rate limiting or retry with backoff beyond the node's
  `maxAttempts`.
- Secrets are not encrypted at rest.
- Read-only connector actions are not offered to Agents as MCP tools; an
  Agent can use a vendor's own MCP server instead.
- No loop over a list (for example one lookup per extracted IP); look up the
  first value, or run a script node.
