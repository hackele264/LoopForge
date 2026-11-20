# 影子模式试点手册（Splunk notable + CrowdStrike Falcon + 飞书）

影子模式试点让真实告警走完富化和 AI 研判，但**所有响应动作都停在人工审批**，
审批人一律驳回。试点至少运行 2 周，用试点报告回答四个问题：告警量多少、
富化是否可靠（成功率 ≥ 99%）、告警到研判结论多快（p95 ≤ 5 分钟）、Agent
结论和分析员最终结论有多一致。

本手册不含任何凭据。所有密钥由管理员在「告警与案件 → 连接」里自己填写。

## 1. 组成

| 部分 | 作用 | 位置 |
|---|---|---|
| Splunk 拉取式告警源 | 每分钟读一次 `index=notable`，经 Webhook 准入、去重、建案 | [告警源](alert-sources.md) |
| SOP「SOC 影子模式试点 SOP」 | 提取 IOC → CrowdStrike 查终端、查告警 → Agent 研判 → 记录研判结论 → 飞书卡片 → 响应审批 → 网络隔离 | `migrations/051_soc_shadow_pilot_sop.sql`（通用模板） |
| 记录研判结论 | 把 Agent 结论写到案件上（`agentVerdict`） | 内置动作 `loopforge.case_set_verdict`，见 [案件](cases.md#agent-verdict) |
| Lark / 飞书 | 自建应用机器人向 SOC 群发卡片 | 连接器 `lark`（PR #16，feat/lark-connector） |
| 试点报告 | 告警量、运行、富化成功率、研判时延、一致率 | 「告警与案件 → 试点报告」，`GET /api/pilot-report` |

SOP 流程：

```
提取 IOC ─┬─▶ CrowdStrike 查终端 ─▶ CrowdStrike 查告警 ─┐            （有主机字段）
          └─▶ 无主机字段（案件评论）──────────────────────┤            （没有主机字段）
                                  富化失败也走失败分支 ──┤
                                                         ▼ join: any
     Agent 研判（outputSchema: verdict / confidence / rationale）
       ─▶ 记录研判结论 ─▶ 飞书卡片（失败也继续）
       ─▶ 响应审批（runIf verdict == "malicious"，审批人 owner / maintainer）
       ─▶ CrowdStrike 网络隔离（runIf malicious 且查到终端）
```

非恶意结论跳过审批和隔离，运行直接成功；恶意结论停在审批，影子模式下审批人驳回，
隔离不会执行。

### 为什么没有 `shadowMode` 开关

响应节点前的审批是平台强制的（没有审批就保存不了 SOP，引擎执行前还会再查一次），
审批节点指定了审批人，不会自动通过。在此之上，影子模式的“即使误点通过也不执行”
靠**供应商侧最小权限**实现：试点用的 CrowdStrike API Client 只授予只读权限
（见 3.2），隔离请求会被 Falcon 以 403 拒绝，节点失败并记录在案件时间线上。
这样不需要在引擎里加一个额外开关，也不会和其它分支对审批代码的改动冲突。

## 2. 升级与前置条件

1. 升级到包含本功能的版本（`./start.sh pull` 或按 [部署文档](deployment.md) 更新镜像）。
2. **凭据加密**：确认平台有密钥（`AGENTFLOW_SECRET_KEY_FILE`，安装器自动创建），
   并把升级前保存的明文凭据加密：

   ```bash
   docker compose --profile platform exec platform loopforge-secrets status
   docker compose --profile platform exec platform loopforge-secrets encrypt -dry-run
   docker compose --profile platform exec platform loopforge-secrets encrypt
   ```

   密钥文件要和数据库分开备份。详见 [部署 · 凭据加密](deployment.md#credential-encryption)。
3. **数据库迁移**（手动执行，部署不会自动跑）：
   - `migrations/050_case_agent_verdict.sql`：`cases.agent_verdict`、`cases.agent_verdict_at`
     两列。启用了 gorm AutoMigrate 的部署启动时会自动补列，可以跳过；
     执行前先查 `information_schema.columns`，脚本不可重复执行。
   - `migrations/051_soc_shadow_pilot_sop.sql`：把试点 SOP 作为通用模板写入
     `generic_templates`。**必须手动执行**（种子数据不在代码里）。`INSERT IGNORE`，可重复执行。
4. 版本中已包含 Lark 连接器 `lark`（PR #16，feat/lark-connector）。没有它时，
   复制后的 SOP 保存会因「unknown connector action lark.send_card」被拒绝，
   所以 051 只在包含 #16 的版本上执行。
5. 平台能访问 Splunk 管理端口（默认 8089）、CrowdStrike API 域名和
   `open.feishu.cn`（国内版）或 `open.larksuite.com`（国际版）。
6. 执行 Agent 研判的执行器（模板里是 `codebuddy`）已配置好模型与密钥，
   沙箱 `generic-docker` 可用（与其它通用 SOP 相同）。

## 3. 试点项目与连接

### 3.1 创建试点项目

新建一个专用项目（例如「SOC 影子试点」），Owner 设为试点负责人。分析员加为
成员（member）或维护者（maintainer）：他们能看案件、关闭案件、审批；
**只有项目 Owner 和平台管理员能看试点报告**。

### 3.2 连接（告警与案件 → 连接）

每个连接都在本项目下新建；下表只列需要填写的字段，值由管理员自行填写。

| 连接 | 服务地址 | 参数 | 凭据 | 建议限流 / 重试 |
|---|---|---|---|---|
| Splunk | 管理端口，如 `https://<splunk 主机>:8089` | — | Token（需搜索 `index=notable` 的权限） | `rateLimitPerSecond` 2，`maxRetries` 3 |
| CrowdStrike Falcon | 所在云区域的 API 地址（默认 `https://api.crowdstrike.com`，EU 为 `https://api.eu-1.crowdstrike.com` 等） | — | API Client ID、API Client Secret | `rateLimitPerSecond` 5，`rateLimitBurst` 5，`maxRetries` 3 |
| Lark / 飞书 | 默认 `https://open.larksuite.com`（国际版）；飞书国内版改为 `https://open.feishu.cn` | — | App ID、App Secret（自建应用） | `rateLimitPerSecond` 2，`rateLimitBurst` 5，`maxRetries` 2 |

- Splunk 管理端口是自签名证书时，在连接的「HTTPS 证书」里固定证书 SHA-256
  （`openssl x509 -noout -fingerprint -sha256`）。
- **CrowdStrike API Client 只给只读权限**：`Hosts: Read`、`Alerts: Read`。
  不要给 `Hosts: Write`，这是影子模式的兜底（见第 1 节）。试点结束、准备开启真实响应时
  再另建一个有写权限的 Client。
- 三个连接都可以点「测试」：Splunk 跑一次搜索，CrowdStrike 查一个不存在的主机，
  Lark 读取机器人信息（`bot_info`，返回应用名和启用状态，不发消息）。

## 4. 飞书 / Lark 侧设置

试点用**自建应用的机器人**发消息（不是群里的“自定义机器人” Webhook）：

1. 在开发者后台（飞书 <https://open.feishu.cn/app>，Lark <https://open.larksuite.com/app>）
   创建**企业自建应用**，在「添加应用能力」里开启**机器人**。
2. 权限管理里申请发消息权限（以群身份发送消息，例如 `im:message:send_as_bot`），
   发布版本并由企业管理员审核通过。
3. 在「凭证与基础信息」复制 App ID、App Secret，填到 Lark 连接；连接页点「测试」应返回机器人名称。
4. 把机器人加入 SOC 值班群（群设置 → 群机器人 → 添加机器人 → 选择该应用）。
5. 取得群的 `chat_id`（`oc_` 开头）：可在开放平台 API 调试台调用「获取用户或机器人所在的群列表」
   （`GET /open-apis/im/v1/chats`），或在群设置里查看群 ID。
6. 文档：发送消息 <https://open.larksuite.com/document/server-docs/im-v1/message/create>，
   机器人信息 <https://open.larksuite.com/document/client-docs/bot-v3/obtain-bot-info>
   （飞书国内版对应 open.feishu.cn 下同路径）。

App Secret 等同于密码，只填在连接里，不要贴到群里或工单里。

## 5. 采用 SOP

1. 「SOP → 通用模板」找到「SOC 影子模式试点 SOP」，**复制到本项目**
   （`POST /api/workflows/soc-shadow-pilot/clone`），角色「SOC 告警研判」随之复制。
2. 在流程设计器里给每个动作节点选择本项目的连接：
   - 「CrowdStrike 查终端」「CrowdStrike 查告警」「CrowdStrike 网络隔离」→ CrowdStrike 连接；
   - 「飞书通知 SOC」→ Lark 连接，并在节点输入里把 `REPLACE_WITH_SOC_CHAT_ID`
     换成 SOC 群的 `chat_id`，把正文链接里的 `LOOPFORGE_HOST` 换成 LoopForge 访问地址
     （卡片正文末尾是跳回运行页的链接）。
   「提取 IOC」「无主机字段」「记录研判结论」是内置动作，不需要连接。
3. 主机字段：模板用 `coalesce(trigger.dest_nt_host, trigger.dest_host, trigger.dest)`
   取主机名。若贵司 notable 用别的字段，修改「CrowdStrike 查终端」「无主机字段」
   的执行条件和两个 CrowdStrike 节点的输入（三处保持一致）。多值字段（列表）会让
   查终端失败并走失败分支，研判照常进行。
4. 「CrowdStrike 查告警」用 `device.hostname:'<主机>'` 查最近 20 条 Falcon 告警
   （Alerts API v2，`created_timestamp.desc`），只返回 composite_id 和总数。
5. 「响应审批」：审批人默认是项目 owner 和 maintainer；可以改为具体用户 ID。
   **不要删除审批节点或去掉执行条件**。当前版本已支持双人审批与审批超时
   （PR #15 的 `requiredApprovals` / `timeoutMinutes`），可以在审批节点上加，但影子模式下不需要；
   不要设置超时后自动通过的行为。
6. 「SOC 告警研判」角色：按需改执行器 / 模型。提示词通过 `{{trigger}}`、
   `{{node.<id>.data}}` 拿到告警和富化结果（每项最多 6,000 字节，作为不可信数据加围栏），要求先调用
   `submit_output` 提交 `{verdict, confidence, rationale}` 再 `submit_gate_result pass`。
7. 保存。保存时平台会校验：动作与输入存在、执行条件只读上游节点、响应动作前有审批。

## 6. Webhook 与 Splunk 告警源

在 SOP 的「流程设置 → Webhook 触发」新建 Webhook：

| 字段 | 建议值 |
|---|---|
| 标题字段 `titleField` | `search_name` |
| 严重度字段 `severityField` | `urgency` |
| 去重字段 `dedupFields` | `event_id` |
| 去重窗口 | 3600 秒 |
| 建案方式 `caseMode` | `per_alert`（每条 notable 一个案件，一致率按告警计）；同一事件反复触发较多时可改 `per_fingerprint` |
| 限流 | `rateLimitPerMinute` 60，`rateLimitBurst` 120（超出的告警下次拉取会重读，不会丢） |

然后在 Webhook 卡片上「定时拉取」新建告警源，选 Splunk 预设：

| 字段 | 值 |
|---|---|
| 连接 | 上面的 Splunk 连接 |
| 动作 | `search` |
| search | `search index=notable \| sort 0 _time` |
| earliest / latest / count | `{{ window.since }}` / `{{ window.until }}` / `{{ window.limit }}` |
| idPath / timePath | `event_id` / `_time` |
| pollSeconds / lagSeconds | 60 / 60 |
| lookbackSeconds | 0（不回灌历史告警） |

先点「试拉取」确认能看到告警和标题，再保存并启用。第一条告警进来后打开它的运行，
确认：富化节点成功、研判节点输出了结论、案件上出现「Agent 研判」、飞书群收到卡片。
飞书节点失败时看运行日志里的错误：`code` 非 0 时多为机器人不在群里、`chat_id` 错误或缺少发消息权限；
获取 `tenant_access_token` 失败说明 App ID / App Secret 不对或服务地址选错了版本（国内版 / 国际版）。

## 7. 分析员怎么处理

1. 在飞书卡片末尾点「在 LoopForge 中查看运行」，或在「告警与案件」打开案件。
2. **独立研判**：先看告警、IOC、富化结果和时间线，形成自己的结论，再参考 Agent 结论。
   一致率衡量的是 Agent 能否替代一线判断，照抄 Agent 结论会让指标失真。
3. 恶意结论会停在「响应审批」：**一律驳回**，备注写「影子模式」以及你认为是否该隔离。
   驳回和备注会记在案件时间线（`case.approval`）。
4. 关闭案件，选择结论：
   - `resolved`（已处置）：确认是真实威胁 / 恶意活动（试点期间在原有流程里处置）；
   - `false_positive`（误报）：检测误报，或真实但无害的活动；
   - `duplicate`（重复）：与另一案件重复（不计入一致率）。
5. 不确定的案件先保持未关闭，补充评论；未关闭的案件不进入一致率。

## 8. 每日检查（值班负责人，约 5 分钟）

- 告警源：最近一次拉取时间、读取 / 新增数，没有持续错误；有「限流」告警表示告警量超出 Webhook 限流，评估是否调高。
- Webhook 调用记录：`failed` / `rejected` 是否异常。
- 试点报告（今天）：富化成功率、p95 时延、没有结论的案件数、`runs.active`（停在审批未处理的运行）。
- 停在审批的运行逐个驳回，避免堆积。
- 失败的运行：看是富化失败（CrowdStrike 401/403/429）、研判失败（执行器、未提交结构化输出）还是飞书失败。
- 前一天的案件是否都已由分析员关闭。

## 9. 试点报告

「告警与案件 → 试点报告」选日期范围（默认最近 14 天），可导出 CSV；也可调用：

```
GET /api/pilot-report?projectId=<项目>&from=2026-11-24&to=2026-12-07          # JSON
GET /api/pilot-report?projectId=<项目>&from=2026-11-24&to=2026-12-07&format=csv
```

`from` / `to` 接受 `YYYY-MM-DD`（`to` 含当天）或 RFC 3339，范围最长 92 天。
只有项目 Owner 和平台管理员可以查看；项目受限的 API Token 必须覆盖该项目。

| 指标 | 口径 |
|---|---|
| 告警（准入）`alerts.admitted` | 本项目 `receivedAt` 在范围内的告警，含重复告警 |
| 去重 `alerts.deduplicated` | 其中标记为重复的告警（命中未过期指纹，没有自己的运行） |
| 限流 `alerts.rateLimited` | 范围内状态为 `rate_limited` 的 Webhook 调用记录。调用记录每个 Webhook 只保留最近 200 条，`deliveriesComplete=false` 表示记录没覆盖到范围起点，此数为下限 |
| 运行 `runs.*` | 范围内创建、由本项目告警启动或关联本项目案件的运行；`active` 是仍在运行或停在审批的 |
| 连接器动作 `actions.*` | 案件时间线上范围内的 `case.action`（真正执行过的外部动作）按成功 / 失败统计。`overall` 含富化和通用（飞书），`enrichment` 只含富化（CrowdStrike 查询），`byConnector` 按连接器。**响应动作不计入成功率**，单列在 `responseExecuted`（影子模式下应为 0）；停在审批没执行的动作不产生记录 |
| 研判时延 `latency.*` | 范围内新建的案件：首次研判结论时间（`agentVerdictFirstAt`）减去该案件最早告警的接收时间（没有告警时用案件创建时间）。p50 / p95 为最近秩百分位，单位秒 |
| 一致率 `agreement.*` | 范围内新建且已关闭的案件。对照规则：`malicious` ↔ `resolved`；`benign`、`false_positive` ↔ `false_positive`；Agent 结论 `needs_review` 和关闭结论 `duplicate` 不计（`excluded`），没有 Agent 结论的已关闭案件也不计（矩阵里记为 `none`）。`rate = matched / (matched + mismatched)` |

报告只读，不改动任何数据；口径也随 JSON 响应的 `definitions` 一起返回。

## 10. 验收标准

全部满足才算试点通过：

1. 连续运行 **≥ 14 天**（报告范围覆盖整个试点期），期间没有超过 1 天的中断。
2. **富化成功率 ≥ 99%**（`actions.enrichment.rate`，且 `actions.enrichment.total` 有足够样本）。
3. **告警→研判结论 p95 ≤ 5 分钟**（`latency.p95Seconds ≤ 300`），`latency.withoutVerdict` 有合理解释（例如运行失败已复盘）。
4. **一致率已记录**：报告导出 CSV 归档，`agreement.matched + agreement.mismatched` 覆盖试点期大部分已关闭案件，混淆矩阵中的不一致案件逐个复盘。一致率的目标值由试点负责人在试点结束时确定，本手册不预设。
5. `actions.responseExecuted = 0`：影子模式期间没有任何响应动作被执行。

## 11. 停止与回滚

按影响从小到大：

1. **暂停告警**：在 Webhook 卡片上停用告警源（或停用 Webhook）。已有案件和报告保留。
2. **停止通知**：删除 Lark 连接，或在群里移除机器人 / 在开发者后台停用应用。
3. **停止研判**：停用 Webhook 后取消仍在运行的运行（运行页 → 取消）。停在审批的运行驳回即可。
4. **收回凭据**：删除 CrowdStrike / Splunk 连接，并在供应商侧吊销 API Client 和 Token。
5. **回滚版本**：回退镜像即可；`cases.agent_verdict*` 两列和 `generic_templates` 中
   `soc-shadow-pilot` 行对旧版本无影响，可保留。确需删除时：

   ```sql
   DELETE FROM generic_templates WHERE id = 'soc-shadow-pilot';
   ALTER TABLE cases DROP COLUMN agent_verdict, DROP COLUMN agent_verdict_at;
   ```

   （启用了 AutoMigrate 的新版本启动时会重新补列。）已复制到项目的 SOP 是副本，需在项目里单独删除。

## 12. 已知限制

- SOP 还没有对真实租户端到端跑过；连接器模板按公开文档编写，模板与校验有单元测试（httptest 假服务）。
- CrowdStrike 查告警只返回 ID 和总数，没有拉告警详情；需要详情时在研判前加一个「获取告警详情」节点（`get_alerts`，注意列表为空时要用执行条件跳过）。
- 告警字段原样进入 Agent 提示词（已要求 Agent 把它当数据）；Agent 没有任何响应权限，响应只能经审批节点执行。
- 每个限流都是单进程内存计数；多个 API 进程时按进程数折算。
- Webhook 调用记录只保留最近 200 条，限流计数可能是下限（报告里会标出）。
- 飞书卡片的颜色是固定值；不同结论用不同颜色需要拆成多个带执行条件的通知节点。
- 飞书通知依赖 PR #16（`lark` 连接器）；在它合入前 051 不应执行。

## 附录：本次试点实例

以下是本次试点实例已经建好的对象（凭据由管理员在连接里自行填写，本文不含任何密钥）。
告警源、Webhook 和 SOP 尚未创建，按第 5、6 节用本附录的 ID 创建。

| 对象 | ID / 值 | 用在 |
|---|---|---|
| 项目 | `shadow-pilot`（影子试点） | 复制 SOP、Webhook、告警源、试点报告的 `projectId` |
| Splunk 连接 | `cn-02c15adfa31a9004`（本地部署，已固定证书） | Splunk notable 告警源 |
| CrowdStrike 连接 | `cn-f7f5fc71aaa30908`（`api.us-2.crowdstrike.com`） | 「CrowdStrike 查终端」「CrowdStrike 查告警」「CrowdStrike 网络隔离」节点；可选的 Falcon 告警源 |
| Lark 连接 | `cn-01ec1c1553af74c9`（连接器 `lark`） | 「飞书通知 SOC」节点 |
| AbuseIPDB 连接 | `cn-f938c8824e2dc756` | 可选的 IP 富化（见下） |
| IPinfo 连接 | `cn-6f2a220c8a9c9c90` | 可选的 IP 富化（模板可能仍在另一分支改写，暂不依赖） |
| SOC 群 `chat_id` | `oc_abd46aec6f884973b8d83f658db70fb8` | 替换「飞书通知 SOC」节点的 `REPLACE_WITH_SOC_CHAT_ID`；审批通知也发到该群 |

通用模板里不写任何实例的连接 ID：复制到 `shadow-pilot` 后，在流程设计器里给每个动作节点
选上表的连接即可（节点字段 `action.connectionId`）。

**可选：CrowdStrike Falcon 告警源。** 如需同时把 Falcon 告警纳入试点，在同一个 Webhook
（或单独一个 Webhook）上按 [告警源 · CrowdStrike 预设](alert-sources.md#presets) 新建告警源，
连接选 `cn-f7f5fc71aaa30908`，附加 FQL 条件填产品过滤：

```
product:['epp','automated-lead','automated-lead-context','aidr','ngsiem']
```

（即产品 `epp,automated-lead,automated-lead-context,aidr,ngsiem`）。Falcon 告警的字段与 Splunk notable 不同：
Webhook 用标题字段 `display_name`、严重度字段 `severity_name`、去重字段 `composite_id`；
主机名在 `device.hostname`，需要把 SOP 里取主机的表达式改为
`coalesce(trigger.dest_nt_host, trigger.dest_host, trigger.dest, trigger.device.hostname)`（三处一致）。
两类告警进同一个项目时，试点报告按项目合并统计。

**可选：IP 富化。** 需要时在「提取 IOC」之后、「Agent 研判」之前加一个 AbuseIPDB 节点
（连接 `cn-f938c8824e2dc756`，IP 取 `{{ first(nodes.extract.data.ipv4) }}`，执行条件
`len(nodes.extract.data.ipv4) > 0`），并按第 1 节的分支方式让它与研判之间用成功 / 失败两条边相连、
研判节点保持 `join: any`，再在研判提示词里加 `{{node.<节点 ID>.data}}`。不加不影响验收。
