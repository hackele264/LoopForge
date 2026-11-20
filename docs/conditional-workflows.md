# Conditional workflows and named approvals

SOP workflows can branch on data, hand failures to error branches and require
named approvers. Every field below is optional: a workflow that sets none of
them runs exactly as before.

## Workflow fields

| Field | Where | Meaning |
|---|---|---|
| `runIf` | node | Boolean expression. The node runs only when it holds; otherwise it is `skipped`. |
| `join` | node | `all` (default): every incoming edge must be taken. `any`: the first taken edge starts the node. |
| `when: "error"` | edge | Taken when the source node fails for good (no retries or rework left). |
| `outputSchema` | node | JSON Schema for the node's structured output (`NodeRun.data`). |
| `approvers` | approval node | `{"userIds": [..], "roles": ["owner" \| "maintainer" \| "member" \| "admin"]}` |

Validation runs when a workflow is saved and when a run starts: expressions
must compile and may only read nodes upstream of the node they guard.

## How branches settle

An edge's outcome comes from its source node:

| Source node | `success` edge | `error` edge |
|---|---|---|
| `succeeded` | taken | dead |
| `failed`, handled by an error edge | dead | taken |
| `skipped` | dead | dead |
| anything else | undecided | undecided |

With `join: all` a node is skipped as soon as one incoming edge is dead; with
`join: any` once all are dead. Skips propagate down a branch in one pass and
each skipped node records `skipReason` (`condition_false` or
`branch_not_taken`) and a `node.skipped` event.

A node's final failure goes, in order, to: an automatic retry, a reject to
`rejectTo`, its error edges (marking `errorRouted: true`), and only then fails
the run. A run whose nodes all succeeded, were skipped or had their failure
routed ends as `succeeded`.

Rejecting, retrying or rerunning resets nodes to `pending` and clears
`data`, `skipReason`, `errorRouted` and `decidedBy`; branches are re-derived.

## Expressions

Expressions read three roots and have no side effects:

- `trigger`: the run's trigger payload.
- `nodes["<id>"]` or `nodes.<id>`: `.status`, `.data` (structured output) and
  `.gate` (an agent's submitted gate result).
- `run`: `.id`, `.input`, `.caseId` and `.projectId`.

Operators: `== != < <= > >= in && || !`, unary `-`, list literals `[..]`.
Functions: `len`, `lower`, `upper`, `contains`, `startsWith`, `endsWith`,
`exists`, plus `iocs`, `first`, `join`, `split`, `coalesce`, `str` and
`base64url` (see [connectors](connectors.md#inputs-and-outputs)). A missing field reads as `null`; ordering against `null` is false.
An evaluation error (for example comparing a number with a string) fails the
node, which an error edge can handle.

```text
nodes.triage.data.verdict == "malicious" && nodes.triage.data.confidence >= 0.8
trigger.severity in ["high", "critical"]
```

## Trigger payloads and script output

`POST /api/runs` accepts an optional `trigger` JSON object (up to 1 MiB).
Child SOP runs inherit their parent's trigger.

When a run uses any of the features above, local script nodes get two
environment variables:

- `LOOPFORGE_TRIGGER`: path of the trigger payload file (absent without one).
- `LOOPFORGE_OUTPUT`: where the script may write a JSON object (up to 64 KiB).

After the script succeeds the engine validates the file against
`outputSchema` and stores it as the node's `data`. A node with a schema must
write the file. The schema check covers `type`, `required`, `properties`,
`items` and `enum`; other keywords are ignored. Scripts dispatched to a
connected execution machine do not get structured output yet.

Agent nodes with an `outputSchema` get a `submit_output` tool from the same
gate MCP server that provides `submit_gate_result`; its input schema is the
node's `outputSchema`. The tool validates the object, rejects it without
writing when it does not match (so the agent can fix and resubmit), and
accepts it only once. `submit_gate_result` with `pass` is refused until
`submit_output` has succeeded; `rework`, `fail` and `human` need no output.
The engine validates the file again before marking the node succeeded and
fails the node if it is missing. The output file travels back from connected
execution machines like the gate result does, but that path has only been
covered by unit-level wiring, not an end-to-end run. The mock executor
writes the value of an `[[mock:output={...}]]` prompt directive.

## Named approvals

Approve, reject and pass record who acted: `decidedBy`/`decidedAt` on the node,
`actorUserId`/`actorKind` on the event (`user`, `bot` or `service`), and the
approver in the gate's `decision.md`. `run_events.actor_user_id` is indexed.

A gate with `approvers` accepts only the users it names; service tokens without
a user are always refused. Set `AGENTFLOW_APPROVAL_REQUIRE_NAMED=true` to make
every gate refuse service callers.

## In the designer

- Every node except preview builds has three outlets: 成功 (success edge),
  失败分支 (error edge, orange) and 失败打回 (reject route, dashed red).
- The node drawer's 执行条件 section edits `runIf`, shows which upstream nodes
  the condition may read and flags mistakes as you type; nodes with two or
  more inputs also get the join choice. 试运行条件 evaluates the condition
  through `POST /api/workflow-conditions/check` against a sample trigger and
  sample upstream results, prefilled from the upstream nodes' output schemas. Script nodes add an output schema
  editor, and approval nodes a 谁可以确认 picker (roles plus user IDs).
- Nodes show their condition, join and approvers as tags. 配置检查 warns
  about invalid conditions, conditions that read nodes without an output
  schema, `join: any` with a single input, join-all nodes that merge
  mutually exclusive branches, and nodes with both reject and error routes.
- The run page shows skipped nodes dashed, and the node panel lists the skip
  reason, routed failures, the deciding user and the structured output.

## Database

`runs.trigger_payload` and `run_events.actor_user_id` are added by gorm's
incremental AutoMigrate; `migrations/039_conditional_workflows.sql` is the
manual equivalent.
