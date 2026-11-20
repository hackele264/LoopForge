package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
)

// executeActionNode runs a connector action in the platform process: no
// sandbox, no execution machine. Its result becomes the node's structured
// output (nodes.<id>.data) for downstream conditions and inputs.
func (e *Engine) executeActionNode(ctx context.Context, runID string, wf domain.WorkflowDefinition, node domain.WorkflowNode, attempt, generation int) {
	fail := func(err error) {
		if err == nil || ctx.Err() != nil {
			return
		}
		e.nodeFailedAt(runID, node, attempt, generation, err, nodeRejects(node))
	}
	run, ok := e.repo.RunState(runID)
	if !ok {
		fail(errors.New("run disappeared"))
		return
	}
	if node.Action == nil {
		fail(errors.New("动作节点没有选择动作"))
		return
	}
	c, a, ok := connector.Default().Action(node.Action.Connector, node.Action.Action)
	if !ok {
		fail(fmt.Errorf("连接器动作 %s 不存在", connector.Key(node.Action.Connector, node.Action.Action)))
		return
	}
	// The save-time check also runs here because the run snapshot may come
	// from a workflow saved before the check existed.
	if a.Category == connector.CategoryResponse && !connector.GatedByApproval(wf, node.ID) {
		fail(fmt.Errorf("响应动作「%s」前必须有人工审批", a.Title))
		return
	}
	var conn *domain.Connection
	if !c.Builtin {
		id := strings.TrimSpace(node.Action.ConnectionID)
		if id == "" {
			fail(fmt.Errorf("动作「%s」没有选择连接", a.Title))
			return
		}
		found, ok := e.repo.Connection(id)
		if !ok {
			fail(fmt.Errorf("连接 %s 不存在", id))
			return
		}
		if found.ProjectID != run.ExecutionContext.ProjectID {
			fail(fmt.Errorf("连接「%s」不属于本运行所在的项目", found.Name))
			return
		}
		conn = &found
	}
	inputs, err := connector.EvalNodeInputs(node.Action.Inputs, conditionEnv(run))
	if err != nil {
		fail(err)
		return
	}
	label := c.Title + " · " + a.Title
	e.updateRun(runID, func(r *domain.Run) {
		if nr := r.Nodes[node.ID]; nr != nil {
			nr.Activity = "正在执行动作 " + label
		}
	})
	started := time.Now()
	result, execErr := e.actions.Execute(ctx, connector.Call{
		Connector: c, Action: a, Connection: conn, Inputs: inputs,
		Run: connector.RunContext{RunID: run.ID, NodeID: node.ID, ProjectID: run.ExecutionContext.ProjectID, CaseID: run.ExecutionContext.CaseID, UserID: run.ExecutionContext.ResponsibleUserID},
	})
	if ctx.Err() != nil {
		return
	}
	attrs := map[string]any{"connector": c.ID, "action": a.ID, "category": a.Category, "durationMs": time.Since(started).Milliseconds()}
	if conn != nil {
		attrs["connectionId"] = conn.ID
	}
	if !c.Builtin {
		e.recordCaseAction(run, node, c, a, conn, result, execErr)
		e.auditConnectorAction(run, node, c, a, conn, execErr)
	}
	if execErr != nil {
		e.observe(runID, node.ID, domain.TelemetryEvent{Category: "connector", Name: "connector.action.failed", Phase: "finish", Level: "error", Message: label + "：" + execErr.Error(), Attributes: attrs})
		fail(execErr)
		return
	}
	data, err := json.Marshal(result.Output)
	if err != nil {
		fail(err)
		return
	}
	e.observe(runID, node.ID, domain.TelemetryEvent{Category: "connector", Name: "connector.action.succeeded", Phase: "finish", Message: result.Summary, Attributes: attrs})
	e.updateRun(runID, func(r *domain.Run) {
		nr := r.Nodes[node.ID]
		if !shouldCommitNodeOutcome(*r, nr, generation, attempt, true) {
			return
		}
		nr.Data = domain.RawJSON(data)
		nr.Output = result.Summary
		nr.Error = ""
		nr.Activity = ""
		nr.Status = "succeeded"
		nr.FinishedAt = time.Now().UTC()
		e.event(r, node.ID, "node.succeeded", node.Name+"："+result.Summary)
	})
}

// recordCaseAction puts an external action on the timeline of the run's
// case, so the case shows what was done to which system and by which run.
func (e *Engine) recordCaseAction(run domain.Run, node domain.WorkflowNode, c *connector.Connector, a *connector.Action, conn *domain.Connection, result connector.Result, execErr error) {
	caseID := strings.TrimSpace(run.ExecutionContext.CaseID)
	if caseID == "" {
		return
	}
	via := ""
	if conn != nil {
		via = "，连接「" + conn.Name + "」"
	}
	message := fmt.Sprintf("动作「%s · %s」成功（HTTP %v%s）", c.Title, a.Title, result.Output["status"], via)
	if execErr != nil {
		detail := execErr.Error()
		if len([]rune(detail)) > 500 {
			detail = string([]rune(detail)[:500]) + "…"
		}
		message = fmt.Sprintf("动作「%s · %s」失败：%s", c.Title, a.Title, detail)
	}
	data := map[string]any{"runId": run.ID, "nodeId": node.ID, "connector": c.ID, "action": a.ID, "category": a.Category, "ok": execErr == nil}
	if conn != nil {
		data["connectionId"] = conn.ID
		data["connection"] = conn.Name
	}
	raw, _ := json.Marshal(data)
	ev := domain.CaseEvent{
		Type:      domain.CaseEventAction,
		Message:   message,
		ActorKind: domain.ActorSystem,
		Data:      domain.RawJSON(raw),
		CreatedAt: time.Now().UTC(),
	}
	if err := e.repo.AppendCaseEvents(caseID, ev); err != nil {
		e.observe(run.ID, node.ID, domain.TelemetryEvent{Category: "connector", Name: "case.action.record_failed", Level: "warn", Message: err.Error()})
	}
}

// recordCaseDecision puts a human approval or rejection of a case run's
// node on the case timeline, attributed to the person who decided.
func (e *Engine) recordCaseDecision(run domain.Run, nodeID, verb, note string, actor domain.Actor) {
	caseID := strings.TrimSpace(run.ExecutionContext.CaseID)
	if caseID == "" {
		return
	}
	name := nodeID
	for _, n := range run.WorkflowSnapshot.Nodes {
		if n.ID == nodeID && strings.TrimSpace(n.Name) != "" {
			name = n.Name
		}
	}
	message := fmt.Sprintf("%s了「%s」", verb, name)
	if note = strings.TrimSpace(note); note != "" {
		if len([]rune(note)) > 500 {
			note = string([]rune(note)[:500]) + "…"
		}
		message += "：" + note
	}
	raw, _ := json.Marshal(map[string]any{"runId": run.ID, "nodeId": nodeID})
	ev := domain.CaseEvent{Type: domain.CaseEventApproval, Message: message, ActorUserID: actor.UserID, ActorKind: actor.Kind, Data: domain.RawJSON(raw), CreatedAt: time.Now().UTC()}
	if err := e.repo.AppendCaseEvents(caseID, ev); err != nil {
		e.observe(run.ID, nodeID, domain.TelemetryEvent{Category: "orchestration", Name: "case.approval.record_failed", Level: "warn", Message: err.Error()})
	}
}

// auditConnectorAction records a call that used a connection's credentials
// in the platform audit log.
func (e *Engine) auditConnectorAction(run domain.Run, node domain.WorkflowNode, c *connector.Connector, a *connector.Action, conn *domain.Connection, execErr error) {
	detail := map[string]any{"runId": run.ID, "nodeId": node.ID, "connector": c.ID, "action": a.ID, "category": a.Category, "caseId": run.ExecutionContext.CaseID}
	ev := domain.AuditEvent{Action: "connector.action", ActorKind: domain.ActorSystem, ActorUserID: run.ExecutionContext.ResponsibleUserID, ProjectID: run.ExecutionContext.ProjectID, Target: connector.Key(c.ID, a.ID), Outcome: domain.AuditSuccess}
	if conn != nil {
		detail["connectionId"] = conn.ID
		detail["connection"] = conn.Name
	}
	if execErr != nil {
		ev.Outcome = domain.AuditFailure
		msg := execErr.Error()
		if len([]rune(msg)) > 300 {
			msg = string([]rune(msg)[:300]) + "…"
		}
		detail["error"] = msg
	}
	if raw, err := json.Marshal(detail); err == nil {
		ev.Detail = domain.RawJSON(raw)
	}
	if err := e.repo.AppendAudit(ev); err != nil {
		e.observe(run.ID, node.ID, domain.TelemetryEvent{Category: "connector", Name: "audit.record_failed", Level: "warn", Message: err.Error()})
	}
}
