package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/expr"
)

// maxForEachDataBytes bounds the structured output of a looping action
// node. Larger results are shrunk step by step (see boundForEachData).
const maxForEachDataBytes = 256 << 10

// forEachItemResult is one entry of a looping node's results, in input order.
type forEachItemResult struct {
	Index  int            `json:"index"`
	Item   any            `json:"item"`
	OK     bool           `json:"ok"`
	Output map[string]any `json:"output,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// forEachData is a looping action node's structured output (nodes.<id>.data).
type forEachData struct {
	Total     int                 `json:"total"`
	Succeeded int                 `json:"succeeded"`
	Failed    int                 `json:"failed"`
	Results   []forEachItemResult `json:"results"`
	// Truncated names what was dropped to fit maxForEachDataBytes:
	// "bodies" (raw response bodies), "outputs" (every item output) or
	// "items" (outputs and item values; errors shortened).
	Truncated string `json:"truncated,omitempty"`
}

// evalForEachItems evaluates a node's forEach expression. A null result is
// an empty list; anything else that is not a list is an error.
func evalForEachItems(node domain.WorkflowNode, env map[string]any) ([]any, error) {
	program, err := expr.Compile(node.ForEach)
	if err != nil {
		return nil, fmt.Errorf("forEach：%w", err)
	}
	v, err := program.Eval(env)
	if err != nil {
		return nil, fmt.Errorf("forEach：%w", err)
	}
	switch list := v.(type) {
	case nil:
		return nil, nil
	case []any:
		return list, nil
	}
	return nil, fmt.Errorf("forEach 必须得到列表，实际得到 %s", jsonTypeName(v))
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case bool:
		return "布尔值"
	case float64:
		return "数字"
	case string:
		return "文本"
	case map[string]any:
		return "对象"
	}
	return fmt.Sprintf("%T", v)
}

// executeActionForEach runs a looping action node: the connector action once
// per item, at most ForEachConcurrencyOf(node) at a time. One item failing
// does not stop the others; the node's outcome follows forEachFailOn. A
// cancelled run stops starting new items and commits nothing.
func (e *Engine) executeActionForEach(ctx context.Context, runID string, run domain.Run, node domain.WorkflowNode, c *connector.Connector, a *connector.Action, conn *domain.Connection, attempt, generation int, fail func(error)) {
	env := conditionEnv(run)
	items, err := evalForEachItems(node, env)
	if err != nil {
		fail(err)
		return
	}
	if limit := domain.ForEachLimitOf(node); len(items) > limit {
		fail(fmt.Errorf("forEach 得到 %d 项，超过上限 %d（forEachLimit，最大 %d）", len(items), limit, domain.ForEachMaxLimit))
		return
	}
	label := c.Title + " · " + a.Title
	total := len(items)
	e.updateRun(runID, func(r *domain.Run) {
		if nr := r.Nodes[node.ID]; nr != nil {
			nr.Activity = fmt.Sprintf("正在对 %d 项执行动作 %s", total, label)
		}
	})
	started := time.Now()
	results := make([]forEachItemResult, total)
	var (
		mu         sync.Mutex
		done       int
		lastReport time.Time
		wg         sync.WaitGroup
	)
	report := func() {
		mu.Lock()
		done++
		n := done
		due := n == total || time.Since(lastReport) >= 500*time.Millisecond
		if due {
			lastReport = time.Now()
		}
		mu.Unlock()
		if !due || ctx.Err() != nil {
			return
		}
		e.updateRun(runID, func(r *domain.Run) {
			if nr := r.Nodes[node.ID]; nr != nil && nr.Status == "running" {
				nr.Activity = fmt.Sprintf("正在执行动作 %s（%d/%d）", label, n, total)
			}
		})
	}
	sem := make(chan struct{}, min(domain.ForEachConcurrencyOf(node), max(1, total)))
loop:
	for i, item := range items {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		if ctx.Err() != nil {
			<-sem
			break
		}
		wg.Add(1)
		go func(i int, item any) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = e.runForEachItem(ctx, run, node, c, a, conn, env, i, item)
			report()
		}(i, item)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	data := forEachData{Total: total, Results: results}
	var firstErr string
	for _, r := range results {
		if r.OK {
			data.Succeeded++
		} else {
			data.Failed++
			if firstErr == "" {
				firstErr = fmt.Sprintf("第 %d 项：%s", r.Index+1, r.Error)
			}
		}
	}
	raw, err := boundForEachData(&data)
	if err != nil {
		fail(err)
		return
	}
	summary := fmt.Sprintf("%s：%d 项，成功 %d，失败 %d", label, data.Total, data.Succeeded, data.Failed)
	attrs := map[string]any{"connector": c.ID, "action": a.ID, "category": a.Category, "durationMs": time.Since(started).Milliseconds(),
		"forEachTotal": data.Total, "forEachSucceeded": data.Succeeded, "forEachFailed": data.Failed}
	if conn != nil {
		attrs["connectionId"] = conn.ID
	}
	if !c.Builtin && total > 0 {
		e.recordCaseForEach(run, node, c, a, conn, data)
	}
	failed := data.Failed > 0 && (domain.ForEachFailOnOf(node) == domain.ForEachFailOnAny || data.Failed == data.Total)
	if failed {
		e.observe(runID, node.ID, domain.TelemetryEvent{Category: "connector", Name: "connector.action.failed", Phase: "finish", Level: "error", Message: summary, Attributes: attrs})
		// Publish the per-item results before failing, so an error branch
		// can read which items failed.
		e.updateRun(runID, func(r *domain.Run) {
			nr := r.Nodes[node.ID]
			if !shouldCommitNodeOutcome(*r, nr, generation, attempt, false) {
				return
			}
			nr.Data = domain.RawJSON(raw)
			nr.Output = summary
		})
		fail(fmt.Errorf("%d 项中 %d 项失败，%s", data.Total, data.Failed, firstErr))
		return
	}
	e.observe(runID, node.ID, domain.TelemetryEvent{Category: "connector", Name: "connector.action.succeeded", Phase: "finish", Message: summary, Attributes: attrs})
	e.updateRun(runID, func(r *domain.Run) {
		nr := r.Nodes[node.ID]
		if !shouldCommitNodeOutcome(*r, nr, generation, attempt, true) {
			return
		}
		nr.Data = domain.RawJSON(raw)
		nr.Output = summary
		nr.Error = ""
		nr.Activity = ""
		nr.Status = "succeeded"
		nr.FinishedAt = time.Now().UTC()
		e.event(r, node.ID, "node.succeeded", node.Name+"："+summary)
	})
}

// runForEachItem renders the inputs for one item and runs the action.
func (e *Engine) runForEachItem(ctx context.Context, run domain.Run, node domain.WorkflowNode, c *connector.Connector, a *connector.Action, conn *domain.Connection, env map[string]any, index int, item any) forEachItemResult {
	out := forEachItemResult{Index: index, Item: item}
	inputs, err := connector.EvalLoopInputs(node.Action.Inputs, env, item, index)
	if err != nil {
		out.Error = shortError(err.Error(), 500)
		return out
	}
	result, execErr := e.actions.Execute(ctx, connector.Call{
		Connector: c, Action: a, Connection: conn, Inputs: inputs,
		Run: connector.RunContext{RunID: run.ID, NodeID: node.ID, ProjectID: run.ExecutionContext.ProjectID, CaseID: run.ExecutionContext.CaseID, UserID: run.ExecutionContext.ResponsibleUserID},
	})
	if ctx.Err() != nil {
		out.Error = "运行已取消"
		return out
	}
	if !c.Builtin {
		e.auditConnectorAction(run, node, c, a, conn, execErr)
	}
	if execErr != nil {
		out.Error = shortError(execErr.Error(), 500)
		return out
	}
	out.OK = true
	out.Output = result.Output
	return out
}

func shortError(s string, limit int) string {
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}

// boundForEachData marshals data, shrinking it until it fits
// maxForEachDataBytes: first raw response bodies go, then item outputs,
// then item values (errors shortened). Counts are always kept.
func boundForEachData(data *forEachData) ([]byte, error) {
	raw, err := json.Marshal(data)
	if err != nil || len(raw) <= maxForEachDataBytes {
		return raw, err
	}
	for i := range data.Results {
		if out := data.Results[i].Output; out != nil {
			if _, ok := out["body"]; ok {
				out["body"] = nil
				out["bodyTruncated"] = true
			}
		}
	}
	data.Truncated = "bodies"
	if raw, err = json.Marshal(data); err != nil || len(raw) <= maxForEachDataBytes {
		return raw, err
	}
	for i := range data.Results {
		data.Results[i].Output = nil
	}
	data.Truncated = "outputs"
	if raw, err = json.Marshal(data); err != nil || len(raw) <= maxForEachDataBytes {
		return raw, err
	}
	for i := range data.Results {
		data.Results[i].Item = nil
		data.Results[i].Error = shortError(data.Results[i].Error, 120)
	}
	data.Truncated = "items"
	return json.Marshal(data)
}

// recordCaseForEach puts one summary of a looping external action on the
// run's case timeline, instead of one entry per item.
func (e *Engine) recordCaseForEach(run domain.Run, node domain.WorkflowNode, c *connector.Connector, a *connector.Action, conn *domain.Connection, data forEachData) {
	caseID := strings.TrimSpace(run.ExecutionContext.CaseID)
	if caseID == "" {
		return
	}
	via := ""
	if conn != nil {
		via = "，连接「" + conn.Name + "」"
	}
	message := fmt.Sprintf("动作「%s · %s」逐项执行 %d 项：成功 %d，失败 %d%s", c.Title, a.Title, data.Total, data.Succeeded, data.Failed, via)
	info := map[string]any{"runId": run.ID, "nodeId": node.ID, "connector": c.ID, "action": a.ID, "category": a.Category, "ok": data.Failed == 0,
		"total": data.Total, "succeeded": data.Succeeded, "failed": data.Failed}
	if conn != nil {
		info["connectionId"] = conn.ID
		info["connection"] = conn.Name
	}
	raw, _ := json.Marshal(info)
	ev := domain.CaseEvent{Type: domain.CaseEventAction, Message: message, ActorKind: domain.ActorSystem, Data: domain.RawJSON(raw), CreatedAt: time.Now().UTC()}
	if err := e.repo.AppendCaseEvents(caseID, ev); err != nil {
		e.observe(run.ID, node.ID, domain.TelemetryEvent{Category: "connector", Name: "case.action.record_failed", Level: "warn", Message: err.Error()})
	}
}
