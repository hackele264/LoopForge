package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/expr"
)

// Conditional scheduling.
//
// An edge's outcome is derived from its source node's state on every pass,
// never stored, so a reject or retry that resets nodes to pending also resets
// every edge leaving them:
//
//	source succeeded              -> success edge taken, error edge dead
//	source failed + ErrorRouted   -> error edge taken, success edge dead
//	source skipped                -> every edge dead
//	anything else                 -> undecided
//
// A pending node with join "all" runs once every incoming edge is taken and is
// skipped as soon as one is dead; with join "any" it runs on the first taken
// edge and is skipped once all are dead. A node allowed to run then evaluates
// RunIf: false skips it, an evaluation error fails it.
//
// A workflow with only success edges, join "all" and no RunIf never skips a
// node, so these rules reduce exactly to the legacy "every upstream node
// succeeded" readiness.

type edgeOutcome int

const (
	edgeUndecided edgeOutcome = iota
	edgeTaken
	edgeDead
)

func edgeOutcomeOf(e domain.WorkflowEdge, source *domain.NodeRun) edgeOutcome {
	if source == nil {
		return edgeUndecided
	}
	when := domain.EdgeWhen(e)
	switch source.Status {
	case "succeeded":
		if when == domain.EdgeWhenSuccess {
			return edgeTaken
		}
		return edgeDead
	case domain.NodeStatusSkipped:
		return edgeDead
	case "failed":
		if !source.ErrorRouted {
			return edgeUndecided
		}
		if when == domain.EdgeWhenError {
			return edgeTaken
		}
		return edgeDead
	}
	return edgeUndecided
}

// gateState is what the incoming edges say about a pending node.
type gateState int

const (
	gateWait gateState = iota
	gateOpen
	gateClosed
)

func incomingGate(wf domain.WorkflowDefinition, r domain.Run, node domain.WorkflowNode, incoming []domain.WorkflowEdge) gateState {
	if len(incoming) == 0 {
		return gateOpen
	}
	taken, dead := 0, 0
	for _, e := range incoming {
		switch edgeOutcomeOf(e, r.Nodes[e.Source]) {
		case edgeTaken:
			taken++
		case edgeDead:
			dead++
		}
	}
	if domain.NodeJoin(node) == domain.JoinAny {
		switch {
		case taken > 0:
			return gateOpen
		case dead == len(incoming):
			return gateClosed
		}
		return gateWait
	}
	switch {
	case dead > 0:
		return gateClosed
	case taken == len(incoming):
		return gateOpen
	}
	return gateWait
}

func incomingEdges(wf domain.WorkflowDefinition) map[string][]domain.WorkflowEdge {
	out := map[string][]domain.WorkflowEdge{}
	for _, e := range wf.Edges {
		out[e.Target] = append(out[e.Target], e)
	}
	return out
}

func hasErrorEdge(wf domain.WorkflowDefinition, nodeID string) bool {
	for _, e := range wf.Edges {
		if e.Source == nodeID && domain.EdgeWhen(e) == domain.EdgeWhenError {
			return true
		}
	}
	return false
}

// conditionEnv builds the read-only values a RunIf expression can see.
func conditionEnv(r domain.Run) map[string]any {
	var trigger any
	if len(r.TriggerPayload) > 0 {
		_ = json.Unmarshal([]byte(r.TriggerPayload), &trigger)
	}
	nodes := map[string]any{}
	for id, nr := range r.Nodes {
		if nr == nil {
			continue
		}
		entry := map[string]any{"status": nr.Status}
		if len(nr.Data) > 0 {
			var data any
			if json.Unmarshal([]byte(nr.Data), &data) == nil {
				entry["data"] = data
			}
		}
		if nr.GateResult != nil {
			var gate any
			if raw, err := json.Marshal(nr.GateResult); err == nil && json.Unmarshal(raw, &gate) == nil {
				entry["gate"] = gate
			}
		}
		nodes[id] = entry
	}
	return map[string]any{
		"trigger": trigger,
		"nodes":   nodes,
		"run":     map[string]any{"id": r.ID, "input": r.Input, "caseId": r.ExecutionContext.CaseID, "projectId": r.ExecutionContext.ProjectID},
	}
}

// evalRunIf reports whether a node's condition holds. Empty conditions hold.
func evalRunIf(node domain.WorkflowNode, env func() map[string]any) (bool, error) {
	src := strings.TrimSpace(node.RunIf)
	if src == "" {
		return true, nil
	}
	program, err := expr.Compile(src)
	if err != nil {
		return false, err
	}
	return program.EvalBool(env())
}

// branchDecision is a state change settleBranches applies to a pending node.
type branchDecision struct {
	node   domain.WorkflowNode
	skip   string // skip reason, when the node is skipped
	condEr error  // RunIf evaluation error, when the node fails
}

// branchDecisions returns the pending nodes that must be skipped or failed
// on this pass, without changing the run.
func branchDecisions(wf domain.WorkflowDefinition, r domain.Run) []branchDecision {
	incoming := incomingEdges(wf)
	var envCache map[string]any
	env := func() map[string]any {
		if envCache == nil {
			envCache = conditionEnv(r)
		}
		return envCache
	}
	var out []branchDecision
	for _, n := range wf.Nodes {
		nr := r.Nodes[n.ID]
		if nr == nil || nr.Status != "pending" {
			continue
		}
		switch incomingGate(wf, r, n, incoming[n.ID]) {
		case gateClosed:
			out = append(out, branchDecision{node: n, skip: domain.SkipReasonBranchNotTaken})
		case gateOpen:
			ok, err := evalRunIf(n, env)
			if err != nil {
				out = append(out, branchDecision{node: n, condEr: err})
			} else if !ok {
				out = append(out, branchDecision{node: n, skip: domain.SkipReasonConditionFalse})
			}
		}
	}
	return out
}

// settleBranches applies skip and condition-failure decisions until none are
// left, so a whole untaken branch settles in one pass. It reports whether the
// run changed. Callers hold the run for writing (inside updateRun or under
// the run's state lock).
func settleBranches(wf domain.WorkflowDefinition, r *domain.Run) bool {
	changed := false
	for range len(wf.Nodes) + 1 {
		decisions := branchDecisions(wf, *r)
		if len(decisions) == 0 {
			break
		}
		now := time.Now().UTC()
		for _, d := range decisions {
			nr := r.Nodes[d.node.ID]
			nr.FinishedAt = now
			if d.condEr != nil {
				nr.Status = "failed"
				nr.Error = "执行条件求值失败：" + d.condEr.Error()
				nr.ErrorRouted = hasErrorEdge(wf, d.node.ID)
				appendRunEvent(r, d.node.ID, "node.failed", nr.Error)
				if nr.ErrorRouted {
					appendRunEvent(r, d.node.ID, "node.error_routed", "失败已交给错误分支处理")
				}
				continue
			}
			nr.Status = domain.NodeStatusSkipped
			nr.SkipReason = d.skip
			appendRunEvent(r, d.node.ID, "node.skipped", skipMessage(d))
		}
		changed = true
	}
	return changed
}

func skipMessage(d branchDecision) string {
	if d.skip == domain.SkipReasonConditionFalse {
		return fmt.Sprintf("执行条件不成立，已跳过：%s", strings.TrimSpace(d.node.RunIf))
	}
	return "上游分支未走到此节点，已跳过"
}

// appendRunEvent records a run event without an actor; it matches
// Engine.event for code paths that only hold the run.
func appendRunEvent(r *domain.Run, nodeID, eventType, message string) {
	r.Events = append(r.Events, domain.RunEvent{ID: fmt.Sprintf("evt-%d", time.Now().UnixNano()), RunID: r.ID, NodeID: nodeID, Type: eventType, Message: message, Timestamp: time.Now().UTC()})
}

// ConditionCheck is the outcome of a RunIf dry run.
type ConditionCheck struct {
	// Valid reports whether the expression compiles and, when a workflow node
	// was given, only reads that node's upstream.
	Valid bool `json:"valid"`
	// NodeRefs lists the node IDs the expression reads.
	NodeRefs []string `json:"nodeRefs"`
	// Result is the evaluated condition; set only when evaluation succeeded.
	Result *bool `json:"result,omitempty"`
	// Error explains a compile, reference or evaluation failure.
	Error string `json:"error,omitempty"`
	// Stage is where it failed: compile, reference or evaluate.
	Stage string `json:"stage,omitempty"`
}

// CheckCondition compiles a RunIf expression and evaluates it against sample
// data shaped like a run, using the same environment the scheduler builds.
// With wf and nodeID set it also checks the expression only reads nodes
// upstream of nodeID, as saving the workflow would.
func CheckCondition(src string, sample domain.Run, wf *domain.WorkflowDefinition, nodeID string) ConditionCheck {
	program, err := expr.Compile(src)
	if err != nil {
		return ConditionCheck{NodeRefs: []string{}, Error: err.Error(), Stage: "compile"}
	}
	check := ConditionCheck{Valid: true, NodeRefs: program.NodeRefs()}
	if check.NodeRefs == nil {
		check.NodeRefs = []string{}
	}
	if wf != nil && strings.TrimSpace(nodeID) != "" {
		up := domain.UpstreamNodes(*wf, nodeID)
		for _, ref := range check.NodeRefs {
			if !up[ref] {
				check.Valid = false
				check.Stage = "reference"
				check.Error = fmt.Sprintf("node %q is not upstream of %q", ref, nodeID)
				return check
			}
		}
	}
	result, err := program.EvalBool(conditionEnv(sample))
	if err != nil {
		check.Stage = "evaluate"
		check.Error = err.Error()
		return check
	}
	check.Result = &result
	return check
}
