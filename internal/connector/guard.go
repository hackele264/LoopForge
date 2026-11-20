package connector

import (
	"fmt"
	"strings"

	"agentflow/internal/domain"
)

// NodeType is the workflow node type of action nodes.
const NodeType = "action"

// ValidateWorkflow checks a workflow's action nodes against the catalog:
// the action exists, inputs are known and compile, templates only read
// upstream nodes, and every response action is gated by an approval.
func ValidateWorkflow(wf domain.WorkflowDefinition, cat *Catalog) error {
	for _, n := range wf.Nodes {
		if n.Type != NodeType {
			if n.Action != nil {
				return fmt.Errorf("node %s: action applies to action nodes only", n.ID)
			}
			continue
		}
		if err := validateActionNode(wf, n, cat); err != nil {
			return fmt.Errorf("node %s: %w", n.ID, err)
		}
	}
	return nil
}

func validateActionNode(wf domain.WorkflowDefinition, n domain.WorkflowNode, cat *Catalog) error {
	if n.Action == nil || strings.TrimSpace(n.Action.Connector) == "" || strings.TrimSpace(n.Action.Action) == "" {
		return fmt.Errorf("action node needs a connector action")
	}
	c, a, ok := cat.Action(n.Action.Connector, n.Action.Action)
	if !ok {
		return fmt.Errorf("unknown connector action %s", Key(n.Action.Connector, n.Action.Action))
	}
	if c.Builtin && strings.TrimSpace(n.Action.ConnectionID) != "" {
		return fmt.Errorf("built-in actions take no connection")
	}
	for name := range n.Action.Inputs {
		if _, ok := a.Input(name); !ok {
			return fmt.Errorf("action %s has no input %q", Key(c.ID, a.ID), name)
		}
	}
	for _, in := range a.Inputs {
		if in.Required && in.Default == nil && strings.TrimSpace(n.Action.Inputs[in.Name]) == "" {
			return fmt.Errorf("input %s is required", in.Name)
		}
	}
	if err := CheckNodeInputs(n.Action.Inputs); err != nil {
		return err
	}
	up := domain.UpstreamNodes(wf, n.ID)
	for _, ref := range NodeInputRefs(n.Action.Inputs) {
		if !up[ref] {
			return fmt.Errorf("inputs read node %q, which is not upstream", ref)
		}
	}
	if a.Category == CategoryResponse && !GatedByApproval(wf, n.ID) {
		return fmt.Errorf("response action %s must come after an approval node on every path", a.Title)
	}
	return nil
}

// GatedByApproval reports whether every path from a start node to nodeID
// leaves an approval node through a success edge. A path that enters
// nodeID through an approval's error edge (a rejected approval) is not
// gated.
func GatedByApproval(wf domain.WorkflowDefinition, nodeID string) bool {
	byID := map[string]domain.WorkflowNode{}
	incoming := map[string]int{}
	for _, n := range wf.Nodes {
		byID[n.ID] = n
	}
	out := map[string][]domain.WorkflowEdge{}
	for _, e := range wf.Edges {
		out[e.Source] = append(out[e.Source], e)
		incoming[e.Target]++
	}
	// Walk from every start node without crossing an approval's success
	// edge; reaching nodeID means some path bypasses every approval.
	seen := map[string]bool{}
	var stack []string
	for _, n := range wf.Nodes {
		if incoming[n.ID] == 0 {
			stack = append(stack, n.ID)
		}
	}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		if id == nodeID {
			return false
		}
		for _, e := range out[id] {
			if byID[id].Type == "approval" && domain.EdgeWhen(e) == domain.EdgeWhenSuccess {
				continue
			}
			stack = append(stack, e.Target)
		}
	}
	return true
}
