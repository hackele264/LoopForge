package connector

import (
	"fmt"

	"agentflow/internal/domain"
)

// NodeInputRoots returns the names an action node's input templates may
// read: the workflow roots, plus `item` and `index` when the node loops.
func NodeInputRoots(n domain.WorkflowNode) map[string]bool {
	if n.HasForEach() {
		return domain.ForEachRoots
	}
	return WorkflowRoots
}

// CheckNodeInputsFor compiles an action node's input templates with the
// roots its forEach setting allows.
func CheckNodeInputsFor(n domain.WorkflowNode) error {
	if n.Action == nil {
		return nil
	}
	roots := NodeInputRoots(n)
	for name, src := range n.Action.Inputs {
		if err := checkTemplate(src, roots); err != nil {
			return fmt.Errorf("input %s: %w", name, err)
		}
	}
	return nil
}

// EvalLoopInputs renders a looping action node's inputs for one item: env
// is the run environment, extended with `item` and `index`.
func EvalLoopInputs(inputs map[string]string, env map[string]any, item any, index int) (map[string]any, error) {
	scoped := make(map[string]any, len(env)+2)
	for k, v := range env {
		scoped[k] = v
	}
	scoped["item"] = item
	scoped["index"] = float64(index)
	return evalNodeInputs(inputs, domain.ForEachRoots, scoped)
}
