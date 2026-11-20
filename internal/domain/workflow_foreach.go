package domain

import (
	"fmt"
	"strings"

	"agentflow/internal/expr"
)

// List loops on action nodes. WorkflowNode.ForEach is an expression over the
// run (trigger, nodes, run) that yields a list; the node then runs its
// connector action once per element, with the element readable as `item`
// (and its zero-based position as `index`) in the action's input templates.
const (
	// ForEachDefaultConcurrency is how many items run at once when
	// ForEachConcurrency is unset; ForEachMaxConcurrency caps it.
	ForEachDefaultConcurrency = 4
	ForEachMaxConcurrency     = 16
	// ForEachDefaultLimit is the item cap when ForEachLimit is unset;
	// ForEachMaxLimit caps it. A list longer than the cap fails the node
	// before any item runs, so nothing is silently left out.
	ForEachDefaultLimit = 100
	ForEachMaxLimit     = 1000

	// ForEachFailOnAny (default) fails the node when any item fails;
	// ForEachFailOnAll only when every item fails. Either way every item
	// runs and the per-item results are published as the node's data.
	ForEachFailOnAny = "any"
	ForEachFailOnAll = "all"
)

// ForEachRoots are the names a looping action node's input templates may
// read: the workflow roots plus the current `item` and its `index`.
var ForEachRoots = func() map[string]bool {
	out := map[string]bool{"item": true, "index": true}
	for k, v := range expr.Roots {
		out[k] = v
	}
	return out
}()

// HasForEach reports whether the node loops over a list.
func (n WorkflowNode) HasForEach() bool { return strings.TrimSpace(n.ForEach) != "" }

// ForEachConcurrencyOf returns the node's effective item concurrency.
func ForEachConcurrencyOf(n WorkflowNode) int {
	switch {
	case n.ForEachConcurrency <= 0:
		return ForEachDefaultConcurrency
	case n.ForEachConcurrency > ForEachMaxConcurrency:
		return ForEachMaxConcurrency
	}
	return n.ForEachConcurrency
}

// ForEachLimitOf returns the node's effective item cap.
func ForEachLimitOf(n WorkflowNode) int {
	switch {
	case n.ForEachLimit <= 0:
		return ForEachDefaultLimit
	case n.ForEachLimit > ForEachMaxLimit:
		return ForEachMaxLimit
	}
	return n.ForEachLimit
}

// ForEachFailOnOf returns the node's normalised failure policy.
func ForEachFailOnOf(n WorkflowNode) string {
	if strings.EqualFold(strings.TrimSpace(n.ForEachFailOn), ForEachFailOnAll) {
		return ForEachFailOnAll
	}
	return ForEachFailOnAny
}

// ValidateWorkflowForEach checks the list-loop fields: they belong to action
// nodes, the list expression compiles and reads only upstream nodes, and the
// concurrency, limit and failure policy are in range. Settings without a
// forEach expression are refused so a stale value never looks active.
func ValidateWorkflowForEach(wf WorkflowDefinition) error {
	for _, n := range wf.Nodes {
		if !n.HasForEach() {
			if n.ForEachConcurrency != 0 || n.ForEachLimit != 0 || strings.TrimSpace(n.ForEachFailOn) != "" {
				return fmt.Errorf("node %s: forEachConcurrency, forEachLimit and forEachFailOn need forEach", n.ID)
			}
			continue
		}
		if n.Type != "action" {
			return fmt.Errorf("node %s: forEach applies to action nodes only", n.ID)
		}
		program, err := expr.Compile(n.ForEach)
		if err != nil {
			return fmt.Errorf("node %s forEach: %v", n.ID, err)
		}
		up := UpstreamNodes(wf, n.ID)
		for _, ref := range program.NodeRefs() {
			if !up[ref] {
				return fmt.Errorf("node %s forEach reads node %q, which is not upstream of it", n.ID, ref)
			}
		}
		if n.ForEachConcurrency < 0 || n.ForEachConcurrency > ForEachMaxConcurrency {
			return fmt.Errorf("node %s: forEachConcurrency must be between 1 and %d", n.ID, ForEachMaxConcurrency)
		}
		if n.ForEachLimit < 0 || n.ForEachLimit > ForEachMaxLimit {
			return fmt.Errorf("node %s: forEachLimit must be between 1 and %d", n.ID, ForEachMaxLimit)
		}
		if f := strings.TrimSpace(n.ForEachFailOn); f != "" && !strings.EqualFold(f, ForEachFailOnAny) && !strings.EqualFold(f, ForEachFailOnAll) {
			return fmt.Errorf("node %s has unsupported forEachFailOn %q", n.ID, n.ForEachFailOn)
		}
	}
	return nil
}
