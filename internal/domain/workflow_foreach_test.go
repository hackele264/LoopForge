package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateWorkflowForEach(t *testing.T) {
	base := func(mutate func(*WorkflowNode)) WorkflowDefinition {
		lookup := WorkflowNode{ID: "vt", Name: "vt", Type: "action", ForEach: `iocs(nodes.extract.data, "ipv4")`}
		if mutate != nil {
			mutate(&lookup)
		}
		return WorkflowDefinition{ID: "wf",
			Nodes: []WorkflowNode{{ID: "extract", Name: "extract", Type: "action"}, lookup, {ID: "later", Name: "later", Type: "action"}},
			Edges: []WorkflowEdge{{ID: "1", Source: "extract", Target: "vt"}, {ID: "2", Source: "vt", Target: "later"}}}
	}
	if err := ValidateWorkflowBranching(base(nil)); err != nil {
		t.Fatalf("valid loop: %v", err)
	}
	if err := ValidateWorkflowForEach(base(func(n *WorkflowNode) {
		n.ForEachConcurrency, n.ForEachLimit, n.ForEachFailOn = ForEachMaxConcurrency, ForEachMaxLimit, "ALL"
	})); err != nil {
		t.Fatalf("bounds at their maximum: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*WorkflowNode)
		want   string
	}{
		"not an action":   {func(n *WorkflowNode) { n.Type = "script" }, "action nodes only"},
		"bad expression":  {func(n *WorkflowNode) { n.ForEach = "trigger.(" }, "forEach"},
		"unknown root":    {func(n *WorkflowNode) { n.ForEach = "item.ips" }, "forEach"},
		"downstream read": {func(n *WorkflowNode) { n.ForEach = "nodes.later.data.ips" }, "not upstream"},
		"concurrency":     {func(n *WorkflowNode) { n.ForEachConcurrency = ForEachMaxConcurrency + 1 }, "forEachConcurrency"},
		"negative":        {func(n *WorkflowNode) { n.ForEachConcurrency = -1 }, "forEachConcurrency"},
		"limit":           {func(n *WorkflowNode) { n.ForEachLimit = ForEachMaxLimit + 1 }, "forEachLimit"},
		"failOn":          {func(n *WorkflowNode) { n.ForEachFailOn = "most" }, "forEachFailOn"},
		"orphan settings": {func(n *WorkflowNode) { n.ForEach = ""; n.ForEachLimit = 5 }, "need forEach"},
	} {
		err := ValidateWorkflowBranching(base(tc.mutate))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestForEachEffectiveSettings(t *testing.T) {
	n := WorkflowNode{ForEach: "trigger.ips"}
	if !n.HasForEach() || ForEachConcurrencyOf(n) != ForEachDefaultConcurrency || ForEachLimitOf(n) != ForEachDefaultLimit || ForEachFailOnOf(n) != ForEachFailOnAny {
		t.Fatalf("defaults: %d %d %s", ForEachConcurrencyOf(n), ForEachLimitOf(n), ForEachFailOnOf(n))
	}
	n.ForEachConcurrency, n.ForEachLimit, n.ForEachFailOn = 99, 5000, " all "
	if ForEachConcurrencyOf(n) != ForEachMaxConcurrency || ForEachLimitOf(n) != ForEachMaxLimit || ForEachFailOnOf(n) != ForEachFailOnAll {
		t.Fatalf("clamped: %d %d %s", ForEachConcurrencyOf(n), ForEachLimitOf(n), ForEachFailOnOf(n))
	}
	if (WorkflowNode{ForEach: "  "}).HasForEach() {
		t.Fatal("blank forEach loops")
	}
	raw, _ := json.Marshal(WorkflowNode{ID: "x"})
	if strings.Contains(string(raw), "forEach") {
		t.Fatalf("unset loop fields are serialised: %s", raw)
	}
}
