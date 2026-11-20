package connector

import (
	"strings"
	"testing"

	"agentflow/internal/domain"
)

func TestLoopInputsReadItemAndIndex(t *testing.T) {
	node := domain.WorkflowNode{ID: "vt", Type: NodeType, ForEach: "trigger.ips",
		Action: &domain.NodeAction{Connector: "virustotal", Action: "ip_report", ConnectionID: "cn", Inputs: map[string]string{"ip": "{{ item.addr }}"}}}
	if err := CheckNodeInputsFor(node); err != nil {
		t.Fatalf("loop inputs: %v", err)
	}
	wf := domain.WorkflowDefinition{Nodes: []domain.WorkflowNode{node}}
	if err := ValidateWorkflow(wf, Default()); err != nil {
		t.Fatalf("validate loop node: %v", err)
	}
	node.ForEach = ""
	if err := ValidateWorkflow(domain.WorkflowDefinition{Nodes: []domain.WorkflowNode{node}}, Default()); err == nil || !strings.Contains(err.Error(), "item") {
		t.Fatalf("item without forEach: %v", err)
	}

	env := map[string]any{"trigger": map[string]any{"host": "h-1"}}
	got, err := EvalLoopInputs(map[string]string{"ip": "{{ item.addr }}", "note": "#{{ index }} on {{ trigger.host }}", "fixed": "x"}, env, map[string]any{"addr": "10.0.0.9"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got["ip"] != "10.0.0.9" || got["note"] != "#2 on h-1" || got["fixed"] != "x" {
		t.Fatalf("inputs = %v", got)
	}
	if _, leaked := env["item"]; leaked {
		t.Fatal("EvalLoopInputs changed the shared run environment")
	}
	if refs := NodeInputRefs(map[string]string{"ip": "{{ item }} {{ nodes.extract.data.x }}"}); len(refs) != 1 || refs[0] != "extract" {
		t.Fatalf("refs = %v", refs)
	}
}
