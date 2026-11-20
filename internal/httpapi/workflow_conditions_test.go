package httpapi

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"agentflow/internal/domain"
	"agentflow/internal/engine"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
	"agentflow/internal/tracker"
)

func TestCheckWorkflowCondition(t *testing.T) {
	s, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h := New(s, engine.New(s, runtime.NewManager(filepath.Join(t.TempDir(), "workspaces"))), tracker.NewService(), "", "")
	wf := domain.WorkflowDefinition{
		Nodes: []domain.WorkflowNode{{ID: "triage"}, {ID: "contain"}, {ID: "audit"}},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "triage", Target: "contain"}, {ID: "2", Source: "contain", Target: "audit"}},
	}
	type body = map[string]any
	check := func(req body, status int) engine.ConditionCheck {
		t.Helper()
		return requestJSON[engine.ConditionCheck](t, h, http.MethodPost, "/api/workflow-conditions/check", req, status)
	}

	got := check(body{
		"expression": `nodes.triage.data.verdict == "malicious" && trigger.severity in ["high", "critical"]`,
		"trigger":    body{"severity": "high"},
		"nodes":      body{"triage": body{"data": body{"verdict": "malicious"}}},
		"workflow":   wf, "nodeId": "contain",
	}, http.StatusOK)
	if !got.Valid || got.Result == nil || !*got.Result || strings.Join(got.NodeRefs, ",") != "triage" {
		t.Fatalf("true case = %+v", got)
	}

	got = check(body{"expression": `nodes.triage.data.verdict == "malicious"`, "nodes": body{"triage": body{"data": body{"verdict": "benign"}}}}, http.StatusOK)
	if !got.Valid || got.Result == nil || *got.Result {
		t.Fatalf("false case = %+v", got)
	}

	got = check(body{"expression": `nodes.audit.status == "succeeded"`, "workflow": wf, "nodeId": "contain"}, http.StatusOK)
	if got.Valid || got.Stage != "reference" || got.Result != nil {
		t.Fatalf("reference case = %+v", got)
	}

	got = check(body{"expression": `trigger.severity = "high"`}, http.StatusOK)
	if got.Valid || got.Stage != "compile" {
		t.Fatalf("compile case = %+v", got)
	}

	got = check(body{"expression": `trigger.count < "x"`, "trigger": body{"count": 3}}, http.StatusOK)
	if !got.Valid || got.Stage != "evaluate" || got.Result != nil || got.Error == "" {
		t.Fatalf("evaluate case = %+v", got)
	}

	for _, bad := range []body{
		{"expression": "  "},
		{"expression": "trigger.a == 1", "trigger": []int{1}},
		{"expression": "trigger.a == 1", "nodes": body{"x": body{"data": []int{1}}}},
	} {
		check(bad, http.StatusBadRequest)
	}
}
