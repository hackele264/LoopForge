package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/engine"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
	"github.com/gin-gonic/gin"
)

func TestApproveResponseReportsApprovalProgress(t *testing.T) {
	st, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	deadline := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	wf := domain.WorkflowDefinition{ID: "wf", Nodes: []domain.WorkflowNode{
		{ID: "legacy", Type: "approval"},
		{ID: "timed", Type: "approval", Approval: &domain.ApprovalRule{TimeoutMinutes: 60, OnTimeout: domain.ApprovalOnTimeoutReject}},
	}}
	run := domain.Run{ID: "decision", WorkflowID: "wf", Status: "waiting", WorkflowSnapshot: wf, Nodes: map[string]*domain.NodeRun{
		"legacy": {NodeID: "legacy", Status: "waiting_approval", Attempt: 1},
		"timed":  {NodeID: "timed", Status: "waiting_approval", Attempt: 1, Approval: &domain.ApprovalState{Required: 1, Deadline: deadline, OnTimeout: domain.ApprovalOnTimeoutReject}},
	}}
	if err := st.PutRun(run); err != nil {
		t.Fatal(err)
	}
	h := &runsHandlers{deps: &deps{repo: st, engine: engine.New(st, runtime.NewManager(t.TempDir()))}}
	g := gin.New()
	g.POST("/api/runs/:id/approve", h.run)
	approve := func(node string) map[string]any {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/runs/decision/approve", strings.NewReader(`{"nodeId":"`+node+`"}`))
		req.Header.Set("Content-Type", "application/json")
		g.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("approve %s: %d %s", node, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	if body := approve("legacy"); len(body) != 1 || body["ok"] != true {
		t.Fatalf("legacy gate body = %v", body)
	}
	body := approve("timed")
	p, _ := body["approval"].(map[string]any)
	if p == nil || p["approved"] != true || p["approvals"] != float64(1) || p["required"] != float64(1) || p["deadline"] == nil {
		t.Fatalf("timed gate body = %v", body)
	}
}

func TestApproveResponsePartial(t *testing.T) {
	t.Parallel()
	at := time.Now().UTC()
	run := domain.Run{Nodes: map[string]*domain.NodeRun{"g": {Status: "waiting_approval", Approval: &domain.ApprovalState{Required: 2, Votes: []domain.ApprovalVote{{UserID: 3, At: at}}, Escalated: true, EscalatedAt: at}}}}
	p := approveResponse(run, "g")["approval"].(approvalProgress)
	if p.Approved || p.Approvals != 1 || p.Required != 2 || !p.Escalated || p.EscalatedAt == nil || p.Deadline != nil {
		t.Fatalf("progress = %+v", p)
	}
	if note := approvalPendingNote(run, "g"); !strings.Contains(note, "1/2") {
		t.Fatalf("note = %q", note)
	}
}
