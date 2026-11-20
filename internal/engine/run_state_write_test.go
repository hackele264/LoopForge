package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
)

// fanOutRun stores a running run of builtin action nodes a -> (b, c, d) -> e
// whose first node already succeeded.
func fanOutRun(t *testing.T, s *repo.Store, id string) domain.Run {
	t.Helper()
	act := func(id string) domain.WorkflowNode {
		return domain.WorkflowNode{ID: id, Name: id, Type: connector.NodeType, MaxAttempts: 1,
			Action: &domain.NodeAction{Connector: connector.BuiltinID, Action: "extract_iocs", Inputs: map[string]string{"value": "1.2.3.4"}}}
	}
	wf := domain.WorkflowDefinition{ID: "wf-" + id, Name: "fan-out", SandboxProfileID: "local",
		Nodes: []domain.WorkflowNode{act("a"), act("b"), act("c"), act("d"), act("e")},
		Edges: []domain.WorkflowEdge{
			{ID: "1", Source: "a", Target: "b"}, {ID: "2", Source: "a", Target: "c"}, {ID: "3", Source: "a", Target: "d"},
			{ID: "4", Source: "b", Target: "e"}, {ID: "5", Source: "c", Target: "e"}, {ID: "6", Source: "d", Target: "e"},
		}}
	now := time.Now().UTC()
	r := domain.Run{ID: id, WorkflowID: wf.ID, Status: "running", WorkflowSnapshot: wf, CreatedAt: now, UpdatedAt: now,
		Nodes: map[string]*domain.NodeRun{
			"a": {NodeID: "a", Status: "succeeded", Attempt: 1, Data: domain.RawJSON(`{"ipv4":["1.2.3.4"]}`)},
			"b": {NodeID: "b", Status: "pending"}, "c": {NodeID: "c", Status: "pending"},
			"d": {NodeID: "d", Status: "pending"}, "e": {NodeID: "e", Status: "pending"},
		}}
	if err := s.PutRun(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// A fan-out starts with one write. That write must carry everything recovery
// needs: when the instance dies right after it, another instance resumes the
// started nodes without spending an attempt and finishes the run.
func TestBatchedNodeStartSurvivesCrash(t *testing.T) {
	s, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := fanOutRun(t, s, "run-fanout-crash")
	crashed := leaseEngine(t, s, "crashed")
	if err := s.TryAcquireRunLease(r.ID, "crashed", 0, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	before, _ := s.RunState(r.ID)
	wf := before.WorkflowSnapshot
	ready := readyNodes(wf, before)
	if len(ready) != 3 {
		t.Fatalf("ready = %d nodes, want b, c, d", len(ready))
	}
	started, rest := crashed.startReadyNodes(r.ID, ready)
	if len(started) != 3 || len(rest) != 0 {
		t.Fatalf("started %d, rest %d; want all 3 started in one write", len(started), len(rest))
	}
	// The instance dies here: nothing runs the started nodes.
	for _, sn := range started {
		sn.unlock()
	}
	after, _ := s.RunState(r.ID)
	if after.Revision != before.Revision+1 {
		t.Fatalf("revision %d -> %d, want one write for the fan-out", before.Revision, after.Revision)
	}
	startedEvents := 0
	for _, ev := range after.Events {
		if ev.Type == "node.started" {
			startedEvents++
		}
	}
	if startedEvents != 3 {
		t.Fatalf("node.started events = %d, want 3", startedEvents)
	}
	for _, id := range []string{"b", "c", "d"} {
		nr := after.Nodes[id]
		if nr.Status != "running" || nr.Attempt != 1 || !strings.HasPrefix(nr.Activity, "正在执行动作 ") {
			t.Fatalf("node %s persisted as %+v", id, nr)
		}
	}

	time.Sleep(150 * time.Millisecond) // the crashed instance's lease expires
	survivor := leaseEngine(t, s, "survivor")
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = survivor.Drain(ctx)
	}()
	if resumed := survivor.ResumeInterruptedRuns(); len(resumed) != 1 {
		t.Fatalf("resumed = %v", resumed)
	}
	deadline := time.Now().Add(10 * time.Second)
	var final domain.Run
	for time.Now().Before(deadline) {
		final, _ = s.RunState(r.ID)
		if domain.TerminalRunStatus(final.Status) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if final.Status != "succeeded" {
		t.Fatalf("run status = %q after takeover, want succeeded; nodes %+v", final.Status, final.Nodes)
	}
	for _, id := range []string{"b", "c", "d", "e"} {
		nr := final.Nodes[id]
		if nr.Status != "succeeded" || nr.Attempt != 1 || nr.Activity != "" {
			t.Fatalf("node %s = %+v, want succeeded on attempt 1", id, nr)
		}
	}
}

// An update that changes nothing persisted is not written, yet reports
// success; the next real change is written on top of the unchanged revision.
func TestNoOpUpdateIsNotWritten(t *testing.T) {
	s, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := leaseEngine(t, s, "self")
	leaseRun(t, s, "run-noop", "waiting", "pending")
	before, _ := s.RunState("run-noop")
	if !e.updateRunAt("run-noop", false, func(r *domain.Run) { r.Nodes["node"].Status = "pending" }) {
		t.Fatal("a no-op update must report success")
	}
	if got, _ := s.RunState("run-noop"); got.Revision != before.Revision || !got.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("no-op update was written: revision %d -> %d", before.Revision, got.Revision)
	}
	if !e.updateRunAt("run-noop", false, func(r *domain.Run) { r.Nodes["node"].Activity = "x" }) {
		t.Fatal("update not stored")
	}
	if got, _ := s.RunState("run-noop"); got.Revision != before.Revision+1 || got.Nodes["node"].Activity != "x" {
		t.Fatalf("change after a no-op: revision %d, activity %q", got.Revision, got.Nodes["node"].Activity)
	}
}

// The action node's own activity update repeats what its start write already
// stored, so it costs no write.
func TestActionNodeStartCarriesActivity(t *testing.T) {
	node := domain.WorkflowNode{ID: "x", Type: connector.NodeType, Action: &domain.NodeAction{Connector: connector.BuiltinID, Action: "extract_iocs"}}
	got, ok := actionNodeActivity(node)
	c, a, found := connector.Default().Action(connector.BuiltinID, "extract_iocs")
	if !ok || !found || got != "正在执行动作 "+c.Title+" · "+a.Title {
		t.Fatalf("activity = %q, %v", got, ok)
	}
	if _, ok := actionNodeActivity(domain.WorkflowNode{ID: "y", Type: "command"}); ok {
		t.Fatal("non-action nodes get no start activity")
	}
}
