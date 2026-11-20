package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
)

func TestQueuedSOPDoesNotStartAndCancelDoesNotOccupy(t *testing.T) {
	t.Parallel()
	s, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	wf := domain.WorkflowDefinition{ID: "queue-command", Name: "Queue", SandboxProfileID: "local", Nodes: []domain.WorkflowNode{{ID: "work", Type: "command", Command: "true", MaxAttempts: 1}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := s.PutRun(domain.Run{ID: fmt.Sprintf("held-%d", i), Status: "failed", ExecutionContext: domain.TelemetryContext{ProjectID: "p"}}); err != nil {
			t.Fatal(err)
		}
	}
	e := New(s, runtime.NewManager(t.TempDir()))
	e.ConfigureExecution("queue-worker", "queue-host", time.Minute, true)
	r, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "queued" || r.OwnerInstanceID != "" || e.ActiveRunCount() != 0 {
		t.Fatalf("run=%+v active=%d", r, e.ActiveRunCount())
	}
	if r.Nodes["work"].Status != "pending" || r.SandboxID != "" {
		t.Fatal("queued SOP started")
	}
	if len(r.Events) != 1 || r.Events[0].Type != "run.queued" {
		t.Fatalf("events=%+v", r.Events)
	}
	if err := e.DeleteRun(r.ID); err == nil {
		t.Fatal("queued deletion allowed")
	}
	if err := e.Cancel(r.ID); err != nil {
		t.Fatal(err)
	}
	cancelled, _ := s.RunState(r.ID)
	if cancelled.Status != "cancelled" || cancelled.AdmissionState != "unstarted" {
		t.Fatal(cancelled)
	}
	if promoted, err := s.PromoteQueuedRuns(); err != nil || len(promoted) != 0 {
		t.Fatalf("promoted=%v err=%v", promoted, err)
	}
}

func TestQueuedSOPAutomaticallyStartsAfterSuccess(t *testing.T) {
	t.Parallel()
	s, _ := repo.OpenTest()
	defer s.Close()
	wf := domain.WorkflowDefinition{ID: "queue-approval", Name: "Queue", SandboxProfileID: "local", Nodes: []domain.WorkflowNode{{ID: "gate", Name: "Gate", Type: "approval", MaxAttempts: 1}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := s.PutRun(domain.Run{ID: fmt.Sprintf("occupied-%d", i), Status: "failed", ExecutionContext: domain.TelemetryContext{ProjectID: "p"}}); err != nil {
			t.Fatal(err)
		}
	}
	e := New(s, runtime.NewManager(t.TempDir()))
	e.ConfigureExecution("queue-worker", "queue-host", time.Minute, true)
	r, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "p"})
	if err != nil || r.Status != "queued" {
		t.Fatalf("run=%+v err=%v", r, err)
	}
	updates, unsubscribe, err := e.Subscribe(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer unsubscribe()
	<-updates
	held, _ := s.RunState("occupied-0")
	held.Status = "succeeded"
	if err := s.PutRun(held); err != nil {
		t.Fatal(err)
	}
	e.ResumeInterruptedRuns()
	waitRun(t, s, r.ID, 3*time.Second, func(got domain.Run) bool { return got.Status == "waiting" })
	select {
	case update := <-updates:
		if update.Status == "queued" {
			t.Fatal("queue promotion not published")
		}
	case <-time.After(time.Second):
		t.Fatal("no promotion event")
	}
	if err := e.Cancel(r.ID); err != nil {
		t.Fatal(err)
	}
	e.Drain(context.Background())
}

// A run that succeeds frees its project's slot, and the queued run behind
// it starts right away instead of on the next claim loop tick.
func TestSucceededRunAdmitsQueuedRunAtOnce(t *testing.T) {
	t.Parallel()
	s, _ := repo.OpenTest()
	defer s.Close()
	wf := domain.WorkflowDefinition{ID: "queue-handoff", Name: "Queue", SandboxProfileID: "local", Nodes: []domain.WorkflowNode{{ID: "gate", Name: "Gate", Type: "approval", MaxAttempts: 1}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < repo.ProjectRunLimit-1; i++ {
		if err := s.PutRun(domain.Run{ID: fmt.Sprintf("occupied-%d", i), Status: "failed", ExecutionContext: domain.TelemetryContext{ProjectID: "p"}}); err != nil {
			t.Fatal(err)
		}
	}
	e := New(s, runtime.NewManager(t.TempDir()))
	e.ConfigureExecution("queue-worker", "queue-host", time.Minute, true)
	defer e.Drain(context.Background())
	first, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	waitRun(t, s, first.ID, 3*time.Second, func(got domain.Run) bool { return got.Status == "waiting" })
	next, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "p"})
	if err != nil || next.Status != "queued" {
		t.Fatalf("run=%+v err=%v", next, err)
	}
	if len(e.admitKick) != 0 {
		t.Fatal("admission kicked before any run succeeded")
	}
	if err := e.Approve(first.ID, "gate", ""); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s, first.ID, 3*time.Second, func(got domain.Run) bool { return got.Status == "succeeded" })
	// The kick follows the succeeded write, so the status can be seen first.
	select {
	case <-e.admitKick:
	case <-time.After(2 * time.Second):
		t.Fatal("a succeeded run must kick admission")
	}
	if started := e.admitQueued(); len(started) != 1 || started[0] != next.ID {
		t.Fatalf("started=%v, want %s", started, next.ID)
	}
	waitRun(t, s, next.ID, 3*time.Second, func(got domain.Run) bool { return got.Status == "waiting" })
}

// With the claim loop running, the hand-off takes far less than its 2s tick.
func TestClaimLoopAdmitsQueuedRunOnKick(t *testing.T) {
	t.Parallel()
	s, _ := repo.OpenTest()
	defer s.Close()
	wf := domain.WorkflowDefinition{ID: "queue-kick", Name: "Queue", SandboxProfileID: "local", Nodes: []domain.WorkflowNode{{ID: "gate", Name: "Gate", Type: "approval", MaxAttempts: 1}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < repo.ProjectRunLimit; i++ {
		if err := s.PutRun(domain.Run{ID: fmt.Sprintf("occupied-%d", i), Status: "failed", ExecutionContext: domain.TelemetryContext{ProjectID: "p"}}); err != nil {
			t.Fatal(err)
		}
	}
	e := New(s, runtime.NewManager(t.TempDir()))
	e.ConfigureExecution("queue-worker", "queue-host", time.Minute, true)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	defer e.Drain(context.Background())
	queued, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "p"})
	if err != nil || queued.Status != "queued" {
		t.Fatalf("run=%+v err=%v", queued, err)
	}
	e.StartClaimLoop(ctx)
	// Let the loop's first pass go by, so only a kick can admit the run
	// before the next tick.
	time.Sleep(200 * time.Millisecond)
	held, _ := s.RunState("occupied-0")
	held.Status = "succeeded"
	if err := s.PutRun(held); err != nil {
		t.Fatal(err)
	}
	freed := time.Now()
	e.kickAdmission()
	waitRun(t, s, queued.ID, 3*time.Second, func(got domain.Run) bool { return got.Status == "waiting" })
	if waited := time.Since(freed); waited > time.Second {
		t.Fatalf("queued run started %s after the slot freed", waited)
	}
}

// A raised limit admits many runs at once; they are taken over together and
// all start, not one database round trip after another.
func TestAdmittedRunsAreTakenOverInParallel(t *testing.T) {
	t.Parallel()
	s, _ := repo.OpenTest()
	defer s.Close()
	wf := domain.WorkflowDefinition{ID: "queue-burst", Name: "Queue", SandboxProfileID: "local", Nodes: []domain.WorkflowNode{{ID: "gate", Name: "Gate", Type: "approval", MaxAttempts: 1}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	if err := s.PutProject(domain.Project{ID: "p", Key: "p", Name: "p"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < repo.ProjectRunLimit; i++ {
		if err := s.PutRun(domain.Run{ID: fmt.Sprintf("occupied-%d", i), Status: "failed", ExecutionContext: domain.TelemetryContext{ProjectID: "p"}}); err != nil {
			t.Fatal(err)
		}
	}
	e := New(s, runtime.NewManager(t.TempDir()))
	e.ConfigureExecution("burst-worker", "burst-host", time.Minute, true)
	defer e.Drain(context.Background())
	var queued []string
	for i := 0; i < 12; i++ {
		r, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "p"})
		if err != nil || r.Status != "queued" {
			t.Fatalf("run=%+v err=%v", r, err)
		}
		queued = append(queued, r.ID)
	}
	if err := s.SetProjectRunLimit("p", 20); err != nil {
		t.Fatal(err)
	}
	started := e.admitQueued()
	if len(started) != 10 {
		t.Fatalf("started %d runs, want the 10 that fit", len(started))
	}
	for i, id := range started {
		if id != queued[i] {
			t.Fatalf("started out of order: %v", started)
		}
		waitRun(t, s, id, 3*time.Second, func(got domain.Run) bool { return got.Status == "waiting" })
	}
	for _, id := range queued[10:] {
		if r, _ := s.RunState(id); r.Status != "queued" {
			t.Fatalf("%s is %s beyond the limit", id, r.Status)
		}
	}
	for _, id := range queued {
		_ = e.Cancel(id)
	}
}
