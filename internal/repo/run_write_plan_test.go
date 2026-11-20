package repo

import (
	"sync"
	"testing"
	"time"

	"agentflow/internal/domain"

	"gorm.io/gorm"
)

// rowWrites counts the INSERT/UPDATE statements per table and which runs
// columns the UPDATEs set.
type rowWrites struct {
	mu      sync.Mutex
	tables  map[string]int
	columns map[string]bool
}

func countRowWrites(t *testing.T, s *Store) *rowWrites {
	t.Helper()
	w := &rowWrites{}
	w.reset()
	count := func(tx *gorm.DB) {
		if tx.Error != nil {
			return
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		w.tables[tx.Statement.Table]++
		if tx.Statement.Table == "runs" {
			if m, ok := tx.Statement.Dest.(map[string]any); ok {
				for k := range m {
					w.columns[k] = true
				}
			}
		}
	}
	name := t.Name()
	if err := s.DB.Callback().Create().After("gorm:create").Register("count_create_"+name, count); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Callback().Update().After("gorm:update").Register("count_update_"+name, count); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *rowWrites) reset() {
	w.mu.Lock()
	w.tables, w.columns = map[string]int{}, map[string]bool{}
	w.mu.Unlock()
}

func (w *rowWrites) n(table string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tables[table]
}

func planTestRun(id string) domain.Run {
	now := time.Now().UTC()
	return domain.Run{ID: id, WorkflowID: "wf", Status: "running", Input: "investigate", CreatedAt: now, UpdatedAt: now,
		WorkflowSnapshot: domain.WorkflowDefinition{ID: "wf", Name: "snapshot", Nodes: []domain.WorkflowNode{{ID: "a"}, {ID: "b"}}},
		Nodes: map[string]*domain.NodeRun{
			"a": {NodeID: "a", Status: "running", Attempt: 1},
			"b": {NodeID: "b", Status: "pending"},
		},
		Events:    []domain.RunEvent{{ID: "e1", Type: "run.started"}, {ID: "e2", Type: "node.started", NodeID: "a"}},
		Artifacts: []domain.Artifact{{ID: "art-1", NodeID: "a", Attempt: 1, Name: "report.md", Content: "big report"}},
	}
}

// Events are appended by index: a write stores only the events added since
// the stored ones, not the whole history again.
func TestPutRunAppendsOnlyNewEvents(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	run := planTestRun("run-events")
	if err := s.PutRun(run); err != nil {
		t.Fatal(err)
	}
	w := countRowWrites(t, s)
	stored, _ := s.RunState(run.ID)
	stored.Events = append(stored.Events, domain.RunEvent{ID: "e3", Type: "node.succeeded", NodeID: "a"})
	if err := s.PutRun(stored); err != nil {
		t.Fatal(err)
	}
	if got := w.n("run_events"); got != 1 {
		t.Fatalf("run_events rows written = %d, want only the new one", got)
	}
	got, _ := s.RunState(run.ID)
	if len(got.Events) != 3 || got.Events[2].ID != "e3" || got.Events[0].ID != "e1" {
		t.Fatalf("events = %+v", got.Events)
	}
}

func TestPutRunFromWritesOnlyChanges(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	run := planTestRun("run-plan")
	if err := s.PutRun(run); err != nil {
		t.Fatal(err)
	}
	w := countRowWrites(t, s)

	// Nothing changed: no write at all, not even a revision bump.
	current, base, ok := s.RunStateForWrite(run.ID)
	if !ok {
		t.Fatal("run missing")
	}
	if stored, err := s.PutRunFrom(current, base); err != nil || stored {
		t.Fatalf("unchanged PutRunFrom = (%v, %v), want (false, nil)", stored, err)
	}
	if n := w.n("runs") + w.n("run_nodes") + w.n("run_events") + w.n("run_artifacts"); n != 0 {
		t.Fatalf("unchanged run wrote %d rows", n)
	}
	if after, _ := s.RunState(run.ID); after.Revision != current.Revision {
		t.Fatalf("revision moved without a write: %d -> %d", current.Revision, after.Revision)
	}

	// One node changes in place (the base must not alias the mutated run).
	current, base, _ = s.RunStateForWrite(run.ID)
	current.Nodes["a"].Status = "succeeded"
	current.Nodes["a"].Output = "done"
	current.Events = append(current.Events, domain.RunEvent{ID: "e3", Type: "node.succeeded", NodeID: "a"})
	w.reset()
	if stored, err := s.PutRunFrom(current, base); err != nil || !stored {
		t.Fatalf("PutRunFrom = (%v, %v)", stored, err)
	}
	if got := w.n("run_nodes"); got != 1 {
		t.Fatalf("run_nodes rows written = %d, want only node a", got)
	}
	if got := w.n("run_artifacts"); got != 0 {
		t.Fatalf("unchanged artifact rewritten %d times", got)
	}
	if got := w.n("run_events"); got != 1 {
		t.Fatalf("run_events rows written = %d, want 1", got)
	}
	for _, col := range []string{"snapshot", "input", "execution_context", "repository"} {
		if w.columns[col] {
			t.Fatalf("unchanged column %s was rewritten", col)
		}
	}
	if !w.columns["status"] || !w.columns["revision"] {
		t.Fatalf("header update lacks status/revision: %v", w.columns)
	}
	got, _ := s.RunState(run.ID)
	if got.Revision != current.Revision+1 || got.Nodes["a"].Status != "succeeded" || got.Nodes["a"].Output != "done" ||
		got.Nodes["b"].Status != "pending" || got.WorkflowSnapshot.Name != "snapshot" || got.Input != "investigate" ||
		len(got.Artifacts) != 1 || got.Artifacts[0].Content != "big report" || len(got.Events) != 3 {
		t.Fatalf("stored run after a planned write: %+v", got)
	}

	// A changed large column and artifact are written.
	current, base, _ = s.RunStateForWrite(run.ID)
	current.WorkflowSnapshot.Name = "renamed"
	current.Artifacts[0].Content = "new report"
	w.reset()
	if _, err := s.PutRunFrom(current, base); err != nil {
		t.Fatal(err)
	}
	if !w.columns["snapshot"] || w.n("run_artifacts") != 1 || w.n("run_nodes") != 0 {
		t.Fatalf("changed snapshot/artifact not written: columns %v, artifacts %d, nodes %d", w.columns, w.n("run_artifacts"), w.n("run_nodes"))
	}
	got, _ = s.RunState(run.ID)
	if got.WorkflowSnapshot.Name != "renamed" || got.Artifacts[0].Content != "new report" {
		t.Fatalf("stored run: snapshot %q artifact %q", got.WorkflowSnapshot.Name, got.Artifacts[0].Content)
	}
}

// When another write lands between the read and the write, the planned
// write falls back to a full write, exactly like PutRun.
func TestPutRunFromFallsBackAfterAConcurrentWrite(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	run := planTestRun("run-plan-race")
	if err := s.PutRun(run); err != nil {
		t.Fatal(err)
	}
	mine, base, _ := s.RunStateForWrite(run.ID)

	other, _ := s.RunState(run.ID)
	other.Nodes["b"].Status = "running"
	other.WorkflowSnapshot.Name = "other"
	if err := s.PutRun(other); err != nil {
		t.Fatal(err)
	}

	w := countRowWrites(t, s)
	mine.Nodes["a"].Status = "succeeded"
	if _, err := s.PutRunFrom(mine, base); err != nil {
		t.Fatal(err)
	}
	if got := w.n("run_nodes"); got != 2 {
		t.Fatalf("run_nodes rows written = %d, want a full write of both nodes", got)
	}
	got, _ := s.RunState(run.ID)
	// Same result as a full PutRun of the stale copy.
	if got.Nodes["a"].Status != "succeeded" || got.Nodes["b"].Status != "pending" || got.WorkflowSnapshot.Name != "snapshot" {
		t.Fatalf("fallback write: nodes a=%s b=%s snapshot=%q", got.Nodes["a"].Status, got.Nodes["b"].Status, got.WorkflowSnapshot.Name)
	}
}
