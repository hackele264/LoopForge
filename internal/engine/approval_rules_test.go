package engine

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agentflow/internal/apperr"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
)

func approvalTestProject(t *testing.T, s *repo.Store) {
	t.Helper()
	project := domain.Project{ID: "sec", Key: "SEC", Name: "sec", OwnerID: 1, Members: []domain.ProjectMember{{UserID: 8, Role: "member"}, {UserID: 9, Role: "member"}, {UserID: 10, Role: "viewer"}}}
	if err := s.PutProject(project); err != nil {
		t.Fatal(err)
	}
}

func approvalUser(id int64) domain.Actor {
	return domain.Actor{UserID: id, Kind: domain.ActorUser, Login: "user" + string(rune('0'+id%10))}
}

func startApprovalRun(t *testing.T, e *Engine, s *repo.Store, wf domain.WorkflowDefinition) domain.Run {
	t.Helper()
	if _, ok := s.Workflow(wf.ID); !ok {
		if err := s.PutWorkflow(wf); err != nil {
			t.Fatal(err)
		}
	}
	r, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "waiting")
	got, _ := s.RunState(r.ID)
	return got
}

func approvalAudits(t *testing.T, s *repo.Store, action string) []domain.AuditEvent {
	t.Helper()
	list, err := s.AuditEvents(repo.AuditFilter{Action: action})
	if err != nil {
		t.Fatal(err)
	}
	var out []domain.AuditEvent
	for _, ev := range list {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

func wantAppErr(t *testing.T, err error, kind apperr.Kind, what string) {
	t.Helper()
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Kind != kind {
		t.Fatalf("%s: error = %v, want kind %v", what, err, kind)
	}
}

func TestTwoPersonApprovalNeedsDistinctApprovers(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	approvalTestProject(t, s)
	wf := domain.WorkflowDefinition{ID: "two-person", Name: "two", SandboxProfileID: "local", ProjectID: "sec",
		Nodes: []domain.WorkflowNode{
			{ID: "gate", Name: "gate", Type: "approval", MaxAttempts: 1, Approvers: &domain.ApproverPolicy{Roles: []string{"member"}}, Approval: &domain.ApprovalRule{RequiredApprovals: 2}},
			{ID: "respond", Name: "respond", Type: "command", Command: "true", MaxAttempts: 1},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "gate", Target: "respond"}}}
	r := startApprovalRun(t, e, s, wf)
	if st := r.Nodes["gate"].Approval; st == nil || st.Required != 2 || len(st.Votes) != 0 || !st.Deadline.IsZero() {
		t.Fatalf("approval state on waiting = %+v", st)
	}
	if err := e.ApproveAs(r.ID, "gate", "", approvalUser(8)); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	got, _ := s.RunState(r.ID)
	if got.Status != "waiting" || got.Nodes["gate"].Status != "waiting_approval" || len(got.Nodes["gate"].Approval.Votes) != 1 {
		t.Fatalf("after one approval: run %s node %s votes %+v", got.Status, got.Nodes["gate"].Status, got.Nodes["gate"].Approval)
	}
	wantAppErr(t, e.ApproveAs(r.ID, "gate", "", approvalUser(8)), apperr.Conflict, "same person twice")
	wantAppErr(t, e.ApproveAs(r.ID, "gate", "", domain.Actor{Kind: domain.ActorService}), apperr.Forbidden, "service")
	wantAppErr(t, e.ApproveAs(r.ID, "gate", "", approvalUser(10)), apperr.Forbidden, "viewer")
	if err := e.ApproveAs(r.ID, "gate", "", approvalUser(9)); err != nil {
		t.Fatalf("second approval: %v", err)
	}
	waitFor(t, s, r.ID, "succeeded")
	got, _ = s.RunState(r.ID)
	votes := got.Nodes["gate"].Approval.Votes
	if len(votes) != 2 || votes[0].UserID != 8 || votes[1].UserID != 9 || got.Nodes["gate"].DecidedBy != 9 {
		t.Fatalf("votes = %+v decidedBy %d", votes, got.Nodes["gate"].DecidedBy)
	}
	var decision string
	for _, a := range got.Artifacts {
		if a.NodeID == "gate" && a.Name == "decision" {
			full, _ := s.Artifact(r.ID, a.ID)
			decision = full.Content
		}
	}
	if !strings.Contains(decision, "Approvals:") || !strings.Contains(decision, "user8") || !strings.Contains(decision, "user9") {
		t.Fatalf("decision artifact lacks the approvers: %q", decision)
	}
	audits := approvalAudits(t, s, "approval.vote")
	if len(audits) != 2 {
		t.Fatalf("approval.vote audit entries = %d, want 2", len(audits))
	}
	seen := map[int64]bool{}
	for _, ev := range audits {
		seen[ev.ActorUserID] = true
		if ev.ProjectID != "sec" || ev.Target != r.ID+"/gate" {
			t.Fatalf("audit entry = %+v", ev)
		}
	}
	if !seen[8] || !seen[9] {
		t.Fatalf("audit actors = %v", seen)
	}
	partial := 0
	for _, ev := range got.Events {
		if ev.Type == "gate.vote" && ev.ActorUserID == 8 {
			partial++
		}
	}
	if partial != 1 {
		t.Fatalf("gate.vote events by user 8 = %d", partial)
	}
}

func TestTwoPersonRejectDecidesAndRetryResetsVotes(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	approvalTestProject(t, s)
	wf := domain.WorkflowDefinition{ID: "two-reject", Name: "two", SandboxProfileID: "local", ProjectID: "sec",
		Nodes: []domain.WorkflowNode{
			{ID: "prep", Name: "prep", Type: "command", Command: "true", MaxAttempts: 1},
			{ID: "gate", Name: "gate", Type: "approval", MaxAttempts: 1, RejectTo: "prep", MaxReworks: 3, Approvers: &domain.ApproverPolicy{Roles: []string{"member"}}, Approval: &domain.ApprovalRule{RequiredApprovals: 2}},
			{ID: "respond", Name: "respond", Type: "command", Command: "true", MaxAttempts: 1},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "prep", Target: "gate"}, {ID: "2", Source: "gate", Target: "respond"}}}
	r := startApprovalRun(t, e, s, wf)
	if err := e.ApproveAs(r.ID, "gate", "", approvalUser(8)); err != nil {
		t.Fatal(err)
	}
	// One rejection decides at once, whatever the votes.
	if err := e.RejectAs(r.ID, domain.RejectRequest{NodeID: "gate", TargetID: "prep", Reason: "no"}, approvalUser(9)); err != nil {
		t.Fatalf("reject: %v", err)
	}
	waitForNode(t, s, r.ID, "gate", func(n *domain.NodeRun) bool {
		return n.Status == "waiting_approval" && n.Approval != nil && len(n.Approval.Votes) == 0
	})
	got, _ := s.RunState(r.ID)
	if got.Nodes["prep"].ReworkCount != 1 {
		t.Fatalf("prep rework = %d", got.Nodes["prep"].ReworkCount)
	}
	if audits := approvalAudits(t, s, "approval.reject"); len(audits) != 1 || audits[0].ActorUserID != 9 {
		t.Fatalf("approval.reject audits = %+v", audits)
	}
	// A retry of the waiting gate also starts over.
	waitFor(t, s, r.ID, "waiting")
	if err := e.ApproveAs(r.ID, "gate", "", approvalUser(8)); err != nil {
		t.Fatal(err)
	}
	if err := e.Retry(r.ID, "gate", "again", ""); err != nil {
		t.Fatalf("retry: %v", err)
	}
	waitForNode(t, s, r.ID, "gate", func(n *domain.NodeRun) bool {
		return n.Status == "waiting_approval" && n.Attempt >= 2 && n.Approval != nil && len(n.Approval.Votes) == 0
	})
	waitFor(t, s, r.ID, "waiting")
	// After the reset user 8 may approve again.
	if err := e.ApproveAs(r.ID, "gate", "", approvalUser(8)); err != nil {
		t.Fatalf("approval after retry: %v", err)
	}
}

func waitForNode(t *testing.T, s *repo.Store, runID, nodeID string, ok func(*domain.NodeRun) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := s.RunState(runID)
		if n := r.Nodes[nodeID]; n != nil && ok(n) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	r, _ := s.RunState(runID)
	t.Fatalf("node %s never reached the expected state: %+v (approval %+v)", nodeID, r.Nodes[nodeID], r.Nodes[nodeID].Approval)
}

func TestApprovalTimeoutEscalates(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	approvalTestProject(t, s)
	wf := domain.WorkflowDefinition{ID: "escalate", Name: "esc", SandboxProfileID: "local", ProjectID: "sec",
		Nodes: []domain.WorkflowNode{
			{ID: "gate", Name: "gate", Type: "approval", MaxAttempts: 1, Approvers: &domain.ApproverPolicy{UserIDs: []int64{8}},
				Approval: &domain.ApprovalRule{TimeoutMinutes: 30, OnTimeout: domain.ApprovalOnTimeoutEscalate, EscalateTo: &domain.ApproverPolicy{UserIDs: []int64{9}}}},
			{ID: "respond", Name: "respond", Type: "command", Command: "true", MaxAttempts: 1},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "gate", Target: "respond"}}}
	byEscalation := startApprovalRun(t, e, s, wf)
	byOriginal := startApprovalRun(t, e, s, wf)
	st := byEscalation.Nodes["gate"].Approval
	if st == nil || st.Deadline.IsZero() || st.OnTimeout != domain.ApprovalOnTimeoutEscalate {
		t.Fatalf("approval state = %+v", st)
	}
	wantAppErr(t, e.ApproveAs(byEscalation.ID, "gate", "", approvalUser(9)), apperr.Forbidden, "escalation approver before the deadline")
	if n := e.SweepApprovalTimeouts(time.Now().UTC()); n != 0 {
		t.Fatalf("sweep before the deadline fired %d", n)
	}
	later := st.Deadline.Add(time.Minute)
	if n := e.SweepApprovalTimeouts(later); n != 2 {
		t.Fatalf("sweep after the deadline fired %d, want 2", n)
	}
	if n := e.SweepApprovalTimeouts(later.Add(time.Hour)); n != 0 {
		t.Fatalf("second sweep fired %d, want 0", n)
	}
	got, _ := s.RunState(byEscalation.ID)
	if got.Status != "waiting" || !got.Nodes["gate"].Approval.Escalated || got.Nodes["gate"].Approval.EscalatedAt.IsZero() {
		t.Fatalf("after escalation: run %s approval %+v", got.Status, got.Nodes["gate"].Approval)
	}
	escalations := 0
	for _, ev := range got.Events {
		if ev.Type == "gate.escalated" && ev.ActorKind == domain.ActorSystem {
			escalations++
		}
	}
	if escalations != 1 {
		t.Fatalf("gate.escalated events = %d", escalations)
	}
	if err := e.ApproveAs(byEscalation.ID, "gate", "", approvalUser(9)); err != nil {
		t.Fatalf("escalation approver after the deadline: %v", err)
	}
	if err := e.ApproveAs(byOriginal.ID, "gate", "", approvalUser(8)); err != nil {
		t.Fatalf("original approver after escalation: %v", err)
	}
	waitFor(t, s, byEscalation.ID, "succeeded")
	waitFor(t, s, byOriginal.ID, "succeeded")
	got, _ = s.RunState(byEscalation.ID)
	if v := got.Nodes["gate"].Approval.Votes; len(v) != 1 || !v[0].Escalation {
		t.Fatalf("escalation vote = %+v", v)
	}
	if audits := approvalAudits(t, s, "approval.escalated"); len(audits) != 2 || audits[0].ActorKind != domain.ActorSystem {
		t.Fatalf("approval.escalated audits = %+v", audits)
	}
}

func TestApprovalTimeoutRejects(t *testing.T) {
	t.Parallel()
	gate := func(extra func(*domain.WorkflowNode)) domain.WorkflowNode {
		n := domain.WorkflowNode{ID: "gate", Name: "gate", Type: "approval", MaxAttempts: 1, Approval: &domain.ApprovalRule{TimeoutMinutes: 5, OnTimeout: domain.ApprovalOnTimeoutReject}}
		if extra != nil {
			extra(&n)
		}
		return n
	}
	respond := domain.WorkflowNode{ID: "respond", Name: "respond", Type: "command", Command: "true", MaxAttempts: 1}
	t.Run("error edge takes over", func(t *testing.T) {
		t.Parallel()
		e, s := newBranchEngine(t)
		approvalTestProject(t, s)
		wf := domain.WorkflowDefinition{ID: "timeout-route", Name: "route", SandboxProfileID: "local", ProjectID: "sec",
			Nodes: []domain.WorkflowNode{gate(nil), respond, {ID: "handle", Name: "handle", Type: "command", Command: "true", MaxAttempts: 1}},
			Edges: []domain.WorkflowEdge{{ID: "1", Source: "gate", Target: "respond"}, {ID: "2", Source: "gate", Target: "handle", When: domain.EdgeWhenError}}}
		r := startApprovalRun(t, e, s, wf)
		if n := e.SweepApprovalTimeouts(r.Nodes["gate"].Approval.Deadline.Add(time.Second)); n != 1 {
			t.Fatalf("fired %d", n)
		}
		waitFor(t, s, r.ID, "succeeded")
		got, _ := s.RunState(r.ID)
		g := got.Nodes["gate"]
		if g.Status != "failed" || !g.ErrorRouted || !g.Approval.TimedOut || !strings.Contains(g.Error, "审批超时") {
			t.Fatalf("gate = %+v approval %+v", g, g.Approval)
		}
		if got.Nodes["handle"].Status != "succeeded" || got.Nodes["respond"].Status != domain.NodeStatusSkipped {
			t.Fatalf("statuses = %v", nodeStatuses(got))
		}
		if audits := approvalAudits(t, s, "approval.timeout_rejected"); len(audits) != 1 || audits[0].ActorKind != domain.ActorSystem {
			t.Fatalf("timeout audits = %+v", audits)
		}
	})
	t.Run("no route fails the run", func(t *testing.T) {
		t.Parallel()
		e, s := newBranchEngine(t)
		approvalTestProject(t, s)
		wf := domain.WorkflowDefinition{ID: "timeout-fail", Name: "fail", SandboxProfileID: "local", ProjectID: "sec",
			Nodes: []domain.WorkflowNode{gate(nil), respond},
			Edges: []domain.WorkflowEdge{{ID: "1", Source: "gate", Target: "respond"}}}
		r := startApprovalRun(t, e, s, wf)
		if n := e.SweepApprovalTimeouts(r.Nodes["gate"].Approval.Deadline.Add(time.Second)); n != 1 {
			t.Fatalf("fired %d", n)
		}
		waitFor(t, s, r.ID, "failed")
		got, _ := s.RunState(r.ID)
		if got.Nodes["gate"].Status != "failed" || got.Nodes["gate"].ErrorRouted || got.Nodes["respond"].Status != "pending" {
			t.Fatalf("statuses = %v", nodeStatuses(got))
		}
	})
	t.Run("reject route sends back", func(t *testing.T) {
		t.Parallel()
		e, s := newBranchEngine(t)
		approvalTestProject(t, s)
		wf := domain.WorkflowDefinition{ID: "timeout-rework", Name: "rework", SandboxProfileID: "local", ProjectID: "sec",
			Nodes: []domain.WorkflowNode{{ID: "prep", Name: "prep", Type: "command", Command: "true", MaxAttempts: 1},
				gate(func(n *domain.WorkflowNode) {
					n.RejectTo, n.MaxReworks = "prep", 1
					n.Approvers = &domain.ApproverPolicy{UserIDs: []int64{8}}
				}), respond},
			Edges: []domain.WorkflowEdge{{ID: "0", Source: "prep", Target: "gate"}, {ID: "1", Source: "gate", Target: "respond"}}}
		r := startApprovalRun(t, e, s, wf)
		if n := e.SweepApprovalTimeouts(r.Nodes["gate"].Approval.Deadline.Add(time.Second)); n != 1 {
			t.Fatalf("fired %d", n)
		}
		waitForNode(t, s, r.ID, "prep", func(n *domain.NodeRun) bool { return n.ReworkCount == 1 })
		waitFor(t, s, r.ID, "waiting")
		got, _ := s.RunState(r.ID)
		if got.Nodes["gate"].Status != "waiting_approval" {
			t.Fatalf("gate after timeout rework = %s", got.Nodes["gate"].Status)
		}
		// The rework budget is spent: the next deadline fails the node.
		if n := e.SweepApprovalTimeouts(got.Nodes["gate"].Approval.Deadline.Add(time.Second)); n != 1 {
			t.Fatalf("second deadline fired %d", n)
		}
		waitFor(t, s, r.ID, "failed")
		rejected := false
		got, _ = s.RunState(r.ID)
		for _, ev := range got.Events {
			if ev.Type == "gate.rejected" && ev.ActorKind == domain.ActorSystem {
				rejected = true
			}
		}
		if !rejected {
			t.Fatal("no system gate.rejected event")
		}
		if n, m := len(approvalAudits(t, s, "approval.timeout_rejected")), len(approvalAudits(t, s, "approval.reject")); n != 2 || m != 0 {
			t.Fatalf("timeout audits %d, reject audits %d", n, m)
		}
	})
}

// TestApprovalDeadlineSurvivesRestart: the deadline is read from the store by
// engines that never saw the run start, and two replicas sweeping at once
// fire it exactly once.
func TestApprovalDeadlineSurvivesRestart(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	approvalTestProject(t, s)
	wf := domain.WorkflowDefinition{ID: "restart", Name: "restart", SandboxProfileID: "local", ProjectID: "sec",
		Nodes: []domain.WorkflowNode{
			{ID: "gate", Name: "gate", Type: "approval", MaxAttempts: 1, Approvers: &domain.ApproverPolicy{UserIDs: []int64{8}},
				Approval: &domain.ApprovalRule{TimeoutMinutes: 10, OnTimeout: domain.ApprovalOnTimeoutEscalate, EscalateTo: &domain.ApproverPolicy{Roles: []string{"member"}}}},
		}}
	r := startApprovalRun(t, e, s, wf)
	deadline := r.Nodes["gate"].Approval.Deadline
	waitForLeaseRelease(t, s, r.ID)

	var replicas []*Engine
	for _, id := range []string{"replica-a", "replica-b"} {
		reopened := repo.ReopenTest(s)
		replica := New(reopened, runtime.NewManager(filepath.Join(t.TempDir(), "workspaces")))
		replica.ConfigureExecution(id, "", 0, true)
		replicas = append(replicas, replica)
	}
	var wg sync.WaitGroup
	fired := make([]int, len(replicas))
	for i, replica := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fired[i] = replica.SweepApprovalTimeouts(deadline.Add(time.Second))
		}()
	}
	wg.Wait()
	if fired[0]+fired[1] != 1 {
		t.Fatalf("replicas fired %v, want exactly one", fired)
	}
	for _, replica := range replicas {
		if n := replica.SweepApprovalTimeouts(deadline.Add(time.Hour)); n != 0 {
			t.Fatalf("repeat sweep fired %d", n)
		}
	}
	got, _ := s.RunState(r.ID)
	count := 0
	for _, ev := range got.Events {
		if ev.Type == "gate.escalated" {
			count++
		}
	}
	if count != 1 || !got.Nodes["gate"].Approval.Escalated || got.OwnerInstanceID != "" {
		t.Fatalf("escalations %d approval %+v owner %q", count, got.Nodes["gate"].Approval, got.OwnerInstanceID)
	}
	// Anyone with the member role may decide now.
	if err := replicas[0].ApproveAs(r.ID, "gate", "", approvalUser(9)); err != nil {
		t.Fatalf("escalated approval: %v", err)
	}
	waitFor(t, s, r.ID, "succeeded")
}

func waitForLeaseRelease(t *testing.T, s *repo.Store, runID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r, _ := s.RunState(runID); r.OwnerInstanceID == "" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("the starting engine kept the lease of a waiting run")
}
