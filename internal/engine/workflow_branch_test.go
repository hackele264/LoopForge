package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"agentflow/internal/apperr"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
)

// legacyReadyNodes is the readiness rule before conditional workflows: every
// upstream node succeeded. Kept here as the reference for the property test.
func legacyReadyNodes(wf domain.WorkflowDefinition, r domain.Run) []string {
	deps := map[string][]string{}
	for _, e := range wf.Edges {
		deps[e.Target] = append(deps[e.Target], e.Source)
	}
	var out []string
	for _, n := range wf.Nodes {
		if r.Nodes[n.ID].Status != "pending" {
			continue
		}
		ready := true
		for _, d := range deps[n.ID] {
			if r.Nodes[d].Status != "succeeded" {
				ready = false
			}
		}
		if ready {
			out = append(out, n.ID)
		}
	}
	return out
}

func nodeIDs(nodes []domain.WorkflowNode) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

// TestReadyNodesMatchesLegacyWithoutBranching is the compatibility guarantee:
// with only success edges, join "all" and no RunIf, the new scheduler picks
// exactly the nodes the old one did and never skips anything.
func TestReadyNodesMatchesLegacyWithoutBranching(t *testing.T) {
	t.Parallel()
	statuses := []string{"pending", "running", "succeeded", "failed", "waiting_approval", "cancelled", "pending_input"}
	rng := rand.New(rand.NewSource(42))
	for iteration := 0; iteration < 10000; iteration++ {
		size := 1 + rng.Intn(9)
		wf := domain.WorkflowDefinition{ID: "p"}
		r := domain.Run{Nodes: map[string]*domain.NodeRun{}}
		for i := 0; i < size; i++ {
			id := fmt.Sprintf("n%d", i)
			wf.Nodes = append(wf.Nodes, domain.WorkflowNode{ID: id})
			r.Nodes[id] = &domain.NodeRun{NodeID: id, Status: statuses[rng.Intn(len(statuses))]}
		}
		for target := 1; target < size; target++ {
			for source := 0; source < target; source++ {
				if rng.Intn(3) == 0 {
					when := ""
					if rng.Intn(2) == 0 {
						when = "success"
					}
					wf.Edges = append(wf.Edges, domain.WorkflowEdge{ID: fmt.Sprintf("e%d-%d", source, target), Source: fmt.Sprintf("n%d", source), Target: fmt.Sprintf("n%d", target), When: when})
				}
			}
		}
		got, want := nodeIDs(readyNodes(wf, r)), legacyReadyNodes(wf, r)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("iteration %d: readyNodes = %v, legacy = %v\nworkflow=%+v", iteration, got, want, wf.Edges)
		}
		if decisions := branchDecisions(wf, r); len(decisions) != 0 {
			t.Fatalf("iteration %d: legacy workflow produced branch decisions %+v", iteration, decisions)
		}
	}
}

func branchRun(statuses map[string]string) domain.Run {
	r := domain.Run{Nodes: map[string]*domain.NodeRun{}}
	for id, status := range statuses {
		r.Nodes[id] = &domain.NodeRun{NodeID: id, Status: status}
	}
	return r
}

func TestEdgeOutcomes(t *testing.T) {
	t.Parallel()
	success := domain.WorkflowEdge{Source: "a", Target: "b"}
	errEdge := domain.WorkflowEdge{Source: "a", Target: "b", When: "error"}
	cases := []struct {
		name   string
		source *domain.NodeRun
		edge   domain.WorkflowEdge
		want   edgeOutcome
	}{
		{"succeeded success", &domain.NodeRun{Status: "succeeded"}, success, edgeTaken},
		{"succeeded error", &domain.NodeRun{Status: "succeeded"}, errEdge, edgeDead},
		{"routed success", &domain.NodeRun{Status: "failed", ErrorRouted: true}, success, edgeDead},
		{"routed error", &domain.NodeRun{Status: "failed", ErrorRouted: true}, errEdge, edgeTaken},
		{"unrouted failure", &domain.NodeRun{Status: "failed"}, errEdge, edgeUndecided},
		{"skipped", &domain.NodeRun{Status: "skipped"}, success, edgeDead},
		{"running", &domain.NodeRun{Status: "running"}, success, edgeUndecided},
		{"waiting", &domain.NodeRun{Status: "waiting_approval"}, success, edgeUndecided},
		{"missing", nil, success, edgeUndecided},
	}
	for _, c := range cases {
		if got := edgeOutcomeOf(c.edge, c.source); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestSettleBranchesSkipsAndPropagates(t *testing.T) {
	t.Parallel()
	// triage -> malicious(runIf) -> isolate -> notify(join any) <- close(runIf) <- triage
	wf := domain.WorkflowDefinition{
		Nodes: []domain.WorkflowNode{
			{ID: "triage"},
			{ID: "malicious", RunIf: `nodes.triage.data.verdict == "malicious"`},
			{ID: "isolate"},
			{ID: "close", RunIf: `nodes.triage.data.verdict == "benign"`},
			{ID: "notify", Join: "any"},
			{ID: "audit"},
		},
		Edges: []domain.WorkflowEdge{
			{ID: "1", Source: "triage", Target: "malicious"},
			{ID: "2", Source: "malicious", Target: "isolate"},
			{ID: "3", Source: "triage", Target: "close"},
			{ID: "4", Source: "isolate", Target: "notify"},
			{ID: "5", Source: "close", Target: "notify"},
			{ID: "6", Source: "isolate", Target: "audit"},
			{ID: "7", Source: "close", Target: "audit"},
		},
	}
	r := branchRun(map[string]string{"triage": "succeeded", "malicious": "pending", "isolate": "pending", "close": "pending", "notify": "pending", "audit": "pending"})
	r.Nodes["triage"].Data = domain.RawJSON(`{"verdict":"benign"}`)

	if got := nodeIDs(readyNodes(wf, r)); !reflect.DeepEqual(got, []string{"close"}) {
		t.Fatalf("ready = %v, want [close]", got)
	}
	if !settleBranches(wf, &r) {
		t.Fatal("expected the malicious branch to settle")
	}
	for id, want := range map[string]string{"malicious": "skipped", "isolate": "skipped", "close": "pending", "notify": "pending", "audit": "skipped"} {
		if got := r.Nodes[id].Status; got != want {
			t.Errorf("%s = %s, want %s", id, got, want)
		}
	}
	if r.Nodes["malicious"].SkipReason != domain.SkipReasonConditionFalse || r.Nodes["isolate"].SkipReason != domain.SkipReasonBranchNotTaken {
		t.Errorf("skip reasons = %q / %q", r.Nodes["malicious"].SkipReason, r.Nodes["isolate"].SkipReason)
	}
	// join any: notify waits for close even though isolate is dead.
	if got := nodeIDs(readyNodes(wf, r)); !reflect.DeepEqual(got, []string{"close"}) {
		t.Fatalf("ready after settle = %v, want [close]", got)
	}
	r.Nodes["close"].Status = "succeeded"
	if got := nodeIDs(readyNodes(wf, r)); !reflect.DeepEqual(got, []string{"notify"}) {
		t.Fatalf("ready after close = %v, want [notify]", got)
	}
	r.Nodes["notify"].Status = "succeeded"
	if !allSucceeded(wf, r) || hasFailed(wf, r) {
		t.Fatal("a run with only succeeded and skipped nodes must settle as succeeded")
	}
	skippedEvents := 0
	for _, ev := range r.Events {
		if ev.Type == "node.skipped" {
			skippedEvents++
		}
	}
	if skippedEvents != 3 {
		t.Errorf("node.skipped events = %d, want 3", skippedEvents)
	}
}

func TestRunIfEvaluationErrorFailsNodeAndRoutes(t *testing.T) {
	t.Parallel()
	wf := domain.WorkflowDefinition{
		Nodes: []domain.WorkflowNode{{ID: "a"}, {ID: "b", RunIf: `trigger.count < "x"`}, {ID: "fallback"}},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "a", Target: "b"}, {ID: "2", Source: "b", Target: "fallback", When: "error"}},
	}
	r := branchRun(map[string]string{"a": "succeeded", "b": "pending", "fallback": "pending"})
	r.TriggerPayload = domain.RawJSON(`{"count": 3}`)
	settleBranches(wf, &r)
	if r.Nodes["b"].Status != "failed" || !r.Nodes["b"].ErrorRouted {
		t.Fatalf("b = %+v, want failed and routed", r.Nodes["b"])
	}
	if got := nodeIDs(readyNodes(wf, r)); !reflect.DeepEqual(got, []string{"fallback"}) {
		t.Fatalf("ready = %v, want [fallback]", got)
	}
	if hasFailed(wf, r) {
		t.Fatal("a routed failure must not fail the run")
	}
}

func TestValidateWorkflowBranching(t *testing.T) {
	t.Parallel()
	base := func() domain.WorkflowDefinition {
		return domain.WorkflowDefinition{
			Nodes: []domain.WorkflowNode{{ID: "a"}, {ID: "b"}, {ID: "c", Type: "approval"}},
			Edges: []domain.WorkflowEdge{{ID: "1", Source: "a", Target: "b"}, {ID: "2", Source: "b", Target: "c"}},
		}
	}
	ok := base()
	ok.Nodes[2].RunIf = `nodes.a.data.x == 1 && nodes["b"].status == "succeeded"`
	ok.Nodes[2].Join = "any"
	ok.Nodes[2].Approvers = &domain.ApproverPolicy{Roles: []string{"owner"}}
	ok.Edges[1].When = "error"
	if err := domain.ValidateWorkflowBranching(ok); err != nil {
		t.Fatalf("valid workflow rejected: %v", err)
	}
	bad := map[string]func(*domain.WorkflowDefinition){
		"not upstream":           func(w *domain.WorkflowDefinition) { w.Nodes[0].RunIf = `nodes.c.status == "x"` },
		"compile error":          func(w *domain.WorkflowDefinition) { w.Nodes[1].RunIf = `nodes.a.data.x ==` },
		"unknown join":           func(w *domain.WorkflowDefinition) { w.Nodes[1].Join = "some" },
		"unknown edge condition": func(w *domain.WorkflowDefinition) { w.Edges[0].When = "maybe" },
		"approvers on agent":     func(w *domain.WorkflowDefinition) { w.Nodes[0].Approvers = &domain.ApproverPolicy{UserIDs: []int64{1}} },
		"unknown approver role": func(w *domain.WorkflowDefinition) {
			w.Nodes[2].Approvers = &domain.ApproverPolicy{Roles: []string{"boss"}}
		},
		"schema not object": func(w *domain.WorkflowDefinition) { w.Nodes[0].OutputSchema = json.RawMessage(`[1]`) },
	}
	for name, mutate := range bad {
		w := base()
		mutate(&w)
		if err := domain.ValidateWorkflowBranching(w); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func newBranchEngine(t *testing.T) (*Engine, *repo.Store) {
	t.Helper()
	s, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return New(s, runtime.NewManager(filepath.Join(t.TempDir(), "workspaces"))), s
}

func nodeStatuses(r domain.Run) map[string]string {
	out := map[string]string{}
	for id, n := range r.Nodes {
		out[id] = n.Status
	}
	return out
}

// TestConditionalWorkflowRunsEndToEnd runs real script nodes: a classifier
// writes structured output, conditions pick one branch, a join-any node runs
// once, and an always-failing script is handed to its error edge.
func TestConditionalWorkflowRunsEndToEnd(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	wf := domain.WorkflowDefinition{ID: "soar-branch", Name: "branch", SandboxProfileID: "local",
		Nodes: []domain.WorkflowNode{
			{ID: "classify", Name: "classify", Type: "script", ScriptLanguage: "shell", MaxAttempts: 1,
				Script:       `sev=$(sed -n 's/.*"severity": *"\([a-z]*\)".*/\1/p' "$LOOPFORGE_TRIGGER"); printf '{"verdict":"%s","score":0.9}' "$sev" > "$LOOPFORGE_OUTPUT"`,
				OutputSchema: json.RawMessage(`{"type":"object","required":["verdict"],"properties":{"verdict":{"type":"string"}}}`)},
			{ID: "high", Name: "high", Type: "command", Command: "true", MaxAttempts: 1, RunIf: `nodes.classify.data.verdict == "high" && nodes.classify.data.score >= 0.8`},
			{ID: "low", Name: "low", Type: "command", Command: "true", MaxAttempts: 1, RunIf: `nodes.classify.data.verdict == "low"`},
			{ID: "after-low", Name: "after-low", Type: "command", Command: "true", MaxAttempts: 1},
			{ID: "notify", Name: "notify", Type: "command", Command: "true", MaxAttempts: 1, Join: "any"},
			{ID: "boom", Name: "boom", Type: "command", Command: "exit 3", MaxAttempts: 1},
			{ID: "cleanup", Name: "cleanup", Type: "command", Command: "true", MaxAttempts: 1},
			{ID: "never", Name: "never", Type: "command", Command: "true", MaxAttempts: 1},
		},
		Edges: []domain.WorkflowEdge{
			{ID: "1", Source: "classify", Target: "high", When: "success"},
			{ID: "2", Source: "classify", Target: "low", When: "success"},
			{ID: "3", Source: "low", Target: "after-low", When: "success"},
			{ID: "4", Source: "high", Target: "notify", When: "success"},
			{ID: "5", Source: "after-low", Target: "notify", When: "success"},
			{ID: "6", Source: "notify", Target: "boom", When: "success"},
			{ID: "7", Source: "boom", Target: "cleanup", When: "error"},
			{ID: "8", Source: "boom", Target: "never", When: "success"},
		}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	r, err := e.StartWithTrigger(wf.ID, "", json.RawMessage(`{"severity": "high"}`), nil, domain.TelemetryContext{})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "succeeded")
	got, _ := s.RunState(r.ID)
	want := map[string]string{"classify": "succeeded", "high": "succeeded", "low": "skipped", "after-low": "skipped",
		"notify": "succeeded", "boom": "failed", "cleanup": "succeeded", "never": "skipped"}
	if statuses := nodeStatuses(got); !reflect.DeepEqual(statuses, want) {
		t.Fatalf("statuses = %v\nwant       %v", statuses, want)
	}
	if !got.Nodes["boom"].ErrorRouted {
		t.Fatal("boom's failure should be routed to its error edge")
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(got.Nodes["classify"].Data), &data); err != nil || data["verdict"] != "high" {
		t.Fatalf("classify data = %s (%v)", got.Nodes["classify"].Data, err)
	}
	if string(got.TriggerPayload) != `{"severity": "high"}` {
		t.Fatalf("trigger payload = %s", got.TriggerPayload)
	}
}

func TestScriptOutputSchemaViolationFailsNode(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	wf := domain.WorkflowDefinition{ID: "soar-schema", Name: "schema", SandboxProfileID: "local",
		Nodes: []domain.WorkflowNode{{ID: "out", Name: "out", Type: "script", ScriptLanguage: "shell", MaxAttempts: 1,
			Script:       `printf '{"verdict": 3}' > "$LOOPFORGE_OUTPUT"`,
			OutputSchema: json.RawMessage(`{"type":"object","properties":{"verdict":{"type":"string"}}}`)}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	r, err := e.Start(wf.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "failed")
	got, _ := s.RunState(r.ID)
	if n := got.Nodes["out"]; n.Status != "failed" || len(n.Data) != 0 {
		t.Fatalf("out = status %s data %s error %q", n.Status, n.Data, n.Error)
	}
}

func TestApproverPolicyAndActorAudit(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	project := domain.Project{ID: "sec", Key: "SEC", Name: "sec", OwnerID: 1, Members: []domain.ProjectMember{{UserID: 7, Role: "viewer"}, {UserID: 8, Role: "member"}}}
	if err := s.PutProject(project); err != nil {
		t.Fatal(err)
	}
	wf := domain.WorkflowDefinition{ID: "soar-approve", Name: "approve", SandboxProfileID: "local", ProjectID: "sec",
		Nodes: []domain.WorkflowNode{
			{ID: "gate", Name: "gate", Type: "approval", MaxAttempts: 1, Approvers: &domain.ApproverPolicy{UserIDs: []int64{42}, Roles: []string{"member"}}},
			{ID: "respond", Name: "respond", Type: "command", Command: "true", MaxAttempts: 1},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "gate", Target: "respond"}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	r, err := e.StartWithRepositoriesContext(wf.ID, "", nil, domain.TelemetryContext{ProjectID: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "waiting")
	for name, actor := range map[string]domain.Actor{
		"anonymous": {},
		"service":   {Kind: domain.ActorService},
		"viewer":    {UserID: 7, Kind: domain.ActorUser, Login: "viewer"},
		"stranger":  {UserID: 99, Kind: domain.ActorUser, Login: "stranger"},
	} {
		err := e.ApproveAs(r.ID, "gate", "", actor)
		var ae *apperr.Error
		if !errors.As(err, &ae) || ae.Kind != apperr.Forbidden {
			t.Fatalf("%s: ApproveAs error = %v, want forbidden", name, err)
		}
	}
	if err := e.ApproveAs(r.ID, "gate", "looks right", domain.Actor{UserID: 8, Kind: domain.ActorUser, Login: "analyst"}); err != nil {
		t.Fatalf("member approval: %v", err)
	}
	waitFor(t, s, r.ID, "succeeded")
	got, _ := s.RunState(r.ID)
	if got.Nodes["gate"].DecidedBy != 8 || got.Nodes["gate"].DecidedAt.IsZero() {
		t.Fatalf("gate decision = by %d at %v", got.Nodes["gate"].DecidedBy, got.Nodes["gate"].DecidedAt)
	}
	found := false
	for _, ev := range got.Events {
		if ev.Type == "gate.approved" {
			found = ev.ActorUserID == 8 && ev.ActorKind == domain.ActorUser
		}
	}
	if !found {
		t.Fatalf("gate.approved event lacks the actor: %+v", got.Events)
	}
}

func TestApproverPolicyAllows(t *testing.T) {
	t.Parallel()
	project := domain.Project{OwnerID: 1, Members: []domain.ProjectMember{{UserID: 2, Role: "maintainer"}, {UserID: 3, Role: "member"}, {UserID: 4, Role: "viewer"}}}
	user := func(id int64) domain.Actor { return domain.Actor{UserID: id, Kind: domain.ActorUser} }
	cases := []struct {
		roles []string
		actor domain.Actor
		admin bool
		want  bool
	}{
		{[]string{"owner"}, user(1), false, true},
		{[]string{"owner"}, user(2), false, false},
		{[]string{"maintainer"}, user(2), false, true},
		{[]string{"maintainer"}, user(3), false, false},
		{[]string{"member"}, user(3), false, true},
		{[]string{"member"}, user(4), false, false},
		{[]string{"admin"}, user(9), true, true},
		{[]string{"admin"}, user(9), false, false},
		{[]string{"member"}, domain.Actor{UserID: 3, Kind: domain.ActorService}, false, false},
		{[]string{"member"}, domain.Actor{UserID: 3, Kind: domain.ActorBot}, false, true},
	}
	for i, c := range cases {
		p := &domain.ApproverPolicy{Roles: c.roles}
		if got := p.Allows(c.actor, project, c.admin); got != c.want {
			t.Errorf("case %d (%v, %+v, admin=%v) = %v, want %v", i, c.roles, c.actor, c.admin, got, c.want)
		}
	}
}

func TestRejectResetClearsBranchState(t *testing.T) {
	t.Parallel()
	n := &domain.NodeRun{Status: "skipped", SkipReason: "condition_false", Data: domain.RawJSON(`{}`), ErrorRouted: true, DecidedBy: 3}
	n.ResetBranchState()
	if n.SkipReason != "" || n.Data != "" || n.ErrorRouted || n.DecidedBy != 0 || !n.DecidedAt.IsZero() {
		t.Fatalf("branch state not cleared: %+v", n)
	}
}

// TestAgentStructuredOutputDrivesBranches runs a mock agent that submits
// structured output; a condition on it picks the downstream branch. An agent
// that declares a schema but never submits fails instead of passing silently.
func TestAgentStructuredOutputDrivesBranches(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	for id, prompt := range map[string]string{
		"judge-submits": `研判告警 [[mock:output={"verdict":"malicious","confidence":0.95}]]`,
		"judge-silent":  `研判告警，但不提交结构化结果`,
	} {
		if err := s.PutAgent(domain.AgentDefinition{ID: id, Name: id, ExecutorID: "mock", Prompt: prompt}); err != nil {
			t.Fatal(err)
		}
	}
	schema := json.RawMessage(`{"type":"object","required":["verdict"],"properties":{"verdict":{"enum":["malicious","benign"]},"confidence":{"type":"number"}}}`)
	flow := func(id, agent string) domain.WorkflowDefinition {
		return domain.WorkflowDefinition{ID: id, Name: id, SandboxProfileID: "local",
			Nodes: []domain.WorkflowNode{
				{ID: "judge", Name: "judge", Type: "agent", AgentID: agent, ExecutorID: "mock", MaxAttempts: 1, OutputSchema: schema},
				{ID: "contain", Name: "contain", Type: "command", Command: "true", MaxAttempts: 1, RunIf: `nodes.judge.data.verdict == "malicious" && nodes.judge.data.confidence > 0.9`},
				{ID: "close", Name: "close", Type: "command", Command: "true", MaxAttempts: 1, RunIf: `nodes.judge.data.verdict == "benign"`},
			},
			Edges: []domain.WorkflowEdge{{ID: "1", Source: "judge", Target: "contain"}, {ID: "2", Source: "judge", Target: "close"}}}
	}
	ok := flow("agent-output-ok", "judge-submits")
	silent := flow("agent-output-missing", "judge-silent")
	for _, wf := range []domain.WorkflowDefinition{ok, silent} {
		if err := s.PutWorkflow(wf); err != nil {
			t.Fatal(err)
		}
	}
	r, err := e.Start(ok.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "succeeded")
	got, _ := s.RunState(r.ID)
	if statuses := nodeStatuses(got); !reflect.DeepEqual(statuses, map[string]string{"judge": "succeeded", "contain": "succeeded", "close": "skipped"}) {
		t.Fatalf("statuses = %v", statuses)
	}
	if got.Nodes["judge"].Data != `{"confidence":0.95,"verdict":"malicious"}` {
		t.Fatalf("judge data = %s", got.Nodes["judge"].Data)
	}

	r, err = e.Start(silent.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "failed")
	got, _ = s.RunState(r.ID)
	if n := got.Nodes["judge"]; n.Status != "failed" || !strings.Contains(n.Error, "submit_output") {
		t.Fatalf("silent judge = %s / %q", n.Status, n.Error)
	}
}
