package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
)

type fakeCaseService struct {
	mu       sync.Mutex
	comments []string
	changes  []connector.CaseChange
	runs     []connector.RunContext
}

func (f *fakeCaseService) CaseComment(_ context.Context, run connector.RunContext, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.comments = append(f.comments, body)
	f.runs = append(f.runs, run)
	return nil
}

func (f *fakeCaseService) CaseUpdate(_ context.Context, run connector.RunContext, change connector.CaseChange) (domain.Case, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, change)
	f.runs = append(f.runs, run)
	return domain.Case{Number: 1, Status: change.Status, Severity: "high"}, nil
}

func (f *fakeCaseService) CaseAddIOCs(context.Context, connector.RunContext, []domain.CaseIOC) (int, error) {
	return 0, nil
}

// TestActionNodesRunPhishingPlaybook runs a phishing playbook made of
// action nodes against a fake vendor: extract IOCs from the alert, look up
// the URL, ask for approval only when it is malicious, contain the host,
// then close the case.
func TestActionNodesRunPhishingPlaybook(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	cases := &fakeCaseService{}
	e.SetCaseService(cases)

	var mu sync.Mutex
	var contained []any
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v3/urls/"):
			if r.Header.Get("x-apikey") != "vt-key" {
				w.WriteHeader(401)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/v3/urls/")
			raw, _ := base64.RawURLEncoding.DecodeString(id)
			if string(raw) != "http://login-micros0ft.example/reset" {
				w.WriteHeader(404)
				return
			}
			io.WriteString(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":12,"suspicious":1}}}}`)
		case r.URL.Path == "/oauth2/token":
			io.WriteString(w, `{"access_token":"cs-token","expires_in":1800}`)
		case r.URL.Path == "/devices/entities/devices-actions/v2":
			if r.Header.Get("Authorization") != "Bearer cs-token" || r.URL.Query().Get("action_name") != "contain" {
				w.WriteHeader(403)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			contained = body["ids"].([]any)
			mu.Unlock()
			w.WriteHeader(202)
			io.WriteString(w, `{"resources":[{"id":"dev-9"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer vendor.Close()

	if err := s.PutProject(domain.Project{ID: "sec", Key: "SEC", Name: "sec"}); err != nil {
		t.Fatal(err)
	}
	cs, err := s.CreateCase(domain.Case{ID: "case-1", ProjectID: "sec", Title: "phish", Severity: "high", Status: "new"}, repo.CaseChange{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, c := range []domain.Connection{
		{ID: "cn-vt", ProjectID: "sec", ConnectorID: "virustotal", Name: "vt", BaseURL: vendor.URL, Secrets: map[string]string{"api_key": "vt-key"}, CreatedAt: now, UpdatedAt: now},
		{ID: "cn-cs", ProjectID: "sec", ConnectorID: "crowdstrike", Name: "falcon", BaseURL: vendor.URL, Secrets: map[string]string{"client_id": "id", "client_secret": "secret"}, CreatedAt: now, UpdatedAt: now},
		{ID: "cn-other", ProjectID: "elsewhere", ConnectorID: "virustotal", Name: "foreign", BaseURL: vendor.URL, Secrets: map[string]string{"api_key": "vt-key"}, CreatedAt: now, UpdatedAt: now},
	} {
		if err := s.PutConnection(c); err != nil {
			t.Fatal(err)
		}
	}

	action := func(id, conn, connectorID, act string, inputs map[string]string) domain.WorkflowNode {
		return domain.WorkflowNode{ID: id, Name: id, Type: connector.NodeType, MaxAttempts: 1, Action: &domain.NodeAction{Connector: connectorID, Action: act, ConnectionID: conn, Inputs: inputs}}
	}
	wf := domain.WorkflowDefinition{ID: "phish", Name: "phish", SandboxProfileID: "local", ProjectID: "sec",
		Nodes: []domain.WorkflowNode{
			action("extract", "", connector.BuiltinID, "extract_iocs", map[string]string{"value": "{{ trigger }}"}),
			action("vt", "cn-vt", "virustotal", "url_report", map[string]string{"url": "{{ first(nodes.extract.data.url) }}"}),
			{ID: "approve", Name: "approve", Type: "approval", MaxAttempts: 1, RunIf: "nodes.vt.data.malicious > 0"},
			action("contain", "cn-cs", "crowdstrike", "contain", map[string]string{"device_id": "{{ trigger.alert.device_id }}"}),
			action("close", "", connector.BuiltinID, "case_update", map[string]string{"status": "closed", "resolution": "resolved"}),
		},
		Edges: []domain.WorkflowEdge{
			{ID: "1", Source: "extract", Target: "vt"},
			{ID: "2", Source: "vt", Target: "approve"},
			{ID: "3", Source: "approve", Target: "contain"},
			{ID: "4", Source: "contain", Target: "close"},
		}}
	if err := validate(wf); err != nil {
		t.Fatal(err)
	}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	trigger := json.RawMessage(`{"alert":{"subject":"Reset your password","body":"click http://login-micros0ft.example/reset now","device_id":"dev-9"}}`)
	r, err := e.StartWithTrigger(wf.ID, "", trigger, nil, domain.TelemetryContext{ProjectID: "sec", CaseID: cs.ID})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "waiting")
	got, _ := s.RunState(r.ID)
	var vt map[string]any
	if err := json.Unmarshal([]byte(got.Nodes["vt"].Data), &vt); err != nil || vt["malicious"] != 12.0 {
		t.Fatalf("vt data = %s (%v)", got.Nodes["vt"].Data, err)
	}
	mu.Lock()
	if contained != nil {
		mu.Unlock()
		t.Fatal("the host was contained before the approval")
	}
	mu.Unlock()
	if err := e.ApproveAs(r.ID, "approve", "confirmed phishing", domain.Actor{UserID: 1, Kind: domain.ActorUser, Login: "analyst"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "succeeded")
	mu.Lock()
	if len(contained) != 1 || contained[0] != "dev-9" {
		t.Fatalf("contain ids = %v", contained)
	}
	mu.Unlock()
	cases.mu.Lock()
	if len(cases.changes) != 1 || cases.changes[0].Status != "closed" || cases.runs[0].CaseID != cs.ID || cases.runs[0].RunID != r.ID {
		t.Fatalf("case changes = %+v runs = %+v", cases.changes, cases.runs)
	}
	cases.mu.Unlock()
	events, err := s.CaseEvents(cs.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, ev := range events {
		if ev.Type == domain.CaseEventAction {
			actions = append(actions, ev.Message)
		}
	}
	if len(actions) != 2 || !strings.Contains(strings.Join(actions, "\n"), "动作「CrowdStrike Falcon · 网络隔离终端」成功（HTTP 202，连接「falcon」）") {
		t.Fatalf("case action events = %v", actions)
	}
	approved := false
	for _, ev := range events {
		if ev.Type == domain.CaseEventApproval {
			approved = ev.ActorUserID == 1 && ev.Message == "批准了「approve」：confirmed phishing"
		}
	}
	if !approved {
		t.Fatalf("approval missing from the case timeline: %+v", events)
	}

	// A connection of another project is refused at run time.
	wf2 := domain.WorkflowDefinition{ID: "foreign", Name: "foreign", SandboxProfileID: "local", ProjectID: "sec",
		Nodes: []domain.WorkflowNode{action("vt", "cn-other", "virustotal", "url_report", map[string]string{"url": "http://x.example/"})}}
	if err := s.PutWorkflow(wf2); err != nil {
		t.Fatal(err)
	}
	r2, err := e.StartWithTrigger(wf2.ID, "", json.RawMessage(`{}`), nil, domain.TelemetryContext{ProjectID: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r2.ID, "failed")
	got2, _ := s.RunState(r2.ID)
	if !strings.Contains(got2.Nodes["vt"].Error, "不属于本运行所在的项目") {
		t.Fatalf("foreign connection error = %q", got2.Nodes["vt"].Error)
	}
}

func TestValidateRejectsUngatedResponseAction(t *testing.T) {
	wf := domain.WorkflowDefinition{ID: "bad", Name: "bad", SandboxProfileID: "local",
		Nodes: []domain.WorkflowNode{{ID: "contain", Name: "contain", Type: connector.NodeType, MaxAttempts: 1,
			Action: &domain.NodeAction{Connector: "crowdstrike", Action: "contain", ConnectionID: "cn", Inputs: map[string]string{"device_id": "d"}}}}}
	if err := validate(wf); err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("validate = %v", err)
	}
}

// TestResponseApprovalNeedsInteractivePerson: an approval whose success path
// reaches a response action refuses service callers and API tokens.
func TestResponseApprovalNeedsInteractivePerson(t *testing.T) {
	t.Parallel()
	e, s := newBranchEngine(t)
	wf := domain.WorkflowDefinition{ID: "contain-approval", Name: "contain", SandboxProfileID: "local",
		Nodes: []domain.WorkflowNode{
			{ID: "ok", Name: "确认隔离", Type: "approval", MaxAttempts: 1},
			{ID: "contain", Name: "contain", Type: connector.NodeType, MaxAttempts: 1, Action: &domain.NodeAction{Connector: "crowdstrike", Action: "contain", ConnectionID: "missing", Inputs: map[string]string{"device_id": "d"}}},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "ok", Target: "contain"}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	r, err := e.StartWithTrigger(wf.ID, "", json.RawMessage(`{}`), nil, domain.TelemetryContext{})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, r.ID, "waiting")
	for name, actor := range map[string]domain.Actor{
		"service": {Kind: domain.ActorService},
		"token":   {UserID: 5, Kind: domain.ActorUser, Login: "bot", TokenID: "tok-1"},
	} {
		if err := e.ApproveAs(r.ID, "ok", "", actor); err == nil {
			t.Fatalf("%s approval of a response gate was accepted", name)
		}
	}
	if err := e.ApproveAs(r.ID, "ok", "", domain.Actor{UserID: 5, Kind: domain.ActorUser, Login: "analyst"}); err != nil {
		t.Fatalf("interactive approval: %v", err)
	}
	// The containment then fails on the missing connection, which is fine:
	// the point is that the gate opened only for a person.
	waitFor(t, s, r.ID, "failed")
}
