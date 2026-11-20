package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentflow/internal/auth"
	"agentflow/internal/connector"
	"agentflow/internal/domain"
)

func TestConnectionsAPIHidesSecretsAndTests(t *testing.T) {
	f := newWebhookFixture(t)
	viewer := domain.User{ID: 62, LoginName: "viewer"}
	stranger := domain.User{ID: 63, LoginName: "stranger"}
	for _, u := range []domain.User{viewer, stranger} {
		if err := f.s.PutUser(u); err != nil {
			t.Fatal(err)
		}
	}
	project, _ := f.s.Project("sec")
	project.Members = []domain.ProjectMember{{UserID: viewer.ID, Role: "viewer"}}
	if err := f.s.PutProject(project); err != nil {
		t.Fatal(err)
	}
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "vt-secret" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"WrongCredentialsError"}`)
			return
		}
		io.WriteString(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":0},"reputation":5}}}`)
	}))
	defer vendor.Close()

	list := requestJSONAuthed[[]connector.Connector](t, f.h, viewer, http.MethodGet, "/api/connectors", nil, http.StatusOK)
	if len(list) < 12 || list[0].ID != connector.BuiltinID {
		t.Fatalf("catalog = %d connectors", len(list))
	}

	body := map[string]any{"projectId": "sec", "connectorId": "virustotal", "name": "团队 VT", "baseUrl": vendor.URL, "secrets": map[string]string{"api_key": "wrong"}}
	requestJSONAuthed[map[string]any](t, f.h, viewer, http.MethodPost, "/api/connections", body, http.StatusForbidden)
	created := requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPost, "/api/connections", body, http.StatusCreated)
	if created.ID == "" || strings.Join(created.SecretsSet, ",") != "api_key" {
		t.Fatalf("created = %+v", created)
	}
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/connections", map[string]any{"projectId": "sec", "connectorId": "virustotal", "name": "x", "secrets": map[string]string{"nope": "1"}}, http.StatusBadRequest)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/connections", map[string]any{"projectId": "sec", "connectorId": connector.BuiltinID, "name": "x"}, http.StatusBadRequest)

	// Reads never carry secret values.
	rec := requestAuthed(t, f.h, viewer, http.MethodGet, "/api/connections?projectId=sec", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "wrong") {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	requestJSONAuthed[map[string]any](t, f.h, stranger, http.MethodGet, "/api/connections?projectId=sec", nil, http.StatusForbidden)

	failed := requestJSONAuthed[connectionTestResult](t, f.h, f.owner, http.MethodPost, "/api/connections/"+created.ID+"/test", nil, http.StatusOK)
	if failed.OK || !strings.Contains(failed.Error, "HTTP 401") || strings.Contains(failed.Error, "wrong") {
		t.Fatalf("test with wrong key = %+v", failed)
	}
	// An empty secret keeps the stored value; a new one replaces it.
	requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPut, "/api/connections/"+created.ID, map[string]any{"name": "团队 VT", "secrets": map[string]string{"api_key": ""}}, http.StatusOK)
	if stored, _ := f.s.Connection(created.ID); stored.Secrets["api_key"] != "wrong" {
		t.Fatal("empty secret should keep the stored value")
	}
	requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPut, "/api/connections/"+created.ID, map[string]any{"secrets": map[string]string{"api_key": "vt-secret"}}, http.StatusOK)
	ok := requestJSONAuthed[connectionTestResult](t, f.h, f.owner, http.MethodPost, "/api/connections/"+created.ID+"/test", nil, http.StatusOK)
	if !ok.OK || ok.Output["reputation"] != 5.0 {
		t.Fatalf("test = %+v", ok)
	}
	requestJSONAuthed[map[string]any](t, f.h, viewer, http.MethodPost, "/api/connections/"+created.ID+"/test", nil, http.StatusForbidden)
	cleared := requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPut, "/api/connections/"+created.ID, map[string]any{"clearSecrets": []string{"api_key"}}, http.StatusOK)
	if len(cleared.SecretsSet) != 0 {
		t.Fatalf("cleared = %+v", cleared)
	}
	rec = requestAuthed(t, f.h, f.owner, http.MethodDelete, "/api/connections/"+created.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
}

// TestPlaybookCaseActionsFireTriggers runs a playbook of built-in case
// actions on a case: its comment and severity change land on the timeline
// attributed to the run, and the escalation fires the project's trigger,
// exactly as if an analyst had made the change.
func TestPlaybookCaseActionsFireTriggers(t *testing.T) {
	f := newWebhookFixture(t)
	wf := domain.WorkflowDefinition{ID: "triage", Name: "triage", ProjectID: "sec", SandboxProfileID: "local",
		Nodes: []domain.WorkflowNode{
			{ID: "note", Name: "note", Type: connector.NodeType, MaxAttempts: 1, Action: &domain.NodeAction{Connector: connector.BuiltinID, Action: "case_comment", Inputs: map[string]string{"body": "研判：{{ trigger.case.title }} 为钓鱼"}}},
			{ID: "raise", Name: "raise", Type: connector.NodeType, MaxAttempts: 1, Action: &domain.NodeAction{Connector: connector.BuiltinID, Action: "case_update", Inputs: map[string]string{"severity": "critical", "status": "investigating"}}},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "note", Target: "raise"}}}
	if err := f.s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	requestJSONAuthed[domain.CaseTrigger](t, f.h, f.owner, http.MethodPost, "/api/case-triggers", map[string]any{
		"projectId": "sec", "workflowId": "phish", "name": "on escalation", "enabled": true, "events": []string{"case.escalated"}}, http.StatusCreated)
	cs := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPost, "/api/cases", map[string]any{"projectId": "sec", "title": "Invoice lure", "severity": "low"}, http.StatusCreated)
	startedOut := requestJSONAuthed[map[string]string](t, f.h, f.owner, http.MethodPost, "/api/cases/"+cs.ID+"/runs", map[string]any{"workflowId": "triage"}, http.StatusCreated)
	started := domain.Run{ID: startedOut["runId"]}
	f.runs = append(f.runs, started.ID)
	f.waitRunsDone()
	if r, _ := f.s.RunState(started.ID); r.Status != "succeeded" {
		t.Fatalf("playbook run = %s %+v", r.Status, r.Nodes)
	}
	detail := requestJSONAuthed[caseDetail](t, f.h, f.owner, http.MethodGet, "/api/cases/"+cs.ID, nil, http.StatusOK)
	for _, r := range detail.Runs {
		f.runs = append(f.runs, r.ID)
	}
	if detail.Case.Severity != "critical" || detail.Case.Status != "investigating" || len(detail.Runs) != 2 {
		t.Fatalf("case = %+v runs = %+v", detail.Case, detail.Runs)
	}
	comment := false
	for _, ev := range detail.Events {
		if ev.Type == domain.CaseEventComment {
			comment = ev.Message == "研判：Invoice lure 为钓鱼" && ev.ActorKind == domain.ActorSystem && strings.Contains(string(ev.Data), started.ID)
		}
	}
	if !comment {
		t.Fatalf("playbook comment missing or unattributed: %+v", detail.Events)
	}
	if got := eventTypes(detail.Events); !strings.Contains(got, "case.severity_changed,case.escalated,case.status_changed") {
		t.Fatalf("timeline = %s", got)
	}
}

func requestAuthed(t *testing.T, h http.Handler, user domain.User, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	token, err := auth.NewClientFromEnv().SignUser(&auth.User{ID: user.ID, LoginName: user.LoginName, AuthTime: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
	req.Header.Set("Origin", "http://"+req.Host)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWorkflowSaveRejectsUngatedResponseAndForeignConnection(t *testing.T) {
	f := newWebhookFixture(t)
	if err := f.s.PutProject(domain.Project{ID: "other", Key: "OTH", Name: "other", OwnerID: f.owner.ID}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, c := range []domain.Connection{
		{ID: "cn-sec", ProjectID: "sec", ConnectorID: "crowdstrike", Name: "falcon", CreatedAt: now, UpdatedAt: now},
		{ID: "cn-other", ProjectID: "other", ConnectorID: "crowdstrike", Name: "falcon-other", CreatedAt: now, UpdatedAt: now},
	} {
		if err := f.s.PutConnection(c); err != nil {
			t.Fatal(err)
		}
	}
	wf := func(conn string, gated bool) domain.WorkflowDefinition {
		w := domain.WorkflowDefinition{ID: "contain-wf", Name: "contain", ProjectID: "sec", SandboxProfileID: "local",
			Nodes: []domain.WorkflowNode{
				{ID: "ok", Name: "ok", Type: "approval", MaxAttempts: 1},
				{ID: "contain", Name: "contain", Type: connector.NodeType, MaxAttempts: 1, Action: &domain.NodeAction{Connector: "crowdstrike", Action: "contain", ConnectionID: conn, Inputs: map[string]string{"device_id": "{{ trigger.device }}"}}},
			}}
		if gated {
			w.Edges = []domain.WorkflowEdge{{ID: "1", Source: "ok", Target: "contain"}}
		}
		return w
	}
	rec := requestAuthed(t, f.h, f.owner, http.MethodPut, "/api/workflows", wf("cn-sec", false))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "approval") {
		t.Fatalf("ungated: %d %s", rec.Code, rec.Body.String())
	}
	rec = requestAuthed(t, f.h, f.owner, http.MethodPut, "/api/workflows", wf("cn-other", true))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "another project") {
		t.Fatalf("foreign connection: %d %s", rec.Code, rec.Body.String())
	}
	rec = requestAuthed(t, f.h, f.owner, http.MethodPut, "/api/workflows", wf("cn-sec", true))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid: %d %s", rec.Code, rec.Body.String())
	}
}

func TestConnectionRateAndRetrySettings(t *testing.T) {
	f := newWebhookFixture(t)
	body := map[string]any{"projectId": "sec", "connectorId": "virustotal", "name": "VT", "secrets": map[string]string{"api_key": "k"},
		"rateLimitPerSecond": 2.5, "rateLimitBurst": 4, "maxRetries": 1}
	created := requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPost, "/api/connections", body, http.StatusCreated)
	if created.RateLimitPerSecond != 2.5 || created.RateLimitBurst != 4 || created.MaxRetries == nil || *created.MaxRetries != 1 {
		t.Fatalf("created = %+v", created)
	}
	// Omitted fields keep their values; null restores the default retries.
	updated := requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPut, "/api/connections/"+created.ID, map[string]any{"name": "VT 2"}, http.StatusOK)
	if updated.RateLimitPerSecond != 2.5 || updated.MaxRetries == nil {
		t.Fatalf("update without the fields = %+v", updated)
	}
	updated = requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPut, "/api/connections/"+created.ID, map[string]any{"maxRetries": nil, "rateLimitPerSecond": 0, "rateLimitBurst": 0}, http.StatusOK)
	stored, _ := f.s.Connection(created.ID)
	if updated.MaxRetries != nil || stored.Retries() != domain.ConnectionDefaultRetries || stored.RateLimitPerSecond != 0 {
		t.Fatalf("reset = %+v", stored)
	}
	for _, bad := range []map[string]any{{"maxRetries": 11}, {"maxRetries": "x"}, {"rateLimitPerSecond": -1}, {"rateLimitBurst": 5000}} {
		requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPut, "/api/connections/"+created.ID, bad, http.StatusBadRequest)
	}
}
