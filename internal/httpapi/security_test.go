package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agentflow/internal/domain"
)

func doBearer(t *testing.T, h http.Handler, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func putSecurityUsers(t *testing.T, f *webhookFixture) (viewer, stranger domain.User) {
	t.Helper()
	viewer = domain.User{ID: 72, LoginName: "analyst-viewer"}
	stranger = domain.User{ID: 73, LoginName: "stranger"}
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
	return viewer, stranger
}

func TestProjectReadIsolationForRuns(t *testing.T) {
	f := newWebhookFixture(t)
	viewer, stranger := putSecurityUsers(t, f)
	run := requestJSONAuthed[domain.Run](t, f.h, f.owner, http.MethodPost, "/api/runs", map[string]any{"workflowId": "phish", "projectId": "sec"}, http.StatusCreated)
	f.runs = append(f.runs, run.ID)
	f.waitRunsDone()

	list := requestAuthed(t, f.h, stranger, http.MethodGet, "/api/runs", nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), run.ID) {
		t.Fatalf("stranger run list: %d leaks run=%v", list.Code, strings.Contains(list.Body.String(), run.ID))
	}
	for _, path := range []string{"/api/runs/" + run.ID, "/api/runs/" + run.ID + "/logs", "/api/runs/" + run.ID + "/telemetry"} {
		if rec := requestAuthed(t, f.h, stranger, http.MethodGet, path, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("stranger GET %s = %d", path, rec.Code)
		}
	}
	if rec := requestAuthed(t, f.h, viewer, http.MethodGet, "/api/runs/"+run.ID, nil); rec.Code != http.StatusOK {
		t.Fatalf("viewer member GET run = %d", rec.Code)
	}
	if rec := requestAuthed(t, f.h, viewer, http.MethodGet, "/api/runs", nil); !strings.Contains(rec.Body.String(), run.ID) {
		t.Fatal("viewer member should see the run in the list")
	}
	t.Setenv("AGENTFLOW_PROJECT_READ_ISOLATION", "false")
	if rec := requestAuthed(t, f.h, stranger, http.MethodGet, "/api/runs/"+run.ID, nil); rec.Code != http.StatusOK {
		t.Fatalf("isolation off: stranger GET run = %d", rec.Code)
	}
}

func TestScopedTokens(t *testing.T) {
	f := newWebhookFixture(t)
	_, stranger := putSecurityUsers(t, f)
	if err := f.s.PutProject(domain.Project{ID: "other", Key: "OTH", Name: "other", OwnerID: f.owner.ID}); err != nil {
		t.Fatal(err)
	}
	type created struct {
		Token    string          `json:"token"`
		Metadata domain.APIToken `json:"metadata"`
	}
	scoped := requestJSONAuthed[created](t, f.h, f.owner, http.MethodPost, "/api/auth/tokens", map[string]any{"name": "soc bot", "scopes": []string{"read", "cases:write"}, "projectIds": []string{"sec"}}, http.StatusCreated)
	if strings.Join(scoped.Metadata.Scopes, ",") != "read,cases:write" || strings.Join(scoped.Metadata.ProjectIDs, ",") != "sec" {
		t.Fatalf("metadata = %+v", scoped.Metadata)
	}
	listed := requestJSONAuthed[[]domain.APIToken](t, f.h, f.owner, http.MethodGet, "/api/auth/tokens", nil, http.StatusOK)
	if len(listed) != 1 || strings.Join(listed[0].Scopes, ",") != "read,cases:write" {
		t.Fatalf("stored token = %+v", listed)
	}
	tok := scoped.Token
	if rec := doBearer(t, f.h, tok, http.MethodGet, "/api/cases?projectId=sec", nil); rec.Code != http.StatusOK {
		t.Fatalf("read sec cases = %d %s", rec.Code, rec.Body.String())
	}
	if rec := doBearer(t, f.h, tok, http.MethodPost, "/api/cases", map[string]any{"projectId": "sec", "title": "from bot", "severity": "low"}); rec.Code != http.StatusCreated {
		t.Fatalf("create case = %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/runs", map[string]any{"workflowId": "phish", "projectId": "sec"}},
		{http.MethodPost, "/api/case-triggers", map[string]any{"projectId": "sec", "workflowId": "phish", "name": "x", "events": []string{"case.created"}}},
	} {
		if rec := doBearer(t, f.h, tok, c.method, c.path, c.body); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "缺少权限") {
			t.Fatalf("%s %s = %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	if rec := doBearer(t, f.h, tok, http.MethodGet, "/api/cases?projectId=other", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other project read = %d", rec.Code)
	}
	if rec := doBearer(t, f.h, tok, http.MethodPost, "/api/cases", map[string]any{"projectId": "other", "title": "x", "severity": "low"}); rec.Code != http.StatusForbidden {
		t.Fatalf("other project write = %d", rec.Code)
	}
	// MCP tool calls are checked as their own requests.
	rpc := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "runs_start", "arguments": map[string]any{"body": map[string]any{"workflowId": "phish", "projectId": "sec"}}}}
	if rec := doBearer(t, f.h, tok, http.MethodPost, "/mcp", rpc); !strings.Contains(rec.Body.String(), "缺少权限") && !strings.Contains(rec.Body.String(), "403") {
		t.Fatalf("MCP call bypassed scopes: %d %s", rec.Code, rec.Body.String())
	}

	// Legacy tokens keep full access.
	full := requestJSONAuthed[created](t, f.h, f.owner, http.MethodPost, "/api/auth/tokens", map[string]any{"name": "legacy"}, http.StatusCreated)
	if rec := doBearer(t, f.h, full.Token, http.MethodGet, "/api/cases?projectId=other", nil); rec.Code != http.StatusOK {
		t.Fatalf("legacy token read = %d", rec.Code)
	}

	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/auth/tokens", map[string]any{"name": "x", "scopes": []string{"admin"}}, http.StatusBadRequest)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/auth/tokens", map[string]any{"name": "x", "scopes": []string{"root"}}, http.StatusBadRequest)
	requestJSONAuthed[map[string]any](t, f.h, stranger, http.MethodPost, "/api/auth/tokens", map[string]any{"name": "x", "projectIds": []string{"sec"}}, http.StatusBadRequest)
}

func TestAuditLogRecordsAndExports(t *testing.T) {
	f := newWebhookFixture(t)
	_, stranger := putSecurityUsers(t, f)
	auditor := domain.User{ID: 80, LoginName: "auditor"}
	if err := f.s.PutUser(auditor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GrantPlatformAdmin(auditor.LoginName); err != nil {
		t.Fatal(err)
	}
	// A failed password login is recorded with the attempted name.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", strings.NewReader(`{"login":"secops","password":"wrong-password"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+req.Host)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login = %d", rec.Code)
	}
	created := requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/auth/tokens", map[string]any{"name": "bot", "scopes": []string{"cases:write"}}, http.StatusCreated)
	token := created["token"].(string)
	if rec := doBearer(t, f.h, token, http.MethodPost, "/api/cases", map[string]any{"projectId": "sec", "title": "bot case", "severity": "low"}); rec.Code != http.StatusCreated {
		t.Fatalf("bot case = %d", rec.Code)
	}
	requestAuthed(t, f.h, stranger, http.MethodGet, "/api/cases?projectId=sec", nil)

	events := requestJSONAuthed[[]domain.AuditEvent](t, f.h, auditor, http.MethodGet, "/api/audit", nil, http.StatusOK)
	find := func(match func(domain.AuditEvent) bool) *domain.AuditEvent {
		for i := range events {
			if match(events[i]) {
				return &events[i]
			}
		}
		return nil
	}
	if e := find(func(e domain.AuditEvent) bool { return e.Action == "auth.login" }); e == nil || e.ActorLogin != "secops" || e.Outcome != domain.AuditDenied {
		t.Fatalf("login failure event = %+v", e)
	}
	if e := find(func(e domain.AuditEvent) bool { return e.Action == "auth.token.create" }); e == nil || e.ActorUserID != f.owner.ID || !strings.Contains(string(e.Detail), "cases:write") {
		t.Fatalf("token creation event = %+v", e)
	}
	if e := find(func(e domain.AuditEvent) bool { return e.Action == "api POST /api/cases" }); e == nil || e.TokenID == "" || e.ActorUserID != f.owner.ID || e.Outcome != domain.AuditSuccess || e.ProjectID != "sec" {
		t.Fatalf("token write event = %+v", e)
	}
	if e := find(func(e domain.AuditEvent) bool {
		return e.Action == "api GET /api/cases" && e.ActorUserID == stranger.ID
	}); e == nil || e.Outcome != domain.AuditDenied || e.ProjectID != "sec" {
		t.Fatalf("denied read event = %+v", e)
	}
	if e := find(func(e domain.AuditEvent) bool {
		return strings.Contains(e.Action, "/api/auth/tokens") && e.Action != "auth.token.create"
	}); e != nil {
		t.Fatalf("token listing should not be logged as a write: %+v", e)
	}

	csvRec := requestAuthed(t, f.h, auditor, http.MethodGet, "/api/audit/export?format=csv&action=auth.", nil)
	if csvRec.Code != http.StatusOK || !strings.HasPrefix(csvRec.Header().Get("Content-Type"), "text/csv") || !strings.Contains(csvRec.Body.String(), "time,action,outcome") || !strings.Contains(csvRec.Body.String(), "auth.login") || strings.Contains(csvRec.Body.String(), "api POST") {
		t.Fatalf("csv export: %d %q", csvRec.Code, csvRec.Body.String())
	}
	if rec := requestAuthed(t, f.h, f.owner, http.MethodGet, "/api/audit", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin audit read = %d", rec.Code)
	}
	if rec := doBearer(t, f.h, token, http.MethodGet, "/api/audit", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("token audit read = %d", rec.Code)
	}
}
