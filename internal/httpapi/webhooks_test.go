package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/engine"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
	"agentflow/internal/tracker"
)

type webhookFixture struct {
	t     *testing.T
	s     *repo.Store
	h     http.Handler
	owner domain.User
	runs  []string
}

func newWebhookFixture(t *testing.T) *webhookFixture {
	t.Helper()
	t.Setenv("AGENTFLOW_SESSION_SECRET", "webhook-test-session-secret")
	// Production deployments require login; the ingress must still work
	// without a session because it authenticates with its URL secret.
	t.Setenv("AGENTFLOW_AUTH_REQUIRED", "true")
	s, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	owner := domain.User{ID: 41, LoginName: "secops", ChineseName: "安全值班"}
	if err := s.PutUser(owner); err != nil {
		t.Fatal(err)
	}
	if err := s.PutProject(domain.Project{ID: "sec", Key: "SEC", Name: "SEC", OwnerID: owner.ID}); err != nil {
		t.Fatal(err)
	}
	wf := domain.WorkflowDefinition{ID: "phish", Name: "phish", ProjectID: "sec", SandboxProfileID: "local",
		Nodes: []domain.WorkflowNode{{ID: "noop", Name: "noop", Type: "command", Command: "true", MaxAttempts: 1}}}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	h := New(s, engine.New(s, runtime.NewManager(filepath.Join(t.TempDir(), "workspaces"))), tracker.NewService(), "", "")
	f := &webhookFixture{t: t, s: s, h: h, owner: owner}
	// Registered after TempDir, so it runs first: let started runs finish
	// writing their workspaces before the directory is removed.
	t.Cleanup(func() {
		deadline := time.Now().Add(30 * time.Second)
		for _, id := range f.runs {
			for time.Now().Before(deadline) {
				if r, ok := s.RunState(id); !ok || domain.TerminalRunStatus(r.Status) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	return f
}

func (f *webhookFixture) create(body map[string]any) webhookCreated {
	f.t.Helper()
	return requestJSONAuthed[webhookCreated](f.t, f.h, f.owner, http.MethodPost, "/api/webhooks", body, http.StatusCreated)
}

func (f *webhookFixture) hook(method, path string, body []byte, header map[string]string, remote string) (*httptest.ResponseRecorder, map[string]any) {
	f.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	if remote != "" {
		req.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if id, ok := out["runId"].(string); ok && rec.Code == http.StatusAccepted {
		f.runs = append(f.runs, id)
	}
	return rec, out
}

func TestWebhookManagementHidesSecrets(t *testing.T) {
	f := newWebhookFixture(t)
	created := f.create(map[string]any{"projectId": "sec", "workflowId": "phish", "name": "SIEM", "enabled": true,
		"signatureHeader": "X-Signature", "signingSecret": "hmac-key", "dedupFields": []string{"alert.id"}})
	if created.Secret == "" || created.Path != "/api/hooks/"+created.Webhook.ID+"/"+created.Secret {
		t.Fatalf("created = %+v", created)
	}
	w := created.Webhook
	if w.SigningSecret != "" || w.SecretHash != "" || !w.HasSigningSecret || w.CreatedBy != f.owner.ID || w.DedupWindowSeconds != domain.WebhookDefaultDedupWind || w.SecretPrefix != created.Secret[:6] {
		t.Fatalf("view = %+v", w)
	}
	list := requestJSONAuthed[[]map[string]any](t, f.h, f.owner, http.MethodGet, "/api/webhooks?projectId=sec", nil, http.StatusOK)
	raw, _ := json.Marshal(list)
	if len(list) != 1 || strings.Contains(string(raw), "hmac-key") || strings.Contains(string(raw), created.Secret) || strings.Contains(string(raw), "secretHash") {
		t.Fatalf("list leaks secrets: %s", raw)
	}

	// Updating without a signing secret keeps the stored one.
	updated := requestJSONAuthed[domain.Webhook](t, f.h, f.owner, http.MethodPut, "/api/webhooks/"+w.ID, map[string]any{
		"projectId": "other", "workflowId": "phish", "name": "SIEM 2", "enabled": false, "signatureHeader": "X-Signature"}, http.StatusOK)
	stored, _ := f.s.Webhook(w.ID)
	if updated.Name != "SIEM 2" || updated.ProjectID != "sec" || stored.SigningSecret != "hmac-key" || stored.SecretHash != domain.HashWebhookSecret(created.Secret) {
		t.Fatalf("update = %+v stored = %+v", updated, stored)
	}

	for name, body := range map[string]map[string]any{
		"unknown workflow":  {"projectId": "sec", "workflowId": "nope", "name": "x"},
		"bad cidr":          {"projectId": "sec", "workflowId": "phish", "name": "x", "allowedCidrs": []string{"nonsense"}},
		"header w/o secret": {"projectId": "sec", "workflowId": "phish", "name": "x", "signatureHeader": "X-Sig"},
		"bad method":        {"projectId": "sec", "workflowId": "phish", "name": "x", "methods": []string{"DELETE"}},
		"window too long":   {"projectId": "sec", "workflowId": "phish", "name": "x", "dedupFields": []string{"a"}, "dedupWindowSeconds": 9999999},
	} {
		got := requestJSONAuthed[map[string]string](t, f.h, f.owner, http.MethodPost, "/api/webhooks", body, http.StatusBadRequest)
		if got["error"] == "" {
			t.Errorf("%s: no error message", name)
		}
	}
	stranger := domain.User{ID: 77, LoginName: "stranger"}
	if err := f.s.PutUser(stranger); err != nil {
		t.Fatal(err)
	}
	requestJSONAuthed[map[string]any](t, f.h, stranger, http.MethodGet, "/api/webhooks/"+w.ID, nil, http.StatusForbidden)
	requestJSON[map[string]any](t, f.h, http.MethodGet, "/api/webhooks?projectId=sec", nil, http.StatusUnauthorized)
}

func TestWebhookIngressStartsDeduplicatesAndRejects(t *testing.T) {
	f := newWebhookFixture(t)
	created := f.create(map[string]any{"projectId": "sec", "workflowId": "phish", "name": "SIEM", "enabled": true,
		"titleField": "alert.title", "dedupFields": []string{"alert.rule", "alert.host"}, "dedupWindowSeconds": 600,
		"allowedCidrs": []string{"10.0.0.0/8", "192.0.2.7"}})
	path := created.Path
	body := []byte(`{"alert":{"title":"Phishing link clicked","rule":"R-17","host":"pc-9","severity":"high"}}`)

	rec, out := f.hook(http.MethodPost, path, body, nil, "10.1.2.3:5000")
	if rec.Code != http.StatusAccepted || out["status"] != "started" {
		t.Fatalf("first alert: %d %v", rec.Code, out)
	}
	runID, _ := out["runId"].(string)
	run, ok := f.s.RunState(runID)
	if !ok || run.Input != "Phishing link clicked" || !strings.Contains(string(run.TriggerPayload), `"severity":"high"`) || run.ExecutionContext.ResponsibleUserID != f.owner.ID || run.ExecutionContext.ProjectID != "sec" {
		t.Fatalf("run = ok %v input %q trigger %s ctx %+v", ok, run.Input, run.TriggerPayload, run.ExecutionContext)
	}

	// Same rule and host, different title: a duplicate of the first alert.
	rec, out = f.hook(http.MethodPost, path, []byte(`{"alert":{"title":"again","rule":"R-17","host":"pc-9"}}`), nil, "192.0.2.7:1")
	if rec.Code != http.StatusOK || out["status"] != "deduplicated" || out["runId"] != runID || out["hits"] != float64(2) {
		t.Fatalf("duplicate: %d %v", rec.Code, out)
	}
	rec, out = f.hook(http.MethodPost, path, []byte(`{"alert":{"rule":"R-17","host":"pc-10"}}`), nil, "10.0.0.1:1")
	if rec.Code != http.StatusAccepted || out["runId"] == runID {
		t.Fatalf("other host must start its own run: %d %v", rec.Code, out)
	}

	secretless := "/api/hooks/" + created.Webhook.ID + "/wrong"
	for name, c := range map[string]struct {
		method, path, remote string
		want                 int
	}{
		"wrong secret":   {http.MethodPost, secretless, "10.0.0.1:1", http.StatusUnauthorized},
		"unknown hook":   {http.MethodPost, "/api/hooks/wh-missing/" + created.Secret, "10.0.0.1:1", http.StatusUnauthorized},
		"blocked source": {http.MethodPost, path, "203.0.113.5:1", http.StatusForbidden},
		"wrong method":   {http.MethodPut, path, "10.0.0.1:1", http.StatusMethodNotAllowed},
	} {
		if rec, _ := f.hook(c.method, c.path, body, nil, c.remote); rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, c.want)
		}
	}
	if rec, _ := f.hook(http.MethodPost, path, []byte(`not json`), nil, "10.0.0.1:1"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json: %d", rec.Code)
	}
	big := append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), webhookMaxBody)...)
	if rec, _ := f.hook(http.MethodPost, path, append(big, []byte(`"}`)...), nil, "10.0.0.1:1"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", rec.Code)
	}

	deliveries := requestJSONAuthed[[]domain.WebhookDelivery](t, f.h, f.owner, http.MethodGet, "/api/webhooks/"+created.Webhook.ID+"/deliveries", nil, http.StatusOK)
	counts := map[string]int{}
	for _, d := range deliveries {
		counts[d.Status]++
	}
	// Unknown hooks and wrong secrets are not logged against the webhook.
	if counts["started"] != 2 || counts["deduplicated"] != 1 || counts["rejected"] != 4 {
		t.Fatalf("delivery counts = %v", counts)
	}

	// Disabling stops ingestion; rotating invalidates the old URL.
	requestJSONAuthed[domain.Webhook](t, f.h, f.owner, http.MethodPut, "/api/webhooks/"+created.Webhook.ID, map[string]any{"workflowId": "phish", "name": "SIEM", "enabled": false}, http.StatusOK)
	if rec, _ := f.hook(http.MethodPost, path, body, nil, "10.0.0.1:1"); rec.Code != http.StatusConflict {
		t.Errorf("disabled: %d", rec.Code)
	}
	requestJSONAuthed[domain.Webhook](t, f.h, f.owner, http.MethodPut, "/api/webhooks/"+created.Webhook.ID, map[string]any{"workflowId": "phish", "name": "SIEM", "enabled": true}, http.StatusOK)
	rotated := requestJSONAuthed[webhookCreated](t, f.h, f.owner, http.MethodPost, "/api/webhooks/"+created.Webhook.ID+"/rotate", nil, http.StatusOK)
	if rec, _ := f.hook(http.MethodPost, path, []byte(`{}`), nil, "10.0.0.1:1"); rec.Code != http.StatusUnauthorized {
		t.Errorf("old secret after rotation: %d", rec.Code)
	}
	if rec, _ := f.hook(http.MethodPost, rotated.Path, []byte(`[1,2]`), nil, "10.0.0.1:1"); rec.Code != http.StatusAccepted {
		t.Errorf("new secret: %d", rec.Code)
	}
}

func TestWebhookSignatureAndQueryPayload(t *testing.T) {
	f := newWebhookFixture(t)
	created := f.create(map[string]any{"projectId": "sec", "workflowId": "phish", "name": "EDR", "enabled": true,
		"methods": []string{"POST", "GET"}, "signatureHeader": "X-Hub-Signature-256", "signingSecret": "k3y"})
	body := []byte(`[{"id":1}]`)
	mac := hmac.New(sha256.New, []byte("k3y"))
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	rec, out := f.hook(http.MethodPost, created.Path, body, map[string]string{"X-Hub-Signature-256": good}, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("signed: %d %v", rec.Code, out)
	}
	run, _ := f.s.RunState(out["runId"].(string))
	if string(run.TriggerPayload) != `{"body":[{"id":1}]}` {
		t.Fatalf("non-object body must be wrapped: %s", run.TriggerPayload)
	}
	for _, sig := range []string{"", "sha256=00", strings.Repeat("a", 64)} {
		if rec, _ := f.hook(http.MethodPost, created.Path, body, map[string]string{"X-Hub-Signature-256": sig}, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("signature %q: %d", sig, rec.Code)
		}
	}
	// GET has no body to sign; signing an empty body still applies.
	mac = hmac.New(sha256.New, []byte("k3y"))
	rec, out = f.hook(http.MethodGet, created.Path+"?host=pc-1&tag=a&tag=b", nil, map[string]string{"X-Hub-Signature-256": hex.EncodeToString(mac.Sum(nil))}, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("GET: %d %v", rec.Code, out)
	}
	run, _ = f.s.RunState(out["runId"].(string))
	if string(run.TriggerPayload) != `{"host":"pc-1","tag":["a","b"]}` {
		t.Fatalf("query payload = %s", run.TriggerPayload)
	}
}

func TestWebhookPathIsRedactedInLogs(t *testing.T) {
	if got := redactWebhookPath("/api/hooks/wh-1/s3cret"); got != "/api/hooks/wh-1/[redacted]" {
		t.Fatalf("redacted = %q", got)
	}
	if got := redactWebhookPath("/api/webhooks/wh-1"); got != "/api/webhooks/wh-1" {
		t.Fatalf("management path changed: %q", got)
	}
}
