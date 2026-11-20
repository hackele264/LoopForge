package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"agentflow/internal/domain"
	"agentflow/internal/engine"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
	"agentflow/internal/secretbox"
	"agentflow/internal/tracker"
)

// TestConnectionsAPIWithEncryptedSecrets stores secrets sealed at rest, never
// returns them (nor their envelope) from the API, and fails clearly, without
// using empty secrets, when the key no longer matches.
func TestConnectionsAPIWithEncryptedSecrets(t *testing.T) {
	key, _ := secretbox.New(bytes.Repeat([]byte{7}, secretbox.KeySize))
	f := newWebhookFixture(t, repo.WithSecretKeyring(key))
	var gotKey string
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-apikey")
		w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":0},"reputation":1}}}`))
	}))
	defer vendor.Close()

	body := map[string]any{"projectId": "sec", "connectorId": "virustotal", "name": "vt", "baseUrl": vendor.URL, "secrets": map[string]string{"api_key": "vt-very-secret"}}
	created := requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPost, "/api/connections", body, http.StatusCreated)

	var raw []byte
	if err := f.s.DB.Raw("SELECT secrets FROM connections WHERE id = ?", created.ID).Row().Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), `"`+secretbox.Prefix) || strings.Contains(string(raw), "vt-very-secret") {
		t.Fatalf("stored secrets column = %s", raw)
	}
	for _, path := range []string{"/api/connections?projectId=sec", "/api/connections/" + created.ID} {
		rec := requestAuthed(t, f.h, f.owner, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "vt-very-secret") || strings.Contains(rec.Body.String(), "lfenc") {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	res := requestJSONAuthed[connectionTestResult](t, f.h, f.owner, http.MethodPost, "/api/connections/"+created.ID+"/test", nil, http.StatusOK)
	if !res.OK || gotKey != "vt-very-secret" {
		t.Fatalf("test = %+v, vendor saw key %q", res, gotKey)
	}

	// The same database under another key: secret reads fail, nothing is
	// sent. Viewing the record needs no secrets and still works.
	other, _ := secretbox.New(bytes.Repeat([]byte{8}, secretbox.KeySize))
	s2 := repo.ReopenTest(f.s, repo.WithSecretKeyring(other))
	h2 := New(s2, engine.New(s2, runtime.NewManager(filepath.Join(t.TempDir(), "w"))), tracker.NewService(), "", "")
	gotKey = ""
	if rec := requestAuthed(t, h2, f.owner, http.MethodGet, "/api/connections/"+created.ID, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "vt-very-secret") {
		t.Fatalf("GET with wrong key: %d %s", rec.Code, rec.Body.String())
	}
	if rec := requestAuthed(t, h2, f.owner, http.MethodPut, "/api/connections/"+created.ID, map[string]any{"name": "renamed"}); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "vt-very-secret") {
		t.Fatalf("PUT with wrong key: %d %s", rec.Code, rec.Body.String())
	}
	rec := requestAuthed(t, h2, f.owner, http.MethodPost, "/api/connections/"+created.ID+"/test", nil)
	if rec.Code != http.StatusServiceUnavailable || gotKey != "" {
		t.Fatalf("test with wrong key: %d %s (vendor saw %q)", rec.Code, rec.Body.String(), gotKey)
	}
	if c, err := f.s.Connection(created.ID); err != nil || c.Name != "vt" {
		t.Fatalf("connection changed by a failed update: %+v %v", c, err)
	}
	// A connection whose secrets cannot be read can still be deleted.
	if rec := requestAuthed(t, h2, f.owner, http.MethodDelete, "/api/connections/"+created.ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE with wrong key: %d %s", rec.Code, rec.Body.String())
	}
}
