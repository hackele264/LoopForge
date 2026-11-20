package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agentflow/internal/domain"
)

const splunkLike = `
id: splunk_test
title: Splunk Test
auth: {type: bearer, secret: token}
secrets: [{name: token, label: Token, required: true}]
actions:
  - id: search
    title: Search
    category: enrichment
    inputs: [{name: search, type: string, required: true}]
    request:
      method: POST
      path: /services/search/jobs
      form: {search: "{{ inputs.search }}", exec_mode: oneshot, output_mode: json}
    output:
      items: response.body.results
`

// A self-signed server (a Splunk management port) is reachable only through
// the certificate it is pinned to, or a CA bundle that trusts it.
func TestConnectionTLSPinAndCABundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Header.Get("Authorization") != "Bearer tok" || r.PostForm.Get("exec_mode") != "oneshot" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"results":[{"_time":"2026-11-20T08:00:00.000+00:00","search_name":"Notable"}]}`)
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	pin := hex.EncodeToString(sum[:])
	c := mustParse(t, splunkLike)
	a, _ := c.Action("search")
	x := NewExecutor(nil, nil)
	call := func(conn domain.Connection) (Result, error) {
		conn.ConnectorID, conn.Name, conn.BaseURL, conn.Secrets = c.ID, "splunk", srv.URL, map[string]string{"token": "tok"}
		return x.Execute(context.Background(), Call{Connector: c, Action: a, Connection: &conn, Inputs: map[string]any{"search": "search index=notable"}})
	}

	if _, err := call(domain.Connection{ID: "plain"}); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an unpinned self-signed server must fail verification, got %v", err)
	}
	res, err := call(domain.Connection{ID: "pinned", TLSCertSHA256: pin})
	if err != nil {
		t.Fatalf("pinned call: %v", err)
	}
	if items, _ := res.Output["items"].([]any); len(items) != 1 {
		t.Fatalf("output = %v", res.Output)
	}
	wrong := strings.Repeat("0", 64)
	if _, err := call(domain.Connection{ID: "wrong", TLSCertSHA256: wrong}); err == nil || !strings.Contains(err.Error(), "指纹") {
		t.Fatalf("a wrong pin must fail, got %v", err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if _, err := call(domain.Connection{ID: "ca", TLSCAPEM: ca}); err != nil {
		t.Fatalf("CA bundle call: %v", err)
	}
	if _, err := call(domain.Connection{ID: "ca+wrong-pin", TLSCAPEM: ca, TLSCertSHA256: wrong}); err == nil {
		t.Fatal("a CA bundle must not bypass a wrong pin")
	}
}

func TestConnectionTLSValidation(t *testing.T) {
	base := domain.Connection{ProjectID: "p", ConnectorID: "splunk", Name: "s", BaseURL: "https://splunk:8089"}
	ok := base
	ok.TLSCertSHA256 = domain.NormalizeCertPin(strings.ToUpper("AB:" + strings.Repeat("cd", 31)))
	if err := ok.ValidateConnectionBase(); err != nil {
		t.Fatalf("openssl-style pin rejected: %v", err)
	}
	for name, mutate := range map[string]func(*domain.Connection){
		"short pin":  func(c *domain.Connection) { c.TLSCertSHA256 = "abcd" },
		"not PEM":    func(c *domain.Connection) { c.TLSCAPEM = "hello" },
		"http + pin": func(c *domain.Connection) { c.BaseURL, c.TLSCertSHA256 = "http://splunk:8089", strings.Repeat("a", 64) },
	} {
		c := base
		mutate(&c)
		if err := c.ValidateConnectionBase(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
