package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"agentflow/internal/domain"
)

func mustParse(t *testing.T, src string) *Connector {
	t.Helper()
	c, err := ParseTemplate([]byte(src), "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const vtLike = `
id: vt_test
title: VT Test
baseUrl: https://unused.example
auth: {type: header, name: x-apikey, secret: api_key}
secrets: [{name: api_key, label: Key, required: true}]
actions:
  - id: url_report
    title: URL
    category: enrichment
    inputs: [{name: url, type: string, required: true}]
    request:
      method: GET
      path: /api/v3/urls/{{ base64url(inputs.url) }}
    success: [200, 404]
    output:
      found: response.status == 200
      malicious: response.body.data.attributes.last_analysis_stats.malicious
  - id: domain
    title: Domain
    category: enrichment
    inputs: [{name: domain, type: string, required: true}, {name: days, type: number, default: 90}]
    request:
      method: GET
      path: /domains/{{ inputs.domain }}
      query: {days: "{{ inputs.days }}", empty: "{{ inputs.missing_is_null }}"}
`

func TestHeaderAuthPathEscapingAndOutputs(t *testing.T) {
	var gotKey, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath = r.Header.Get("x-apikey"), r.URL.EscapedPath()
		if strings.HasSuffix(r.URL.Path, "unknown") {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":7}}}}`)
	}))
	defer srv.Close()
	c := mustParse(t, strings.Replace(vtLike, "x", "x", 1))
	conn := &domain.Connection{ID: "cn1", ConnectorID: c.ID, Name: "vt", BaseURL: srv.URL, Secrets: map[string]string{"api_key": "sekret-123"}}
	x := NewExecutor(nil, nil)
	a, _ := c.Action("url_report")
	res, err := x.Execute(context.Background(), Call{Connector: c, Action: a, Connection: conn, Inputs: map[string]any{"url": "http://evil.example/a?b=1"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotKey != "sekret-123" {
		t.Fatalf("api key header = %q", gotKey)
	}
	if gotPath != "/api/v3/urls/aHR0cDovL2V2aWwuZXhhbXBsZS9hP2I9MQ" {
		t.Fatalf("path = %q", gotPath)
	}
	if res.Output["found"] != true || res.Output["malicious"] != 7.0 || res.Output["status"] != 200.0 {
		t.Fatalf("output = %#v", res.Output)
	}

	d, _ := c.Action("domain")
	res, err = x.Execute(context.Background(), Call{Connector: c, Action: d, Connection: conn, Inputs: map[string]any{"domain": "a/b c"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/domains/a%2Fb%20c" {
		t.Fatalf("path segment not escaped: %q", gotPath)
	}
	_ = res
}

func TestQueryAuthSecretIsRedactedFromErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		io.WriteString(w, "boom key="+r.URL.Query().Get("key"))
	}))
	defer srv.Close()
	c := mustParse(t, `
id: q_test
title: Q
auth: {type: query, name: key, secret: api_key}
secrets: [{name: api_key, label: Key, required: true}]
actions:
  - id: host
    title: Host
    category: enrichment
    inputs: [{name: ip, type: string, required: true}]
    request: {method: GET, path: "/host/{{ inputs.ip }}"}
`)
	conn := &domain.Connection{ID: "cn", ConnectorID: c.ID, Name: "q", BaseURL: srv.URL, Secrets: map[string]string{"api_key": "TOPSECRET"}}
	a, _ := c.Action("host")
	_, err := NewExecutor(nil, nil).Execute(context.Background(), Call{Connector: c, Action: a, Connection: conn, Inputs: map[string]any{"ip": "1.2.3.4"}})
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("secret leaked: %v", err)
	}
	// A transport error carries the URL, query secret included.
	conn.BaseURL = "http://127.0.0.1:1"
	_, err = NewExecutor(nil, nil).Execute(context.Background(), Call{Connector: c, Action: a, Connection: conn, Inputs: map[string]any{"ip": "1.2.3.4"}})
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("transport error leaked secret or did not fail: %v", err)
	}
}

func TestOAuthClientCredentialsTokenIsCached(t *testing.T) {
	var tokenCalls atomic.Int32
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tenant-1/token":
			tokenCalls.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "cs" || r.Form.Get("scope") != "api/.default" || r.Form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `{"access_token":"tok-1","expires_in":3600}`)
		default:
			auth = r.Header.Get("Authorization")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["Comment"] != "isolate pc-7" {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(201)
			io.WriteString(w, `{"id":"act-1","status":"Pending"}`)
		}
	}))
	defer srv.Close()
	c := mustParse(t, `
id: oauth_test
title: OAuth
auth:
  type: oauth2_client_credentials
  tokenUrl: "/{{ params.tenant }}/token"
  scope: api/.default
params: [{name: tenant, label: Tenant, required: true}]
secrets: [{name: client_id, label: ID, required: true}, {name: client_secret, label: Secret, required: true}]
actions:
  - id: isolate
    title: Isolate
    category: response
    inputs: [{name: machine, type: string, required: true}, {name: comment, type: string, required: true}]
    request:
      method: POST
      path: "/machines/{{ inputs.machine }}/isolate"
      body: {Comment: "{{ inputs.comment }}", Type: Full}
    output: {actionId: response.body.id}
`)
	conn := &domain.Connection{ID: "cn-o", ConnectorID: c.ID, Name: "o", BaseURL: srv.URL, Params: map[string]string{"tenant": "tenant-1"}, Secrets: map[string]string{"client_id": "cid", "client_secret": "cs"}}
	a, _ := c.Action("isolate")
	x := NewExecutor(nil, nil)
	for i := 0; i < 2; i++ {
		res, err := x.Execute(context.Background(), Call{Connector: c, Action: a, Connection: conn, Inputs: map[string]any{"machine": "m1", "comment": "isolate pc-7"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Output["actionId"] != "act-1" {
			t.Fatalf("output = %#v", res.Output)
		}
	}
	if auth != "Bearer tok-1" {
		t.Fatalf("authorization = %q", auth)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token fetched %d times, want 1", tokenCalls.Load())
	}
	// Missing required param fails before any call.
	bad := *conn
	bad.Params = nil
	if _, err := x.Execute(context.Background(), Call{Connector: c, Action: a, Connection: &bad, Inputs: map[string]any{"machine": "m1", "comment": "x"}}); err == nil || !strings.Contains(err.Error(), "Tenant") {
		t.Fatalf("missing param err = %v", err)
	}
}

func TestFailIfAndCrossHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect followed to another host with key %q", r.Header.Get("x-key"))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
			return
		}
		io.WriteString(w, `{"errcode":93000,"errmsg":"invalid webhook url"}`)
	}))
	defer srv.Close()
	c := mustParse(t, `
id: bot_test
title: Bot
auth: {type: header, name: x-key, secret: key}
secrets: [{name: key, label: Key, required: true}]
actions:
  - id: send
    title: Send
    category: utility
    request: {method: POST, path: /send, body: {msgtype: text}}
    failIf: response.body.errcode != 0
  - id: follow
    title: Follow
    category: utility
    request: {method: GET, path: /redirect}
    success: [302]
`)
	conn := &domain.Connection{ID: "cn-b", ConnectorID: c.ID, Name: "b", BaseURL: srv.URL, Secrets: map[string]string{"key": "k-secret"}}
	send, _ := c.Action("send")
	x := NewExecutor(nil, nil)
	if _, err := x.Execute(context.Background(), Call{Connector: c, Action: send, Connection: conn}); err == nil || !strings.Contains(err.Error(), "93000") {
		t.Fatalf("failIf err = %v", err)
	}
	follow, _ := c.Action("follow")
	if _, err := x.Execute(context.Background(), Call{Connector: c, Action: follow, Connection: conn}); err != nil {
		t.Fatalf("redirect should stop at the 302: %v", err)
	}
}

func TestCoerceInputs(t *testing.T) {
	a := &Action{Inputs: []Input{
		{Name: "n", Type: TypeNumber, Default: 90.0},
		{Name: "s", Type: TypeString, Required: true, Enum: []string{"Full", "Selective"}},
		{Name: "l", Type: TypeList},
		{Name: "b", Type: TypeBoolean},
	}}
	got, err := CoerceInputs(a, map[string]any{"s": "Full", "l": "1.2.3.4", "b": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if got["n"] != 90.0 || got["b"] != true || len(got["l"].([]any)) != 1 {
		t.Fatalf("got %#v", got)
	}
	if _, err := CoerceInputs(a, map[string]any{"s": "Half"}); err == nil {
		t.Fatal("enum not enforced")
	}
	if _, err := CoerceInputs(a, map[string]any{}); err == nil {
		t.Fatal("required not enforced")
	}
	if _, err := CoerceInputs(a, map[string]any{"s": "Full", "zzz": 1}); err == nil {
		t.Fatal("unknown input accepted")
	}
}

func TestBuiltinExtractIOCs(t *testing.T) {
	cat, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c, a, ok := cat.Action(BuiltinID, "extract_iocs")
	if !ok {
		t.Fatal("extract_iocs missing")
	}
	res, err := NewExecutor(nil, nil).Execute(context.Background(), Call{Connector: c, Action: a, Inputs: map[string]any{"value": map[string]any{"from": "bad@evil.example", "body": "visit http://evil.example/login from 203.0.113.9"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Output["url"].([]any)) != 1 || len(res.Output["ipv4"].([]any)) != 1 || res.Output["count"].(float64) < 4 {
		t.Fatalf("output = %#v", res.Output)
	}
	// Case actions need a case service and a case.
	cc, ca, _ := cat.Action(BuiltinID, "case_comment")
	if _, err := NewExecutor(nil, nil).Execute(context.Background(), Call{Connector: cc, Action: ca, Inputs: map[string]any{"body": "x"}}); err == nil {
		t.Fatal("case action without case service should fail")
	}
}

func TestGatedByApproval(t *testing.T) {
	wf := func(edges ...domain.WorkflowEdge) domain.WorkflowDefinition {
		return domain.WorkflowDefinition{Nodes: []domain.WorkflowNode{{ID: "triage", Type: "agent"}, {ID: "approve", Type: "approval"}, {ID: "isolate", Type: NodeType}, {ID: "other", Type: "script"}}, Edges: edges}
	}
	e := func(s, t, when string) domain.WorkflowEdge {
		return domain.WorkflowEdge{ID: s + t, Source: s, Target: t, When: when}
	}
	if !GatedByApproval(wf(e("triage", "approve", ""), e("approve", "isolate", "")), "isolate") {
		t.Fatal("approval → isolate should be gated")
	}
	if GatedByApproval(wf(e("triage", "isolate", "")), "isolate") {
		t.Fatal("no approval should not be gated")
	}
	if GatedByApproval(wf(e("triage", "approve", ""), e("approve", "isolate", ""), e("triage", "other", ""), e("other", "isolate", "")), "isolate") {
		t.Fatal("a second path bypassing the approval should not be gated")
	}
	if GatedByApproval(wf(e("triage", "approve", ""), e("approve", "isolate", "error")), "isolate") {
		t.Fatal("an approval's error edge (rejection) should not count as gated")
	}
}

func TestValidateWorkflowRejectsUngatedResponseAndUnknownInputs(t *testing.T) {
	cat, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	node := domain.WorkflowNode{ID: "iso", Type: NodeType, Action: &domain.NodeAction{Connector: "defender", Action: "isolate", ConnectionID: "cn", Inputs: map[string]string{"machine_id": "{{ trigger.machine }}", "comment": "x"}}}
	ungated := domain.WorkflowDefinition{Nodes: []domain.WorkflowNode{node}}
	if err := ValidateWorkflow(ungated, cat); err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("err = %v", err)
	}
	gated := domain.WorkflowDefinition{Nodes: []domain.WorkflowNode{{ID: "ok", Type: "approval"}, node}, Edges: []domain.WorkflowEdge{{ID: "e", Source: "ok", Target: "iso"}}}
	if err := ValidateWorkflow(gated, cat); err != nil {
		t.Fatal(err)
	}
	gated.Nodes[1].Action.Inputs["nope"] = "1"
	if err := ValidateWorkflow(gated, cat); err == nil {
		t.Fatal("unknown input accepted")
	}
	delete(gated.Nodes[1].Action.Inputs, "nope")
	gated.Nodes[1].Action.Inputs["comment"] = "{{ nodes.later.data.x }}"
	if err := ValidateWorkflow(gated, cat); err == nil || !strings.Contains(err.Error(), "upstream") {
		t.Fatalf("non-upstream ref err = %v", err)
	}
}
