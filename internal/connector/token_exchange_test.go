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

// The shipped Lark template exchanges app credentials for a tenant token,
// caches it, and sends message content as an escaped JSON string.
func TestLarkTemplateExchangesTokenAndEscapesContent(t *testing.T) {
	cat, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c, ok := cat.Connector("lark")
	if !ok {
		t.Fatal("lark connector missing")
	}
	var tokenCalls atomic.Int32
	var gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			tokenCalls.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || body["app_id"] != "cli_1" || body["app_secret"] != "s3cret" {
				io.WriteString(w, `{"code":10014,"msg":"app secret invalid"}`)
				return
			}
			io.WriteString(w, `{"code":0,"msg":"ok","tenant_access_token":"t-abc","expire":7200}`)
		case "/open-apis/im/v1/messages":
			gotAuth = r.Header.Get("Authorization")
			if r.URL.Query().Get("receive_id_type") != "chat_id" {
				io.WriteString(w, `{"code":230001,"msg":"bad receive_id_type"}`)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			io.WriteString(w, `{"code":0,"msg":"success","data":{"message_id":"om_1"}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	conn := &domain.Connection{ID: "cn-lark", ConnectorID: "lark", Name: "lark", BaseURL: srv.URL, Secrets: map[string]string{"app_id": "cli_1", "app_secret": "s3cret"}}
	x := NewExecutor(nil, nil)
	markdown := "**告警** \"钓鱼\"\n<a> & 'x'"
	send, _ := c.Action("send_card")
	for i := 0; i < 2; i++ {
		res, err := x.Execute(context.Background(), Call{Connector: c, Action: send, Connection: conn, Inputs: map[string]any{"chat_id": "oc_1", "title": `高危 "A"`, "markdown": markdown, "color": "red"}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Output["messageId"] != "om_1" {
			t.Fatalf("output = %#v", res.Output)
		}
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token fetched %d times, want 1", tokenCalls.Load())
	}
	if gotAuth != "Bearer t-abc" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotBody["receive_id"] != "oc_1" || gotBody["msg_type"] != "interactive" {
		t.Fatalf("body = %#v", gotBody)
	}
	var card struct {
		Header struct {
			Template string `json:"template"`
			Title    struct {
				Content string `json:"content"`
			} `json:"title"`
		} `json:"header"`
		Elements []struct {
			Content string `json:"content"`
		} `json:"elements"`
	}
	content, _ := gotBody["content"].(string)
	if err := json.Unmarshal([]byte(content), &card); err != nil {
		t.Fatalf("content is not JSON: %v: %s", err, content)
	}
	if card.Header.Template != "red" || card.Header.Title.Content != `高危 "A"` || len(card.Elements) != 1 || card.Elements[0].Content != markdown {
		t.Fatalf("card = %+v", card)
	}

	// A rejected exchange names the vendor's message and never the secret.
	bad := *conn
	bad.ID = "cn-lark-bad"
	bad.Secrets = map[string]string{"app_id": "cli_1", "app_secret": "wrong-secret"}
	text, _ := c.Action("send_text")
	_, err = x.Execute(context.Background(), Call{Connector: c, Action: text, Connection: &bad, Inputs: map[string]any{"chat_id": "oc_1", "text": "hi"}})
	if err == nil || !strings.Contains(err.Error(), "app secret invalid") || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("bad secret err = %v", err)
	}
}

func TestTokenExchangeValidation(t *testing.T) {
	base := `
id: tx
title: TX
baseUrl: https://unused.example
secrets: [{name: key, label: Key, required: true}]
actions: [{id: a, title: A, category: enrichment, request: {method: GET, path: /a}}]
auth:
  type: token_exchange
`
	for name, auth := range map[string]string{
		"no url":            "  tokenBody: {k: key}\n  tokenField: token\n",
		"no body":           "  tokenUrl: /t\n  tokenField: token\n",
		"no field":          "  tokenUrl: /t\n  tokenBody: {k: key}\n",
		"undeclared secret": "  tokenUrl: /t\n  tokenBody: {k: other}\n  tokenField: token\n",
	} {
		if _, err := ParseTemplate([]byte(base+auth), "test"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseTemplate([]byte(base+"  tokenUrl: /t\n  tokenBody: {k: key}\n  tokenField: data.token\n  expiresField: data.ttl\n"), "test"); err != nil {
		t.Fatal(err)
	}
}
