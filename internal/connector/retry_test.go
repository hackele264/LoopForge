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
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/ratelimit"
)

const retryTemplate = `
id: retry_test
title: Retry
auth: {type: query, name: key, secret: api_key}
secrets: [{name: api_key, label: Key, required: true}]
actions:
  - id: lookup
    title: Lookup
    category: enrichment
    request: {method: GET, path: /lookup}
  - id: isolate
    title: Isolate
    category: response
    request: {method: POST, path: /isolate, body: {host: h1}}
`

// fastExecutor retries with millisecond backoff and its own limit registry.
func fastExecutor() *Executor {
	x := NewExecutor(nil, nil)
	x.retryBase = time.Millisecond
	x.limitReg = ratelimit.NewRegistry()
	return x
}

func retryCall(t *testing.T, base, action string) (Call, *domain.Connection) {
	t.Helper()
	c := mustParse(t, retryTemplate)
	a, _ := c.Action(action)
	conn := &domain.Connection{ID: "cn-retry", ConnectorID: c.ID, Name: "r", BaseURL: base, Secrets: map[string]string{"api_key": "TOPSECRET"}}
	return Call{Connector: c, Action: a, Connection: conn}, conn
}

func TestRetryOn429HonoursRetryAfterForAnyMethod(t *testing.T) {
	var calls atomic.Int32
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	call, _ := retryCall(t, srv.URL, "isolate")
	started := time.Now()
	res, err := fastExecutor().Execute(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond {
		t.Fatalf("Retry-After ignored: retried after %v", elapsed)
	}
	if bodies[1] != bodies[0] || !strings.Contains(bodies[1], "h1") {
		t.Fatalf("retried body differs: %q", bodies)
	}
	retries, _ := res.Output["retries"].([]any)
	if len(retries) != 1 {
		t.Fatalf("retries output = %#v", res.Output["retries"])
	}
	entry := retries[0].(map[string]any)
	if entry["status"] != 429.0 || entry["waitMs"] != 1000.0 {
		t.Fatalf("retry entry = %#v", entry)
	}
	if !strings.Contains(res.Summary, "重试 1 次") {
		t.Fatalf("summary = %q", res.Summary)
	}
}

func TestRetryOn5xxOnlyForGet(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "down key="+r.URL.Query().Get("key"))
			return
		}
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	get, _ := retryCall(t, srv.URL, "lookup")
	res, err := fastExecutor().Execute(context.Background(), get)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || len(res.Output["retries"].([]any)) != 2 {
		t.Fatalf("GET calls = %d, output = %#v", calls.Load(), res.Output)
	}
	raw, _ := json.Marshal(res.Output)
	if strings.Contains(string(raw), "TOPSECRET") {
		t.Fatalf("secret in output: %s", raw)
	}

	calls.Store(0)
	post, _ := retryCall(t, srv.URL, "isolate")
	_, err = fastExecutor().Execute(context.Background(), post)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("POST err = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("POST was retried on 5xx: %d calls", calls.Load())
	}
	if strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("secret leaked: %v", err)
	}
}

func TestRetriesAreBoundedAndConfigurable(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	call, conn := retryCall(t, srv.URL, "lookup")
	_, err := fastExecutor().Execute(context.Background(), call)
	if err == nil || !strings.Contains(err.Error(), "重试 3 次") {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 1+domain.ConnectionDefaultRetries {
		t.Fatalf("calls = %d", calls.Load())
	}
	zero := 0
	conn.MaxRetries = &zero
	calls.Store(0)
	if _, err := fastExecutor().Execute(context.Background(), call); err == nil {
		t.Fatal("expected failure")
	}
	if calls.Load() != 1 {
		t.Fatalf("maxRetries 0 still retried: %d calls", calls.Load())
	}
}

func TestRetryTransportErrorOnlyForGet(t *testing.T) {
	call, _ := retryCall(t, "http://127.0.0.1:1", "lookup")
	_, err := fastExecutor().Execute(context.Background(), call)
	if err == nil || !strings.Contains(err.Error(), "重试 3 次") || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("GET transport err = %v", err)
	}
	post, _ := retryCall(t, "http://127.0.0.1:1", "isolate")
	_, err = fastExecutor().Execute(context.Background(), post)
	if err == nil || strings.Contains(err.Error(), "重试") {
		t.Fatalf("POST transport err = %v", err)
	}
}

func TestRetryWaitStopsOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	call, _ := retryCall(t, srv.URL, "lookup")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	_, err := fastExecutor().Execute(ctx, call)
	if err == nil {
		t.Fatal("expected an error")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("cancel did not stop the wait: %v", elapsed)
	}

	// A deadline shorter than Retry-After fails at once instead of waiting.
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started = time.Now()
	_, err = fastExecutor().Execute(ctx, call)
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") || time.Since(started) > time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(started))
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := map[string]time.Duration{
		"":     0,
		"7":    7 * time.Second,
		"0":    0,
		"-3":   0,
		"9999": retryMaxWait,
		"soon": 0,
		now.Add(12 * time.Second).Format(http.TimeFormat): 12 * time.Second,
		now.Add(-time.Minute).Format(http.TimeFormat):     0,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBackoffGrowsWithJitterAndCap(t *testing.T) {
	x := NewExecutor(nil, nil)
	for attempt, max := range map[int]time.Duration{1: 500 * time.Millisecond, 2: time.Second, 3: 2 * time.Second, 20: retryMaxBackoff} {
		for i := 0; i < 20; i++ {
			d := x.backoff(attempt)
			if d < max/2 || d > max {
				t.Fatalf("backoff(%d) = %v, want within [%v, %v]", attempt, d, max/2, max)
			}
		}
	}
}

func TestConnectionRateLimitSpacesCalls(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	call, conn := retryCall(t, srv.URL, "lookup")
	conn.RateLimitPerSecond, conn.RateLimitBurst = 10, 2
	x := fastExecutor()
	started := time.Now()
	for i := 0; i < 4; i++ {
		if _, err := x.Execute(context.Background(), call); err != nil {
			t.Fatal(err)
		}
	}
	// Two go at once, the next two wait 100ms each.
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond {
		t.Fatalf("4 calls at 10/s with burst 2 took only %v", elapsed)
	}
	// A cancelled wait does not send the request.
	conn.RateLimitPerSecond, conn.RateLimitBurst = 0.01, 1
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	before := calls.Load()
	_, _ = x.Execute(ctx, call) // takes the fresh bucket's burst token
	_, err := x.Execute(ctx, call)
	if err == nil || calls.Load() != before+1 {
		t.Fatalf("err = %v, calls %d → %d", err, before, calls.Load())
	}
}
