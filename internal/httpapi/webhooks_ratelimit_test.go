package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/ratelimit"
	"agentflow/internal/repo"
)

func TestWebhookRateLimitAnswers429AndSparesDuplicates(t *testing.T) {
	f := newWebhookFixture(t)
	created := f.create(map[string]any{"projectId": "sec", "workflowId": "phish", "name": "SIEM", "enabled": true,
		"dedupFields": []string{"alert.id"}, "rateLimitPerMinute": 1, "rateLimitBurst": 2})
	if created.Webhook.RateLimitPerMinute != 1 || created.Webhook.RateLimitBurst != 2 {
		t.Fatalf("limit not stored: %+v", created.Webhook)
	}
	send := func(id string) (int, map[string]any, http.Header) {
		rec, out := f.hook(http.MethodPost, created.Path, []byte(`{"alert":{"id":"`+id+`"}}`), nil, "")
		return rec.Code, out, rec.Header()
	}
	if code, out, _ := send("a"); code != http.StatusAccepted {
		t.Fatalf("first alert: %d %v", code, out)
	}
	// A duplicate is absorbed by dedup and leaves the budget alone.
	if code, out, _ := send("a"); code != http.StatusOK || out["status"] != "deduplicated" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	if code, out, _ := send("b"); code != http.StatusAccepted {
		t.Fatalf("second distinct alert within the burst: %d %v", code, out)
	}
	code, out, header := send("c")
	if code != http.StatusTooManyRequests || out["status"] != domain.WebhookDeliveryRateLimited {
		t.Fatalf("over the limit: %d %v", code, out)
	}
	retryAfter, err := strconv.Atoi(header.Get("Retry-After"))
	if err != nil || retryAfter < 1 || retryAfter > 60 {
		t.Fatalf("Retry-After = %q", header.Get("Retry-After"))
	}
	// The refused alert's fingerprint was released: sent again it is still
	// refused by the limit, not counted as a duplicate.
	if code, out, _ := send("c"); code != http.StatusTooManyRequests {
		t.Fatalf("resent alert: %d %v", code, out)
	}
	if alerts, _ := f.s.Alerts(repo.AlertFilter{ProjectID: "sec"}); len(alerts) != 3 {
		t.Fatalf("alerts stored = %d, want 3 (two started, one duplicate)", len(alerts))
	}
	deliveries := requestJSONAuthed[[]domain.WebhookDelivery](t, f.h, f.owner, http.MethodGet, "/api/webhooks/"+created.Webhook.ID+"/deliveries", nil, http.StatusOK)
	counts := map[string]int{}
	for _, d := range deliveries {
		counts[d.Status]++
		if d.Status == domain.WebhookDeliveryRateLimited && (d.HTTPStatus != http.StatusTooManyRequests || d.AlertID != "" || !strings.Contains(d.Message, "rate limit")) {
			t.Fatalf("rate limited delivery = %+v", d)
		}
	}
	if counts["started"] != 2 || counts["deduplicated"] != 1 || counts[domain.WebhookDeliveryRateLimited] != 2 {
		t.Fatalf("delivery counts = %v", counts)
	}

	// Removing the limit lets alerts through again.
	requestJSONAuthed[domain.Webhook](t, f.h, f.owner, http.MethodPut, "/api/webhooks/"+created.Webhook.ID, map[string]any{
		"workflowId": "phish", "name": "SIEM", "enabled": true, "dedupFields": []string{"alert.id"}}, http.StatusOK)
	if code, out, _ := send("c"); code != http.StatusAccepted {
		t.Fatalf("after removing the limit: %d %v", code, out)
	}
	for name, body := range map[string]map[string]any{
		"negative rate":      {"rateLimitPerMinute": -1},
		"burst without rate": {"rateLimitBurst": 5},
		"rate too high":      {"rateLimitPerMinute": domain.WebhookMaxRatePerMinute + 1},
	} {
		body["projectId"], body["workflowId"], body["name"] = "sec", "phish", "x"
		got := requestJSONAuthed[map[string]string](t, f.h, f.owner, http.MethodPost, "/api/webhooks", body, http.StatusBadRequest)
		if got["error"] == "" {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestAlertSourceDefersWhenItsWebhookIsRateLimited(t *testing.T) {
	f := newAlertSourceFixture(t)
	hook := f.webhook
	hook.RateLimitPerMinute, hook.RateLimitBurst = 1, 2
	requestJSONAuthed[domain.Webhook](t, f.h, f.owner, http.MethodPut, "/api/webhooks/"+hook.ID, hook, http.StatusOK)
	now := time.Now().UTC()
	for i, id := range []string{"r1", "r2", "r3"} {
		f.falcon.add(id, "alert "+id, "Low", now.Add(time.Duration(i-30)*time.Minute))
	}
	src := requestJSONAuthed[domain.AlertSource](t, f.h, f.owner, http.MethodPost, "/api/alert-sources", f.sourceBody(nil), http.StatusCreated)
	f.pollDue()
	f.trackRuns()
	got, _ := f.s.AlertSource(src.ID)
	if got.State.LastAdmitted != 2 || got.State.Failures != 0 || got.State.LastError != "" || !strings.Contains(got.State.LastWarning, "限流") {
		t.Fatalf("state after a limited pass = %+v", got.State)
	}
	if got.State.Checkpoint == nil || !got.State.Checkpoint.Equal(*src.State.Checkpoint) {
		t.Fatalf("checkpoint moved: %v, was %v", got.State.Checkpoint, src.State.Checkpoint)
	}
	if got.State.NextRunAt == nil || got.State.NextRunAt.Before(time.Now().Add(time.Second)) || got.State.NextRunAt.After(time.Now().Add(61*time.Second)) {
		t.Fatalf("next run = %v, want after the Retry-After", got.State.NextRunAt)
	}
	deliveries, _ := f.s.WebhookDeliveries(f.webhook.ID, 10)
	limited := 0
	for _, d := range deliveries {
		if d.Status == domain.WebhookDeliveryRateLimited {
			limited++
		}
	}
	if limited != 1 {
		t.Fatalf("rate limited deliveries = %d", limited)
	}

	// Once the budget refills the deferred alert is admitted, the others are
	// not admitted twice.
	f.sources.webhooks.limits = ratelimit.NewRegistry()
	if err := f.s.RequestAlertSourceRun(src.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	f.pollDue()
	f.trackRuns()
	got, _ = f.s.AlertSource(src.ID)
	if got.State.LastAdmitted != 1 || got.State.TotalAdmitted != 3 || got.State.LastWarning != "" {
		t.Fatalf("state after the budget refilled = %+v", got.State)
	}
}

func TestWebhookFingerprintPurgeRunsOnSchedule(t *testing.T) {
	s, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	past := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := s.ClaimWebhookFingerprint("wh-1", "expired", time.Minute, past); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimWebhookFingerprint("wh-1", "live", time.Hour, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h := &webhooksHandlers{deps: &deps{repo: s}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.startFingerprintPurge(ctx, 10*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for h.purged.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.purged.Load() != 1 {
		t.Fatalf("purged = %d, want 1", h.purged.Load())
	}
	// The live fingerprint survives: it still absorbs a duplicate.
	claim, err := s.ClaimWebhookFingerprint("wh-1", "live", time.Hour, time.Now().UTC())
	if err != nil || claim.Claimed || claim.Hits != 2 {
		t.Fatalf("live fingerprint claim = %+v, %v", claim, err)
	}
}
