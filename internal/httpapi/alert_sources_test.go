package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/engine"
	"agentflow/internal/notification"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"
	"agentflow/internal/tracker"
)

// fakeFalcon serves the Falcon OAuth and Alerts v2 endpoints over a fixed
// set of alerts, ignoring the filter (it records it) so the source's own
// ID deduplication is what keeps repeats out.
type fakeFalcon struct {
	mu      sync.Mutex
	alerts  []map[string]any
	filters []string
	batches []int
}

func (f *fakeFalcon) add(id, name, severity string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, map[string]any{"composite_id": id, "display_name": name, "severity_name": severity,
		"hostname": "wks-" + id, "created_timestamp": at.UTC().Format(time.RFC3339Nano)})
}

func (f *fakeFalcon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/oauth2/token":
		io.WriteString(w, `{"access_token":"falcon-token","expires_in":1800}`)
	case "/alerts/queries/alerts/v2":
		if r.Header.Get("Authorization") != "Bearer falcon-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.filters = append(f.filters, r.URL.Query().Get("filter"))
		ids := []string{}
		for _, a := range f.alerts {
			ids = append(ids, a["composite_id"].(string))
		}
		json.NewEncoder(w).Encode(map[string]any{"resources": ids, "meta": map[string]any{"pagination": map[string]any{"total": len(ids)}}})
	case "/alerts/entities/alerts/v2":
		var body struct {
			CompositeIDs []string `json:"composite_ids"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.batches = append(f.batches, len(body.CompositeIDs))
		out := []map[string]any{}
		for _, id := range body.CompositeIDs {
			for _, a := range f.alerts {
				if a["composite_id"] == id {
					out = append(out, a)
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"resources": out})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type alertSourceFixture struct {
	*webhookFixture
	sources *alertSourcesHandlers
	falcon  *fakeFalcon
	webhook domain.Webhook
	conn    domain.Connection
}

func newAlertSourceFixture(t *testing.T) *alertSourceFixture {
	t.Helper()
	f := newWebhookFixture(t)
	// Rebuild the handler with a Background so the poller is reachable.
	bg := &Background{}
	f.h = newWithNotifications(f.s, engine.New(f.s, runtime.NewManager(filepath.Join(t.TempDir(), "workspaces"))), tracker.NewService(), "", "", notification.New(f.s), bg, nil)
	falcon := &fakeFalcon{}
	srv := httptest.NewServer(falcon)
	t.Cleanup(srv.Close)
	created := f.create(map[string]any{"projectId": "sec", "workflowId": "phish", "name": "Falcon 告警", "enabled": true,
		"titleField": "display_name", "severityField": "severity_name", "dedupFields": []string{"composite_id"}, "caseMode": domain.WebhookCasePerAlert})
	conn := requestJSONAuthed[domain.Connection](t, f.h, f.owner, http.MethodPost, "/api/connections", map[string]any{
		"projectId": "sec", "connectorId": "crowdstrike", "name": "Falcon", "baseUrl": srv.URL,
		"secrets": map[string]string{"client_id": "id", "client_secret": "secret"}}, http.StatusCreated)
	return &alertSourceFixture{webhookFixture: f, sources: bg.alertSources, falcon: falcon, webhook: created.Webhook, conn: conn}
}

func (f *alertSourceFixture) sourceBody(extra map[string]any) map[string]any {
	body := map[string]any{"projectId": "sec", "webhookId": f.webhook.ID, "name": "Falcon EDR", "connectionId": f.conn.ID,
		"action": "list_alert_ids", "inputs": map[string]string{"filter": "created_timestamp:>='{{ window.sinceIso }}'+created_timestamp:<'{{ window.untilIso }}'", "limit": "{{ window.limit }}"},
		"detailAction": "get_alerts", "detailInput": "ids", "idPath": "composite_id", "timePath": "created_timestamp",
		"pollSeconds": 30, "lagSeconds": 0, "lookbackSeconds": 3600}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// pollDue runs every due source once, as the poller loop would.
func (f *alertSourceFixture) pollDue() []domain.AlertSource {
	f.t.Helper()
	due, err := f.s.ClaimDueAlertSources(f.sources.owner, time.Now().UTC(), alertSourceLease, 10)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, s := range due {
		f.sources.pass(context.Background(), s)
	}
	return due
}

func (f *alertSourceFixture) trackRuns() {
	list, _ := f.s.WebhookDeliveries(f.webhook.ID, 100)
	for _, d := range list {
		if d.RunID != "" {
			f.runs = append(f.runs, d.RunID)
		}
	}
}

func TestAlertSourcePullsFalconAlertsThroughItsWebhook(t *testing.T) {
	f := newAlertSourceFixture(t)
	now := time.Now().UTC()
	f.falcon.add("ldt:1", "可疑 PowerShell", "High", now.Add(-20*time.Minute))
	f.falcon.add("ldt:2", "凭据转储", "Critical", now.Add(-10*time.Minute))

	preview := requestJSONAuthed[alertSourcePreview](t, f.h, f.owner, http.MethodPost, "/api/alert-sources/preview", f.sourceBody(nil), http.StatusOK)
	if preview.Fetched != 2 || len(preview.Titles) != 2 || preview.Titles[0] != "可疑 PowerShell" || preview.IDs[1] != "ldt:2" {
		t.Fatalf("preview = %+v", preview)
	}
	if alerts, _ := f.s.Alerts(repo.AlertFilter{ProjectID: "sec"}); len(alerts) != 0 {
		t.Fatalf("preview admitted %d alerts", len(alerts))
	}

	src := requestJSONAuthed[domain.AlertSource](t, f.h, f.owner, http.MethodPost, "/api/alert-sources", f.sourceBody(nil), http.StatusCreated)
	if !src.Enabled || src.State.Checkpoint == nil || now.Sub(*src.State.Checkpoint) < 59*time.Minute {
		t.Fatalf("new source = %+v", src)
	}
	if due := f.pollDue(); len(due) != 1 {
		t.Fatalf("due = %d", len(due))
	}
	f.trackRuns()
	got, _ := f.s.AlertSource(src.ID)
	if got.State.LastError != "" || got.State.LastFetched != 2 || got.State.LastAdmitted != 2 || got.State.TotalAdmitted != 2 {
		t.Fatalf("state after first pass = %+v", got.State)
	}
	if got.State.NextRunAt == nil || got.State.NextRunAt.Before(now.Add(25*time.Second)) {
		t.Fatalf("next run = %v", got.State.NextRunAt)
	}
	f.falcon.mu.Lock()
	filter := f.falcon.filters[len(f.falcon.filters)-1]
	f.falcon.mu.Unlock()
	if !strings.HasPrefix(filter, "created_timestamp:>='"+src.State.Checkpoint.UTC().Format(time.RFC3339)+"'") {
		t.Fatalf("window not rendered into the filter: %s", filter)
	}
	deliveries, _ := f.s.WebhookDeliveries(f.webhook.ID, 10)
	if len(deliveries) != 2 || deliveries[0].SourceID != src.ID || deliveries[0].Status != domain.WebhookDeliveryStarted || deliveries[0].RunID == "" {
		t.Fatalf("deliveries = %+v", deliveries)
	}
	cases, _ := f.s.Cases(repo.CaseFilter{ProjectID: "sec"})
	if len(cases) != 2 {
		t.Fatalf("cases = %d", len(cases))
	}
	titles := map[string]string{}
	for _, c := range cases {
		titles[c.Title] = c.Severity
	}
	if titles["凭据转储"] != "critical" || titles["可疑 PowerShell"] != "high" {
		t.Fatalf("case titles/severities = %v", titles)
	}

	// The product returns old alerts again: only the new one is admitted.
	f.falcon.add("ldt:3", "横向移动", "Medium", now.Add(-time.Minute))
	if err := f.s.RequestAlertSourceRun(src.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	f.pollDue()
	f.trackRuns()
	got, _ = f.s.AlertSource(src.ID)
	if got.State.LastFetched != 3 || got.State.LastAdmitted != 1 || got.State.TotalAdmitted != 3 {
		t.Fatalf("state after second pass = %+v", got.State)
	}
	if alerts, _ := f.s.Alerts(repo.AlertFilter{ProjectID: "sec"}); len(alerts) != 3 {
		t.Fatalf("alerts = %d, want 3", len(alerts))
	}
	// Nothing due until its poll interval passes.
	if due := f.pollDue(); len(due) != 0 {
		t.Fatalf("polled again before due: %d", len(due))
	}
}

func TestAlertSourceRejectsResponseActionsAndPausesWithItsWebhook(t *testing.T) {
	f := newAlertSourceFixture(t)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/alert-sources",
		f.sourceBody(map[string]any{"action": "contain", "inputs": map[string]string{"device_id": "x"}, "detailAction": "", "detailInput": ""}), http.StatusBadRequest)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/alert-sources",
		f.sourceBody(map[string]any{"inputs": map[string]string{"filter": "{{ trigger.x }}"}}), http.StatusBadRequest)

	src := requestJSONAuthed[domain.AlertSource](t, f.h, f.owner, http.MethodPost, "/api/alert-sources", f.sourceBody(nil), http.StatusCreated)
	hook := f.webhook
	hook.Enabled = false
	requestJSONAuthed[domain.Webhook](t, f.h, f.owner, http.MethodPut, "/api/webhooks/"+hook.ID, hook, http.StatusOK)
	f.falcon.add("ldt:9", "不应拉取", "High", time.Now().Add(-time.Minute))
	f.pollDue()
	got, _ := f.s.AlertSource(src.ID)
	if got.State.Failures != 1 || !strings.Contains(got.State.LastError, "停用") || got.State.LastFetched != 0 {
		t.Fatalf("state with webhook disabled = %+v", got.State)
	}
	f.falcon.mu.Lock()
	calls := len(f.falcon.filters)
	f.falcon.mu.Unlock()
	if calls != 0 {
		t.Fatalf("polled the product %d times while the webhook was disabled", calls)
	}

	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodDelete, "/api/webhooks/"+hook.ID, nil, http.StatusOK)
	if _, ok := f.s.AlertSource(src.ID); ok {
		t.Fatal("deleting the webhook left its alert source")
	}
}

func TestAlertSourceResumesAFullPageFromItsLastAlert(t *testing.T) {
	f := newAlertSourceFixture(t)
	now := time.Now().UTC()
	for i, id := range []string{"a", "b", "c"} {
		f.falcon.add(id, "alert "+id, "Low", now.Add(time.Duration(i-30)*time.Minute))
	}
	src := requestJSONAuthed[domain.AlertSource](t, f.h, f.owner, http.MethodPost, "/api/alert-sources", f.sourceBody(map[string]any{"pageLimit": 3}), http.StatusCreated)
	f.pollDue()
	f.trackRuns()
	got, _ := f.s.AlertSource(src.ID)
	last, _ := time.Parse(time.RFC3339Nano, f.falcon.alerts[2]["created_timestamp"].(string))
	if got.State.Checkpoint == nil || !got.State.Checkpoint.Equal(last) || got.State.LastWarning != "" {
		t.Fatalf("full page checkpoint = %v (want %v), warning %q", got.State.Checkpoint, last, got.State.LastWarning)
	}
	if got.State.NextRunAt == nil || got.State.NextRunAt.After(time.Now().UTC()) {
		t.Fatalf("a source behind should poll again at once, next = %v", got.State.NextRunAt)
	}
}

func TestAlertItemTimeReadsCommonFormats(t *testing.T) {
	want := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	for _, v := range []any{"2026-11-20T08:00:00Z", "2026-11-20T16:00:00.000+08:00", float64(want.Unix()), float64(want.UnixMilli()), "1795161600"} {
		got, ok := alertItemTime(map[string]any{"t": v}, "t")
		if !ok || !got.Equal(want) {
			t.Fatalf("%v → %v %v", v, got, ok)
		}
	}
}
