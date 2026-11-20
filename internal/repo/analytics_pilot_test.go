package repo

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"agentflow/internal/domain"
)

// seedPilotFixture stores a small pilot: seven cases in range with alerts,
// verdicts and resolutions, plus rows outside the range or project that the
// report must ignore. It returns the range.
func seedPilotFixture(t *testing.T, s *Store) (time.Time, time.Time) {
	t.Helper()
	t0 := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
	from, to := t0.Add(-time.Hour), t0.Add(14*24*time.Hour)
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
	type fixture struct {
		id, verdict, status, resolution string
		alertAt, verdictAt              int // seconds after t0; verdictAt < 0: none
	}
	cases := []fixture{
		{"c1", "malicious", "closed", "resolved", 0, 60},
		{"c2", "benign", "closed", "false_positive", 10, 130},
		{"c3", "false_positive", "closed", "resolved", 20, 620},
		{"c4", "needs_review", "closed", "false_positive", 20, 50},
		{"c5", "malicious", "closed", "duplicate", 30, 40},
		{"c6", "", "investigating", "", 40, -1},
		{"c7", "malicious", "new", "", 0, 300},
	}
	for _, f := range cases {
		alert := domain.Alert{ID: "a-" + f.id, ProjectID: "pilot", Title: f.id, Severity: "high", ReceivedAt: at(f.alertAt)}
		c := domain.Case{ID: f.id, ProjectID: "pilot", Title: f.id, Severity: "high", Status: f.status, Resolution: f.resolution, CreatedAt: at(f.alertAt + 1), UpdatedAt: at(f.alertAt + 1), AgentVerdict: f.verdict}
		if f.verdictAt >= 0 {
			v := at(f.verdictAt)
			c.AgentVerdictAt, c.AgentVerdictFirstAt = &v, &v
		}
		if _, err := s.CreateCase(c, CaseChange{Alerts: []domain.Alert{alert}}); err != nil {
			t.Fatal(err)
		}
	}
	// A duplicate alert joined c1; c6's alert started run r6 without a case link.
	if err := s.PutAlert(domain.Alert{ID: "a-dup", ProjectID: "pilot", CaseID: "c1", Duplicate: true, Title: "dup", Severity: "high", ReceivedAt: at(5)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlertRun("a-c6", "r6"); err != nil {
		t.Fatal(err)
	}
	// Outside the range or the project.
	old := from.Add(-time.Hour)
	v := old.Add(time.Minute)
	if _, err := s.CreateCase(domain.Case{ID: "c-old", ProjectID: "pilot", Title: "old", Severity: "low", Status: "closed", Resolution: "false_positive", AgentVerdict: "malicious", AgentVerdictFirstAt: &v, CreatedAt: old, UpdatedAt: old}, CaseChange{Alerts: []domain.Alert{{ID: "a-old", ProjectID: "pilot", ReceivedAt: old}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCase(domain.Case{ID: "c-other", ProjectID: "other", Title: "x", Severity: "low", Status: "closed", Resolution: "resolved", AgentVerdict: "malicious", AgentVerdictFirstAt: &v, CreatedAt: at(0), UpdatedAt: at(0)}, CaseChange{Alerts: []domain.Alert{{ID: "a-other", ProjectID: "other", ReceivedAt: at(0)}}}); err != nil {
		t.Fatal(err)
	}
	runs := []struct {
		id, status, caseID string
		created            time.Time
	}{
		{"r1", "succeeded", "c1", at(1)}, {"r2", "failed", "c2", at(11)}, {"r3", "waiting", "c3", at(21)},
		{"r6", "succeeded", "", at(41)}, {"r-old", "succeeded", "c1", old}, {"r-other", "failed", "c-other", at(1)},
	}
	for _, r := range runs {
		created := r.created
		if err := s.DB.Create(&runRow{ID: r.id, Status: r.status, CaseID: r.caseID, Created: &created, Updated: &created}).Error; err != nil {
			t.Fatal(err)
		}
	}
	action := func(caseID, connector, category string, ok bool, sec int) domain.CaseEvent {
		data, _ := json.Marshal(map[string]any{"connector": connector, "action": "x", "category": category, "ok": ok})
		return domain.CaseEvent{Type: domain.CaseEventAction, Message: "m", Data: domain.RawJSON(data), CreatedAt: at(sec)}
	}
	for caseID, events := range map[string][]domain.CaseEvent{
		"c1":      {action("c1", "crowdstrike", "enrichment", true, 2), action("c1", "crowdstrike", "enrichment", true, 3), action("c1", "lark_bot", "utility", true, 70)},
		"c2":      {action("c2", "crowdstrike", "enrichment", false, 12)},
		"c3":      {action("c3", "crowdstrike", "response", true, 900)},
		"c-other": {action("c-other", "crowdstrike", "enrichment", false, 2)},
	} {
		if err := s.AppendCaseEvents(caseID, events...); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range []domain.Webhook{{ID: "w1", ProjectID: "pilot", WorkflowID: "wf"}, {ID: "w-other", ProjectID: "other", WorkflowID: "wf"}} {
		if err := s.PutWebhook(w); err != nil {
			t.Fatal(err)
		}
	}
	for i, d := range []domain.WebhookDelivery{
		{WebhookID: "w1", Status: "started", ReceivedAt: at(0)}, {WebhookID: "w1", Status: "started", ReceivedAt: at(10)},
		{WebhookID: "w1", Status: "deduplicated", ReceivedAt: at(5)}, {WebhookID: "w1", Status: "rate_limited", ReceivedAt: at(6)},
		{WebhookID: "w1", Status: "rate_limited", ReceivedAt: at(7)}, {WebhookID: "w1", Status: "rate_limited", ReceivedAt: old},
		{WebhookID: "w-other", Status: "rate_limited", ReceivedAt: at(7)},
	} {
		d.ID = "d" + string(rune('a'+i))
		if err := s.RecordWebhookDelivery(d); err != nil {
			t.Fatal(err)
		}
	}
	return from, to
}

func TestPilotReportOnFixture(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	from, to := seedPilotFixture(t, s)
	rep, err := s.PilotReport("pilot", from, to)
	if err != nil {
		t.Fatal(err)
	}
	a := rep.Alerts
	if a.Admitted != 8 || a.Deduplicated != 1 || a.Cased != 8 || a.Cases != 7 {
		t.Fatalf("alerts = %+v", a)
	}
	if a.RateLimited != 2 || a.Deliveries["started"] != 2 || a.Deliveries["deduplicated"] != 1 || !a.DeliveriesComplete {
		t.Fatalf("deliveries = %+v", a)
	}
	if r := rep.Runs; r.Started != 4 || r.Succeeded != 2 || r.Failed != 1 || r.Active != 1 {
		t.Fatalf("runs = %+v", r)
	}
	act := rep.Actions
	if act.Overall.Total != 4 || act.Overall.Succeeded != 3 || act.Enrichment.Total != 3 || act.Enrichment.Succeeded != 2 || act.ResponseExecuted != 1 {
		t.Fatalf("actions = %+v", act)
	}
	if math.Abs(act.Enrichment.Rate-2.0/3) > 1e-9 || len(act.ByConnector) != 2 || act.ByConnector[0].Connector != "crowdstrike" || act.ByConnector[0].Failed != 1 || act.ByConnector[1].Rate != 1 {
		t.Fatalf("actions = %+v", act)
	}
	// Latencies 60, 120, 600, 30, 10, 300 seconds.
	if l := rep.Latency; l.WithVerdict != 6 || l.WithoutVerdict != 1 || l.P50Seconds != 60 || l.P95Seconds != 600 || l.MaxSeconds != 600 {
		t.Fatalf("latency = %+v", l)
	}
	g := rep.Agreement
	if g.Matched != 2 || g.Mismatch != 1 || g.Excluded != 2 || g.OpenWithVerdict != 1 || math.Abs(g.Rate-2.0/3) > 1e-9 {
		t.Fatalf("agreement = %+v", g)
	}
	if g.Matrix["malicious"]["resolved"] != 1 || g.Matrix["false_positive"]["resolved"] != 1 || g.Matrix["needs_review"]["false_positive"] != 1 || g.Matrix["malicious"]["duplicate"] != 1 {
		t.Fatalf("matrix = %+v", g.Matrix)
	}
	// The verdict column mirrors the payload for queries.
	var row caseRow
	if err := s.DB.First(&row, "id = ?", "c1").Error; err != nil || row.AgentVerdict != "malicious" || row.AgentVerdictAt == nil {
		t.Fatalf("row = %+v, %v", row, err)
	}
	empty, err := s.PilotReport("nobody", from, to)
	if err != nil || empty.Alerts.Admitted != 0 || empty.Runs.Started != 0 || empty.Actions.ByConnector == nil {
		t.Fatalf("empty = %+v, %v", empty, err)
	}
}
