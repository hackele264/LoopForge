package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentflow/internal/auth"
	"agentflow/internal/connector"
	"agentflow/internal/domain"
)

func TestCaseAgentVerdictIsRecordedAndReadable(t *testing.T) {
	f := newWebhookFixture(t)
	stranger := domain.User{ID: 63, LoginName: "stranger"}
	if err := f.s.PutUser(stranger); err != nil {
		t.Fatal(err)
	}
	cs := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPost, "/api/cases", map[string]any{"projectId": "sec", "title": "Notable: lateral movement", "severity": "high"}, http.StatusCreated)
	h := &casesHandlers{deps: &deps{repo: f.s}}
	conf := 0.82
	run := connector.RunContext{RunID: "run-1", NodeID: "verdict", ProjectID: "sec", CaseID: cs.ID}
	got, err := h.CaseSetVerdict(t.Context(), run, connector.CaseVerdict{Verdict: "Malicious", Confidence: &conf, Rationale: "beaconing to known C2"})
	if err != nil || got.AgentVerdict != "malicious" || got.AgentVerdictRunID != "run-1" || got.AgentVerdictFirstAt == nil {
		t.Fatalf("verdict = %+v, %v", got, err)
	}
	first := *got.AgentVerdictFirstAt
	time.Sleep(5 * time.Millisecond)
	run.RunID = "run-2"
	again, err := h.CaseSetVerdict(t.Context(), run, connector.CaseVerdict{Verdict: "needs_review"})
	if err != nil || again.AgentVerdict != "needs_review" || again.AgentConfidence != nil || !again.AgentVerdictFirstAt.Equal(first) || !again.AgentVerdictAt.After(first) {
		t.Fatalf("second verdict = %+v, %v", again, err)
	}
	if _, err := h.CaseSetVerdict(t.Context(), run, connector.CaseVerdict{Verdict: "suspicious"}); err == nil {
		t.Fatal("unknown verdict accepted")
	}
	// A run of another project cannot set the verdict.
	if _, err := h.CaseSetVerdict(t.Context(), connector.RunContext{RunID: "x", ProjectID: "other", CaseID: cs.ID}, connector.CaseVerdict{Verdict: "benign"}); err == nil {
		t.Fatal("verdict from another project's run accepted")
	}

	detail := requestJSONAuthed[caseDetail](t, f.h, f.owner, http.MethodGet, "/api/cases/"+cs.ID, nil, http.StatusOK)
	if detail.Case.AgentVerdict != "needs_review" || detail.Case.AgentVerdictRunID != "run-2" {
		t.Fatalf("case = %+v", detail.Case)
	}
	if !strings.Contains(eventTypes(detail.Events), "case.agent_verdict,case.agent_verdict") {
		t.Fatalf("timeline = %s", eventTypes(detail.Events))
	}
	requestJSONAuthed[map[string]any](t, f.h, stranger, http.MethodGet, "/api/cases/"+cs.ID, nil, http.StatusForbidden)
	// The verdict is not writable through the case API.
	updated := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"agentVerdict": "benign"}, http.StatusOK)
	if updated.AgentVerdict != "needs_review" {
		t.Fatalf("case API changed the verdict: %+v", updated)
	}
}

func TestPilotReportAccessAndExport(t *testing.T) {
	f := newWebhookFixture(t)
	member := domain.User{ID: 61, LoginName: "analyst"}
	stranger := domain.User{ID: 62, LoginName: "stranger"}
	for _, u := range []domain.User{member, stranger} {
		if err := f.s.PutUser(u); err != nil {
			t.Fatal(err)
		}
	}
	project, _ := f.s.Project("sec")
	project.Members = []domain.ProjectMember{{UserID: member.ID, Role: "maintainer"}}
	if err := f.s.PutProject(project); err != nil {
		t.Fatal(err)
	}
	cs := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPost, "/api/cases", map[string]any{"projectId": "sec", "title": "n", "severity": "high"}, http.StatusCreated)
	h := &casesHandlers{deps: &deps{repo: f.s}}
	if _, err := h.CaseSetVerdict(t.Context(), connector.RunContext{RunID: "r", ProjectID: "sec", CaseID: cs.ID}, connector.CaseVerdict{Verdict: "benign"}); err != nil {
		t.Fatal(err)
	}
	requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"status": "closed", "resolution": "false_positive"}, http.StatusOK)

	day := time.Now().UTC().Format("2006-01-02")
	path := "/api/pilot-report?projectId=sec&from=" + day + "&to=" + day
	rep := requestJSONAuthed[domain.PilotReport](t, f.h, f.owner, http.MethodGet, path, nil, http.StatusOK)
	if rep.Alerts.Cases != 1 || rep.Agreement.Matched != 1 || rep.Agreement.Rate != 1 || rep.Latency.WithVerdict != 1 || rep.Definitions["agreement"] == "" {
		t.Fatalf("report = %+v", rep)
	}
	// Only the owner (or a platform admin): members and strangers are refused.
	requestJSONAuthed[map[string]any](t, f.h, member, http.MethodGet, path, nil, http.StatusForbidden)
	requestJSONAuthed[map[string]any](t, f.h, stranger, http.MethodGet, path, nil, http.StatusForbidden)
	requestJSON[map[string]any](t, f.h, http.MethodGet, path, nil, http.StatusUnauthorized)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodGet, "/api/pilot-report?projectId=sec&from=2026-01-01&to=2026-12-31", nil, http.StatusBadRequest)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodGet, "/api/pilot-report", nil, http.StatusBadRequest)

	req := httptest.NewRequest(http.MethodGet, path+"&format=csv", nil)
	token, err := auth.NewClientFromEnv().SignUser(&auth.User{ID: f.owner.ID, LoginName: f.owner.LoginName, AuthTime: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") || !strings.Contains(body, "agreement.rate,1.0000") || !strings.Contains(body, "matrix.benign.false_positive,1") {
		t.Fatalf("csv %d %s:\n%s", rec.Code, rec.Header().Get("Content-Type"), body)
	}
}
