package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"agentflow/internal/domain"
)

func (f *webhookFixture) waitRunsDone() {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for _, id := range f.runs {
		for time.Now().Before(deadline) {
			if r, ok := f.s.RunState(id); !ok || domain.TerminalRunStatus(r.Status) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func eventTypes(events []domain.CaseEvent) string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type)
	}
	return strings.Join(out, ",")
}

func TestWebhookAlertsOpenAndJoinCases(t *testing.T) {
	f := newWebhookFixture(t)
	created := f.create(map[string]any{"projectId": "sec", "workflowId": "phish", "name": "SIEM", "enabled": true,
		"titleField": "alert.title", "severityField": "alert.severity", "dedupFields": []string{"alert.rule", "alert.host"}, "caseMode": "per_fingerprint"})

	rec, out := f.hook(http.MethodPost, created.Path, []byte(`{"alert":{"title":"Beacon to evil.example.com","rule":"C2","host":"pc-1","severity":"CRITICAL","url":"http://evil.example.com/x","src":"10.9.8.7"}}`), nil, "")
	if rec.Code != http.StatusAccepted || out["caseId"] == "" || out["alertId"] == "" {
		t.Fatalf("first alert: %d %v", rec.Code, out)
	}
	caseID := out["caseId"].(string)
	run, _ := f.s.RunState(out["runId"].(string))
	if run.ExecutionContext.CaseID != caseID {
		t.Fatalf("run not linked to case: %+v", run.ExecutionContext)
	}
	rec, dup := f.hook(http.MethodPost, created.Path, []byte(`{"alert":{"title":"again","rule":"C2","host":"pc-1","severity":"low","md5":"d41d8cd98f00b204e9800998ecf8427e"}}`), nil, "")
	if rec.Code != http.StatusOK || dup["caseId"] != caseID {
		t.Fatalf("duplicate should join the case: %d %v", rec.Code, dup)
	}
	f.waitRunsDone()

	detail := requestJSONAuthed[caseDetail](t, f.h, f.owner, http.MethodGet, "/api/cases/"+caseID, nil, http.StatusOK)
	if detail.Case.Number != 1 || detail.Case.Severity != "critical" || detail.Case.AlertCount != 2 || len(detail.Alerts) != 2 || len(detail.Runs) != 1 {
		t.Fatalf("case detail = %+v alerts %d runs %d", detail.Case, len(detail.Alerts), len(detail.Runs))
	}
	iocs := map[string]bool{}
	for _, ioc := range detail.IOCs {
		iocs[ioc.Type+":"+ioc.Value] = true
	}
	for _, want := range []string{"domain:evil.example.com", "url:http://evil.example.com/x", "ipv4:10.9.8.7", "md5:d41d8cd98f00b204e9800998ecf8427e"} {
		if !iocs[want] {
			t.Errorf("missing IOC %s in %v", want, iocs)
		}
	}
	if got := eventTypes(detail.Events); got != "case.created,case.run_started,case.alert_added" {
		t.Fatalf("timeline = %s", got)
	}

	// Alerts from a webhook without a case mode stay uncased.
	plain := f.create(map[string]any{"projectId": "sec", "workflowId": "phish", "name": "EDR", "enabled": true})
	_, out = f.hook(http.MethodPost, plain.Path, []byte(`{"x":1}`), nil, "")
	if out["caseId"] != "" {
		t.Fatalf("plain webhook opened a case: %v", out)
	}
	uncased := requestJSONAuthed[[]domain.Alert](t, f.h, f.owner, http.MethodGet, "/api/alerts?projectId=sec&uncased=true", nil, http.StatusOK)
	if len(uncased) != 1 || uncased[0].Payload != "" || uncased[0].Severity != "medium" {
		t.Fatalf("uncased alerts = %+v", uncased)
	}
	full := requestJSONAuthed[domain.Alert](t, f.h, f.owner, http.MethodGet, "/api/alerts/"+uncased[0].ID, nil, http.StatusOK)
	if full.Payload != `{"x":1}` {
		t.Fatalf("alert payload = %s", full.Payload)
	}
	// Escalating it into the existing case attaches it.
	joined := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPost, "/api/alerts/"+full.ID+"/escalate", map[string]any{"caseId": caseID}, http.StatusOK)
	if joined.AlertCount != 3 {
		t.Fatalf("escalate into case: %+v", joined)
	}
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/alerts/"+full.ID+"/escalate", map[string]any{}, http.StatusConflict)
	f.waitRunsDone()
}

func TestCaseLifecycleTriggersAndAccess(t *testing.T) {
	f := newWebhookFixture(t)
	viewer := domain.User{ID: 52, LoginName: "viewer"}
	stranger := domain.User{ID: 53, LoginName: "stranger"}
	for _, u := range []domain.User{viewer, stranger} {
		if err := f.s.PutUser(u); err != nil {
			t.Fatal(err)
		}
	}
	project, _ := f.s.Project("sec")
	project.Members = []domain.ProjectMember{{UserID: viewer.ID, Role: "viewer"}}
	if err := f.s.PutProject(project); err != nil {
		t.Fatal(err)
	}
	trigger := requestJSONAuthed[domain.CaseTrigger](t, f.h, f.owner, http.MethodPost, "/api/case-triggers", map[string]any{
		"projectId": "sec", "workflowId": "phish", "name": "escalation playbook", "enabled": true, "events": []string{"case.escalated"}}, http.StatusCreated)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/case-triggers", map[string]any{
		"projectId": "sec", "workflowId": "phish", "name": "bad", "events": []string{"case.comment"}}, http.StatusBadRequest)

	cs := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPost, "/api/cases", map[string]any{"projectId": "sec", "title": "Suspicious login", "severity": "low"}, http.StatusCreated)
	if cs.Number != 1 || cs.Status != "new" {
		t.Fatalf("created = %+v", cs)
	}
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"status": "closed"}, http.StatusBadRequest)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"severity": "urgent"}, http.StatusBadRequest)

	updated := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"severity": "high", "status": "investigating", "assigneeId": f.owner.ID}, http.StatusOK)
	if updated.Severity != "high" || updated.Status != "investigating" || updated.AssigneeID != f.owner.ID {
		t.Fatalf("updated = %+v", updated)
	}
	requestJSONAuthed[domain.CaseEvent](t, f.h, f.owner, http.MethodPost, "/api/cases/"+cs.ID+"/comments", map[string]any{"body": "Looks like credential stuffing"}, http.StatusCreated)
	requestJSONAuthed[domain.CaseIOC](t, f.h, f.owner, http.MethodPost, "/api/cases/"+cs.ID+"/iocs", map[string]any{"type": "ipv4", "value": "198.51.100.4"}, http.StatusCreated)
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPost, "/api/cases/"+cs.ID+"/iocs", map[string]any{"type": "phone", "value": "1"}, http.StatusBadRequest)

	detail := requestJSONAuthed[caseDetail](t, f.h, f.owner, http.MethodGet, "/api/cases/"+cs.ID, nil, http.StatusOK)
	for _, r := range detail.Runs {
		f.runs = append(f.runs, r.ID)
	}
	if len(detail.Runs) != 1 {
		t.Fatalf("escalation should start the trigger's playbook once: %+v", detail.Runs)
	}
	run, _ := f.s.RunState(detail.Runs[0].ID)
	if run.ExecutionContext.CaseTriggerID != trigger.ID || run.ExecutionContext.ResponsibleUserID != f.owner.ID || !strings.Contains(string(run.TriggerPayload), `"type":"case.escalated"`) || !strings.Contains(string(run.TriggerPayload), `"Suspicious login"`) {
		t.Fatalf("trigger run = ctx %+v payload %s", run.ExecutionContext, run.TriggerPayload)
	}
	want := "case.created,case.severity_changed,case.escalated,case.status_changed,case.assigned,case.run_started,case.comment,case.ioc_added"
	if got := eventTypes(detail.Events); got != want {
		t.Fatalf("timeline = %s\nwant       %s", got, want)
	}
	if detail.Events[0].ActorUserID != f.owner.ID || detail.Events[0].ActorKind != domain.ActorUser {
		t.Fatalf("created event actor = %+v", detail.Events[0])
	}

	// Re-escalating while the trigger's run is still active starts nothing.
	f.waitRunsDone()
	requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"severity": "medium"}, http.StatusOK)
	requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"severity": "critical"}, http.StatusOK)
	detail = requestJSONAuthed[caseDetail](t, f.h, f.owner, http.MethodGet, "/api/cases/"+cs.ID, nil, http.StatusOK)
	for _, r := range detail.Runs {
		f.runs = append(f.runs, r.ID)
	}
	if len(detail.Runs) != 2 {
		t.Fatalf("a finished trigger run allows the next escalation: %d runs", len(detail.Runs))
	}

	closed := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"status": "closed", "resolution": "false_positive"}, http.StatusOK)
	if closed.ClosedAt == nil || closed.Resolution != "false_positive" {
		t.Fatalf("closed = %+v", closed)
	}
	reopened := requestJSONAuthed[domain.Case](t, f.h, f.owner, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"status": "investigating"}, http.StatusOK)
	if reopened.ClosedAt != nil || reopened.Resolution != "" {
		t.Fatalf("reopened = %+v", reopened)
	}

	// Viewers read but cannot write; non-members cannot read.
	requestJSONAuthed[caseDetail](t, f.h, viewer, http.MethodGet, "/api/cases/"+cs.ID, nil, http.StatusOK)
	requestJSONAuthed[[]domain.Case](t, f.h, viewer, http.MethodGet, "/api/cases?projectId=sec&status=open", nil, http.StatusOK)
	requestJSONAuthed[map[string]any](t, f.h, viewer, http.MethodPut, "/api/cases/"+cs.ID, map[string]any{"severity": "low"}, http.StatusForbidden)
	requestJSONAuthed[map[string]any](t, f.h, stranger, http.MethodGet, "/api/cases/"+cs.ID, nil, http.StatusForbidden)
	requestJSONAuthed[map[string]any](t, f.h, stranger, http.MethodGet, "/api/alerts?projectId=sec", nil, http.StatusForbidden)
	requestJSON[map[string]any](t, f.h, http.MethodGet, "/api/cases?projectId=sec", nil, http.StatusUnauthorized)

	// A manual playbook run is linked to the case.
	started := requestJSONAuthed[map[string]string](t, f.h, f.owner, http.MethodPost, "/api/cases/"+cs.ID+"/runs", map[string]any{"workflowId": "phish"}, http.StatusCreated)
	f.runs = append(f.runs, started["runId"])
	if r, _ := f.s.RunState(started["runId"]); r.ExecutionContext.CaseID != cs.ID || r.ExecutionContext.CaseTriggerID != "" {
		t.Fatalf("manual run ctx = %+v", r.ExecutionContext)
	}
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodDelete, "/api/case-triggers/"+trigger.ID, nil, http.StatusOK)
}
