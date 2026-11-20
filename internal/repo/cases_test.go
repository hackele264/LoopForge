package repo

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"agentflow/internal/domain"
)

func exerciseCaseStorage(t *testing.T, s *Store, project string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Concurrent creations get distinct, gap-free numbers.
	var wg sync.WaitGroup
	var mu sync.Mutex
	numbers := []int{}
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := s.CreateCase(domain.Case{ID: fmt.Sprintf("%s-case-%d", project, i), ProjectID: project, Title: "t", Severity: "medium", Status: domain.CaseStatusNew, CreatedAt: now, UpdatedAt: now}, CaseChange{})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			numbers = append(numbers, c.Number)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	sort.Ints(numbers)
	for i, n := range numbers {
		if n != i+1 {
			t.Fatalf("case numbers = %v", numbers)
		}
	}

	alert := domain.Alert{ID: project + "-alert-1", ProjectID: project, Title: "a", Severity: "high", Payload: domain.RawJSON(`{"ip":"10.0.0.1"}`), ReceivedAt: now}
	if err := s.PutAlert(alert); err != nil {
		t.Fatal(err)
	}
	created, err := s.CreateCase(domain.Case{ID: project + "-case-x", ProjectID: project, Title: "phish", Severity: "high", Status: domain.CaseStatusNew, CreatedAt: now, UpdatedAt: now}, CaseChange{
		Alerts: []domain.Alert{alert},
		IOCs:   []domain.CaseIOC{{Type: "ipv4", Value: "10.0.0.1", AlertID: alert.ID, FirstSeen: now}, {Type: "ipv4", Value: "10.0.0.1", FirstSeen: now}},
		Events: []domain.CaseEvent{{Type: domain.CaseEventCreated, Message: "created", CreatedAt: now}},
	})
	if err != nil || created.AlertCount != 1 || created.Number != 13 {
		t.Fatalf("created = %+v, %v", created, err)
	}
	if a, _ := s.Alert(alert.ID); a.CaseID != created.ID {
		t.Fatalf("alert not attached: %+v", a)
	}
	second := domain.Alert{ID: project + "-alert-2", ProjectID: project, Title: "dup", Severity: "high", ReceivedAt: now.Add(time.Second)}
	updated, err := s.UpdateCase(created.ID, func(c *domain.Case, _ int) (CaseChange, error) {
		c.Status = domain.CaseStatusInvestigating
		c.UpdatedAt = now.Add(time.Second)
		return CaseChange{Alerts: []domain.Alert{second}, IOCs: []domain.CaseIOC{{Type: "ipv4", Value: "10.0.0.1", FirstSeen: now}, {Type: "domain", Value: "Evil.Example", FirstSeen: now}},
			Events: []domain.CaseEvent{{Type: domain.CaseEventAlertAdded, Message: "dup", CreatedAt: now.Add(time.Second)}}}, nil
	})
	if err != nil || updated.AlertCount != 2 || updated.Status != domain.CaseStatusInvestigating {
		t.Fatalf("updated = %+v, %v", updated, err)
	}
	iocs, _ := s.CaseIOCs(created.ID)
	events, _ := s.CaseEvents(created.ID, 0)
	alerts, _ := s.Alerts(AlertFilter{ProjectID: project, CaseID: created.ID})
	uncased, _ := s.Alerts(AlertFilter{ProjectID: project, Uncased: true})
	if len(iocs) != 2 || len(events) != 2 || events[0].Type != domain.CaseEventCreated || len(alerts) != 2 || alerts[0].Payload != "" || len(uncased) != 0 {
		t.Fatalf("iocs %v events %v alerts %v uncased %v", iocs, events, alerts, uncased)
	}
	if _, err := s.UpdateCase("missing", func(*domain.Case, int) (CaseChange, error) { return CaseChange{}, nil }); err != ErrCaseNotFound {
		t.Fatalf("missing case error = %v", err)
	}
	open, _ := s.Cases(CaseFilter{ProjectID: project, Status: "open"})
	if len(open) != 13 || open[0].ID != created.ID {
		t.Fatalf("open cases = %d, first %s", len(open), open[0].ID)
	}

	trigger := domain.CaseTrigger{ID: project + "-trg", ProjectID: project, WorkflowID: "wf", Name: "n", Enabled: true, Events: []string{domain.CaseEventCreated}, CreatedAt: now, UpdatedAt: now}
	if err := s.PutCaseTrigger(trigger); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.CaseTriggers(project); len(list) != 1 {
		t.Fatalf("triggers = %v", list)
	}
	if err := s.DeleteCaseTrigger(trigger.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCaseStorage(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	exerciseCaseStorage(t, s, "p")
}

func TestCaseStorageOnMySQL(t *testing.T) {
	dsn := os.Getenv("AGENTFLOW_WEBHOOK_TEST_DSN")
	if dsn == "" {
		t.Skip("disposable local Docker MySQL only")
	}
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	project := fmt.Sprintf("case-mysql-%d", time.Now().UnixNano())
	defer func() {
		s.DB.Where("project_id = ?", project).Delete(&caseRow{})
		s.DB.Where("project_id = ?", project).Delete(&alertRow{})
		s.DB.Where("project_id = ?", project).Delete(&caseCounterRow{})
		s.DB.Where("case_id LIKE ?", project+"%").Delete(&caseIOCRow{})
		s.DB.Where("case_id LIKE ?", project+"%").Delete(&caseEventRow{})
	}()
	exerciseCaseStorage(t, s, project)
}
