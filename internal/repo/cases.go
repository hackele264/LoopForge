package repo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"agentflow/internal/domain"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CasesRepo owns security alerts, cases, their indicators and timelines,
// and the triggers that start playbooks from case events.
type CasesRepo struct{ *deps }

type alertRow struct {
	ID          string    `gorm:"primaryKey;size:64"`
	ProjectID   string    `gorm:"size:128;index:idx_alerts_project_received,priority:1"`
	WebhookID   string    `gorm:"size:64;index"`
	CaseID      string    `gorm:"size:64;index"`
	RunID       string    `gorm:"size:64"`
	Severity    string    `gorm:"size:16"`
	Fingerprint string    `gorm:"size:64"`
	ReceivedAt  time.Time `gorm:"index:idx_alerts_project_received,priority:2"`
	Payload     []byte    `gorm:"type:json"`
}

func (alertRow) TableName() string { return "alerts" }

type caseRow struct {
	ID        string `gorm:"primaryKey;size:64"`
	ProjectID string `gorm:"size:128;uniqueIndex:idx_cases_project_number,priority:1;index:idx_cases_project_updated,priority:1"`
	Number    int    `gorm:"uniqueIndex:idx_cases_project_number,priority:2"`
	Status    string `gorm:"size:32;index"`
	Severity  string `gorm:"size:16"`
	Payload   []byte `gorm:"type:json"`
	CreatedAt time.Time
	UpdatedAt time.Time `gorm:"index:idx_cases_project_updated,priority:2"`
}

func (caseRow) TableName() string { return "cases" }

type caseIOCRow struct {
	CaseID    string `gorm:"primaryKey;size:64"`
	Type      string `gorm:"primaryKey;size:16"`
	ValueKey  string `gorm:"primaryKey;size:64"` // SHA-256 of the lowercased value
	Value     string `gorm:"type:text"`
	AlertID   string `gorm:"size:64"`
	FirstSeen time.Time
}

func (caseIOCRow) TableName() string { return "case_iocs" }

type caseEventRow struct {
	ID          string    `gorm:"primaryKey;size:64"`
	CaseID      string    `gorm:"size:64;index:idx_case_events_case,priority:1"`
	CreatedAt   time.Time `gorm:"index:idx_case_events_case,priority:2"`
	Type        string    `gorm:"size:64"`
	ActorUserID int64     `gorm:"index"`
	Payload     []byte    `gorm:"type:json"`
}

func (caseEventRow) TableName() string { return "case_events" }

type caseTriggerRow struct {
	ID        string `gorm:"primaryKey;size:64"`
	ProjectID string `gorm:"size:128;index"`
	Payload   []byte `gorm:"type:json"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (caseTriggerRow) TableName() string { return "case_triggers" }

// ErrCaseNotFound reports a missing case.
var ErrCaseNotFound = errors.New("case not found")

// newRowID returns prefix-<nanoseconds>-<random>; the random part keeps IDs
// unique when rows are created in the same clock tick.
func newRowID(prefix string) string {
	raw := make([]byte, 4)
	_, _ = rand.Read(raw)
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UnixNano(), hex.EncodeToString(raw))
}

// ---------- alerts ----------

func alertToRow(a domain.Alert) (alertRow, error) {
	payload, err := json.Marshal(a)
	if err != nil {
		return alertRow{}, err
	}
	return alertRow{ID: a.ID, ProjectID: a.ProjectID, WebhookID: a.WebhookID, CaseID: a.CaseID, RunID: a.RunID, Severity: a.Severity, Fingerprint: a.Fingerprint, ReceivedAt: a.ReceivedAt, Payload: payload}, nil
}

func alertFromRow(row alertRow) (domain.Alert, error) {
	var a domain.Alert
	if err := json.Unmarshal(row.Payload, &a); err != nil {
		return domain.Alert{}, err
	}
	a.CaseID, a.RunID = row.CaseID, row.RunID
	return a, nil
}

// PutAlert stores or replaces an alert.
func (r *CasesRepo) PutAlert(a domain.Alert) error {
	if a.ID == "" {
		a.ID = newRowID("alert")
	}
	row, err := alertToRow(a)
	if err != nil {
		return err
	}
	return r.DB.Save(&row).Error
}

// Alert returns one alert with its payload.
func (r *CasesRepo) Alert(id string) (domain.Alert, bool) {
	var row alertRow
	if err := r.DB.First(&row, "id = ?", id).Error; err != nil {
		return domain.Alert{}, false
	}
	a, err := alertFromRow(row)
	return a, err == nil
}

// AlertFilter narrows Alerts.
type AlertFilter struct {
	ProjectID string
	CaseID    string
	// Uncased lists only alerts not attached to a case.
	Uncased bool
	Limit   int
}

// Alerts lists alerts newest first. Payloads are dropped from list results.
func (r *CasesRepo) Alerts(f AlertFilter) ([]domain.Alert, error) {
	q := r.DB.Model(&alertRow{})
	if f.ProjectID != "" {
		q = q.Where("project_id = ?", f.ProjectID)
	}
	if f.CaseID != "" {
		q = q.Where("case_id = ?", f.CaseID)
	}
	if f.Uncased {
		q = q.Where("case_id = ? OR case_id IS NULL", "")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows := []alertRow{}
	if err := q.Order("received_at DESC").Limit(f.Limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Alert, 0, len(rows))
	for _, row := range rows {
		a, err := alertFromRow(row)
		if err != nil {
			return nil, err
		}
		a.Payload = ""
		out = append(out, a)
	}
	return out, nil
}

// SetAlertRun records the run an alert started.
func (r *CasesRepo) SetAlertRun(alertID, runID string) error {
	a, ok := r.Alert(alertID)
	if !ok {
		return fmt.Errorf("alert %s not found", alertID)
	}
	a.RunID = runID
	return r.PutAlert(a)
}

// ---------- cases ----------

func caseToRow(c domain.Case) (caseRow, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return caseRow{}, err
	}
	return caseRow{ID: c.ID, ProjectID: c.ProjectID, Number: c.Number, Status: c.Status, Severity: c.Severity, Payload: payload, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}, nil
}

func caseFromRow(row caseRow) (domain.Case, error) {
	var c domain.Case
	if err := json.Unmarshal(row.Payload, &c); err != nil {
		return domain.Case{}, err
	}
	return c, nil
}

// Case returns one case.
func (r *CasesRepo) Case(id string) (domain.Case, bool) {
	var row caseRow
	if err := r.DB.First(&row, "id = ?", id).Error; err != nil {
		return domain.Case{}, false
	}
	c, err := caseFromRow(row)
	return c, err == nil
}

// CaseFilter narrows Cases.
type CaseFilter struct {
	ProjectID string
	Status    string // empty: all; "open": every status but closed
	Limit     int
}

// Cases lists cases, most recently updated first.
func (r *CasesRepo) Cases(f CaseFilter) ([]domain.Case, error) {
	q := r.DB.Model(&caseRow{})
	if f.ProjectID != "" {
		q = q.Where("project_id = ?", f.ProjectID)
	}
	switch f.Status {
	case "":
	case "open":
		q = q.Where("status <> ?", domain.CaseStatusClosed)
	default:
		q = q.Where("status = ?", f.Status)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 200
	}
	rows := []caseRow{}
	if err := q.Order("updated_at DESC").Limit(f.Limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Case, 0, len(rows))
	for _, row := range rows {
		c, err := caseFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// CaseChange is applied by CreateCase and UpdateCase inside one
// transaction: the case row, alerts to attach, indicators to add and the
// timeline events describing the change.
type CaseChange struct {
	Alerts []domain.Alert
	IOCs   []domain.CaseIOC
	Events []domain.CaseEvent
}

// caseCounterRow holds the last case number per project; locking it
// serializes number allocation across instances.
type caseCounterRow struct {
	ProjectID  string `gorm:"primaryKey;size:128"`
	LastNumber int
}

func (caseCounterRow) TableName() string { return "case_counters" }

// CreateCase assigns the next per-project case number and stores the case
// with its alerts, indicators and events in one transaction.
func (r *CasesRepo) CreateCase(c domain.Case, change CaseChange) (domain.Case, error) {
	if c.ID == "" {
		c.ID = newRowID("case")
	}
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		// Seed the counter from existing cases the first time a project
		// gets one; the primary key makes concurrent seeds collapse.
		var max struct{ N int }
		if err := tx.Model(&caseRow{}).Select("COALESCE(MAX(number), 0) AS n").Where("project_id = ?", c.ProjectID).Scan(&max).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&caseCounterRow{ProjectID: c.ProjectID, LastNumber: max.N}).Error; err != nil {
			return err
		}
		var counter caseCounterRow
		if err := r.locking(tx).First(&counter, "project_id = ?", c.ProjectID).Error; err != nil {
			return err
		}
		c.Number = counter.LastNumber + 1
		if err := tx.Model(&caseCounterRow{}).Where("project_id = ?", c.ProjectID).Update("last_number", c.Number).Error; err != nil {
			return err
		}
		c.AlertCount = len(change.Alerts)
		row, err := caseToRow(c)
		if err != nil {
			return err
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return r.applyChange(tx, c.ID, change)
	})
	if err != nil {
		return domain.Case{}, err
	}
	return c, nil
}

// UpdateCase applies mutate to the locked case and stores it with change.
// mutate returns the change to record; returning an error aborts.
func (r *CasesRepo) UpdateCase(id string, mutate func(c *domain.Case, alertCount int) (CaseChange, error)) (domain.Case, error) {
	var out domain.Case
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		var row caseRow
		if err := r.locking(tx).First(&row, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrCaseNotFound
			}
			return err
		}
		c, err := caseFromRow(row)
		if err != nil {
			return err
		}
		change, err := mutate(&c, c.AlertCount)
		if err != nil {
			return err
		}
		newAlerts := 0
		for _, a := range change.Alerts {
			if a.CaseID != c.ID {
				newAlerts++
			}
		}
		c.AlertCount += newAlerts
		updated, err := caseToRow(c)
		if err != nil {
			return err
		}
		updated.CreatedAt = row.CreatedAt
		if err := tx.Save(&updated).Error; err != nil {
			return err
		}
		out = c
		return r.applyChange(tx, c.ID, change)
	})
	return out, err
}

func (r *CasesRepo) applyChange(tx *gorm.DB, caseID string, change CaseChange) error {
	for _, a := range change.Alerts {
		a.CaseID = caseID
		row, err := alertToRow(a)
		if err != nil {
			return err
		}
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
	}
	for _, ioc := range change.IOCs {
		row := caseIOCRow{CaseID: caseID, Type: ioc.Type, ValueKey: hexSHA256(strings.ToLower(ioc.Value)), Value: ioc.Value, AlertID: ioc.AlertID, FirstSeen: ioc.FirstSeen}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return err
		}
	}
	for i, e := range change.Events {
		e.CaseID = caseID
		if e.ID == "" {
			e.ID = fmt.Sprintf("%s-%d", newRowID("cev"), i)
		}
		payload, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := tx.Create(&caseEventRow{ID: e.ID, CaseID: caseID, CreatedAt: e.CreatedAt, Type: e.Type, ActorUserID: e.ActorUserID, Payload: payload}).Error; err != nil {
			return err
		}
	}
	return nil
}

// AppendCaseEvents adds timeline entries without touching the case row.
func (r *CasesRepo) AppendCaseEvents(caseID string, events ...domain.CaseEvent) error {
	return r.DB.Transaction(func(tx *gorm.DB) error { return r.applyChange(tx, caseID, CaseChange{Events: events}) })
}

// CaseIOCs lists a case's indicators by type then value.
func (r *CasesRepo) CaseIOCs(caseID string) ([]domain.CaseIOC, error) {
	rows := []caseIOCRow{}
	if err := r.DB.Where("case_id = ?", caseID).Order("type, value_key").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.CaseIOC, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.CaseIOC{CaseID: row.CaseID, Type: row.Type, Value: row.Value, AlertID: row.AlertID, FirstSeen: row.FirstSeen})
	}
	return out, nil
}

// CaseEvents returns a case's timeline, oldest first.
func (r *CasesRepo) CaseEvents(caseID string, limit int) ([]domain.CaseEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows := []caseEventRow{}
	if err := r.DB.Where("case_id = ?", caseID).Order("created_at ASC, id ASC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.CaseEvent, 0, len(rows))
	for _, row := range rows {
		var e domain.CaseEvent
		if err := json.Unmarshal(row.Payload, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// CaseRuns returns summaries of the runs linked to a case, newest first.
func (r *CasesRepo) CaseRuns(caseID string) ([]CaseRunRef, error) {
	rows := []CaseRunRef{}
	err := r.DB.Table("runs").Select("id, workflow_id, status, created_at, updated_at").Where("case_id = ?", caseID).Order("created_at DESC").Limit(200).Scan(&rows).Error
	return rows, err
}

// CaseRunRef is a run linked to a case.
type CaseRunRef struct {
	ID         string    `json:"id"`
	WorkflowID string    `json:"workflowId"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// CountTriggerRuns counts runs a trigger started for a case, and how many
// of them are still active.
func (r *CasesRepo) CountTriggerRuns(caseID, triggerID string) (total, active int, err error) {
	rows := []struct {
		Status           string
		ExecutionContext []byte
	}{}
	if err = r.DB.Table("runs").Select("status, execution_context").Where("case_id = ?", caseID).Scan(&rows).Error; err != nil {
		return 0, 0, err
	}
	for _, row := range rows {
		var ctx domain.TelemetryContext
		if json.Unmarshal(row.ExecutionContext, &ctx) != nil || ctx.CaseTriggerID != triggerID {
			continue
		}
		total++
		if !domain.TerminalRunStatus(row.Status) {
			active++
		}
	}
	return total, active, nil
}

// ---------- triggers ----------

// PutCaseTrigger stores a trigger.
func (r *CasesRepo) PutCaseTrigger(t domain.CaseTrigger) error {
	payload, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return r.DB.Save(&caseTriggerRow{ID: t.ID, ProjectID: t.ProjectID, Payload: payload, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt}).Error
}

// CaseTrigger returns one trigger.
func (r *CasesRepo) CaseTrigger(id string) (domain.CaseTrigger, bool) {
	var row caseTriggerRow
	if err := r.DB.First(&row, "id = ?", id).Error; err != nil {
		return domain.CaseTrigger{}, false
	}
	var t domain.CaseTrigger
	return t, json.Unmarshal(row.Payload, &t) == nil
}

// CaseTriggers lists a project's triggers, oldest first.
func (r *CasesRepo) CaseTriggers(projectID string) ([]domain.CaseTrigger, error) {
	rows := []caseTriggerRow{}
	if err := r.DB.Where("project_id = ?", projectID).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.CaseTrigger, 0, len(rows))
	for _, row := range rows {
		var t domain.CaseTrigger
		if err := json.Unmarshal(row.Payload, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// DeleteCaseTrigger removes a trigger.
func (r *CasesRepo) DeleteCaseTrigger(id string) error {
	return r.DB.Delete(&caseTriggerRow{}, "id = ?", id).Error
}
