package repo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"agentflow/internal/domain"
)

// AuditRepo owns the platform audit log.
type AuditRepo struct{ *deps }

type auditEventRow struct {
	ID          string    `gorm:"primaryKey;size:64"`
	At          time.Time `gorm:"index"`
	ActorUserID int64     `gorm:"index"`
	Action      string    `gorm:"size:160;index"`
	ProjectID   string    `gorm:"size:128;index"`
	Outcome     string    `gorm:"size:16"`
	Payload     []byte    `gorm:"type:json"`
}

func (auditEventRow) TableName() string { return "audit_events" }

// AppendAudit stores one event, filling ID and time when empty.
func (r *AuditRepo) AppendAudit(e domain.AuditEvent) error {
	if e.ID == "" {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		e.ID = "au-" + hex.EncodeToString(raw)
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return r.DB.Create(&auditEventRow{ID: e.ID, At: e.At, ActorUserID: e.ActorUserID, Action: e.Action, ProjectID: e.ProjectID, Outcome: e.Outcome, Payload: payload}).Error
}

// AuditFilter narrows AuditEvents. Zero values do not filter.
type AuditFilter struct {
	From, To    time.Time
	ActorUserID int64
	Action      string // prefix match (SQL LIKE; admin-only input)
	ProjectID   string
	Outcome     string
	Limit       int
}

// AuditEvents lists events, newest first. Limit defaults to 200 and is
// capped at 10000.
func (r *AuditRepo) AuditEvents(f AuditFilter) ([]domain.AuditEvent, error) {
	q := r.DB.Model(&auditEventRow{})
	if !f.From.IsZero() {
		q = q.Where("at >= ?", f.From)
	}
	if !f.To.IsZero() {
		q = q.Where("at < ?", f.To)
	}
	if f.ActorUserID > 0 {
		q = q.Where("actor_user_id = ?", f.ActorUserID)
	}
	if f.Action != "" {
		q = q.Where("action LIKE ?", f.Action+"%")
	}
	if f.ProjectID != "" {
		q = q.Where("project_id = ?", f.ProjectID)
	}
	if f.Outcome != "" {
		q = q.Where("outcome = ?", f.Outcome)
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 10000 {
		limit = 10000
	}
	var rows []auditEventRow
	if err := q.Order("at DESC, id DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AuditEvent, 0, len(rows))
	for _, row := range rows {
		var e domain.AuditEvent
		if err := json.Unmarshal(row.Payload, &e); err != nil {
			return nil, fmt.Errorf("audit event %s: %w", row.ID, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// PurgeAuditBefore deletes events older than cutoff and reports how many.
func (r *AuditRepo) PurgeAuditBefore(cutoff time.Time) (int64, error) {
	res := r.DB.Where("at < ?", cutoff).Delete(&auditEventRow{})
	return res.RowsAffected, res.Error
}
