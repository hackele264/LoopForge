package repo

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"agentflow/internal/domain"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AlertSourcesRepo owns pull alert sources, their poll leases and the alert
// IDs each source has admitted.
type AlertSourcesRepo struct{ *deps }

// ErrAlertSourceNotFound is returned for an unknown source.
var ErrAlertSourceNotFound = errors.New("alert source not found")

// alertSourceRow keeps the configuration (Payload) and what the poller
// records (State) in separate columns, so saving one never overwrites the
// other.
type alertSourceRow struct {
	ID         string     `gorm:"primaryKey;size:64"`
	ProjectID  string     `gorm:"size:128;index"`
	WebhookID  string     `gorm:"size:64;index"`
	Enabled    bool       `gorm:"index:idx_alert_sources_due,priority:1"`
	NextRunAt  *time.Time `gorm:"index:idx_alert_sources_due,priority:2"`
	LeaseOwner string     `gorm:"size:128"`
	LeaseUntil *time.Time
	Payload    []byte `gorm:"type:json"`
	State      []byte `gorm:"type:json"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (alertSourceRow) TableName() string { return "alert_sources" }

// alertSourceSeenRow is one alert a source admitted; ItemKey is the hex
// SHA-256 of its ID.
type alertSourceSeenRow struct {
	SourceID string    `gorm:"primaryKey;size:64"`
	ItemKey  string    `gorm:"primaryKey;size:64"`
	SeenAt   time.Time `gorm:"index"`
}

func (alertSourceSeenRow) TableName() string { return "alert_source_seen" }

func alertSourceFromRow(row alertSourceRow) (domain.AlertSource, error) {
	var s domain.AlertSource
	if err := json.Unmarshal(row.Payload, &s); err != nil {
		return s, err
	}
	s.State = domain.AlertSourceState{}
	if len(row.State) > 0 {
		if err := json.Unmarshal(row.State, &s.State); err != nil {
			return s, err
		}
	}
	s.ID, s.ProjectID, s.WebhookID, s.Enabled = row.ID, row.ProjectID, row.WebhookID, row.Enabled
	s.State.NextRunAt = row.NextRunAt
	return s, nil
}

// CreateAlertSource stores a new source, due at once.
func (r *AlertSourcesRepo) CreateAlertSource(s domain.AlertSource) error {
	state := s.State
	s.State = domain.AlertSourceState{}
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	rawState, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return r.DB.Create(&alertSourceRow{ID: s.ID, ProjectID: s.ProjectID, WebhookID: s.WebhookID, Enabled: s.Enabled, NextRunAt: state.NextRunAt,
		Payload: payload, State: rawState, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt}).Error
}

// UpdateAlertSourceConfig replaces a source's configuration, leaving its
// poll state and lease alone. A source switched on is due at once.
func (r *AlertSourcesRepo) UpdateAlertSourceConfig(s domain.AlertSource) error {
	s.State = domain.AlertSourceState{}
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	updates := map[string]any{"enabled": s.Enabled, "payload": payload, "updated_at": s.UpdatedAt}
	res := r.DB.Model(&alertSourceRow{}).Where("id = ?", s.ID).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrAlertSourceNotFound
	}
	return nil
}

// AlertSource returns one source.
func (r *AlertSourcesRepo) AlertSource(id string) (domain.AlertSource, bool) {
	var row alertSourceRow
	if err := r.DB.First(&row, "id = ?", id).Error; err != nil {
		return domain.AlertSource{}, false
	}
	s, err := alertSourceFromRow(row)
	return s, err == nil
}

// AlertSources lists a project's sources, optionally of one webhook, by name.
func (r *AlertSourcesRepo) AlertSources(projectID, webhookID string) ([]domain.AlertSource, error) {
	q := r.DB.Where("project_id = ?", projectID)
	if webhookID != "" {
		q = q.Where("webhook_id = ?", webhookID)
	}
	var rows []alertSourceRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AlertSource, 0, len(rows))
	for _, row := range rows {
		s, err := alertSourceFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteAlertSource removes a source and the IDs it admitted.
func (r *AlertSourcesRepo) DeleteAlertSource(id string) error {
	return r.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Delete(&alertSourceRow{}, "id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrAlertSourceNotFound
		}
		return tx.Delete(&alertSourceSeenRow{}, "source_id = ?", id).Error
	})
}

// DeleteAlertSourcesOfWebhook removes every source feeding a webhook.
func (r *AlertSourcesRepo) DeleteAlertSourcesOfWebhook(webhookID string) error {
	var ids []string
	if err := r.DB.Model(&alertSourceRow{}).Where("webhook_id = ?", webhookID).Pluck("id", &ids).Error; err != nil {
		return err
	}
	for _, id := range ids {
		if err := r.DeleteAlertSource(id); err != nil && err != ErrAlertSourceNotFound {
			return err
		}
	}
	return nil
}

// RequestAlertSourceRun makes a source due now.
func (r *AlertSourcesRepo) RequestAlertSourceRun(id string, now time.Time) error {
	res := r.DB.Model(&alertSourceRow{}).Where("id = ?", id).Update("next_run_at", now)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrAlertSourceNotFound
	}
	return nil
}

// ClaimDueAlertSources leases up to limit enabled sources whose next run is
// due and that no other poller holds. A lease that expired (its poller
// died) can be taken over.
func (r *AlertSourcesRepo) ClaimDueAlertSources(owner string, now time.Time, ttl time.Duration, limit int) ([]domain.AlertSource, error) {
	var ids []string
	err := r.DB.Model(&alertSourceRow{}).
		Where("enabled = ? AND (next_run_at IS NULL OR next_run_at <= ?) AND (lease_until IS NULL OR lease_until < ?)", true, now, now).
		Order("next_run_at").Limit(limit).Pluck("id", &ids).Error
	if err != nil {
		return nil, err
	}
	until := now.Add(ttl)
	var out []domain.AlertSource
	for _, id := range ids {
		res := r.DB.Model(&alertSourceRow{}).
			Where("id = ? AND enabled = ? AND (lease_until IS NULL OR lease_until < ?)", id, true, now).
			Updates(map[string]any{"lease_owner": owner, "lease_until": until})
		if res.Error != nil {
			return out, res.Error
		}
		if res.RowsAffected == 0 {
			continue
		}
		if s, ok := r.AlertSource(id); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// FinishAlertSourcePass records a pass and releases the lease. It writes
// nothing when owner no longer holds the lease (it expired and another
// poller took the source over).
func (r *AlertSourcesRepo) FinishAlertSourcePass(id, owner string, state domain.AlertSourceState) (bool, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	res := r.DB.Model(&alertSourceRow{}).Where("id = ? AND lease_owner = ?", id, owner).
		Updates(map[string]any{"state": raw, "next_run_at": state.NextRunAt, "lease_owner": "", "lease_until": nil})
	return res.RowsAffected == 1, res.Error
}

// MarkAlertSourceItem records that source admitted the alert with key and
// reports whether it was new. Concurrent callers race on the primary key:
// exactly one sees true.
func (r *AlertSourcesRepo) MarkAlertSourceItem(sourceID, key string, now time.Time) (bool, error) {
	res := r.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&alertSourceSeenRow{SourceID: sourceID, ItemKey: key, SeenAt: now})
	return res.RowsAffected == 1, res.Error
}

// ForgetAlertSourceItem drops a mark, so a failed admission retries on the
// next pass.
func (r *AlertSourcesRepo) ForgetAlertSourceItem(sourceID, key string) error {
	return r.DB.Delete(&alertSourceSeenRow{}, "source_id = ? AND item_key = ?", sourceID, key).Error
}

// PurgeAlertSourceItems deletes marks older than cutoff and reports how many.
func (r *AlertSourcesRepo) PurgeAlertSourceItems(cutoff time.Time) (int64, error) {
	res := r.DB.Where("seen_at < ?", cutoff).Delete(&alertSourceSeenRow{})
	return res.RowsAffected, res.Error
}
