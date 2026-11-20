package repo

import (
	"encoding/json"
	"fmt"
	"time"

	"agentflow/internal/domain"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// WebhooksRepo owns inbound webhooks, their deduplication fingerprints and
// their delivery log.
type WebhooksRepo struct{ *deps }

type webhookRow struct {
	ID         string `gorm:"primaryKey;size:64"`
	ProjectID  string `gorm:"size:128;index"`
	WorkflowID string `gorm:"size:128;index"`
	Payload    []byte `gorm:"type:json"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (webhookRow) TableName() string { return "webhooks" }

// webhookDedupRow is one fingerprint seen by a webhook. A row whose
// ExpiresAt has passed is free to be claimed again.
type webhookDedupRow struct {
	WebhookID   string `gorm:"primaryKey;size:64"`
	Fingerprint string `gorm:"primaryKey;size:64"`
	RunID       string `gorm:"size:64"`
	Hits        int
	FirstSeen   time.Time
	LastSeen    time.Time
	ExpiresAt   time.Time `gorm:"index"`
}

func (webhookDedupRow) TableName() string { return "webhook_dedup" }

type webhookDeliveryRow struct {
	ID         string    `gorm:"primaryKey;size:64"`
	WebhookID  string    `gorm:"size:64;index:idx_webhook_deliveries_hook,priority:1"`
	ReceivedAt time.Time `gorm:"index:idx_webhook_deliveries_hook,priority:2"`
	Payload    []byte    `gorm:"type:json"`
}

func (webhookDeliveryRow) TableName() string { return "webhook_deliveries" }

// webhookDeliveryKeep bounds the delivery log kept per webhook.
const webhookDeliveryKeep = 200

// PutWebhook stores a webhook definition, including its secret hash.
func (r *WebhooksRepo) PutWebhook(w domain.Webhook) error {
	payload, err := json.Marshal(webhookStored(w))
	if err != nil {
		return err
	}
	row := webhookRow{ID: w.ID, ProjectID: w.ProjectID, WorkflowID: w.WorkflowID, Payload: payload, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt}
	return r.DB.Save(&row).Error
}

// webhookStoredForm keeps the fields hidden from the API (secret hash,
// signing secret) in the stored payload.
type webhookStoredForm struct {
	domain.Webhook
	SecretHash    string `json:"secretHash"`
	SigningSecret string `json:"signingSecret,omitempty"`
}

func webhookStored(w domain.Webhook) webhookStoredForm {
	return webhookStoredForm{Webhook: w, SecretHash: w.SecretHash, SigningSecret: w.SigningSecret}
}

func webhookFromRow(row webhookRow) (domain.Webhook, error) {
	var stored webhookStoredForm
	if err := json.Unmarshal(row.Payload, &stored); err != nil {
		return domain.Webhook{}, err
	}
	w := stored.Webhook
	w.SecretHash = stored.SecretHash
	w.SigningSecret = stored.SigningSecret
	w.HasSigningSecret = w.SigningSecret != ""
	return w, nil
}

// Webhook returns one webhook with its secret material.
func (r *WebhooksRepo) Webhook(id string) (domain.Webhook, bool) {
	var row webhookRow
	if err := r.DB.First(&row, "id = ?", id).Error; err != nil {
		return domain.Webhook{}, false
	}
	w, err := webhookFromRow(row)
	return w, err == nil
}

// WebhooksByProject lists a project's webhooks, newest first; workflowID
// narrows the list when set.
func (r *WebhooksRepo) WebhooksByProject(projectID, workflowID string) ([]domain.Webhook, error) {
	rows := []webhookRow{}
	q := r.DB.Where("project_id = ?", projectID)
	if workflowID != "" {
		q = q.Where("workflow_id = ?", workflowID)
	}
	if err := q.Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Webhook, 0, len(rows))
	for _, row := range rows {
		w, err := webhookFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

// DeleteWebhook removes a webhook with its fingerprints and delivery log.
func (r *WebhooksRepo) DeleteWebhook(id string) error {
	return r.DB.Transaction(func(tx *gorm.DB) error {
		for _, model := range []any{&webhookDedupRow{}, &webhookDeliveryRow{}} {
			if err := tx.Where("webhook_id = ?", id).Delete(model).Error; err != nil {
				return err
			}
		}
		return tx.Delete(&webhookRow{}, "id = ?", id).Error
	})
}

// DedupClaim is the outcome of ClaimWebhookFingerprint.
type DedupClaim struct {
	// Claimed means no live run owns the fingerprint and the caller should
	// start one, then record it with SetWebhookFingerprintRun.
	Claimed bool
	// RunID and Hits describe the live fingerprint when not claimed.
	RunID string
	Hits  int
}

// ClaimWebhookFingerprint atomically decides whether an alert starts a run.
// Within the window the first caller claims the fingerprint and later
// callers only count a hit against the run it started.
func (r *WebhooksRepo) ClaimWebhookFingerprint(webhookID, fingerprint string, window time.Duration, now time.Time) (DedupClaim, error) {
	var claim DedupClaim
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		fresh := webhookDedupRow{WebhookID: webhookID, Fingerprint: fingerprint, Hits: 1, FirstSeen: now, LastSeen: now, ExpiresAt: now.Add(window)}
		// Insert first: the primary key makes exactly one concurrent first
		// caller succeed, even when no row exists yet to lock.
		inserted := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&fresh)
		if inserted.Error != nil {
			return inserted.Error
		}
		if inserted.RowsAffected == 1 {
			claim = DedupClaim{Claimed: true, Hits: 1}
			return nil
		}
		var row webhookDedupRow
		if err := r.locking(tx).First(&row, "webhook_id = ? AND fingerprint = ?", webhookID, fingerprint).Error; err != nil {
			return err
		}
		if !row.ExpiresAt.After(now) {
			claim = DedupClaim{Claimed: true, Hits: 1}
			return tx.Model(&webhookDedupRow{}).Where("webhook_id = ? AND fingerprint = ?", webhookID, fingerprint).
				Updates(map[string]any{"run_id": "", "hits": 1, "first_seen": now, "last_seen": now, "expires_at": now.Add(window)}).Error
		}
		claim = DedupClaim{RunID: row.RunID, Hits: row.Hits + 1}
		return tx.Model(&webhookDedupRow{}).Where("webhook_id = ? AND fingerprint = ?", webhookID, fingerprint).
			Updates(map[string]any{"hits": row.Hits + 1, "last_seen": now}).Error
	})
	return claim, err
}

// SetWebhookFingerprintRun records the run a claimed fingerprint started.
func (r *WebhooksRepo) SetWebhookFingerprintRun(webhookID, fingerprint, runID string) error {
	return r.DB.Model(&webhookDedupRow{}).Where("webhook_id = ? AND fingerprint = ?", webhookID, fingerprint).Update("run_id", runID).Error
}

// ReleaseWebhookFingerprint frees a claim whose run failed to start.
func (r *WebhooksRepo) ReleaseWebhookFingerprint(webhookID, fingerprint string) error {
	return r.DB.Where("webhook_id = ? AND fingerprint = ? AND run_id = ?", webhookID, fingerprint, "").Delete(&webhookDedupRow{}).Error
}

// PurgeExpiredWebhookFingerprints deletes fingerprints whose window ended.
func (r *WebhooksRepo) PurgeExpiredWebhookFingerprints(now time.Time) (int64, error) {
	result := r.DB.Where("expires_at <= ?", now).Delete(&webhookDedupRow{})
	return result.RowsAffected, result.Error
}

// RecordWebhookDelivery appends to a webhook's delivery log, keeping the
// most recent webhookDeliveryKeep entries, and stamps LastTriggeredAt for
// deliveries that reached the workflow.
func (r *WebhooksRepo) RecordWebhookDelivery(d domain.WebhookDelivery) error {
	if d.ID == "" {
		d.ID = fmt.Sprintf("whd-%d", d.ReceivedAt.UnixNano())
	}
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return r.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&webhookDeliveryRow{ID: d.ID, WebhookID: d.WebhookID, ReceivedAt: d.ReceivedAt, Payload: payload}).Error; err != nil {
			return err
		}
		var stale []webhookDeliveryRow
		// MySQL rejects OFFSET without LIMIT, so bound the trim explicitly.
		if err := tx.Select("id").Where("webhook_id = ?", d.WebhookID).Order("received_at DESC").Limit(1000).Offset(webhookDeliveryKeep).Find(&stale).Error; err != nil {
			return err
		}
		if len(stale) > 0 {
			ids := make([]string, 0, len(stale))
			for _, s := range stale {
				ids = append(ids, s.ID)
			}
			if err := tx.Where("id IN ?", ids).Delete(&webhookDeliveryRow{}).Error; err != nil {
				return err
			}
		}
		if d.Status != domain.WebhookDeliveryStarted && d.Status != domain.WebhookDeliveryDeduplicated {
			return nil
		}
		var row webhookRow
		if err := r.locking(tx).First(&row, "id = ?", d.WebhookID).Error; err != nil {
			return err
		}
		w, err := webhookFromRow(row)
		if err != nil {
			return err
		}
		at := d.ReceivedAt
		w.LastTriggeredAt = &at
		raw, err := json.Marshal(webhookStored(w))
		if err != nil {
			return err
		}
		return tx.Model(&webhookRow{}).Where("id = ?", d.WebhookID).Update("payload", raw).Error
	})
}

// WebhookDeliveries returns a webhook's most recent deliveries first.
func (r *WebhooksRepo) WebhookDeliveries(webhookID string, limit int) ([]domain.WebhookDelivery, error) {
	if limit <= 0 || limit > webhookDeliveryKeep {
		limit = 50
	}
	rows := []webhookDeliveryRow{}
	if err := r.DB.Where("webhook_id = ?", webhookID).Order("received_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.WebhookDelivery, 0, len(rows))
	for _, row := range rows {
		var d domain.WebhookDelivery
		if err := json.Unmarshal(row.Payload, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}
