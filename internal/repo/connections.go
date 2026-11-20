package repo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/secretbox"

	"gorm.io/gorm"
)

// ConnectionsRepo owns connector connections: per-project endpoints and
// credentials used by action nodes.
type ConnectionsRepo struct {
	*deps
	// secrets seals the secrets column; nil keeps it in plaintext.
	secrets *secretbox.Keyring
}

// ErrConnectionNotFound is returned for an unknown connection.
var ErrConnectionNotFound = errors.New("connection not found")

type connectionRow struct {
	ID          string `gorm:"primaryKey;size:64"`
	ProjectID   string `gorm:"size:128;index"`
	ConnectorID string `gorm:"size:64;index"`
	Payload     []byte `gorm:"type:json"`
	// Secrets is kept out of Payload so listing queries can skip it. With a
	// key configured it holds a JSON string, the secretbox envelope of the
	// JSON object of secret name → value, bound to the row ID; legacy rows
	// hold that JSON object in plaintext.
	Secrets   []byte `gorm:"type:json"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (connectionRow) TableName() string { return "connections" }

// PutConnection stores a connection including its secrets.
func (r *ConnectionsRepo) PutConnection(c domain.Connection) error {
	c.SecretsSet = secretNames(c.Secrets)
	payload, err := json.Marshal(c)
	if err != nil {
		return err
	}
	secrets, err := r.encodeConnectionSecrets(c.ID, c.Secrets)
	if err != nil {
		return err
	}
	row := connectionRow{ID: c.ID, ProjectID: c.ProjectID, ConnectorID: c.ConnectorID, Payload: payload, Secrets: secrets, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
	return r.DB.Save(&row).Error
}

func secretNames(secrets map[string]string) []string {
	names := []string{}
	for k, v := range secrets {
		if v != "" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}

// Connection returns one connection with its secrets. It returns
// ErrConnectionNotFound for an unknown ID and an error wrapping
// ErrStoredSecretsUnreadable when the secrets are sealed with a key that is
// not configured: callers never get a connection with missing secrets.
func (r *ConnectionsRepo) Connection(id string) (domain.Connection, error) {
	var row connectionRow
	if err := r.DB.First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Connection{}, ErrConnectionNotFound
		}
		return domain.Connection{}, err
	}
	return r.connectionFromRow(row, true)
}

// ConnectionInfo returns one connection without reading its secrets, so a
// caller can check access (or delete it) even when the secrets cannot be
// decrypted. SecretsSet still lists the secret names.
func (r *ConnectionsRepo) ConnectionInfo(id string) (domain.Connection, error) {
	var row connectionRow
	if err := r.DB.Select("id", "project_id", "connector_id", "payload", "created_at", "updated_at").First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domain.Connection{}, ErrConnectionNotFound
		}
		return domain.Connection{}, err
	}
	return r.connectionFromRow(row, false)
}

func (r *ConnectionsRepo) connectionFromRow(row connectionRow, withSecrets bool) (domain.Connection, error) {
	var c domain.Connection
	if err := json.Unmarshal(row.Payload, &c); err != nil {
		return domain.Connection{}, err
	}
	c.Secrets = nil
	if withSecrets {
		secrets, err := r.decodeConnectionSecrets(row.ID, row.Secrets)
		if err != nil {
			return domain.Connection{}, err
		}
		c.Secrets = secrets
	}
	return c, nil
}

func connectionSecretsAAD(id string) []byte { return secretAAD("connections", "secrets", id) }

// encodeConnectionSecrets is the stored form of the secrets column: the JSON
// object, sealed into a JSON string when a key is configured (a JSON string
// keeps the column's json type valid on MySQL).
func (r *ConnectionsRepo) encodeConnectionSecrets(id string, secrets map[string]string) ([]byte, error) {
	plain, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	return r.sealConnectionSecrets(id, plain)
}

func (r *ConnectionsRepo) sealConnectionSecrets(id string, plain []byte) ([]byte, error) {
	if !r.secrets.Enabled() {
		return plain, nil
	}
	sealed, err := r.secrets.Seal(plain, connectionSecretsAAD(id))
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealed)
}

// parseConnectionSecretsColumn tells a sealed column (a JSON string holding
// an envelope) from a legacy plaintext one (a JSON object, null or empty).
func parseConnectionSecretsColumn(col []byte) (sealed string, isSealed bool, err error) {
	trimmed := bytes.TrimSpace(col)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false, nil
	}
	if err := json.Unmarshal(trimmed, &sealed); err != nil || !secretbox.IsSealed(sealed) {
		return "", false, secretbox.ErrMalformed
	}
	return sealed, true, nil
}

func (r *ConnectionsRepo) decodeConnectionSecrets(id string, col []byte) (map[string]string, error) {
	sealed, isSealed, err := parseConnectionSecretsColumn(col)
	if err != nil {
		return nil, unreadable("connections", id, err)
	}
	plain := bytes.TrimSpace(col)
	if isSealed {
		if plain, err = r.secrets.Open(sealed, connectionSecretsAAD(id)); err != nil {
			return nil, unreadable("connections", id, err)
		}
	}
	if len(plain) == 0 {
		return nil, nil
	}
	var secrets map[string]string
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return nil, fmt.Errorf("connection %s: secrets: %w", id, err)
	}
	return secrets, nil
}

// connectionSecretsPass scans the secrets column. Without rewrite it only
// checks that every sealed value opens; with rewrite it also seals plaintext
// rows and re-seals rows under a previous key (unless dryRun). Only the
// secrets column is written: updated_at and the payload are left alone.
func (r *ConnectionsRepo) connectionSecretsPass(rewrite, dryRun bool) (SecretsReport, error) {
	report := SecretsReport{Table: "connections"}
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		var rows []connectionRow
		q := tx.Select("id", "secrets").Order("id")
		if rewrite && !dryRun {
			q = r.locking(q)
		}
		if err := q.Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			aad := connectionSecretsAAD(row.ID)
			sealed, isSealed, err := parseConnectionSecretsColumn(row.Secrets)
			if err != nil {
				return unreadable("connections", row.ID, err)
			}
			plain, err := classify(r.secrets, aad, sealed, isSealed, &report)
			if err != nil {
				return unreadable("connections", row.ID, err)
			}
			if !rewrite || (isSealed && r.secrets.IsCurrent(sealed)) {
				continue
			}
			if !isSealed {
				var legacy map[string]string
				if trimmed := bytes.TrimSpace(row.Secrets); len(trimmed) > 0 {
					if err := json.Unmarshal(trimmed, &legacy); err != nil {
						return fmt.Errorf("connections row %s: secrets are not a JSON object", row.ID)
					}
				}
				if plain, err = json.Marshal(legacy); err != nil {
					return err
				}
			}
			if dryRun {
				continue
			}
			col, err := r.sealConnectionSecrets(row.ID, plain)
			if err != nil {
				return err
			}
			if err := tx.Model(&connectionRow{}).Where("id = ?", row.ID).UpdateColumn("secrets", col).Error; err != nil {
				return err
			}
			report.Rewritten++
		}
		return nil
	})
	return report, err
}

// Connections lists a project's connections without secrets; connectorID
// narrows the list when set.
func (r *ConnectionsRepo) Connections(projectID, connectorID string) ([]domain.Connection, error) {
	var rows []connectionRow
	q := r.DB.Select("id", "project_id", "connector_id", "payload", "created_at", "updated_at").Where("project_id = ?", projectID)
	if connectorID != "" {
		q = q.Where("connector_id = ?", connectorID)
	}
	if err := q.Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Connection, 0, len(rows))
	for _, row := range rows {
		c, err := r.connectionFromRow(row, false)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// DeleteConnection removes a connection.
func (r *ConnectionsRepo) DeleteConnection(id string) error {
	res := r.DB.Delete(&connectionRow{}, "id = ?", id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrConnectionNotFound
	}
	return nil
}
