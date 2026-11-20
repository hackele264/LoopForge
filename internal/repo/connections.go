package repo

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"agentflow/internal/domain"
)

// ConnectionsRepo owns connector connections: per-project endpoints and
// credentials used by action nodes.
type ConnectionsRepo struct{ *deps }

// ErrConnectionNotFound is returned for an unknown connection.
var ErrConnectionNotFound = errors.New("connection not found")

type connectionRow struct {
	ID          string `gorm:"primaryKey;size:64"`
	ProjectID   string `gorm:"size:128;index"`
	ConnectorID string `gorm:"size:64;index"`
	Payload     []byte `gorm:"type:json"`
	// Secrets is a JSON object of secret name → value, kept out of
	// Payload so listing queries can skip it.
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
	secrets, err := json.Marshal(c.Secrets)
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

// Connection returns one connection with its secrets.
func (r *ConnectionsRepo) Connection(id string) (domain.Connection, bool) {
	var row connectionRow
	if err := r.DB.First(&row, "id = ?", id).Error; err != nil {
		return domain.Connection{}, false
	}
	c, err := connectionFromRow(row, true)
	return c, err == nil
}

func connectionFromRow(row connectionRow, withSecrets bool) (domain.Connection, error) {
	var c domain.Connection
	if err := json.Unmarshal(row.Payload, &c); err != nil {
		return domain.Connection{}, err
	}
	c.Secrets = nil
	if withSecrets && len(row.Secrets) > 0 {
		if err := json.Unmarshal(row.Secrets, &c.Secrets); err != nil {
			return domain.Connection{}, err
		}
	}
	return c, nil
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
		c, err := connectionFromRow(row, false)
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
