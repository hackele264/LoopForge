package domain

import (
	"fmt"
	"strings"
	"time"
)

// Connection holds the endpoint and credentials one project uses for one
// connector (for example the team's VirusTotal key). Secrets are write-only:
// the API reports which secret names are set, never their values.
type Connection struct {
	ID          string `json:"id"`
	ProjectID   string `json:"projectId"`
	ConnectorID string `json:"connectorId"`
	Name        string `json:"name"`
	// BaseURL overrides the connector's default endpoint (on-premise
	// products, regional clouds). Empty uses the connector default.
	BaseURL string `json:"baseUrl,omitempty"`
	// Params are the connector's non-secret settings (tenant ID, region).
	Params     map[string]string `json:"params,omitempty"`
	SecretsSet []string          `json:"secretsSet,omitempty"`
	CreatedBy  int64             `json:"createdBy,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
	UpdatedAt  time.Time         `json:"updatedAt"`
	// Secrets is never serialized; only the repository and the action
	// executor read it.
	Secrets map[string]string `json:"-"`
}

// ValidateConnectionBase checks the fields that do not depend on the
// connector definition.
func (c Connection) ValidateConnectionBase() error {
	if strings.TrimSpace(c.ProjectID) == "" {
		return fmt.Errorf("projectId is required")
	}
	if strings.TrimSpace(c.ConnectorID) == "" {
		return fmt.Errorf("connectorId is required")
	}
	if n := strings.TrimSpace(c.Name); n == "" || len(n) > 120 {
		return fmt.Errorf("name must be 1 to 120 characters")
	}
	if b := strings.TrimSpace(c.BaseURL); b != "" && !strings.HasPrefix(b, "https://") && !strings.HasPrefix(b, "http://") {
		return fmt.Errorf("baseUrl must start with https:// or http://")
	}
	return nil
}
