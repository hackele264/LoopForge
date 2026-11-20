package domain

import (
	"encoding/pem"
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
	Params map[string]string `json:"params,omitempty"`
	// TLSCertSHA256 pins the server certificate by the SHA-256 of its DER
	// bytes, for on-premise products with self-signed certificates (a
	// Splunk management port). CA checks are skipped unless TLSCAPEM is set.
	TLSCertSHA256 string `json:"tlsCertSha256,omitempty"`
	// TLSCAPEM is a PEM bundle of CAs trusted for this connection only.
	TLSCAPEM string `json:"tlsCaPem,omitempty"`
	// RateLimitPerSecond caps the requests one platform process sends
	// through this connection; 0 is unlimited. RateLimitBurst is how many may
	// go at once (0 means 1). Calls over the limit wait for their turn.
	RateLimitPerSecond float64 `json:"rateLimitPerSecond,omitempty"`
	RateLimitBurst     int     `json:"rateLimitBurst,omitempty"`
	// MaxRetries is how many times a call is retried on HTTP 429, and for
	// GET also on 5xx and transport errors; nil uses
	// ConnectionDefaultRetries, 0 turns retries off.
	MaxRetries *int      `json:"maxRetries,omitempty"`
	SecretsSet []string  `json:"secretsSet,omitempty"`
	CreatedBy  int64     `json:"createdBy,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	// Secrets is never serialized; only the repository and the action
	// executor read it.
	Secrets map[string]string `json:"-"`
}

// Connection rate and retry limits.
const (
	ConnectionDefaultRetries = 3
	ConnectionMaxRetries     = 10
	ConnectionMaxRate        = 1000
	ConnectionMaxBurst       = 1000
)

// Retries is how many times a failed call may be retried.
func (c Connection) Retries() int {
	if c.MaxRetries == nil {
		return ConnectionDefaultRetries
	}
	return *c.MaxRetries
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
	if c.TLSCertSHA256 != "" && !validCertPin(c.TLSCertSHA256) {
		return fmt.Errorf("tlsCertSha256 must be 64 hex characters")
	}
	if c.TLSCAPEM != "" {
		if len(c.TLSCAPEM) > 64<<10 {
			return fmt.Errorf("tlsCaPem is too long")
		}
		if block, _ := pem.Decode([]byte(c.TLSCAPEM)); block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("tlsCaPem must hold PEM certificates")
		}
	}
	if c.RateLimitPerSecond < 0 || c.RateLimitPerSecond > ConnectionMaxRate {
		return fmt.Errorf("rateLimitPerSecond must be between 0 and %d", ConnectionMaxRate)
	}
	if c.RateLimitBurst < 0 || c.RateLimitBurst > ConnectionMaxBurst {
		return fmt.Errorf("rateLimitBurst must be between 0 and %d", ConnectionMaxBurst)
	}
	if c.MaxRetries != nil && (*c.MaxRetries < 0 || *c.MaxRetries > ConnectionMaxRetries) {
		return fmt.Errorf("maxRetries must be between 0 and %d", ConnectionMaxRetries)
	}
	if (c.TLSCertSHA256 != "" || c.TLSCAPEM != "") && strings.HasPrefix(strings.TrimSpace(c.BaseURL), "http://") {
		return fmt.Errorf("TLS settings need an https:// baseUrl")
	}
	return nil
}

// NormalizeCertPin lowercases a certificate fingerprint and drops the
// colons and spaces tools such as openssl print.
func NormalizeCertPin(pin string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(pin)))
}

func validCertPin(pin string) bool {
	if len(pin) != 64 {
		return false
	}
	for _, r := range pin {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
