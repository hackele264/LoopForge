package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Webhook starts one SOP when an external system (SIEM, EDR, mail gateway)
// posts an alert to its URL. The URL embeds a random secret; only its hash
// is stored.
type Webhook struct {
	ID         string `json:"id"`
	ProjectID  string `json:"projectId"`
	WorkflowID string `json:"workflowId"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	// SecretHash is the hex SHA-256 of the URL secret; SecretPrefix shows the
	// first characters so operators can tell rotated secrets apart.
	SecretHash   string `json:"-"`
	SecretPrefix string `json:"secretPrefix,omitempty"`
	// Methods lists accepted HTTP methods; empty means POST only.
	Methods []string `json:"methods,omitempty"`
	// AllowedCIDRs restricts callers by source address; empty allows all.
	AllowedCIDRs []string `json:"allowedCidrs,omitempty"`
	// SignatureHeader names a header carrying an HMAC-SHA256 of the raw body
	// keyed by SigningSecret ("sha256=<hex>" or bare hex). Both empty skips it.
	SignatureHeader  string `json:"signatureHeader,omitempty"`
	SigningSecret    string `json:"signingSecret,omitempty"`
	HasSigningSecret bool   `json:"hasSigningSecret,omitempty"`
	// TitleField is a dot path into the payload used as the run input.
	TitleField string `json:"titleField,omitempty"`
	// DedupFields are dot paths whose values form the alert fingerprint; an
	// alert with the fingerprint of one seen within DedupWindowSeconds does
	// not start a new run. Empty disables deduplication.
	DedupFields        []string   `json:"dedupFields,omitempty"`
	DedupWindowSeconds int        `json:"dedupWindowSeconds,omitempty"`
	CreatedBy          int64      `json:"createdBy,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
	LastTriggeredAt    *time.Time `json:"lastTriggeredAt,omitempty"`
}

// Webhook limits.
const (
	WebhookMaxDedupWindow   = 7 * 24 * 60 * 60
	WebhookDefaultDedupWind = 60 * 60
	WebhookMaxFields        = 16
	WebhookMaxPathLength    = 200
)

// WebhookDelivery records one inbound call for troubleshooting.
type WebhookDelivery struct {
	ID          string    `json:"id"`
	WebhookID   string    `json:"webhookId"`
	ReceivedAt  time.Time `json:"receivedAt"`
	Status      string    `json:"status"` // started, deduplicated, rejected, failed
	HTTPStatus  int       `json:"httpStatus"`
	RunID       string    `json:"runId,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Message     string    `json:"message,omitempty"`
	SourceIP    string    `json:"sourceIp,omitempty"`
}

// Webhook delivery statuses.
const (
	WebhookDeliveryStarted      = "started"
	WebhookDeliveryDeduplicated = "deduplicated"
	WebhookDeliveryRejected     = "rejected"
	WebhookDeliveryFailed       = "failed"
)

// HashWebhookSecret is the stored form of a webhook URL secret.
func HashWebhookSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Normalize trims fields and fills defaults before validation.
func (w *Webhook) Normalize() {
	w.Name = strings.TrimSpace(w.Name)
	w.ProjectID = strings.TrimSpace(w.ProjectID)
	w.WorkflowID = strings.TrimSpace(w.WorkflowID)
	w.SignatureHeader = strings.TrimSpace(w.SignatureHeader)
	w.TitleField = strings.TrimSpace(w.TitleField)
	methods := []string{}
	for _, m := range w.Methods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" && !contains(methods, m) {
			methods = append(methods, m)
		}
	}
	w.Methods = methods
	w.AllowedCIDRs = trimNonEmpty(w.AllowedCIDRs)
	w.DedupFields = trimNonEmpty(w.DedupFields)
	if len(w.DedupFields) > 0 && w.DedupWindowSeconds <= 0 {
		w.DedupWindowSeconds = WebhookDefaultDedupWind
	}
}

// Validate checks a normalized webhook definition.
func (w Webhook) Validate() error {
	if w.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(w.Name) > 120 {
		return fmt.Errorf("name is too long")
	}
	if w.ProjectID == "" || w.WorkflowID == "" {
		return fmt.Errorf("projectId and workflowId are required")
	}
	for _, m := range w.Methods {
		if m != http.MethodPost && m != http.MethodPut && m != http.MethodGet {
			return fmt.Errorf("unsupported method %q (POST, PUT or GET)", m)
		}
	}
	if len(w.AllowedCIDRs) > 64 {
		return fmt.Errorf("at most 64 allowed CIDRs")
	}
	for _, cidr := range w.AllowedCIDRs {
		if _, err := ParseCIDROrIP(cidr); err != nil {
			return fmt.Errorf("invalid allowed CIDR %q", cidr)
		}
	}
	if (w.SignatureHeader == "") != (strings.TrimSpace(w.SigningSecret) == "" && !w.HasSigningSecret) {
		return fmt.Errorf("signatureHeader and signingSecret must be set together")
	}
	if w.SignatureHeader != "" && http.CanonicalHeaderKey(w.SignatureHeader) == "" {
		return fmt.Errorf("invalid signature header")
	}
	if len(w.TitleField) > WebhookMaxPathLength {
		return fmt.Errorf("titleField is too long")
	}
	if len(w.DedupFields) > WebhookMaxFields {
		return fmt.Errorf("at most %d dedup fields", WebhookMaxFields)
	}
	for _, f := range w.DedupFields {
		if len(f) > WebhookMaxPathLength {
			return fmt.Errorf("dedup field %q is too long", f)
		}
	}
	if w.DedupWindowSeconds < 0 || w.DedupWindowSeconds > WebhookMaxDedupWindow {
		return fmt.Errorf("dedupWindowSeconds must be between 0 and %d", WebhookMaxDedupWindow)
	}
	return nil
}

// AllowsMethod reports whether method may call the webhook.
func (w Webhook) AllowsMethod(method string) bool {
	if len(w.Methods) == 0 {
		return method == http.MethodPost
	}
	return contains(w.Methods, strings.ToUpper(method))
}

// AllowsIP reports whether ip passes the CIDR allowlist.
func (w Webhook) AllowsIP(ip net.IP) bool {
	if len(w.AllowedCIDRs) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, cidr := range w.AllowedCIDRs {
		if network, err := ParseCIDROrIP(cidr); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDROrIP accepts "10.0.0.0/8" or a single address.
func ParseCIDROrIP(value string) (*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if _, network, err := net.ParseCIDR(value); err == nil {
		return network, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("invalid address %q", value)
	}
	bits := 128
	if ip.To4() != nil {
		ip, bits = ip.To4(), 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// LookupJSONPath reads a dot path ("alert.src.ip", "items.0.id") from a
// decoded JSON value. Missing segments read as nil.
func LookupJSONPath(value any, path string) any {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	current := value
	for _, segment := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]any:
			current = node[segment]
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(node) {
				return nil
			}
			current = node[index]
		default:
			return nil
		}
	}
	return current
}

// WebhookFingerprint hashes the values at fields. It returns "" when no
// field has a value, so an alert missing every key is never deduplicated.
func WebhookFingerprint(payload any, fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	values := make([]any, len(fields))
	present := false
	for i, field := range fields {
		values[i] = LookupJSONPath(payload, field)
		if values[i] != nil {
			present = true
		}
	}
	if !present {
		return ""
	}
	// encoding/json sorts map keys, so equal values always hash alike.
	raw, err := json.Marshal(struct {
		Fields []string `json:"f"`
		Values []any    `json:"v"`
	}{fields, values})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// WebhookTitle renders the run input for an alert.
func WebhookTitle(w Webhook, payload any) string {
	title := ""
	if w.TitleField != "" {
		switch v := LookupJSONPath(payload, w.TitleField).(type) {
		case string:
			title = v
		case nil:
		default:
			if raw, err := json.Marshal(v); err == nil {
				title = string(raw)
			}
		}
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Webhook 告警：" + w.Name
	}
	if len([]rune(title)) > 500 {
		title = string([]rune(title)[:500])
	}
	return title
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func trimNonEmpty(values []string) []string {
	out := []string{}
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
