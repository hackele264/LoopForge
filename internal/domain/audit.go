package domain

import "time"

// AuditEvent is one entry of the platform audit log: who did what, through
// which credential, from where, with what result. Request bodies are never
// recorded.
type AuditEvent struct {
	ID          string    `json:"id"`
	At          time.Time `json:"at"`
	ActorUserID int64     `json:"actorUserId,omitempty"`
	ActorLogin  string    `json:"actorLogin,omitempty"`
	ActorKind   string    `json:"actorKind,omitempty"`
	// TokenID is the API token used, empty for an interactive session.
	TokenID string `json:"tokenId,omitempty"`
	// Action is a dotted name (auth.login, credential.use) or, for API
	// writes, "api " + method + " " + route pattern.
	Action    string  `json:"action"`
	Method    string  `json:"method,omitempty"`
	Path      string  `json:"path,omitempty"`
	ProjectID string  `json:"projectId,omitempty"`
	Target    string  `json:"target,omitempty"`
	Status    int     `json:"status,omitempty"`
	Outcome   string  `json:"outcome"` // success, failure, denied
	IP        string  `json:"ip,omitempty"`
	Detail    RawJSON `json:"detail,omitempty"`
}

// Audit outcomes.
const (
	AuditSuccess = "success"
	AuditFailure = "failure"
	AuditDenied  = "denied"
)

// AuditOutcome classifies an HTTP status.
func AuditOutcome(status int) string {
	switch {
	case status == 401 || status == 403:
		return AuditDenied
	case status >= 400:
		return AuditFailure
	}
	return AuditSuccess
}
