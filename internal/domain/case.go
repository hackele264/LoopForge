package domain

import (
	"fmt"
	"strings"
	"time"
)

// Alert is one inbound security alert, normalized from a webhook delivery
// (or created through the API). Payload keeps the raw object.
type Alert struct {
	ID          string `json:"id"`
	ProjectID   string `json:"projectId"`
	WebhookID   string `json:"webhookId,omitempty"`
	Source      string `json:"source,omitempty"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CaseID      string `json:"caseId,omitempty"`
	RunID       string `json:"runId,omitempty"`
	// Duplicate marks an alert that matched a live fingerprint and started
	// no run of its own.
	Duplicate  bool      `json:"duplicate,omitempty"`
	Payload    RawJSON   `json:"payload,omitempty"`
	ReceivedAt time.Time `json:"receivedAt"`
}

// Case groups related alerts under one investigation.
type Case struct {
	ID          string `json:"id"`
	ProjectID   string `json:"projectId"`
	Number      int    `json:"number"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	// Resolution is set when the case is closed.
	Resolution string     `json:"resolution,omitempty"`
	AssigneeID int64      `json:"assigneeId,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
	AlertCount int        `json:"alertCount"`
	CreatedBy  int64      `json:"createdBy,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
	ClosedAt   *time.Time `json:"closedAt,omitempty"`
}

// CaseIOC is an indicator extracted from a case's alerts or added by hand.
type CaseIOC struct {
	CaseID    string    `json:"caseId"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	AlertID   string    `json:"alertId,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
}

// CaseEvent is one entry on a case timeline.
type CaseEvent struct {
	ID          string    `json:"id"`
	CaseID      string    `json:"caseId"`
	Type        string    `json:"type"`
	Message     string    `json:"message"`
	ActorUserID int64     `json:"actorUserId,omitempty"`
	ActorKind   string    `json:"actorKind,omitempty"`
	Data        RawJSON   `json:"data,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// CaseTrigger starts an SOP when matching case events happen.
type CaseTrigger struct {
	ID         string   `json:"id"`
	ProjectID  string   `json:"projectId"`
	WorkflowID string   `json:"workflowId"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Events     []string `json:"events"`
	// MinSeverity skips cases below this severity; empty matches all.
	MinSeverity string    `json:"minSeverity,omitempty"`
	CreatedBy   int64     `json:"createdBy,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Severities, lowest first.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var severityRank = map[string]int{SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4}

// SeverityRank orders severities; unknown values rank 0.
func SeverityRank(s string) int { return severityRank[s] }

// NormalizeSeverity maps common vendor wordings and numbers onto the four
// levels. Unrecognized values become medium.
func NormalizeSeverity(value any) string {
	switch v := value.(type) {
	case float64:
		switch {
		case v >= 9:
			return SeverityCritical
		case v >= 7:
			return SeverityHigh
		case v >= 4:
			return SeverityMedium
		case v > 0:
			return SeverityLow
		}
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "critical", "crit", "fatal", "emergency", "严重", "紧急", "p0", "p1":
			return SeverityCritical
		case "high", "major", "error", "高", "高危", "p2":
			return SeverityHigh
		case "medium", "moderate", "warning", "warn", "中", "中危", "p3":
			return SeverityMedium
		case "low", "minor", "info", "informational", "notice", "低", "低危", "p4":
			return SeverityLow
		}
	}
	return SeverityMedium
}

// Case statuses and resolutions.
const (
	CaseStatusNew             = "new"
	CaseStatusInvestigating   = "investigating"
	CaseStatusPendingResponse = "pending_response"
	CaseStatusClosed          = "closed"

	CaseResolutionFalsePositive = "false_positive"
	CaseResolutionResolved      = "resolved"
	CaseResolutionDuplicate     = "duplicate"
)

// Case event types. Triggers may subscribe to the starred ones.
const (
	CaseEventCreated         = "case.created"          // *
	CaseEventAlertAdded      = "case.alert_added"      // *
	CaseEventStatusChanged   = "case.status_changed"   // *
	CaseEventSeverityChanged = "case.severity_changed" // *
	CaseEventEscalated       = "case.escalated"        // * severity raised to high or critical
	CaseEventAssigned        = "case.assigned"
	CaseEventUpdated         = "case.updated"
	CaseEventComment         = "case.comment"
	CaseEventIOCAdded        = "case.ioc_added"
	CaseEventRunStarted      = "case.run_started"
	// CaseEventAction records a connector action a playbook ran on the case.
	CaseEventAction = "case.action"
	// CaseEventApproval records a person approving or rejecting a step of
	// a run on the case.
	CaseEventApproval = "case.approval"
)

// CaseTriggerEvents lists the events a trigger may subscribe to.
var CaseTriggerEvents = []string{CaseEventCreated, CaseEventAlertAdded, CaseEventStatusChanged, CaseEventSeverityChanged, CaseEventEscalated}

// CaseTriggerMaxRunsPerCase bounds how many runs triggers may start for one
// case, so a playbook that keeps changing its own case cannot loop forever.
const CaseTriggerMaxRunsPerCase = 20

// ValidateCaseStatus checks a status and the resolution it requires.
func ValidateCaseStatus(status, resolution string) error {
	switch status {
	case CaseStatusNew, CaseStatusInvestigating, CaseStatusPendingResponse:
		if resolution != "" {
			return fmt.Errorf("resolution is only set when closing a case")
		}
	case CaseStatusClosed:
		switch resolution {
		case CaseResolutionFalsePositive, CaseResolutionResolved, CaseResolutionDuplicate:
		default:
			return fmt.Errorf("closing a case needs a resolution: false_positive, resolved or duplicate")
		}
	default:
		return fmt.Errorf("unsupported case status %q", status)
	}
	return nil
}

// ValidateSeverity checks one of the four levels.
func ValidateSeverity(s string) error {
	if severityRank[s] == 0 {
		return fmt.Errorf("severity must be low, medium, high or critical")
	}
	return nil
}

// Normalize trims a trigger and validates it.
func (t *CaseTrigger) Normalize() error {
	t.Name = strings.TrimSpace(t.Name)
	t.ProjectID = strings.TrimSpace(t.ProjectID)
	t.WorkflowID = strings.TrimSpace(t.WorkflowID)
	t.MinSeverity = strings.TrimSpace(t.MinSeverity)
	t.Events = trimNonEmpty(t.Events)
	if t.Name == "" || len(t.Name) > 120 {
		return fmt.Errorf("name is required (at most 120 characters)")
	}
	if t.ProjectID == "" || t.WorkflowID == "" {
		return fmt.Errorf("projectId and workflowId are required")
	}
	if len(t.Events) == 0 {
		return fmt.Errorf("pick at least one event")
	}
	for _, e := range t.Events {
		if !contains(CaseTriggerEvents, e) {
			return fmt.Errorf("unsupported trigger event %q", e)
		}
	}
	if t.MinSeverity != "" {
		if err := ValidateSeverity(t.MinSeverity); err != nil {
			return err
		}
	}
	return nil
}

// Matches reports whether the trigger fires for an event on c.
func (t CaseTrigger) Matches(eventType string, c Case) bool {
	if !t.Enabled || t.ProjectID != c.ProjectID || !contains(t.Events, eventType) {
		return false
	}
	return t.MinSeverity == "" || SeverityRank(c.Severity) >= SeverityRank(t.MinSeverity)
}
