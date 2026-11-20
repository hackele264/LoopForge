package domain

import (
	"fmt"
	"strings"
	"time"
)

// ApprovalRule adds two-person approval and timed escalation to an approval
// node. Every field is optional; a nil rule keeps the single-decision gate.
type ApprovalRule struct {
	// RequiredApprovals is how many distinct named people must approve before
	// the node passes (1 to MaxRequiredApprovals; 0 means 1). A single
	// rejection by an allowed approver still decides immediately.
	RequiredApprovals int `json:"requiredApprovals,omitempty"`
	// TimeoutMinutes starts a deadline when the node begins waiting. Zero
	// means no deadline.
	TimeoutMinutes int `json:"timeoutMinutes,omitempty"`
	// OnTimeout is what happens at the deadline: "escalate" lets EscalateTo
	// decide as well and sends a waiting notification; "reject" rejects the
	// node on behalf of the system.
	OnTimeout string `json:"onTimeout,omitempty"`
	// EscalateTo names who may also decide once the gate escalated.
	EscalateTo *ApproverPolicy `json:"escalateTo,omitempty"`
}

// Approval timeout actions for ApprovalRule.OnTimeout.
const (
	ApprovalOnTimeoutEscalate = "escalate"
	ApprovalOnTimeoutReject   = "reject"
)

// Bounds for ApprovalRule.
const (
	MaxRequiredApprovals      = 3
	MaxApprovalTimeoutMinutes = 30 * 24 * 60
)

// Required returns the number of distinct approvals the node needs.
func (r *ApprovalRule) Required() int {
	if r == nil || r.RequiredApprovals < 1 {
		return 1
	}
	return r.RequiredApprovals
}

// Timeout returns the waiting deadline, zero for none.
func (r *ApprovalRule) Timeout() time.Duration {
	if r == nil || r.TimeoutMinutes <= 0 {
		return 0
	}
	return time.Duration(r.TimeoutMinutes) * time.Minute
}

// Active reports whether the rule changes anything about the gate.
func (r *ApprovalRule) Active() bool {
	return r != nil && (r.Required() > 1 || r.Timeout() > 0)
}

// validateApprovalRule checks one node's rule: bounds, the timeout action and
// its escalation approvers, and that a users-only policy lists enough people.
func validateApprovalRule(n WorkflowNode) error {
	rule := n.Approval
	if rule == nil {
		return nil
	}
	if n.Type != "approval" {
		return fmt.Errorf("node %s: approval rules apply to approval nodes only", n.ID)
	}
	if rule.RequiredApprovals < 0 || rule.RequiredApprovals > MaxRequiredApprovals {
		return fmt.Errorf("node %s: requiredApprovals must be between 1 and %d", n.ID, MaxRequiredApprovals)
	}
	if p := n.Approvers; p != nil && len(p.Roles) == 0 && len(p.UserIDs) > 0 && rule.Required() > len(uniqueIDs(p.UserIDs)) {
		return fmt.Errorf("node %s: requiredApprovals (%d) exceeds the %d listed approvers", n.ID, rule.Required(), len(uniqueIDs(p.UserIDs)))
	}
	if rule.TimeoutMinutes < 0 || rule.TimeoutMinutes > MaxApprovalTimeoutMinutes {
		return fmt.Errorf("node %s: timeoutMinutes must be between 1 and %d", n.ID, MaxApprovalTimeoutMinutes)
	}
	action := strings.TrimSpace(rule.OnTimeout)
	if rule.TimeoutMinutes == 0 {
		if action != "" || !rule.EscalateTo.Empty() {
			return fmt.Errorf("node %s: onTimeout and escalateTo need timeoutMinutes", n.ID)
		}
		return nil
	}
	switch action {
	case ApprovalOnTimeoutEscalate:
		if rule.EscalateTo.Empty() {
			return fmt.Errorf("node %s: onTimeout escalate needs escalateTo", n.ID)
		}
		if err := validateApproverRoles(n.ID, rule.EscalateTo); err != nil {
			return err
		}
	case ApprovalOnTimeoutReject:
		if !rule.EscalateTo.Empty() {
			return fmt.Errorf("node %s: escalateTo applies to onTimeout escalate only", n.ID)
		}
	default:
		return fmt.Errorf("node %s: onTimeout must be %q or %q", n.ID, ApprovalOnTimeoutEscalate, ApprovalOnTimeoutReject)
	}
	return nil
}

func validateApproverRoles(nodeID string, p *ApproverPolicy) error {
	for _, role := range p.Roles {
		switch role {
		case ApproverRoleOwner, ApproverRoleMaintainer, ApproverRoleMember, ApproverRoleAdmin:
		default:
			return fmt.Errorf("node %s has unsupported approver role %q", nodeID, role)
		}
	}
	return nil
}

func uniqueIDs(ids []int64) map[int64]bool {
	out := map[int64]bool{}
	for _, id := range ids {
		if id > 0 {
			out[id] = true
		}
	}
	return out
}

// ApprovalState is the persisted progress of an approval node with an active
// ApprovalRule, stored on its NodeRun. It is recreated each time the node
// starts waiting, so a retry, rework or rerun starts with no votes.
type ApprovalState struct {
	Required int            `json:"required"`
	Votes    []ApprovalVote `json:"votes,omitempty"`
	// Deadline is when the timeout fires; zero without a timeout.
	Deadline  time.Time `json:"deadline,omitzero"`
	OnTimeout string    `json:"onTimeout,omitempty"`
	// Escalated is set once the deadline passed with onTimeout escalate.
	Escalated   bool      `json:"escalated,omitempty"`
	EscalatedAt time.Time `json:"escalatedAt,omitzero"`
	// TimedOut is set when the system rejected the node at the deadline.
	TimedOut bool `json:"timedOut,omitempty"`
}

// ApprovalVote is one person's approval.
type ApprovalVote struct {
	UserID int64     `json:"userId"`
	Login  string    `json:"login,omitempty"`
	Kind   string    `json:"kind,omitempty"`
	At     time.Time `json:"at"`
	// Escalation marks a vote cast under the escalation policy.
	Escalation bool `json:"escalation,omitempty"`
}

// NewApprovalState starts the progress for a node entering waiting at now.
func NewApprovalState(rule *ApprovalRule, now time.Time) *ApprovalState {
	if !rule.Active() {
		return nil
	}
	st := &ApprovalState{Required: rule.Required()}
	if d := rule.Timeout(); d > 0 {
		st.Deadline = now.UTC().Add(d)
		st.OnTimeout = strings.TrimSpace(rule.OnTimeout)
	}
	return st
}

// HasVoted reports whether userID already approved.
func (s *ApprovalState) HasVoted(userID int64) bool {
	if s == nil {
		return false
	}
	for _, v := range s.Votes {
		if v.UserID == userID {
			return true
		}
	}
	return false
}

// Due reports whether the deadline passed and its action has not run yet.
func (s *ApprovalState) Due(now time.Time) bool {
	if s == nil || s.Deadline.IsZero() || now.Before(s.Deadline) || s.TimedOut {
		return false
	}
	return !(s.OnTimeout == ApprovalOnTimeoutEscalate && s.Escalated)
}

// Progress renders "1/2" for messages.
func (s *ApprovalState) Progress() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%d/%d", len(s.Votes), max(1, s.Required))
}
