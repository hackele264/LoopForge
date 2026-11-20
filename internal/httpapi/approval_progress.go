package httpapi

import (
	"time"

	"agentflow/internal/domain"
)

// approvalProgress is the multi-person / deadline state returned by the
// approve endpoint for gates with an approval rule.
type approvalProgress struct {
	// Approved is true once the node passed; false while it waits for more
	// approvals.
	Approved    bool                  `json:"approved"`
	Approvals   int                   `json:"approvals"`
	Required    int                   `json:"required"`
	Votes       []domain.ApprovalVote `json:"votes,omitempty"`
	Deadline    *time.Time            `json:"deadline,omitempty"`
	OnTimeout   string                `json:"onTimeout,omitempty"`
	Escalated   bool                  `json:"escalated,omitempty"`
	EscalatedAt *time.Time            `json:"escalatedAt,omitempty"`
}

// approveResponse is {"ok": true}, plus "approval" when the node has an
// approval rule.
func approveResponse(run domain.Run, nodeID string) map[string]any {
	body := map[string]any{"ok": true}
	nr := run.Nodes[nodeID]
	if nr == nil || nr.Approval == nil {
		return body
	}
	st := nr.Approval
	p := approvalProgress{Approved: nr.Status != "waiting_approval", Approvals: len(st.Votes), Required: max(1, st.Required), Votes: st.Votes, OnTimeout: st.OnTimeout, Escalated: st.Escalated}
	if !st.Deadline.IsZero() {
		d := st.Deadline
		p.Deadline = &d
	}
	if !st.EscalatedAt.IsZero() {
		at := st.EscalatedAt
		p.EscalatedAt = &at
	}
	body["approval"] = p
	return body
}

// approvalPendingNote is appended to chat replies after a partial approval.
func approvalPendingNote(run domain.Run, nodeID string) string {
	nr := run.Nodes[nodeID]
	if nr == nil || nr.Approval == nil || nr.Status != "waiting_approval" {
		return ""
	}
	return "（已批准 " + nr.Approval.Progress() + "，还需其他审批人批准）"
}
