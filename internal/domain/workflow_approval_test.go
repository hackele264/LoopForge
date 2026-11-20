package domain

import (
	"strings"
	"testing"
	"time"
)

func TestValidateApprovalRule(t *testing.T) {
	t.Parallel()
	users := func(ids ...int64) *ApproverPolicy { return &ApproverPolicy{UserIDs: ids} }
	cases := []struct {
		name      string
		node      WorkflowNode
		wantError string
	}{
		{"absent", WorkflowNode{ID: "g", Type: "approval"}, ""},
		{"two of a role", WorkflowNode{ID: "g", Type: "approval", Approvers: &ApproverPolicy{Roles: []string{"member"}}, Approval: &ApprovalRule{RequiredApprovals: 2}}, ""},
		{"two of two users", WorkflowNode{ID: "g", Type: "approval", Approvers: users(1, 2), Approval: &ApprovalRule{RequiredApprovals: 2}}, ""},
		{"escalate", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: 60, OnTimeout: "escalate", EscalateTo: users(3)}}, ""},
		{"reject", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: 60, OnTimeout: "reject"}}, ""},
		{"not an approval node", WorkflowNode{ID: "g", Type: "script", Approval: &ApprovalRule{RequiredApprovals: 2}}, "approval nodes only"},
		{"too many approvals", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{RequiredApprovals: 4}}, "between 1 and 3"},
		{"negative approvals", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{RequiredApprovals: -1}}, "between 1 and 3"},
		{"more than the listed users", WorkflowNode{ID: "g", Type: "approval", Approvers: users(1, 1), Approval: &ApprovalRule{RequiredApprovals: 2}}, "exceeds the 1 listed"},
		{"timeout too long", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: MaxApprovalTimeoutMinutes + 1, OnTimeout: "reject"}}, "timeoutMinutes"},
		{"negative timeout", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: -5, OnTimeout: "reject"}}, "timeoutMinutes"},
		{"timeout without action", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: 5}}, "onTimeout must be"},
		{"unknown action", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: 5, OnTimeout: "ignore"}}, "onTimeout must be"},
		{"escalate without approvers", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: 5, OnTimeout: "escalate"}}, "needs escalateTo"},
		{"escalate to unknown role", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: 5, OnTimeout: "escalate", EscalateTo: &ApproverPolicy{Roles: []string{"boss"}}}}, "unsupported approver role"},
		{"escalateTo with reject", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{TimeoutMinutes: 5, OnTimeout: "reject", EscalateTo: users(3)}}, "escalate only"},
		{"action without timeout", WorkflowNode{ID: "g", Type: "approval", Approval: &ApprovalRule{OnTimeout: "reject"}}, "need timeoutMinutes"},
	}
	for _, c := range cases {
		err := ValidateWorkflowBranching(WorkflowDefinition{Nodes: []WorkflowNode{c.node}})
		switch {
		case c.wantError == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantError != "" && (err == nil || !strings.Contains(err.Error(), c.wantError)):
			t.Errorf("%s: error = %v, want %q", c.name, err, c.wantError)
		}
	}
}

func TestApprovalStateDue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if NewApprovalState(nil, now) != nil || NewApprovalState(&ApprovalRule{RequiredApprovals: 1}, now) != nil {
		t.Fatal("an inactive rule must keep no state")
	}
	st := NewApprovalState(&ApprovalRule{RequiredApprovals: 2, TimeoutMinutes: 10, OnTimeout: "escalate"}, now)
	if st.Required != 2 || !st.Deadline.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("state = %+v", st)
	}
	if st.Due(now.Add(9*time.Minute)) || !st.Due(now.Add(10*time.Minute)) {
		t.Fatal("deadline boundary")
	}
	st.Escalated = true
	if st.Due(now.Add(time.Hour)) {
		t.Fatal("an escalated gate is not due again")
	}
	st.Votes = []ApprovalVote{{UserID: 4}}
	if !st.HasVoted(4) || st.HasVoted(5) || st.Progress() != "1/2" {
		t.Fatalf("votes = %+v", st)
	}
	n := &NodeRun{Approval: st}
	n.ResetBranchState()
	if n.Approval != nil {
		t.Fatal("reset keeps the votes")
	}
}
