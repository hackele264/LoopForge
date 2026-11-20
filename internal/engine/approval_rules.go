package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"agentflow/internal/apperr"
	"agentflow/internal/domain"
)

// Two-person approval: an approval node with an ApprovalRule passes only
// after Required approvals from distinct people. Votes live on the node's
// ApprovalState, which is recreated whenever the node starts waiting, so a
// retry, rework or rerun starts over. A rejection (打回) by any allowed
// approver still decides immediately.

// systemTimeoutActor is the actor recorded when an approval deadline fires.
var systemTimeoutActor = domain.Actor{Kind: domain.ActorSystem, Login: "system:approval-timeout"}

// startApprovalWait records the vote and deadline state for a node that
// starts waiting. Nodes without an active rule keep no state.
func startApprovalWait(nr *domain.NodeRun, node domain.WorkflowNode, now time.Time) {
	if nr == nil {
		return
	}
	nr.Approval = domain.NewApprovalState(node.Approval, now)
}

// approvalNodeDef returns the run's definition of nodeID.
func (e *Engine) approvalNodeDef(r domain.Run, nodeID string) (domain.WorkflowNode, bool) {
	for _, n := range workflowForRun(e.repo, r).Nodes {
		if n.ID == nodeID {
			return n, true
		}
	}
	return domain.WorkflowNode{}, false
}

func (e *Engine) decisionProject(r domain.Run) domain.Project {
	project, _ := e.repo.Project(r.ExecutionContext.ProjectID)
	return project
}

func (e *Engine) actorIsPlatformAdmin(actor domain.Actor) bool {
	return strings.TrimSpace(actor.Login) != "" && e.repo.IsPlatformAdmin(actor.Login)
}

// escalationAllows reports whether the node escalated and actor is one of
// its escalation approvers.
func (e *Engine) escalationAllows(r domain.Run, nodeID string, rule *domain.ApprovalRule, actor domain.Actor) bool {
	nr := r.Nodes[nodeID]
	if rule == nil || rule.EscalateTo.Empty() || nr == nil || nr.Approval == nil || !nr.Approval.Escalated {
		return false
	}
	return rule.EscalateTo.Allows(actor, e.decisionProject(r), e.actorIsPlatformAdmin(actor))
}

// castApprovalVote adds actor's approval to a node with an active rule and
// reports whether the node now has enough approvals. Nodes without a rule
// are complete with the first approval, as before.
func (e *Engine) castApprovalVote(r *domain.Run, nodeID string, actor domain.Actor) (bool, error) {
	node, _ := e.approvalNodeDef(*r, nodeID)
	rule := node.Approval
	nr := r.Nodes[nodeID]
	if !rule.Active() || nr == nil {
		return true, nil
	}
	if nr.Approval == nil {
		// Waiting started before the rule state existed: count from here.
		nr.Approval = &domain.ApprovalState{Required: rule.Required()}
	}
	st := nr.Approval
	if st.Required > 1 {
		if !actor.Named() {
			return false, apperr.New(apperr.Forbidden, "该人工关口需要多人审批，只接受具名用户审批")
		}
		if st.HasVoted(actor.UserID) {
			return false, apperr.Newf(apperr.Conflict, "你已经批准过该关口（%s），需要另一位审批人批准", st.Progress())
		}
	}
	vote := domain.ApprovalVote{UserID: actor.UserID, Login: actor.Login, Kind: actor.Kind, At: time.Now().UTC()}
	if !node.Approvers.Empty() && !node.Approvers.Allows(actor, e.decisionProject(*r), e.actorIsPlatformAdmin(actor)) {
		vote.Escalation = true
	}
	st.Votes = append(st.Votes, vote)
	return len(st.Votes) >= max(1, st.Required), nil
}

// persistApprovalVote saves a partial approval: the node keeps waiting and
// the run is not resumed.
func (e *Engine) persistApprovalVote(runID string, r domain.Run, nodeID string, actor domain.Actor) error {
	st := r.Nodes[nodeID].Approval
	msg := fmt.Sprintf("已批准 %s，等待其他审批人", st.Progress())
	e.eventBy(&r, nodeID, "gate.vote", msg, actor)
	appendControlTelemetry(&r, nodeID, "gate.vote", msg)
	if err := e.repo.PutRunAtRevision(r, r.Revision); err != nil {
		return err
	}
	e.publish(runID)
	e.releaseIdleLease(r)
	e.auditApproval(r, nodeID, "approval.vote", actor, nil)
	return nil
}

// releaseIdleLease gives up a lease taken only to record a decision that
// does not restart the run.
func (e *Engine) releaseIdleLease(r domain.Run) {
	if r.Status == "running" || e.isRunSchedulerActive(r.ID) {
		return
	}
	e.mu.Lock()
	instanceID := e.instanceID
	e.mu.Unlock()
	if r.OwnerInstanceID == instanceID {
		_ = e.repo.ReleaseRunLease(r.ID, instanceID, r.Generation)
	}
}

// approvalVotesByline lists every approver for the decision artifact of a
// multi-person gate.
func approvalVotesByline(nr *domain.NodeRun) string {
	if nr == nil || nr.Approval == nil || len(nr.Approval.Votes) < 2 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Approvals:\n")
	for _, v := range nr.Approval.Votes {
		who := v.Login
		if who == "" {
			who = fmt.Sprintf("user #%d", v.UserID)
		}
		fmt.Fprintf(&b, "- %s (%s) at %s", who, v.Kind, v.At.Format(time.RFC3339))
		if v.Escalation {
			b.WriteString(" (escalation approver)")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// auditApproval writes an approval vote or timeout to the platform audit
// log. Nodes without a rule are covered by the API write log alone.
func (e *Engine) auditApproval(r domain.Run, nodeID, action string, actor domain.Actor, extra map[string]any) {
	nr := r.Nodes[nodeID]
	if nr == nil || nr.Approval == nil {
		return
	}
	detail := map[string]any{"runId": r.ID, "nodeId": nodeID, "votes": len(nr.Approval.Votes), "required": nr.Approval.Required, "caseId": r.ExecutionContext.CaseID}
	if nr.Approval.Escalated {
		detail["escalated"] = true
	}
	for k, v := range extra {
		detail[k] = v
	}
	ev := domain.AuditEvent{Action: action, ActorUserID: actor.UserID, ActorLogin: actor.Login, ActorKind: actor.Kind, TokenID: actor.TokenID, ProjectID: r.ExecutionContext.ProjectID, Target: r.ID + "/" + nodeID, Outcome: domain.AuditSuccess}
	if raw, err := json.Marshal(detail); err == nil {
		ev.Detail = domain.RawJSON(raw)
	}
	if err := e.repo.AppendAudit(ev); err != nil {
		e.observe(r.ID, nodeID, domain.TelemetryEvent{Category: "orchestration", Name: "approval.audit_failed", Level: "warn", Message: err.Error()})
	}
}
