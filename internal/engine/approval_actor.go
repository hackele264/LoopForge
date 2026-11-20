package engine

import (
	"os"
	"strings"
	"time"

	"agentflow/internal/apperr"
	"agentflow/internal/domain"
)

// requireNamedApprovals is the platform switch that makes every gate demand
// a named user, not only gates with an approver policy. Off by default so
// existing service-token integrations keep working.
func requireNamedApprovals() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENTFLOW_APPROVAL_REQUIRE_NAMED"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// authorizeDecision checks that actor may decide nodeID of run r. A node
// with an approver policy accepts only the users it names; any other node
// keeps the legacy rule (already enforced by the HTTP layer) unless the
// platform requires named approvals.
func (e *Engine) authorizeDecision(r domain.Run, nodeID string, actor domain.Actor) error {
	var policy *domain.ApproverPolicy
	for _, n := range workflowForRun(e.repo, r).Nodes {
		if n.ID == nodeID {
			policy = n.Approvers
			break
		}
	}
	if !policy.Empty() {
		if !actor.Named() {
			return apperr.New(apperr.Forbidden, "该人工关口只接受具名用户审批")
		}
		project, _ := e.repo.Project(r.ExecutionContext.ProjectID)
		admin := strings.TrimSpace(actor.Login) != "" && e.repo.IsPlatformAdmin(actor.Login)
		if !policy.Allows(actor, project, admin) {
			return apperr.New(apperr.Forbidden, "你不在该人工关口的审批人名单中")
		}
		return nil
	}
	if requireNamedApprovals() && !actor.Named() {
		return apperr.New(apperr.Forbidden, "平台要求人工决定必须由具名用户做出")
	}
	return nil
}

// eventBy records a run event attributed to actor.
func (e *Engine) eventBy(r *domain.Run, nodeID, eventType, message string, actor domain.Actor) {
	e.event(r, nodeID, eventType, message)
	last := &r.Events[len(r.Events)-1]
	last.ActorUserID = actor.UserID
	last.ActorKind = actor.Kind
}

// recordDecision stamps who decided a node and when.
func recordDecision(n *domain.NodeRun, actor domain.Actor) {
	if n == nil {
		return
	}
	n.DecidedBy = actor.UserID
	n.DecidedAt = time.Now().UTC()
}

// decisionByline renders the approver for decision artifacts.
func decisionByline(actor domain.Actor) string {
	switch {
	case strings.TrimSpace(actor.Login) != "":
		return "Decided by " + actor.Login + " (" + actor.Kind + ") at " + time.Now().UTC().Format(time.RFC3339) + "."
	case actor.Kind != "":
		return "Decided by a " + actor.Kind + " caller at " + time.Now().UTC().Format(time.RFC3339) + "."
	}
	return ""
}
