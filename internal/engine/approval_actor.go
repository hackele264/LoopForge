package engine

import (
	"os"
	"strings"
	"time"

	"agentflow/internal/apperr"
	"agentflow/internal/connector"
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
	var rule *domain.ApprovalRule
	for _, n := range workflowForRun(e.repo, r).Nodes {
		if n.ID == nodeID {
			policy, rule = n.Approvers, n.Approval
			break
		}
	}
	if !policy.Empty() {
		if !actor.Named() {
			return apperr.New(apperr.Forbidden, "该人工关口只接受具名用户审批")
		}
		// After an escalation the escalation approvers may decide too.
		if !policy.Allows(actor, e.decisionProject(r), e.actorIsPlatformAdmin(actor)) && !e.escalationAllows(r, nodeID, rule, actor) {
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

// tokenResponseApprovals lets API tokens approve gates that release
// response actions. Off by default: isolating a host or disabling an account
// needs a person signed in to the platform, not an automation credential.
func tokenResponseApprovals() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENTFLOW_RESPONSE_APPROVAL_ALLOW_TOKEN"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// authorizeResponseRelease checks approvals whose success path reaches a
// response action: the approver must be a named user in an interactive
// session.
func (e *Engine) authorizeResponseRelease(r domain.Run, nodeID string, actor domain.Actor) error {
	wf := workflowForRun(e.repo, r)
	if !releasesResponseAction(wf, nodeID) {
		return nil
	}
	if !actor.Named() {
		return apperr.New(apperr.Forbidden, "该审批之后有响应处置动作，只接受具名用户审批")
	}
	if actor.TokenID != "" && !tokenResponseApprovals() {
		return apperr.New(apperr.Forbidden, "该审批之后有响应处置动作，需要登录平台审批，不接受 API Token")
	}
	return nil
}

// releasesResponseAction reports whether a response action is reachable
// from nodeID through success edges.
func releasesResponseAction(wf domain.WorkflowDefinition, nodeID string) bool {
	byID := map[string]domain.WorkflowNode{}
	for _, n := range wf.Nodes {
		byID[n.ID] = n
	}
	seen := map[string]bool{nodeID: true}
	stack := []string{nodeID}
	cat := connector.Default()
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, e := range wf.Edges {
			if e.Source != id || domain.EdgeWhen(e) != domain.EdgeWhenSuccess || seen[e.Target] {
				continue
			}
			seen[e.Target] = true
			n := byID[e.Target]
			if n.Type == connector.NodeType && n.Action != nil {
				if _, a, ok := cat.Action(n.Action.Connector, n.Action.Action); ok && a.Category == connector.CategoryResponse {
					return true
				}
			}
			stack = append(stack, e.Target)
		}
	}
	return false
}
