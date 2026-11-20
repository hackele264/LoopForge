package domain

import (
	"encoding/json"
	"fmt"
	"strings"

	"agentflow/internal/expr"
)

// ValidateWorkflowBranching checks the conditional-workflow fields: edge
// conditions, join strategies, output schemas, approver policies and RunIf
// expressions. A RunIf must compile and may only read nodes upstream of it.
func ValidateWorkflowBranching(wf WorkflowDefinition) error {
	for _, e := range wf.Edges {
		when := strings.TrimSpace(e.When)
		if when != "" && !strings.EqualFold(when, EdgeWhenSuccess) && !strings.EqualFold(when, EdgeWhenError) {
			return fmt.Errorf("edge %s has unsupported condition %q", e.ID, e.When)
		}
	}
	incoming := map[string][]string{}
	for _, e := range wf.Edges {
		incoming[e.Target] = append(incoming[e.Target], e.Source)
	}
	for _, n := range wf.Nodes {
		join := strings.TrimSpace(n.Join)
		if join != "" && !strings.EqualFold(join, JoinAll) && !strings.EqualFold(join, JoinAny) {
			return fmt.Errorf("node %s has unsupported join %q", n.ID, n.Join)
		}
		if len(n.OutputSchema) > 0 {
			var schema map[string]any
			if err := json.Unmarshal(n.OutputSchema, &schema); err != nil {
				return fmt.Errorf("node %s outputSchema must be a JSON object: %v", n.ID, err)
			}
		}
		if !n.Approvers.Empty() {
			if n.Type != "approval" {
				return fmt.Errorf("node %s: approvers apply to approval nodes only", n.ID)
			}
			for _, role := range n.Approvers.Roles {
				switch role {
				case ApproverRoleOwner, ApproverRoleMaintainer, ApproverRoleMember, ApproverRoleAdmin:
				default:
					return fmt.Errorf("node %s has unsupported approver role %q", n.ID, role)
				}
			}
		}
		src := strings.TrimSpace(n.RunIf)
		if src == "" {
			continue
		}
		program, err := expr.Compile(src)
		if err != nil {
			return fmt.Errorf("node %s runIf: %v", n.ID, err)
		}
		up := upstreamOf(incoming, n.ID)
		for _, ref := range program.NodeRefs() {
			if !up[ref] {
				return fmt.Errorf("node %s runIf reads node %q, which is not upstream of it", n.ID, ref)
			}
		}
	}
	return nil
}

// Approver roles accepted by ApproverPolicy.Roles: the project owner, a
// project maintainer, any non-viewer project member (maintainers included),
// or a platform administrator.
const (
	ApproverRoleOwner      = "owner"
	ApproverRoleMaintainer = "maintainer"
	ApproverRoleMember     = "member"
	ApproverRoleAdmin      = "admin"
)

// Allows reports whether actor may decide a gate guarded by p. Only named
// users qualify; an empty policy is checked by the caller's legacy rule.
func (p *ApproverPolicy) Allows(actor Actor, project Project, platformAdmin bool) bool {
	if p.Empty() || !actor.Named() {
		return false
	}
	for _, id := range p.UserIDs {
		if id == actor.UserID {
			return true
		}
	}
	memberRole := ""
	for _, m := range project.Members {
		if m.UserID == actor.UserID {
			memberRole = strings.ToLower(strings.TrimSpace(m.Role))
		}
	}
	for _, role := range p.Roles {
		switch role {
		case ApproverRoleAdmin:
			if platformAdmin {
				return true
			}
		case ApproverRoleOwner:
			if project.OwnerID > 0 && project.OwnerID == actor.UserID {
				return true
			}
		case ApproverRoleMaintainer:
			if memberRole == "maintainer" || (project.OwnerID > 0 && project.OwnerID == actor.UserID) {
				return true
			}
		case ApproverRoleMember:
			if (memberRole != "" && memberRole != "viewer") || (project.OwnerID > 0 && project.OwnerID == actor.UserID) {
				return true
			}
		}
	}
	return false
}

// UpstreamNodes returns the IDs of every node that can reach nodeID.
func UpstreamNodes(wf WorkflowDefinition, nodeID string) map[string]bool {
	incoming := map[string][]string{}
	for _, e := range wf.Edges {
		incoming[e.Target] = append(incoming[e.Target], e.Source)
	}
	return upstreamOf(incoming, nodeID)
}

func upstreamOf(incoming map[string][]string, start string) map[string]bool {
	out := map[string]bool{}
	stack := append([]string(nil), incoming[start]...)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if out[id] {
			continue
		}
		out[id] = true
		stack = append(stack, incoming[id]...)
	}
	return out
}
