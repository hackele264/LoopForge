package engine

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"agentflow/internal/domain"
)

// Approval deadlines are persisted on the node (ApprovalState.Deadline), so
// they survive restarts. Every executing instance scans them periodically;
// firing one takes the run lease and writes at the read revision, so only
// one replica acts on a deadline and a repeated scan finds it handled.

// approvalSweepInterval is how often executing instances look for due
// approval deadlines.
var approvalSweepInterval = 15 * time.Second

func (e *Engine) approvalTimeoutLoop(ctx context.Context) {
	ticker := time.NewTicker(approvalSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.SweepApprovalTimeouts(time.Now().UTC())
		}
	}
}

// SweepApprovalTimeouts fires the approval deadlines due at now and returns
// how many it handled. Instances that do not execute runs leave deadlines to
// the workers.
func (e *Engine) SweepApprovalTimeouts(now time.Time) int {
	if !e.executes() {
		return 0
	}
	waits, err := e.repo.WaitingApprovals()
	if err != nil {
		log.Printf("approval timeouts: %v", err)
		return 0
	}
	fired := 0
	for _, w := range waits {
		if !w.State.Due(now) {
			continue
		}
		if e.fireApprovalTimeout(w.RunID, w.NodeID, now) {
			fired++
		}
	}
	return fired
}

// fireApprovalTimeout escalates or rejects one due approval node. It reports
// false when the deadline no longer applies or another instance holds the
// run.
func (e *Engine) fireApprovalTimeout(runID, nodeID string, now time.Time) bool {
	defer e.stateLocks.lock(runID)()
	r, ok := e.repo.RunState(runID)
	if !ok || !approvalTimeoutApplies(r, nodeID, now) || e.workspaceBlocked(r) {
		return false
	}
	node, ok := e.approvalNodeDef(r, nodeID)
	if !ok {
		return false
	}
	nr := r.Nodes[nodeID]
	expected := NodeExpectation{NodeID: nodeID, Status: "waiting_approval", Attempt: nr.Attempt, ReworkCount: nr.ReworkCount}
	minutes := 0
	if node.Approval != nil {
		minutes = node.Approval.TimeoutMinutes
	}
	if nr.Approval.OnTimeout == domain.ApprovalOnTimeoutReject && rejectBudgetLeft(r, node) {
		// Same as a person's 打回: the run goes back to RejectTo. rejectLocked
		// takes the lease and checks the node is still in this waiting round.
		audited := r
		reason := fmt.Sprintf("审批超时（%d 分钟），系统自动打回", minutes)
		if err := e.rejectLocked(runID, domain.RejectRequest{NodeID: nodeID, TargetID: node.RejectTo, Reason: reason}, systemTimeoutActor, true, expected); err != nil {
			log.Printf("approval timeout %s/%s: %v", runID, nodeID, err)
			return false
		}
		audited.Nodes[nodeID].Approval.TimedOut = true
		e.auditApproval(audited, nodeID, "approval.timeout_rejected", systemTimeoutActor, map[string]any{"target": node.RejectTo})
		return true
	}
	r, err := e.acquireLease(r)
	if err != nil {
		return false
	}
	// Re-check on the state read under the lease: another replica may have
	// handled the deadline before this one got the lease.
	if !approvalTimeoutApplies(r, nodeID, now) || checkNodeExpectation(r, []NodeExpectation{expected}) != nil {
		e.releaseIdleLease(r)
		return false
	}
	nr = r.Nodes[nodeID]
	if nr.Approval.OnTimeout == domain.ApprovalOnTimeoutEscalate {
		return e.escalateApproval(r, node, now)
	}
	return e.failTimedOutApproval(r, node, minutes, expected)
}

func approvalTimeoutApplies(r domain.Run, nodeID string, now time.Time) bool {
	if domain.TerminalRunStatus(r.Status) || r.CancelRequested || r.PauseRequested {
		return false
	}
	nr := r.Nodes[nodeID]
	return nr != nil && nr.Status == "waiting_approval" && nr.Approval.Due(now)
}

// rejectBudgetLeft uses the automatic-reject budget of nodeFailedAt: at
// least one rework, so a gate that keeps timing out cannot loop forever.
func rejectBudgetLeft(r domain.Run, node domain.WorkflowNode) bool {
	target := r.Nodes[node.RejectTo]
	return node.RejectTo != "" && target != nil && target.ReworkCount < max(1, node.MaxReworks)
}

// escalateApproval lets the escalation approvers decide and sends a waiting
// notification through the workflow's reminder bots.
func (e *Engine) escalateApproval(r domain.Run, node domain.WorkflowNode, now time.Time) bool {
	nr := r.Nodes[node.ID]
	nr.Approval.Escalated = true
	nr.Approval.EscalatedAt = now.UTC()
	msg := "审批超时，已升级：" + describeApprovers(node.Approval.EscalateTo) + " 现在也可以审批"
	if nr.Approval.Required > 1 {
		msg += fmt.Sprintf("（已批准 %s）", nr.Approval.Progress())
	}
	e.eventBy(&r, node.ID, "gate.escalated", msg, systemTimeoutActor)
	appendControlTelemetry(&r, node.ID, "gate.escalated", msg)
	if err := e.repo.PutRunAtRevision(r, r.Revision); err != nil {
		log.Printf("approval escalation %s/%s: %v", r.ID, node.ID, err)
		e.releaseIdleLease(r)
		return false
	}
	e.publish(r.ID)
	e.releaseIdleLease(r)
	log.Printf("approval escalated: run %s node %s", r.ID, node.ID)
	e.auditApproval(r, node.ID, "approval.escalated", systemTimeoutActor, nil)
	return true
}

// failTimedOutApproval rejects a node with onTimeout reject and no rework
// route left: it fails like any node, so an error edge takes over or the run
// fails.
func (e *Engine) failTimedOutApproval(r domain.Run, node domain.WorkflowNode, minutes int, expected NodeExpectation) bool {
	nr := r.Nodes[node.ID]
	nr.Approval.TimedOut = true
	nr.Status = "failed"
	nr.Error = fmt.Sprintf("审批超时（%d 分钟），已自动拒绝", minutes)
	nr.Activity = "审批超时，系统自动拒绝"
	nr.FinishedAt = time.Now().UTC()
	recordDecision(nr, systemTimeoutActor)
	e.eventBy(&r, node.ID, "node.failed", nr.Error, systemTimeoutActor)
	appendControlTelemetry(&r, node.ID, "gate.timeout_rejected", nr.Error)
	if hasErrorEdge(workflowForRun(e.repo, r), node.ID) {
		nr.ErrorRouted = true
		e.event(&r, node.ID, "node.error_routed", "失败已交给错误分支处理")
	}
	r.Status = "running"
	if err := e.persistControlDecision(r.ID, r, expected); err != nil {
		log.Printf("approval timeout %s/%s: %v", r.ID, node.ID, err)
		e.releaseIdleLease(r)
		return false
	}
	e.auditApproval(r, node.ID, "approval.timeout_rejected", systemTimeoutActor, nil)
	e.recordCaseDecision(r, node.ID, "超时拒绝", nr.Error, systemTimeoutActor)
	return true
}

// describeApprovers renders a policy for event messages.
func describeApprovers(p *domain.ApproverPolicy) string {
	if p.Empty() {
		return "升级审批人"
	}
	names := map[string]string{domain.ApproverRoleOwner: "项目 Owner", domain.ApproverRoleMaintainer: "维护者", domain.ApproverRoleMember: "项目成员", domain.ApproverRoleAdmin: "平台管理员"}
	var parts []string
	for _, role := range p.Roles {
		if label, ok := names[role]; ok {
			parts = append(parts, label)
		} else {
			parts = append(parts, role)
		}
	}
	for _, id := range p.UserIDs {
		parts = append(parts, fmt.Sprintf("用户 #%d", id))
	}
	return strings.Join(parts, "、")
}
