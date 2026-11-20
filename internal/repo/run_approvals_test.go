package repo

import (
	"testing"
	"time"

	"agentflow/internal/domain"
)

func TestWaitingApprovalsReadsPersistedDeadlines(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	deadline := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	run := domain.Run{ID: "r1", Status: "waiting", Nodes: map[string]*domain.NodeRun{
		"timed":  {NodeID: "timed", Status: "waiting_approval", Approval: &domain.ApprovalState{Required: 2, Deadline: deadline, OnTimeout: domain.ApprovalOnTimeoutEscalate}},
		"legacy": {NodeID: "legacy", Status: "waiting_approval"},
		"done":   {NodeID: "done", Status: "succeeded", Approval: &domain.ApprovalState{Required: 1, Deadline: deadline}},
	}}
	if err := s.PutRun(run); err != nil {
		t.Fatal(err)
	}
	waits, err := s.WaitingApprovals()
	if err != nil {
		t.Fatal(err)
	}
	if len(waits) != 1 || waits[0].RunID != "r1" || waits[0].NodeID != "timed" || !waits[0].State.Deadline.Equal(deadline) || waits[0].State.Required != 2 {
		t.Fatalf("waits = %+v", waits)
	}
	if notificationTrigger("gate.escalated") != "waiting" {
		t.Fatal("an escalation must send the waiting reminders")
	}
}
