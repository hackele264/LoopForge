package connector

import (
	"context"
	"strings"
	"testing"

	"agentflow/internal/domain"
)

type caseStub struct{}

func (caseStub) CaseComment(context.Context, RunContext, string) error { return nil }
func (caseStub) CaseUpdate(context.Context, RunContext, CaseChange) (domain.Case, error) {
	return domain.Case{}, nil
}
func (caseStub) CaseAddIOCs(context.Context, RunContext, []domain.CaseIOC) (int, error) {
	return 0, nil
}

type verdictStub struct {
	caseStub
	got CaseVerdict
	run RunContext
}

func (v *verdictStub) CaseSetVerdict(_ context.Context, run RunContext, verdict CaseVerdict) (domain.Case, error) {
	v.got, v.run = verdict, run
	return domain.Case{Number: 7, AgentVerdict: verdict.Verdict}, nil
}

func TestBuiltinCaseSetVerdict(t *testing.T) {
	cat, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c, a, ok := cat.Action(BuiltinID, "case_set_verdict")
	if !ok || a.Category != CategoryUtility {
		t.Fatalf("case_set_verdict missing: %v", a)
	}
	stub := &verdictStub{}
	run := RunContext{RunID: "r1", ProjectID: "p", CaseID: "case-1"}
	res, err := NewExecutor(nil, stub).Execute(context.Background(), Call{Connector: c, Action: a, Run: run, Inputs: map[string]any{"verdict": "malicious", "confidence": "0.9", "rationale": "C2"}})
	if err != nil || res.Output["verdict"] != "malicious" || stub.got.Confidence == nil || *stub.got.Confidence != 0.9 || stub.got.Rationale != "C2" || stub.run.RunID != "r1" {
		t.Fatalf("res = %+v, got = %+v, err = %v", res, stub.got, err)
	}
	// The enum rejects other verdicts before the service is called.
	if _, err := NewExecutor(nil, stub).Execute(context.Background(), Call{Connector: c, Action: a, Run: run, Inputs: map[string]any{"verdict": "suspicious"}}); err == nil {
		t.Fatal("unknown verdict accepted")
	}
	// A case service without verdict support refuses clearly.
	if _, err := NewExecutor(nil, caseStub{}).Execute(context.Background(), Call{Connector: c, Action: a, Run: run, Inputs: map[string]any{"verdict": "benign"}}); err == nil || !strings.Contains(err.Error(), "未启用") {
		t.Fatalf("err = %v", err)
	}
}
