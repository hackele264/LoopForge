package domain

import (
	"reflect"
	"testing"

	"agentflow/internal/expr"
)

func TestIOCsExpressionFunction(t *testing.T) {
	env := map[string]any{"trigger": map[string]any{"body": "login at http://evil.example/reset from 203.0.113.9"}}
	p, err := expr.Compile(`iocs(trigger, "ipv4")`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Eval(env)
	if err != nil || !reflect.DeepEqual(got, []any{"203.0.113.9"}) {
		t.Fatalf("iocs ipv4 = %#v (%v)", got, err)
	}
	p, _ = expr.Compile(`len(iocs(trigger.body)) >= 3`)
	if ok, err := p.EvalBool(env); err != nil || !ok {
		t.Fatalf("iocs all = %v (%v)", ok, err)
	}
	if p, err := expr.Compile(`iocs(trigger, "phone")`); err == nil {
		if _, err := p.Eval(env); err == nil {
			t.Fatal("unknown IOC type accepted")
		}
	}
}
