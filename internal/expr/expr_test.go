package expr

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func env(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEvalBool(t *testing.T) {
	e := env(t, `{
		"trigger": {"severity": "high", "score": 87, "tags": ["phish", "mail"], "src": {"ip": "10.0.0.1"}},
		"nodes": {"triage": {"status": "succeeded", "data": {"verdict": "malicious", "confidence": 0.9}},
		          "enrich-ip": {"data": {"hits": []}}},
		"run": {"input": "alert 42"}
	}`)
	cases := []struct {
		src  string
		want bool
	}{
		{`nodes["triage"].data.verdict == "malicious" && nodes.triage.data.confidence >= 0.8`, true},
		{`nodes.triage.data.verdict == 'benign'`, false},
		{`trigger.severity in ["high", "critical"]`, true},
		{`"phish" in trigger.tags`, true},
		{`trigger.score > 90 || trigger.severity == "high"`, true},
		{`!(trigger.score < 50)`, true},
		{`trigger.missing.deep == null`, true},
		{`trigger.missing > 3`, false},
		{`exists(trigger.src.ip) && startsWith(trigger.src.ip, "10.")`, true},
		{`len(nodes["enrich-ip"].data.hits) == 0`, true},
		{`contains(lower(run.input), "alert")`, true},
		{`trigger.tags[1] == "mail"`, true},
		{`trigger.tags[5] == null`, true},
		{`-trigger.score < 0`, true},
		{`"10.0" in trigger.src.ip`, true},
		{`"src" in trigger`, true},
	}
	for _, c := range cases {
		p, err := Compile(c.src)
		if err != nil {
			t.Fatalf("%s: compile: %v", c.src, err)
		}
		got, err := p.EvalBool(e)
		if err != nil {
			t.Fatalf("%s: eval: %v", c.src, err)
		}
		if got != c.want {
			t.Errorf("%s = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	cases := map[string]string{
		``:                                "empty",
		`env.HOME == "x"`:                 "unknown name",
		`exec("ls")`:                      "unknown function",
		`trigger.a ==`:                    "unexpected end",
		`trigger.a = 1`:                   "unexpected character",
		`(trigger.a`:                      `expected ")"`,
		`'open`:                           "unterminated",
		strings.Repeat("a", 2001):         "longer than",
		strings.Repeat("!", 200) + "true": "nested too deeply",
	}
	for src, want := range cases {
		if _, err := Compile(src); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Compile(%q) error = %v, want containing %q", src, err, want)
		}
	}
}

func TestEvalErrors(t *testing.T) {
	e := env(t, `{"trigger": {"n": 1, "s": "x"}}`)
	for _, src := range []string{`trigger.n`, `trigger.n < trigger.s`, `upper(trigger.n) == "1"`} {
		p, err := Compile(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if _, err := p.EvalBool(e); err == nil {
			t.Errorf("%s: expected an evaluation error", src)
		}
	}
}

func TestNodeRefs(t *testing.T) {
	p, err := Compile(`nodes.a.data.x == 1 && nodes["b-2"].status == "succeeded" || nodes.a.data.y in [nodes["c"].data.z]`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.NodeRefs(), []string{"a", "b-2", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("NodeRefs = %v, want %v", got, want)
	}
}
