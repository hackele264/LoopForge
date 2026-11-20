package expr

import (
	"reflect"
	"testing"
)

func TestHelperFunctions(t *testing.T) {
	env := map[string]any{"trigger": map[string]any{"urls": []any{"http://a.example/x", "http://b.example"}, "n": 3.0, "empty": ""}}
	cases := map[string]any{
		`base64url("http://a.example/a?b=1")`: "aHR0cDovL2EuZXhhbXBsZS9hP2I9MQ",
		`first(trigger.urls)`:                 "http://a.example/x",
		`first(trigger.none)`:                 nil,
		`join(trigger.urls, ",")`:             "http://a.example/x,http://b.example",
		`split("a,b", ",")`:                   []any{"a", "b"},
		`coalesce(trigger.empty, null, "x")`:  "x",
		`str(trigger.n)`:                      "3",
		`str(trigger.urls)`:                   `["http://a.example/x","http://b.example"]`,
		`len(split("a b c", " ")) == 3`:       true,
	}
	for src, want := range cases {
		p, err := Compile(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		got, err := p.Eval(env)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", src, got, want)
		}
	}
}

func TestCompileWithRootsAndRegisteredFunctions(t *testing.T) {
	if _, err := CompileWith("response.status == 200", map[string]bool{"response": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileWith("trigger.x", map[string]bool{"response": true}); err == nil {
		t.Fatal("trigger should be unknown outside workflow roots")
	}
	if _, err := Compile("double(1)"); err == nil {
		t.Fatal("unregistered function compiled")
	}
	RegisterFunction("double", func(a []any) (any, error) { return a[0].(float64) * 2, nil })
	RegisterFunction("len", func([]any) (any, error) { return "hijacked", nil })
	p, err := Compile("double(len([1, 2]))")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := p.Eval(nil); got != 4.0 {
		t.Fatalf("double(len) = %v; built-ins must not be replaceable", got)
	}
}
