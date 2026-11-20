package connector

import "testing"

func TestShippedTemplatesLoad(t *testing.T) {
	cat, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Connectors()) < 12 {
		t.Fatalf("expected the built-in connector plus 11+ templates, got %d", len(cat.Connectors()))
	}
	if cat.Connectors()[0].ID != BuiltinID {
		t.Fatalf("built-in connector should be listed first")
	}
	for _, c := range cat.Connectors() {
		if c.TestAction != "" {
			a, _ := c.Action(c.TestAction)
			if _, err := CoerceInputs(a, c.TestInputs); err != nil {
				t.Errorf("%s test inputs: %v", c.ID, err)
			}
		}
	}
}
