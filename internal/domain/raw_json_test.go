package domain

import (
	"encoding/json"
	"testing"
)

func TestRawJSONRoundTripAndComparable(t *testing.T) {
	n := NodeRun{NodeID: "a", Data: RawJSON(`{"verdict":"bad"}`)}
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var back NodeRun
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back != n {
		t.Fatalf("round trip changed the node: %+v", back)
	}
	empty, _ := json.Marshal(NodeRun{NodeID: "b"})
	var probe map[string]any
	_ = json.Unmarshal(empty, &probe)
	if _, present := probe["data"]; present {
		t.Fatalf("empty data must be omitted: %s", empty)
	}
	if err := json.Unmarshal([]byte(`{"data":null}`), &back); err != nil || back.Data != "" {
		t.Fatalf("null data = %q, %v", back.Data, err)
	}
}

func TestValidateNodeOutput(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","required":["verdict"],"properties":{"verdict":{"enum":["bad","good"]},"score":{"type":"number"},"tags":{"type":"array","items":{"type":"string"}}}}`)
	if got, err := ValidateNodeOutput(schema, []byte(`{"verdict":"bad","score":0.5,"tags":["x"]}`)); err != nil || got != `{"score":0.5,"tags":["x"],"verdict":"bad"}` {
		t.Fatalf("valid output = %q, %v", got, err)
	}
	for _, bad := range []string{`[1]`, `{"score":1}`, `{"verdict":"meh"}`, `{"verdict":"bad","score":"1"}`, `{"verdict":"bad","tags":[1]}`, `not json`} {
		if _, err := ValidateNodeOutput(schema, []byte(bad)); err == nil {
			t.Errorf("%s: expected a validation error", bad)
		}
	}
	if _, err := ValidateNodeOutput(nil, []byte(`{"anything":true}`)); err != nil {
		t.Fatalf("schema-less object rejected: %v", err)
	}
}
