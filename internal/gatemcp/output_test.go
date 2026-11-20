package gatemcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func responses(t *testing.T, raw string) map[float64]map[string]any {
	t.Helper()
	out := map[float64]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("bad response %q: %v", line, err)
		}
		if id, ok := msg["id"].(float64); ok {
			out[id] = msg
		}
	}
	return out
}

func errorText(msg map[string]any) string {
	if e, ok := msg["error"].(map[string]any); ok {
		s, _ := e["message"].(string)
		return s
	}
	return ""
}

func TestSubmitOutputGuardsPassDecision(t *testing.T) {
	dir := t.TempDir()
	resultPath := filepath.Join(dir, "gate.json")
	outputPath := filepath.Join(dir, "out", "output.json")
	schema := json.RawMessage(`{"type":"object","required":["verdict"],"properties":{"verdict":{"enum":["malicious","benign"]}}}`)
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"submit_gate_result","arguments":{"decision":"pass","reason":"done"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"submit_output","arguments":{"verdict":"maybe"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"submit_output","arguments":{"verdict":"malicious","ip":"10.0.0.1"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"submit_output","arguments":{"verdict":"benign"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"submit_gate_result","arguments":{"decision":"pass","reason":"done"}}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := RunWithOutput(strings.NewReader(input), &out, resultPath, OutputConfig{Path: outputPath, Schema: schema}); err != nil {
		t.Fatal(err)
	}
	got := responses(t, out.String())
	tools, _ := got[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 || tools[0].(map[string]any)["name"] != "submit_output" {
		t.Fatalf("tools = %v", tools)
	}
	if !strings.Contains(errorText(got[2]), "submit_output") {
		t.Fatalf("pass before output was not refused: %v", got[2])
	}
	if errorText(got[3]) == "" {
		t.Fatalf("invalid output accepted: %v", got[3])
	}
	if errorText(got[4]) != "" {
		t.Fatalf("valid output refused: %v", got[4])
	}
	if !strings.Contains(errorText(got[5]), "already submitted") {
		t.Fatalf("second output not refused: %v", got[5])
	}
	if errorText(got[6]) != "" {
		t.Fatalf("pass after output refused: %v", got[6])
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil || string(raw) != `{"ip":"10.0.0.1","verdict":"malicious"}` {
		t.Fatalf("output file = %s, %v", raw, err)
	}
}

func TestSubmitOutputAllowsNonPassWithoutOutput(t *testing.T) {
	dir := t.TempDir()
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"submit_gate_result","arguments":{"decision":"fail","reason":"cannot reach the EDR"}}}` + "\n"
	var out bytes.Buffer
	if err := RunWithOutput(strings.NewReader(input), &out, filepath.Join(dir, "gate.json"), OutputConfig{Path: filepath.Join(dir, "o.json"), Schema: json.RawMessage(`{"type":"object"}`)}); err != nil {
		t.Fatal(err)
	}
	if msg := responses(t, out.String())[1]; errorText(msg) != "" {
		t.Fatalf("fail decision refused: %v", msg)
	}
}

func TestRunWithoutOutputHidesTool(t *testing.T) {
	var out bytes.Buffer
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"submit_output","arguments":{}}}` + "\n"
	if err := Run(strings.NewReader(input), &out, filepath.Join(t.TempDir(), "gate.json")); err != nil {
		t.Fatal(err)
	}
	got := responses(t, out.String())
	if strings.Contains(out.String(), `"name":"submit_output"`) || errorText(got[2]) != "unknown tool" {
		t.Fatalf("submit_output must not exist without an output path:\n%s", out.String())
	}
	if err := RunWithOutput(strings.NewReader(""), &out, "g.json", OutputConfig{Path: "o.json", Schema: json.RawMessage(`[1]`)}); err == nil {
		t.Fatal("a non-object schema must be rejected at start")
	}
}
