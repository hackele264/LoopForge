package gatemcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"agentflow/internal/domain"
)

const Version = "1.0.0"

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type finding struct {
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title"`
	Evidence string `json:"evidence,omitempty"`
}

type gateResult struct {
	Decision       string    `json:"decision"`
	Reason         string    `json:"reason"`
	ActionRequired string    `json:"actionRequired"`
	Summary        string    `json:"summary"`
	Findings       []finding `json:"findings"`
}

var inputSchema = map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"decision", "reason"},
	"properties": map[string]any{
		"decision":       map[string]any{"type": "string", "enum": []string{"pass", "rework", "fail", "human"}},
		"reason":         map[string]any{"type": "string", "minLength": 1, "maxLength": 4000},
		"actionRequired": map[string]any{"type": "string", "maxLength": 4000},
		"summary":        map[string]any{"type": "string", "maxLength": 4000},
		"findings": map[string]any{
			"type": "array", "maxItems": 50,
			"items": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"title"},
				"properties": map[string]any{
					"severity": map[string]any{"type": "string", "maxLength": 64},
					"title":    map[string]any{"type": "string", "minLength": 1, "maxLength": 500},
					"evidence": map[string]any{"type": "string", "maxLength": 4000},
				},
			},
		},
	},
}

// OutputConfig enables submit_output: the node declared an output schema
// and the engine reads the submitted object from Path.
type OutputConfig struct {
	Path   string
	Schema json.RawMessage
}

func (o OutputConfig) enabled() bool { return strings.TrimSpace(o.Path) != "" }

// Run serves the small JSON-RPC MCP protocol over stdin/stdout.
func Run(stdin io.Reader, stdout io.Writer, resultPath string) error {
	return RunWithOutput(stdin, stdout, resultPath, OutputConfig{})
}

// RunWithOutput is Run with an optional submit_output tool. When output is
// enabled, a pass decision is refused until the structured output has been
// submitted, so a node that passes always carries its declared output.
func RunWithOutput(stdin io.Reader, stdout io.Writer, resultPath string, output OutputConfig) error {
	resultPath = strings.TrimSpace(resultPath)
	if resultPath == "" {
		return fmt.Errorf("AGENTFLOW_GATE_RESULT_PATH is required")
	}
	output.Path = strings.TrimSpace(output.Path)
	if output.enabled() {
		var schema map[string]any
		if len(output.Schema) == 0 || json.Unmarshal(output.Schema, &schema) != nil {
			return fmt.Errorf("AGENTFLOW_OUTPUT_SCHEMA must be a JSON object when AGENTFLOW_OUTPUT_PATH is set")
		}
	}
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			if writeErr := writeResponse(encoder, nil, nil, err.Error()); writeErr != nil {
				return writeErr
			}
			continue
		}
		if strings.HasPrefix(req.Method, "notifications/") {
			continue
		}
		if err := handleRequest(encoder, req, resultPath, output); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handleRequest(encoder *json.Encoder, req request, resultPath string, output OutputConfig) error {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)
		if params.ProtocolVersion == "" {
			params.ProtocolVersion = "2025-06-18"
		}
		return writeResponse(encoder, req.ID, map[string]any{
			"protocolVersion": params.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "agentflow-gate", "version": Version},
			"instructions":    instructions(output),
		}, "")
	case "ping":
		return writeResponse(encoder, req.ID, map[string]any{}, "")
	case "tools/list":
		tools := []any{map[string]any{
			"name":        "submit_gate_result",
			"description": "Submit exactly one terminal node decision. reason explains why. human also requires actionRequired to state exactly what a person must confirm.",
			"inputSchema": inputSchema,
		}}
		if output.enabled() {
			tools = append([]any{map[string]any{
				"name":        "submit_output",
				"description": "Submit this node's structured result exactly once, before submit_gate_result with decision pass. The object must match the input schema; downstream steps branch on it.",
				"inputSchema": json.RawMessage(output.Schema),
			}}, tools...)
		}
		return writeResponse(encoder, req.ID, map[string]any{"tools": tools}, "")
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return writeResponse(encoder, req.ID, nil, "invalid tool parameters")
		}
		if params.Name == "submit_output" && output.enabled() {
			return submitOutput(encoder, req.ID, params.Arguments, output)
		}
		if params.Name != "submit_gate_result" {
			return writeResponse(encoder, req.ID, nil, "unknown tool")
		}
		result, problem := decodeResult(params.Arguments)
		if problem != "" {
			return writeResponse(encoder, req.ID, nil, problem)
		}
		if output.enabled() && result.Decision == "pass" {
			if _, err := os.Stat(output.Path); err != nil {
				return writeResponse(encoder, req.ID, nil, "call submit_output with the structured result before submitting decision pass")
			}
		}
		if err := writeResultExclusive(resultPath, result); err != nil {
			if os.IsExist(err) {
				return writeResponse(encoder, req.ID, nil, "gate result already submitted")
			}
			return writeResponse(encoder, req.ID, nil, err.Error())
		}
		return writeResponse(encoder, req.ID, map[string]any{
			"content": []any{map[string]any{"type": "text", "text": "Gate result submitted. Stop now; this node has reached its terminal decision."}},
			"isError": false,
		}, "")
	default:
		return writeResponse(encoder, req.ID, nil, "method not found")
	}
}

func instructions(output OutputConfig) string {
	if output.enabled() {
		return "Call submit_output once with the node's structured result, then call submit_gate_result exactly once to finish this node."
	}
	return "Call submit_gate_result exactly once to finish this node."
}

// submitOutput validates the structured output against the node schema and
// writes it once. A rejected object is not written, so the agent can fix and
// resubmit; an accepted one cannot be replaced.
func submitOutput(encoder *json.Encoder, id json.RawMessage, raw json.RawMessage, output OutputConfig) error {
	data, err := domain.ValidateNodeOutput(output.Schema, raw)
	if err != nil {
		return writeResponse(encoder, id, nil, err.Error())
	}
	if err := writeBytesExclusive(output.Path, []byte(data)); err != nil {
		if os.IsExist(err) {
			return writeResponse(encoder, id, nil, "structured output already submitted")
		}
		return writeResponse(encoder, id, nil, err.Error())
	}
	return writeResponse(encoder, id, map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "Structured output submitted. Now call submit_gate_result."}},
		"isError": false,
	}, "")
}

func writeBytesExclusive(path string, data []byte) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	ok = true
	return nil
}

func decodeResult(raw json.RawMessage) (gateResult, string) {
	var fields map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return gateResult{}, "arguments must be an object"
	}
	allowed := map[string]bool{"decision": true, "reason": true, "actionRequired": true, "summary": true, "findings": true}
	var unknown []string
	for key := range fields {
		if !allowed[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return gateResult{}, "unknown fields: " + strings.Join(unknown, ", ")
	}
	if rawFindings, ok := fields["findings"]; ok {
		var items []map[string]json.RawMessage
		if string(rawFindings) == "null" || json.Unmarshal(rawFindings, &items) != nil {
			return gateResult{}, "findings must be an array with at most 50 items"
		}
		allowedFinding := map[string]bool{"severity": true, "title": true, "evidence": true}
		for _, item := range items {
			for key := range item {
				if !allowedFinding[key] {
					return gateResult{}, "finding contains unknown fields"
				}
			}
		}
	}
	var result gateResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return gateResult{}, "arguments must match the submit_gate_result schema"
	}
	if result.Findings == nil {
		result.Findings = []finding{}
	}
	switch result.Decision {
	case "pass", "rework", "fail", "human":
	default:
		return gateResult{}, "decision must be pass, rework, fail, or human"
	}
	result.Reason = strings.TrimSpace(result.Reason)
	if result.Reason == "" {
		return gateResult{}, "reason is required"
	}
	if len(result.Reason) > 4000 {
		return gateResult{}, "reason is too long"
	}
	result.ActionRequired = strings.TrimSpace(result.ActionRequired)
	if len(result.ActionRequired) > 4000 {
		return gateResult{}, "actionRequired must be a string with at most 4000 characters"
	}
	if result.Decision == "human" && result.ActionRequired == "" {
		return gateResult{}, "actionRequired is required when decision is human"
	}
	result.Summary = strings.TrimSpace(result.Summary)
	if len(result.Summary) > 4000 {
		return gateResult{}, "summary must be a string with at most 4000 characters"
	}
	if len(result.Findings) > 50 {
		return gateResult{}, "findings must be an array with at most 50 items"
	}
	for i := range result.Findings {
		result.Findings[i].Title = strings.TrimSpace(result.Findings[i].Title)
		if result.Findings[i].Title == "" {
			return gateResult{}, "each finding requires a title"
		}
		if len(result.Findings[i].Title) > 500 {
			return gateResult{}, "finding title is too long"
		}
		if len(result.Findings[i].Severity) > 64 {
			return gateResult{}, "finding severity is invalid"
		}
		if len(result.Findings[i].Evidence) > 4000 {
			return gateResult{}, "finding evidence is invalid"
		}
	}
	return result, ""
}

func writeResultExclusive(path string, result gateResult) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if !ok {
			_ = os.Remove(path)
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(result); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeResponse(encoder *json.Encoder, id json.RawMessage, result any, problem string) error {
	response := map[string]any{"jsonrpc": "2.0", "id": id}
	if problem != "" {
		response["error"] = map[string]any{"code": -32602, "message": problem}
	} else {
		response["result"] = result
	}
	return encoder.Encode(response)
}
