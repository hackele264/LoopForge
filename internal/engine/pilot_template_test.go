package engine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/expr"
	"agentflow/internal/repo"
)

// loadPilotTemplate reads the generic template the 051 seed inserts, undoing
// the SQL string escaping, so the shipped SQL is the single source tested.
func loadPilotTemplate(t *testing.T) repo.GenericTemplate {
	t.Helper()
	raw, err := os.ReadFile("../../migrations/051_soc_shadow_pilot_sop.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	start := strings.Index(sql, `,'{"Workflow"`)
	end := strings.LastIndex(sql, `}',UTC_TIMESTAMP()`)
	if start < 0 || end < 0 {
		t.Fatal("payload literal not found")
	}
	literal := sql[start+2 : end+1]
	var b strings.Builder
	for i := 0; i < len(literal); i++ {
		switch {
		case literal[i] == '\\' && i+1 < len(literal):
			i++
			b.WriteByte(literal[i])
		case literal[i] == '\'' && i+1 < len(literal) && literal[i+1] == '\'':
			i++
			b.WriteByte('\'')
		case literal[i] == '\'':
			t.Fatalf("unescaped quote at %d", i)
		default:
			b.WriteByte(literal[i])
		}
	}
	var tpl repo.GenericTemplate
	if err := json.Unmarshal([]byte(b.String()), &tpl); err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestShadowPilotTemplateValidates(t *testing.T) {
	t.Parallel()
	tpl := loadPilotTemplate(t)
	wf := tpl.Workflow
	if wf.ID != "soc-shadow-pilot" || len(tpl.Agents) != 1 || tpl.Agents[0].ID != "soc-pilot-triage" {
		t.Fatalf("template = %s, agents %+v", wf.ID, tpl.Agents)
	}
	// The Lark notification uses connector lark (PR #16, feat/lark-connector).
	// Until it is in the catalog, check the node against that connector's
	// contract and validate the rest with a built-in stand-in in its place.
	checked := wf
	if _, _, ok := connector.Default().Action("lark", "send_card"); !ok {
		checked.Nodes = append([]domain.WorkflowNode(nil), wf.Nodes...)
		for i, n := range checked.Nodes {
			if n.ID != "notify" {
				continue
			}
			if n.Action.Connector != "lark" || n.Action.Action != "send_card" {
				t.Fatalf("notify = %+v", n.Action)
			}
			for name := range n.Action.Inputs {
				if name != "chat_id" && name != "title" && name != "markdown" && name != "color" {
					t.Fatalf("notify has input %q, which lark.send_card does not declare", name)
				}
			}
			if err := connector.CheckNodeInputs(n.Action.Inputs); err != nil {
				t.Fatal(err)
			}
			stand := *n.Action
			stand.Connector, stand.Action = connector.BuiltinID, "case_comment"
			stand.Inputs = map[string]string{"body": n.Action.Inputs["markdown"]}
			checked.Nodes[i].Action = &stand
		}
	}
	if err := validate(checked); err != nil {
		t.Fatalf("workflow does not validate: %v", err)
	}
	wf = checked
	if err := domain.ValidateWorkflowMetricStages(wf); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]domain.WorkflowNode{}
	for _, n := range wf.Nodes {
		nodes[n.ID] = n
	}
	cat := connector.Default()
	responses := 0
	for _, n := range wf.Nodes {
		if n.Type != connector.NodeType {
			continue
		}
		_, a, ok := cat.Action(n.Action.Connector, n.Action.Action)
		if !ok {
			t.Fatalf("node %s: unknown action", n.ID)
		}
		switch n.ID {
		case "cs_host", "cs_detections":
			if a.Category != connector.CategoryEnrichment {
				t.Fatalf("%s is %s, want enrichment", n.ID, a.Category)
			}
		}
		if a.Category == connector.CategoryResponse {
			responses++
			if !connector.GatedByApproval(wf, n.ID) {
				t.Fatalf("response node %s is not behind an approval", n.ID)
			}
			if !strings.Contains(n.RunIf, `nodes.triage.data.verdict == "malicious"`) {
				t.Fatalf("response node %s runIf = %q", n.ID, n.RunIf)
			}
		}
	}
	if responses != 1 {
		t.Fatalf("want exactly one response node, got %d", responses)
	}
	approve := nodes["approve"]
	if approve.Type != "approval" || approve.Approvers.Empty() || approve.RunIf != `nodes.triage.data.verdict == "malicious"` {
		t.Fatalf("approve = %+v", approve)
	}
	if nodes["verdict"].Action.Action != "case_set_verdict" {
		t.Fatal("verdict node changed")
	}
	// The triage schema's verdict enum is exactly the accepted verdicts.
	var schema struct {
		Required   []string `json:"required"`
		Properties struct {
			Verdict struct {
				Enum []string `json:"enum"`
			} `json:"verdict"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(nodes["triage"].OutputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if strings.Join(schema.Properties.Verdict.Enum, ",") != strings.Join(domain.AgentVerdicts, ",") || len(schema.Required) != 3 {
		t.Fatalf("triage schema = %+v", schema)
	}
	// The response branch runs only for malicious verdicts.
	runIf, err := expr.Compile(approve.RunIf)
	if err != nil {
		t.Fatal(err)
	}
	for verdict, want := range map[string]bool{"malicious": true, "benign": false, "false_positive": false, "needs_review": false} {
		got, err := runIf.Eval(map[string]any{"nodes": map[string]any{"triage": map[string]any{"data": map[string]any{"verdict": verdict}}}})
		if err != nil || got != want {
			t.Fatalf("runIf(%s) = %v, %v", verdict, got, err)
		}
	}
	// The host branches are mutually exclusive.
	for _, payload := range []map[string]any{{"dest": "pc-7"}, {"search_name": "x"}} {
		env := map[string]any{"trigger": payload}
		a, _ := expr.Compile(nodes["cs_host"].RunIf)
		b, _ := expr.Compile(nodes["no_host"].RunIf)
		x, _ := a.Eval(env)
		y, _ := b.Eval(env)
		if x == y {
			t.Fatalf("host branches both %v for %v", x, payload)
		}
	}
	// The triage prompt pastes the trigger and enrichment data.
	for _, want := range []string{"{{trigger}}", "{{node.cs_host.data}}", "{{node.cs_detections.data}}", "submit_output"} {
		if !strings.Contains(tpl.Agents[0].Prompt, want) {
			t.Fatalf("triage prompt lacks %s", want)
		}
	}
}
