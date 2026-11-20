package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"agentflow/internal/domain"
)

// Structured node output for script nodes.
//
// Before a script runs locally the engine writes the run's trigger payload to
// .loopforge/trigger.json in the run workspace and exports two variables:
//
//	LOOPFORGE_TRIGGER  absolute path of the trigger payload file (may not exist)
//	LOOPFORGE_OUTPUT   absolute path where the script may write a JSON object
//
// After the script succeeds the engine reads LOOPFORGE_OUTPUT, validates it
// against the node's OutputSchema and stores it as NodeRun.Data. A node that
// declares a schema must write the file; one without a schema may.

const loopforgeDir = ".loopforge"

// structuredIOEnabled limits trigger/output files to runs that use the
// conditional-workflow features, so legacy workflows see an unchanged
// workspace.
func structuredIOEnabled(run domain.Run, wf domain.WorkflowDefinition) bool {
	if len(run.TriggerPayload) > 0 {
		return true
	}
	for _, n := range wf.Nodes {
		if len(n.OutputSchema) > 0 || strings.TrimSpace(n.RunIf) != "" || domain.NodeJoin(n) == domain.JoinAny {
			return true
		}
	}
	for _, e := range wf.Edges {
		if domain.EdgeWhen(e) == domain.EdgeWhenError {
			return true
		}
	}
	return false
}

func nodeOutputRel(nodeID string) string {
	return filepath.ToSlash(filepath.Join(loopforgeDir, "output", safeNodeFile(nodeID)+".json"))
}

func safeNodeFile(nodeID string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 || r == '.' {
			return '_'
		}
		return r
	}, nodeID)
}

// prepareScriptIO writes the trigger file and clears any stale output file in
// the workspace, returning the shell prefix that exports both paths. The
// paths are resolved inside the sandbox, so they hold for local and
// containerised workspaces alike.
func prepareScriptIO(workspace string, run domain.Run, nodeID string) (string, error) {
	if strings.TrimSpace(workspace) == "" {
		return "", nil
	}
	if err := os.MkdirAll(filepath.Join(workspace, loopforgeDir, "output"), 0o755); err != nil {
		return "", fmt.Errorf("prepare structured output directory: %w", err)
	}
	triggerPath := filepath.Join(workspace, loopforgeDir, "trigger.json")
	if len(run.TriggerPayload) > 0 {
		if err := os.WriteFile(triggerPath, []byte(run.TriggerPayload), 0o644); err != nil {
			return "", fmt.Errorf("write trigger payload: %w", err)
		}
	} else {
		_ = os.Remove(triggerPath)
	}
	outputRel := nodeOutputRel(nodeID)
	if err := os.Remove(filepath.Join(workspace, filepath.FromSlash(outputRel))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("clear stale structured output: %w", err)
	}
	// bindExecutionTarget exports AGENTFLOW_WORKSPACE before it may cd into a
	// repository directory, so anchor both paths on it.
	return fmt.Sprintf("export LOOPFORGE_TRIGGER=\"${AGENTFLOW_WORKSPACE:-$PWD}/%s/trigger.json\" LOOPFORGE_OUTPUT=\"${AGENTFLOW_WORKSPACE:-$PWD}/%s\"; ", loopforgeDir, outputRel), nil
}

// readScriptOutput loads and validates the structured output a script wrote.
// It returns nil data when the script wrote nothing and no schema demands it.
func readScriptOutput(workspace string, node domain.WorkflowNode) (domain.RawJSON, error) {
	if strings.TrimSpace(workspace) == "" {
		return "", nil
	}
	raw, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(nodeOutputRel(node.ID))))
	if errors.Is(err, fs.ErrNotExist) {
		if len(node.OutputSchema) > 0 {
			return "", fmt.Errorf("structured output: node declares outputSchema but the script did not write $LOOPFORGE_OUTPUT")
		}
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("structured output: %w", err)
	}
	data, err := domain.ValidateNodeOutput(node.OutputSchema, raw)
	if err != nil {
		return "", fmt.Errorf("structured output: %w", err)
	}
	return data, nil
}
