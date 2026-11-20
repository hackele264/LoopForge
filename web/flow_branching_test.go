package web

import (
	"os/exec"
	"testing"
)

func TestFlowDesignerBranchingHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "flow_branching_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("flow branching: %v\n%s", err, out)
	}
}
