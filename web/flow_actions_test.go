package web

import (
	"os/exec"
	"testing"
)

func TestFlowActionHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "flow_actions_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("flow actions: %v\n%s", err, out)
	}
}
