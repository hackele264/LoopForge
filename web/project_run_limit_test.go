package web

import (
	"os/exec"
	"testing"
)

func TestProjectRunLimitHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "project_run_limit_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("project run limit: %v\n%s", err, out)
	}
}
