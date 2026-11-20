package web

import (
	"os/exec"
	"testing"
)

func TestCasesViewHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "cases_view_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("cases view: %v\n%s", err, out)
	}
}
