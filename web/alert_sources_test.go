package web

import (
	"os/exec"
	"testing"
)

func TestAlertSourceHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "alert_sources_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("alert sources: %v\n%s", err, out)
	}
}
