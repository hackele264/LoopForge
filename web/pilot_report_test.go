package web

import (
	"os/exec"
	"testing"
)

func TestPilotReportViewHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "pilot_report_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("pilot report view: %v\n%s", err, out)
	}
}
