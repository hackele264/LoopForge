package web

import (
	"os/exec"
	"testing"
)

func TestApprovalRuleHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "approval_rules_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("approval rules: %v\n%s", err, out)
	}
}
