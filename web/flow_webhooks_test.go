package web

import (
	"os/exec"
	"testing"
)

func TestFlowWebhookHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	if out, err := exec.Command(node, "flow_webhooks_test.js", appBundlePath(t)).CombinedOutput(); err != nil {
		t.Fatalf("flow webhooks: %v\n%s", err, out)
	}
}
