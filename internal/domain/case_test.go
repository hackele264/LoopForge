package domain

import (
	"fmt"
	"strings"
	"testing"
)

func TestExtractIOCs(t *testing.T) {
	payload := decodeJSON(t, `{
		"alert": {"title": "Beacon to http://evil.example.com/a?b=1, from 10.1.2.3 and 999.1.1.1",
		          "sender": "Attacker@Mail.Example.org",
		          "file": {"name": "invoice.pdf", "md5": "D41D8CD98F00B204E9800998ECF8427E",
		                   "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		          "host": "c2.badhost.net",
		          "refs": ["CVE-2024-3094", "see https://203.0.113.9/x."]}
	}`)
	got := map[string]bool{}
	for _, ioc := range ExtractIOCs(payload) {
		got[ioc.Type+":"+ioc.Value] = true
	}
	for _, want := range []string{
		"url:http://evil.example.com/a?b=1", "domain:evil.example.com", "ipv4:10.1.2.3",
		"email:attacker@mail.example.org", "domain:mail.example.org",
		"md5:d41d8cd98f00b204e9800998ecf8427e", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"domain:c2.badhost.net", "cve:CVE-2024-3094", "url:https://203.0.113.9/x", "ipv4:203.0.113.9",
	} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	for _, unwanted := range []string{"ipv4:999.1.1.1", "domain:invoice.pdf"} {
		if got[unwanted] {
			t.Errorf("false positive %s", unwanted)
		}
	}
	many := map[string]any{}
	for i := 0; i < 300; i++ {
		many[fmt.Sprintf("k%03d", i)] = fmt.Sprintf("10.0.%d.%d", i/250, i%250)
	}
	if n := len(ExtractIOCs(many)); n != MaxIOCsPerAlert {
		t.Fatalf("extraction cap = %d", n)
	}
}

func TestNormalizeSeverityAndStatus(t *testing.T) {
	for in, want := range map[any]string{"CRITICAL": "critical", "高危": "high", "warning": "medium", "info": "low", 9.5: "critical", 7.0: "high", 5.0: "medium", 1.0: "low", "weird": "medium", nil: "medium"} {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%v) = %s, want %s", in, got, want)
		}
	}
	if ValidateCaseStatus("closed", "") == nil || ValidateCaseStatus("new", "resolved") == nil || ValidateCaseStatus("open", "") == nil {
		t.Fatal("invalid status combinations accepted")
	}
	if ValidateCaseStatus("closed", "false_positive") != nil || ValidateCaseStatus("investigating", "") != nil {
		t.Fatal("valid status rejected")
	}
}

func TestCaseTriggerRules(t *testing.T) {
	tr := CaseTrigger{Name: " t ", ProjectID: "p", WorkflowID: "w", Enabled: true, Events: []string{"case.created", " case.escalated "}, MinSeverity: "high"}
	if err := tr.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !tr.Matches("case.created", Case{ProjectID: "p", Severity: "critical"}) || tr.Matches("case.created", Case{ProjectID: "p", Severity: "medium"}) ||
		tr.Matches("case.comment", Case{ProjectID: "p", Severity: "high"}) || tr.Matches("case.created", Case{ProjectID: "q", Severity: "high"}) {
		t.Fatal("trigger matching")
	}
	bad := CaseTrigger{Name: "x", ProjectID: "p", WorkflowID: "w", Events: []string{"case.comment"}}
	if err := bad.Normalize(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("comment events must not trigger playbooks: %v", err)
	}
}
