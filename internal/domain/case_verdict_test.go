package domain

import "testing"

func TestVerdictAgreementMapping(t *testing.T) {
	cases := []struct{ verdict, resolution, want string }{
		{"malicious", "resolved", AgreementMatch},
		{"malicious", "false_positive", AgreementMismatch},
		{"benign", "false_positive", AgreementMatch},
		{"false_positive", "false_positive", AgreementMatch},
		{"benign", "resolved", AgreementMismatch},
		{"needs_review", "resolved", AgreementExcluded},
		{"malicious", "duplicate", AgreementExcluded},
		{"", "resolved", AgreementExcluded},
		{"malicious", "", AgreementExcluded},
	}
	for _, c := range cases {
		if got := VerdictAgreement(c.verdict, c.resolution); got != c.want {
			t.Errorf("VerdictAgreement(%q, %q) = %s, want %s", c.verdict, c.resolution, got, c.want)
		}
	}
}

func TestNormalizeAgentVerdict(t *testing.T) {
	c := 0.8
	v, conf, r, err := NormalizeAgentVerdict(" Malicious ", &c, "  reason ")
	if err != nil || v != "malicious" || *conf != 0.8 || r != "reason" {
		t.Fatalf("got %q %v %q %v", v, conf, r, err)
	}
	if _, _, _, err := NormalizeAgentVerdict("suspicious", nil, ""); err == nil {
		t.Fatal("unknown verdict accepted")
	}
	bad := 1.5
	if _, _, _, err := NormalizeAgentVerdict("benign", &bad, ""); err == nil {
		t.Fatal("confidence 1.5 accepted")
	}
}

func TestPercentileNearestRank(t *testing.T) {
	values := []float64{600, 10, 120, 30, 300, 60}
	if Percentile(values, 0.5) != 60 || Percentile(values, 0.95) != 600 || Percentile(nil, 0.95) != 0 {
		t.Fatalf("percentiles wrong")
	}
	if values[0] != 600 {
		t.Fatal("input reordered")
	}
}
