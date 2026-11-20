package domain

import (
	"fmt"
	"math"
	"strings"
)

// Agent verdicts a triage step may record on a case. They are compared with
// the analyst's closing Resolution to measure agreement (pilot report).
const (
	AgentVerdictMalicious     = "malicious"
	AgentVerdictBenign        = "benign"
	AgentVerdictFalsePositive = "false_positive"
	AgentVerdictNeedsReview   = "needs_review"
)

// AgentVerdicts lists the accepted verdicts.
var AgentVerdicts = []string{AgentVerdictMalicious, AgentVerdictBenign, AgentVerdictFalsePositive, AgentVerdictNeedsReview}

// MaxAgentRationale bounds the stored rationale in characters.
const MaxAgentRationale = 4000

// NormalizeAgentVerdict lower-cases and checks a verdict, a confidence
// between 0 and 1 (nil when absent) and trims the rationale.
func NormalizeAgentVerdict(verdict string, confidence *float64, rationale string) (string, *float64, string, error) {
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if !contains(AgentVerdicts, verdict) {
		return "", nil, "", fmt.Errorf("verdict must be one of %s", strings.Join(AgentVerdicts, ", "))
	}
	if confidence != nil {
		c := *confidence
		if math.IsNaN(c) || c < 0 || c > 1 {
			return "", nil, "", fmt.Errorf("confidence must be between 0 and 1")
		}
	}
	rationale = strings.TrimSpace(rationale)
	if r := []rune(rationale); len(r) > MaxAgentRationale {
		rationale = string(r[:MaxAgentRationale]) + "…"
	}
	return verdict, confidence, rationale, nil
}

// Agreement classes of an agent verdict against a closed case's resolution.
const (
	AgreementMatch    = "match"
	AgreementMismatch = "mismatch"
	// AgreementExcluded: needs_review verdicts, duplicate resolutions, and
	// cases without a verdict or not closed are not scored.
	AgreementExcluded = "excluded"
)

// VerdictAgreement maps a verdict and a resolution onto agreement:
//
//	malicious                    ↔ resolved
//	benign, false_positive       ↔ false_positive
//	needs_review (verdict)       → excluded
//	duplicate (resolution)       → excluded
//
// Anything else (no verdict, case not closed) is excluded too.
func VerdictAgreement(verdict, resolution string) string {
	if resolution == CaseResolutionDuplicate || resolution == "" {
		return AgreementExcluded
	}
	var predicted string
	switch verdict {
	case AgentVerdictMalicious:
		predicted = CaseResolutionResolved
	case AgentVerdictBenign, AgentVerdictFalsePositive:
		predicted = CaseResolutionFalsePositive
	default:
		return AgreementExcluded
	}
	if resolution != CaseResolutionResolved && resolution != CaseResolutionFalsePositive {
		return AgreementExcluded
	}
	if predicted == resolution {
		return AgreementMatch
	}
	return AgreementMismatch
}
