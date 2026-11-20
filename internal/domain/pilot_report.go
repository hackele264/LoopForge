package domain

import (
	"math"
	"sort"
	"time"
)

// PilotReport is the shadow-mode pilot's read-only summary for one project
// and time range. See docs/pilot.md for how each number is defined.
type PilotReport struct {
	ProjectID   string    `json:"projectId"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	GeneratedAt time.Time `json:"generatedAt"`

	Alerts      PilotAlerts       `json:"alerts"`
	Runs        PilotRuns         `json:"runs"`
	Actions     PilotActions      `json:"actions"`
	Latency     PilotLatency      `json:"latency"`
	Agreement   PilotAgreement    `json:"agreement"`
	Definitions map[string]string `json:"definitions"`
}

// PilotAlerts counts alerts received in the range.
type PilotAlerts struct {
	// Admitted is every stored alert, duplicates included.
	Admitted int `json:"admitted"`
	// Deduplicated alerts matched a live fingerprint and started no run.
	Deduplicated int `json:"deduplicated"`
	// Cased alerts belong to a case.
	Cased int `json:"cased"`
	// Deliveries counts webhook delivery log entries by status (started,
	// deduplicated, rejected, rate_limited, failed).
	Deliveries map[string]int `json:"deliveries"`
	// RateLimited is Deliveries["rate_limited"].
	RateLimited int `json:"rateLimited"`
	// DeliveriesComplete is false when a webhook's delivery log (the last
	// 200 per webhook) no longer reaches back to From, so delivery counts
	// are a lower bound.
	DeliveriesComplete bool `json:"deliveriesComplete"`
	// Cases opened in the range.
	Cases int `json:"cases"`
}

// PilotRuns counts runs of the project's alerts and cases started in the
// range.
type PilotRuns struct {
	Started   int `json:"started"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
	// Active runs are still running or waiting (for example at the
	// response approval gate).
	Active int `json:"active"`
}

// PilotActionStat is one connector's executed actions.
type PilotActionStat struct {
	Connector string  `json:"connector"`
	Total     int     `json:"total"`
	Succeeded int     `json:"succeeded"`
	Failed    int     `json:"failed"`
	Rate      float64 `json:"rate"`
}

// PilotActions summarizes connector actions executed on the project's
// cases (timeline case.action entries). Response actions are counted apart
// and left out of the rates; actions still waiting at a gate never ran and
// are not counted at all.
type PilotActions struct {
	// Overall covers enrichment and utility actions.
	Overall PilotActionStat `json:"overall"`
	// Enrichment covers only enrichment actions: the pilot's enrichment
	// success rate.
	Enrichment       PilotActionStat   `json:"enrichment"`
	ByConnector      []PilotActionStat `json:"byConnector"`
	ResponseExecuted int               `json:"responseExecuted"`
}

// PilotLatency is the time from a case's first alert to its first agent
// verdict, in seconds, over cases opened in the range.
type PilotLatency struct {
	WithVerdict    int     `json:"withVerdict"`
	WithoutVerdict int     `json:"withoutVerdict"`
	P50Seconds     float64 `json:"p50Seconds"`
	P95Seconds     float64 `json:"p95Seconds"`
	MaxSeconds     float64 `json:"maxSeconds"`
}

// PilotAgreement compares agent verdicts with the resolutions of closed
// cases opened in the range (see VerdictAgreement).
type PilotAgreement struct {
	// Matrix[verdict][resolution] counts closed cases; verdict "none" is a
	// closed case without an agent verdict.
	Matrix   map[string]map[string]int `json:"matrix"`
	Matched  int                       `json:"matched"`
	Mismatch int                       `json:"mismatched"`
	Excluded int                       `json:"excluded"`
	// Rate is Matched / (Matched + Mismatch); 0 when nothing was scored.
	Rate float64 `json:"rate"`
	// OpenWithVerdict cases have a verdict but no resolution yet.
	OpenWithVerdict int `json:"openWithVerdict"`
}

// PilotDefinitions documents the report's numbers in the response itself.
var PilotDefinitions = map[string]string{
	"alerts.admitted":     "alerts stored for the project with receivedAt in [from, to), duplicates included",
	"alerts.deduplicated": "of those, alerts marked duplicate (absorbed by an open fingerprint, no run of their own)",
	"alerts.rateLimited":  "webhook deliveries with status rate_limited in the range; the log keeps the last 200 deliveries per webhook (see deliveriesComplete)",
	"runs":                "runs created in the range that an alert of the project started or that belong to one of its cases",
	"actions":             "case.action timeline entries in the range: connector actions that actually executed, by ok flag; response actions are excluded from rates and counted in responseExecuted",
	"latency":             "cases opened in the range: agentVerdictFirstAt minus the earliest receivedAt of the case's alerts (case createdAt when it has none); nearest-rank percentiles",
	"agreement":           "closed cases opened in the range: malicious matches resolved; benign and false_positive match false_positive; needs_review verdicts and duplicate resolutions are excluded",
}

// Percentile returns the nearest-rank percentile (0 < p <= 1) of values.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// Finish computes the derived rates.
func (s *PilotActionStat) Finish() {
	s.Failed = s.Total - s.Succeeded
	if s.Total > 0 {
		s.Rate = float64(s.Succeeded) / float64(s.Total)
	}
}
