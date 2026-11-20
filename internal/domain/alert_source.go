package domain

import (
	"fmt"
	"strings"
	"time"
)

// AlertSource pulls alerts from a product's API on a schedule (a Splunk
// notable search, the Falcon alerts API) for products that cannot push to a
// webhook. Each source belongs to one webhook: pulled alerts go through that
// webhook's mapping, deduplication, case handling and SOP exactly like pushed
// ones.
//
// One pass calls Action on the connection with Inputs rendered over a time
// window ([since, until), see AlertSourceWindowEnv), reads the list in the
// action's ItemsField output, and when DetailAction is set passes those
// values (IDs) to it in batches to get the alerts themselves. Each alert is
// admitted once, keyed by the value at IDPath.
type AlertSource struct {
	ID        string `json:"id"`
	ProjectID string `json:"projectId"`
	WebhookID string `json:"webhookId"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`

	ConnectionID string `json:"connectionId"`
	// Action is the connector action that lists alerts (or their IDs).
	Action string `json:"action"`
	// Inputs are the action's inputs; values may be {{ }} templates over
	// window (since, until, sinceIso, untilIso, sinceMs, untilMs, limit).
	Inputs map[string]string `json:"inputs,omitempty"`
	// ItemsField is the action output field holding the list; default items.
	ItemsField string `json:"itemsField,omitempty"`
	// DetailAction, when set, receives the listed values in DetailInput
	// (a list input) and returns the alerts in its ItemsField output.
	DetailAction string `json:"detailAction,omitempty"`
	DetailInput  string `json:"detailInput,omitempty"`
	// IDPath is a dot path in an alert whose value identifies it across
	// passes; empty uses a hash of the whole alert.
	IDPath string `json:"idPath,omitempty"`
	// TimePath is a dot path to the alert's time. When a pass returns
	// window.limit items, the next pass resumes from the last item's time
	// instead of skipping the rest of the window.
	TimePath string `json:"timePath,omitempty"`

	PollSeconds   int `json:"pollSeconds"`
	LagSeconds    int `json:"lagSeconds"`
	WindowSeconds int `json:"windowSeconds"`
	// PageLimit is window.limit: how many alerts one call may return.
	PageLimit int `json:"pageLimit"`
	// LookbackSeconds sets where a new source starts: this far before it
	// was created. 0 starts at creation.
	LookbackSeconds int `json:"lookbackSeconds,omitempty"`

	State     AlertSourceState `json:"state"`
	CreatedBy int64            `json:"createdBy,omitempty"`
	CreatedAt time.Time        `json:"createdAt"`
	UpdatedAt time.Time        `json:"updatedAt"`
}

// AlertSourceState is what the poller records; the API never writes it.
type AlertSourceState struct {
	// Checkpoint is the end of the last window fully read.
	Checkpoint    *time.Time `json:"checkpoint,omitempty"`
	NextRunAt     *time.Time `json:"nextRunAt,omitempty"`
	LastRunAt     *time.Time `json:"lastRunAt,omitempty"`
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	// LastWarning flags a pass that succeeded but may have missed alerts.
	LastWarning string `json:"lastWarning,omitempty"`
	// Failures counts consecutive failed passes; it drives the backoff.
	Failures int `json:"failures,omitempty"`
	// LastFetched and LastAdmitted count the alerts of the last pass that
	// was read and that were new.
	LastFetched   int   `json:"lastFetched"`
	LastAdmitted  int   `json:"lastAdmitted"`
	TotalAdmitted int64 `json:"totalAdmitted"`
}

// Alert source limits and defaults.
const (
	AlertSourceDefaultPoll   = 60
	AlertSourceMinPoll       = 30
	AlertSourceMaxPoll       = 24 * 60 * 60
	AlertSourceDefaultLag    = 60
	AlertSourceMaxLag        = 60 * 60
	AlertSourceDefaultWindow = 60 * 60
	AlertSourceMinWindow     = 60
	AlertSourceMaxWindow     = 24 * 60 * 60
	AlertSourceDefaultLimit  = 500
	AlertSourceMaxLimit      = 5000
	AlertSourceMaxLookback   = 7 * 24 * 60 * 60
	AlertSourceMaxBackoff    = 10 * time.Minute
	AlertSourceDetailBatch   = 100
)

// Normalize trims fields and fills defaults.
func (s *AlertSource) Normalize() {
	s.Name = strings.TrimSpace(s.Name)
	s.ConnectionID = strings.TrimSpace(s.ConnectionID)
	s.Action = strings.TrimSpace(s.Action)
	s.DetailAction = strings.TrimSpace(s.DetailAction)
	s.DetailInput = strings.TrimSpace(s.DetailInput)
	s.IDPath = strings.TrimSpace(s.IDPath)
	s.TimePath = strings.TrimSpace(s.TimePath)
	s.ItemsField = strings.TrimSpace(s.ItemsField)
	if s.ItemsField == "" {
		s.ItemsField = "items"
	}
	if s.PollSeconds == 0 {
		s.PollSeconds = AlertSourceDefaultPoll
	}
	if s.LagSeconds == 0 {
		s.LagSeconds = AlertSourceDefaultLag
	}
	if s.WindowSeconds == 0 {
		s.WindowSeconds = AlertSourceDefaultWindow
	}
	if s.PageLimit == 0 {
		s.PageLimit = AlertSourceDefaultLimit
	}
	inputs := map[string]string{}
	for k, v := range s.Inputs {
		if k = strings.TrimSpace(k); k != "" && strings.TrimSpace(v) != "" {
			inputs[k] = v
		}
	}
	s.Inputs = inputs
}

// Validate checks the configuration (not the connector action, which the
// caller resolves against the catalog).
func (s AlertSource) Validate() error {
	switch {
	case s.ProjectID == "" || s.WebhookID == "":
		return fmt.Errorf("projectId and webhookId are required")
	case s.Name == "" || len(s.Name) > 120:
		return fmt.Errorf("name must be 1 to 120 characters")
	case s.ConnectionID == "":
		return fmt.Errorf("connectionId is required")
	case s.Action == "":
		return fmt.Errorf("action is required")
	case (s.DetailAction == "") != (s.DetailInput == ""):
		return fmt.Errorf("detailAction and detailInput go together")
	case s.PollSeconds < AlertSourceMinPoll || s.PollSeconds > AlertSourceMaxPoll:
		return fmt.Errorf("pollSeconds must be %d to %d", AlertSourceMinPoll, AlertSourceMaxPoll)
	case s.LagSeconds < 0 || s.LagSeconds > AlertSourceMaxLag:
		return fmt.Errorf("lagSeconds must be 0 to %d", AlertSourceMaxLag)
	case s.WindowSeconds < AlertSourceMinWindow || s.WindowSeconds > AlertSourceMaxWindow:
		return fmt.Errorf("windowSeconds must be %d to %d", AlertSourceMinWindow, AlertSourceMaxWindow)
	case s.PageLimit < 1 || s.PageLimit > AlertSourceMaxLimit:
		return fmt.Errorf("pageLimit must be 1 to %d", AlertSourceMaxLimit)
	case s.LookbackSeconds < 0 || s.LookbackSeconds > AlertSourceMaxLookback:
		return fmt.Errorf("lookbackSeconds must be 0 to %d", AlertSourceMaxLookback)
	}
	for _, p := range []string{s.IDPath, s.TimePath, s.ItemsField} {
		if len(p) > WebhookMaxPathLength {
			return fmt.Errorf("path %q is too long", p)
		}
	}
	if len(s.Inputs) > 32 {
		return fmt.Errorf("too many inputs")
	}
	for k, v := range s.Inputs {
		if len(k) > 64 || len(v) > 4096 {
			return fmt.Errorf("input %s is too long", k)
		}
	}
	return nil
}

// AlertSourceWindowEnv is what a source's input templates read as window.
func AlertSourceWindowEnv(since, until time.Time, limit int) map[string]any {
	return map[string]any{
		"since": float64(since.Unix()), "until": float64(until.Unix()),
		"sinceMs": float64(since.UnixMilli()), "untilMs": float64(until.UnixMilli()),
		"sinceIso": since.UTC().Format(time.RFC3339), "untilIso": until.UTC().Format(time.RFC3339),
		"limit": float64(limit),
	}
}

// AlertSourceBackoff is how long a source waits after failures in a row.
func AlertSourceBackoff(poll time.Duration, failures int) time.Duration {
	wait := poll
	for i := 1; i < failures && wait < AlertSourceMaxBackoff; i++ {
		wait *= 2
	}
	if wait > AlertSourceMaxBackoff {
		wait = AlertSourceMaxBackoff
	}
	return wait
}
