package domain

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Run struct {
	Kind               string             `json:"kind,omitempty"`
	ID                 string             `json:"id"`
	WorkflowID         string             `json:"workflowId"`
	WorkflowSnapshot   WorkflowDefinition `json:"workflowSnapshot"`
	SandboxID          string             `json:"sandboxId,omitempty"`
	OwnerInstanceID    string             `json:"ownerInstanceId,omitempty"`
	LeaseUntil         time.Time          `json:"leaseUntil,omitempty"`
	Generation         int                `json:"executionGeneration,omitempty"`
	WorkspaceHost      string             `json:"workspaceHost,omitempty"`
	WorkspaceEditorID  int64              `json:"workspaceEditorId,omitempty"`
	WorkspaceEditUntil time.Time          `json:"workspaceEditUntil,omitempty"`
	WorkspaceRoot      string             `json:"workspaceRoot,omitempty"`
	WorkspaceCleanedAt time.Time          `json:"workspaceCleanedAt,omitempty"`
	// WorkspaceCleanupNotBefore delays terminal workspace deletion while a
	// preview finalizer still needs the run directory. Zero means no hold.
	WorkspaceCleanupNotBefore time.Time `json:"workspaceCleanupNotBefore,omitempty"`
	Status                    string    `json:"status"`
	AdmissionState            string    `json:"admissionState,omitempty"`
	QueueEnteredAt            time.Time `json:"queueEnteredAt,omitempty"`
	ConcurrencyExempt         bool      `json:"concurrencyExempt,omitempty"`
	CancelRequested           bool      `json:"cancelRequested"`
	PauseRequested            bool      `json:"pauseRequested"`
	Input                     string    `json:"input"`
	// TriggerPayload is the structured payload that started the run (a JSON
	// object), readable from RunIf expressions as `trigger`.
	TriggerPayload RawJSON           `json:"triggerPayload,omitempty"`
	Repository     RepositoryContext `json:"repository,omitempty"`
	// Repositories lists every repository frozen into this run. Repository
	// mirrors the first entry so old readers (UI cards, tasks) keep working;
	// execution logic must iterate Repositories and treats all entries as
	// equals. Legacy runs only carry Repository.
	Repositories      []RepositoryContext `json:"repositories,omitempty"`
	ExecutionContext  TelemetryContext    `json:"executionContext,omitempty"`
	Nodes             map[string]*NodeRun `json:"nodes"`
	Events            []RunEvent          `json:"events"`
	Telemetry         []TelemetryEvent    `json:"telemetry,omitempty"`
	TelemetrySequence int64               `json:"telemetrySequence"`
	Logs              []LogRecord         `json:"logs,omitempty"`
	LogSequence       int64               `json:"logSequence"`
	Usage             TokenUsage          `json:"usage"`
	ToolCalls         int                 `json:"toolCalls"`
	Artifacts         []Artifact          `json:"artifacts,omitempty"`
	ArtifactCount     int                 `json:"artifactCount,omitempty"`
	HumanContext      string              `json:"humanContext,omitempty"`
	Timing            *RunTiming          `json:"timing,omitempty"`
	CreatedAt         time.Time           `json:"createdAt"`
	UpdatedAt         time.Time           `json:"updatedAt"`
	Revision          int                 `json:"revision"`
}

const RunKindWorkspace = "workspace"
const ConversationWorkspaceWorkflowID = "conversation-workspace"

// IsWorkspace distinguishes an on-demand chat workspace from a scheduled SOP.
func (r Run) IsWorkspace() bool { return r.Kind == RunKindWorkspace }

// IsPersonalWorkspace identifies a workspace whose access is scoped to its owner.
func (r Run) IsPersonalWorkspace() bool {
	return r.IsWorkspace() && r.ExecutionContext.ProjectID == ""
}

// LiveWorkspace reports a chat workspace that is open for edits. It has no SOP
// graph to pause, so Main Bot and people in the IDE edit it side by side and
// rely on expectedSha256 to catch conflicting writes.
func (r Run) LiveWorkspace() bool {
	return r.IsWorkspace() && !r.CancelRequested && r.WorkspaceCleanedAt.IsZero() && (r.Status == "running" || r.Status == "waiting")
}

// HumanEditable reports whether people may edit the workspace in the IDE. Like
// an AI IDE they edit at any time, also while SOP agents run: nothing pauses,
// expectedSha256 catches conflicting writes and agents re-read what changed.
func (r Run) HumanEditable() bool {
	if !r.WorkspaceCleanedAt.IsZero() {
		return false
	}
	switch r.Status {
	case "succeeded", "failed", "cancelled":
		return true
	case "running", "waiting":
		return !r.CancelRequested
	}
	return false
}

// HistoricalGroup is a record of the retired role groups. It has no SOP graph
// that could be resumed or retried.
func (r Run) HistoricalGroup() bool {
	return !r.IsWorkspace() && r.WorkflowSnapshot.CollaborationMode == "group"
}

// HasActiveNode reports whether any node of the run is still executing: it is
// running or paused for input that the agent asked for mid-step.
func (r Run) HasActiveNode() bool {
	for _, nr := range r.Nodes {
		if nr != nil && (nr.Status == "running" || nr.Status == "pending_input") {
			return true
		}
	}
	return false
}

// RepositoryContexts returns the frozen repositories of this run. New runs
// fill Repositories; legacy runs only carry the single Repository field.
func (r Run) RepositoryContexts() []RepositoryContext {
	if len(r.Repositories) > 0 {
		return r.Repositories
	}
	if !r.Repository.IsZero() {
		return []RepositoryContext{r.Repository}
	}
	return nil
}

// UnmarshalJSON lifts the shared sandbox instance from historical node runs.
// NodeRun.SandboxID remains readable during the engine transition, but new
// clients consume the run-level field.
func (r *Run) UnmarshalJSON(raw []byte) error {
	type runAlias Run
	var value runAlias
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*r = Run(value)
	if r.SandboxID != "" {
		return nil
	}
	for _, node := range r.Nodes {
		if node == nil || strings.TrimSpace(node.SandboxID) == "" {
			continue
		}
		if r.SandboxID != "" && r.SandboxID != node.SandboxID {
			return fmt.Errorf("run %q has conflicting legacy node sandbox ids %q and %q", r.ID, r.SandboxID, node.SandboxID)
		}
		r.SandboxID = node.SandboxID
	}
	return nil
}

type NodeRun struct {
	NodeID          string      `json:"nodeId"`
	Status          string      `json:"status"`
	Attempt         int         `json:"attempt"`
	ReworkCount     int         `json:"reworkCount"`
	SandboxID       string      `json:"sandboxId,omitempty"`
	Output          string      `json:"output,omitempty"`
	Error           string      `json:"error,omitempty"`
	Provider        string      `json:"provider,omitempty"`
	Model           string      `json:"model,omitempty"`
	SessionID       string      `json:"sessionId,omitempty"`
	ResumeSessionID string      `json:"resumeSessionId,omitempty"`
	Activity        string      `json:"activity,omitempty"`
	Feedback        string      `json:"feedback,omitempty"`
	Usage           TokenUsage  `json:"usage"`
	UsageSessionID  string      `json:"usageSessionId,omitempty"`
	UsageCursor     TokenUsage  `json:"usageCursor,omitempty"`
	ToolCalls       int         `json:"toolCalls"`
	GateResult      *GateResult `json:"gateResult,omitempty"`
	ChildRunID      string      `json:"childRunId,omitempty"`
	StartedAt       time.Time   `json:"startedAt,omitzero"`
	FinishedAt      time.Time   `json:"finishedAt,omitzero"`
	// SkipReason explains a "skipped" node: condition_false or branch_not_taken.
	SkipReason string `json:"skipReason,omitempty"`
	// Data is the node's validated structured output (a JSON object).
	Data RawJSON `json:"data,omitempty"`
	// ErrorRouted marks a final failure handed to the node's error edges; the
	// run continues and does not fail because of it.
	ErrorRouted bool `json:"errorRouted,omitempty"`
	// DecidedBy / DecidedAt record who last approved, rejected or passed it.
	DecidedBy int64     `json:"decidedBy,omitempty"`
	DecidedAt time.Time `json:"decidedAt,omitzero"`
}

// Node statuses introduced for conditional workflows.
const (
	NodeStatusSkipped = "skipped"

	SkipReasonConditionFalse = "condition_false"
	SkipReasonBranchNotTaken = "branch_not_taken"
)

// ResetBranchState clears the per-attempt branching fields when a node is
// reset to pending by a reject, retry or rework.
func (n *NodeRun) ResetBranchState() {
	if n == nil {
		return
	}
	n.SkipReason = ""
	n.Data = ""
	n.ErrorRouted = false
	n.DecidedBy = 0
	n.DecidedAt = time.Time{}
}

// SettledOK reports whether a node no longer blocks a successful run: it
// succeeded, was skipped, or its failure was routed to an error edge.
func (n *NodeRun) SettledOK() bool {
	if n == nil {
		return false
	}
	switch n.Status {
	case "succeeded", NodeStatusSkipped:
		return true
	case "failed":
		return n.ErrorRouted
	}
	return false
}

// Actor kinds recorded on run events.
const (
	ActorUser    = "user"
	ActorBot     = "bot"
	ActorService = "service"
	ActorSystem  = "system"
)

// Actor identifies who performed a human control action on a run.
type Actor struct {
	UserID int64  `json:"userId,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Login  string `json:"login,omitempty"`
	// TokenID is set when the actor authenticated with an API token rather
	// than an interactive session.
	TokenID string `json:"tokenId,omitempty"`
}

// Named reports whether the actor is a specific platform user.
func (a Actor) Named() bool {
	return a.UserID > 0 && (a.Kind == ActorUser || a.Kind == ActorBot)
}

// GateResult is the structured terminal decision submitted by an Agent through
// the invocation-scoped submit_gate_result MCP tool.
type GateResult struct {
	Decision       string        `json:"decision"` // pass, rework, fail, human
	Reason         string        `json:"reason"`
	ActionRequired string        `json:"actionRequired,omitempty"`
	Summary        string        `json:"summary,omitempty"`
	Findings       []GateFinding `json:"findings,omitempty"`
}

type GateFinding struct {
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title"`
	Evidence string `json:"evidence,omitempty"`
}

type TokenUsage struct {
	InputTokens      int64   `json:"inputTokens"`
	OutputTokens     int64   `json:"outputTokens"`
	CacheReadTokens  int64   `json:"cacheReadTokens"`
	CacheWriteTokens int64   `json:"cacheWriteTokens"`
	TotalTokens      int64   `json:"totalTokens"`
	CostUSD          float64 `json:"costUsd"`
	ReasoningTokens  int64   `json:"reasoningTokens,omitempty"`
	ContextWindow    int64   `json:"contextWindow,omitempty"`
	// CostStatus 区分"成本为 0"与"成本未知"：reported（适配器上报）、estimated（按 token 估算）、
	// unknown（未识别，展示为"未识别"而不是 ¥0）。空值视为 unknown，旧数据向后兼容。
	CostStatus string `json:"costStatus,omitempty"`
}

type TelemetryEvent struct {
	SpecVersion    string            `json:"specVersion"`
	ID             string            `json:"id"`
	RunID          string            `json:"runId"`
	NodeID         string            `json:"nodeId,omitempty"`
	Sequence       int64             `json:"sequence"`
	Timestamp      time.Time         `json:"timestamp"`
	Category       string            `json:"category"` // lifecycle, model, reasoning, output, tool, usage, process, verification, sandbox
	Name           string            `json:"name"`
	Phase          string            `json:"phase,omitempty"` // start, progress, finish
	Level          string            `json:"level,omitempty"`
	Message        string            `json:"message,omitempty"`
	Provider       string            `json:"provider,omitempty"`
	Model          string            `json:"model,omitempty"`
	SessionID      string            `json:"sessionId,omitempty"`
	ToolCallID     string            `json:"toolCallId,omitempty"`
	ParentID       string            `json:"parentId,omitempty"`
	Usage          *TokenUsage       `json:"usage,omitempty"`
	Attributes     map[string]any    `json:"attributes,omitempty"`
	Source         TelemetrySource   `json:"source"`
	Context        TelemetryContext  `json:"context"`
	Metrics        []MetricPoint     `json:"metrics,omitempty"`
	Tool           *ToolObservation  `json:"tool,omitempty"`
	ModelOperation *ModelObservation `json:"modelOperation,omitempty"`
	Error          *ErrorObservation `json:"error,omitempty"`
}

type RunEvent struct {
	ID        string    `json:"id"`
	RunID     string    `json:"runId"`
	NodeID    string    `json:"nodeId,omitempty"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	// ActorUserID / ActorKind record who caused a human control event.
	ActorUserID int64  `json:"actorUserId,omitempty"`
	ActorKind   string `json:"actorKind,omitempty"`
}

// Artifact is an immutable, attempt-scoped snapshot. Keeping old attempts makes
// rework auditable while downstream nodes consume the newest successful version.
type Artifact struct {
	ID        string `json:"id"`
	RunID     string `json:"runId"`
	NodeID    string `json:"nodeId"`
	Attempt   int    `json:"attempt"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Content   string `json:"content"`
	// RepositoryDir records which run repository workspace the artifact was
	// collected from (empty = run workspace root, where SOP deliverables live).
	RepositoryDir string    `json:"repositoryDir,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

// RawJSON is a JSON value kept verbatim as text. Unlike json.RawMessage it is
// comparable, so structs that hold it (Run, NodeRun) still work with ==.
// The empty value marshals as null and is dropped by omitempty.
type RawJSON string

// MarshalJSON writes the stored JSON unchanged.
func (r RawJSON) MarshalJSON() ([]byte, error) {
	if r == "" {
		return []byte("null"), nil
	}
	return []byte(r), nil
}

// UnmarshalJSON stores the raw JSON text; null clears it.
func (r *RawJSON) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*r = ""
		return nil
	}
	*r = RawJSON(b)
	return nil
}
