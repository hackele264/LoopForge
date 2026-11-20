package engine

import (
	"agentflow/internal/apperr"
	"agentflow/internal/domain"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// assignWorkBranches gives every repository without a branch the first
// repository's work branch, else a generated one. A branch the caller
// explicitly continues or creates belongs to its own repository, and a
// read-only checkout has no work branch at all.
func assignWorkBranches(repositories []domain.RepositoryContext, generate func() string) {
	if len(repositories) == 0 {
		return
	}
	workBranch := ""
	if first := repositories[0]; !first.RequireExistingWorkBranch && !first.CreateNewWorkBranch && !first.ReadOnly {
		workBranch = strings.TrimSpace(first.WorkBranch)
	}
	for i := range repositories {
		if repositories[i].ReadOnly {
			repositories[i].WorkBranch = ""
			continue
		}
		if strings.TrimSpace(repositories[i].WorkBranch) == "" {
			if workBranch == "" {
				workBranch = generate()
			}
			repositories[i].WorkBranch = workBranch
		}
	}
}

func (e *Engine) Start(workflowID, input string) (domain.Run, error) {
	return e.StartWithContext(workflowID, input, domain.RepositoryContext{})
}

func (e *Engine) StartWithContext(workflowID, input string, repository domain.RepositoryContext) (domain.Run, error) {
	return e.StartWithRepositoriesContext(workflowID, input, []domain.RepositoryContext{repository}, domain.TelemetryContext{})
}

func (e *Engine) StartWithExecutionContext(workflowID, input string, repository domain.RepositoryContext, executionContext domain.TelemetryContext) (domain.Run, error) {
	return e.StartWithRepositoriesContext(workflowID, input, []domain.RepositoryContext{repository}, executionContext)
}

// StartWithRepositoriesContext starts a run with one or more repositories.
// All repositories are equals: each is checked out into a first-level
// sub-directory, gets the same work branch and, on scheduled runs, its own
// integration merge and MR. SOP deliverables stay at the run workspace root.
func (e *Engine) StartWithRepositoriesContext(workflowID, input string, repositories []domain.RepositoryContext, executionContext domain.TelemetryContext) (domain.Run, error) {
	return e.startWorkflow(workflowID, input, repositories, executionContext, false)
}

// StartWithTrigger starts a run carrying a structured trigger payload (a JSON
// object) that RunIf expressions read as `trigger`.
func (e *Engine) StartWithTrigger(workflowID, input string, trigger json.RawMessage, repositories []domain.RepositoryContext, executionContext domain.TelemetryContext) (domain.Run, error) {
	payload, err := normalizeTriggerPayload(trigger)
	if err != nil {
		return domain.Run{}, err
	}
	return e.startWorkflow(workflowID, input, repositories, executionContext, false, payload)
}

// MaxTriggerPayloadBytes bounds a run's trigger payload.
const MaxTriggerPayloadBytes = 1 << 20

func normalizeTriggerPayload(trigger json.RawMessage) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(trigger)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if len(trimmed) > MaxTriggerPayloadBytes {
		return nil, apperr.Newf(apperr.Invalid, "trigger payload exceeds %d bytes", MaxTriggerPayloadBytes)
	}
	var object map[string]any
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return nil, apperr.New(apperr.Invalid, "trigger must be a JSON object")
	}
	return append(json.RawMessage(nil), trimmed...), nil
}

func (e *Engine) startWorkflow(workflowID, input string, repositories []domain.RepositoryContext, executionContext domain.TelemetryContext, workspace bool, trigger ...json.RawMessage) (domain.Run, error) {
	wf, ok := e.repo.Workflow(workflowID)
	if !ok {
		return domain.Run{}, fmt.Errorf("workflow not found")
	}
	return e.startWorkflowDefinition(wf, input, repositories, executionContext, workspace, trigger...)
}

// startWorkflowDefinition also accepts a run-only conversation workspace definition.
// It never writes a template to the catalog.
func (e *Engine) startWorkflowDefinition(wf domain.WorkflowDefinition, input string, repositories []domain.RepositoryContext, executionContext domain.TelemetryContext, workspace bool, trigger ...json.RawMessage) (domain.Run, error) {
	workflowID := wf.ID
	repositories = normalizeRepositories(repositories)
	domain.AssignRepositoryDirs(repositories)
	e.mu.Lock()
	draining, executeRuns := e.draining, e.executeRuns
	instanceID, ttl := e.instanceID, e.leaseTTL
	e.mu.Unlock()
	if draining {
		return domain.Run{}, ErrExecutionDisabled
	}
	wf.CollaborationMode = ""
	wf.TaskTitle = ""
	wf.GroupMembers = nil
	wf.SOPCheckpoint = nil
	wf.GroupSOPHandoff = nil
	wf.GroupHistory = nil
	if wf.Generic {
		if strings.TrimSpace(executionContext.ProjectID) == "" {
			return domain.Run{}, fmt.Errorf("直接运行通用模板需要先选择项目")
		}
		if _, found := e.repo.Project(executionContext.ProjectID); !found {
			return domain.Run{}, fmt.Errorf("项目 %q 不存在，请刷新后重试", executionContext.ProjectID)
		}
	}
	wf = defaultWorkflowSandboxProfile(wf)
	wf, err := domain.AttachPreviewBuild(wf)
	if err != nil {
		return domain.Run{}, err
	}
	if err := validate(wf); err != nil {
		return domain.Run{}, err
	}
	profile, ok := e.repo.Sandbox(wf.SandboxProfileID)
	if !ok {
		return domain.Run{}, fmt.Errorf("sandbox profile %q not found", wf.SandboxProfileID)
	}
	if workspace {
		if _, err := e.repo.ConversationSandbox(executionContext.ProjectID, profile.ID); err != nil {
			return domain.Run{}, err
		}
	}
	resources, err := resolveSandboxResources(e.repo, profile)
	if err != nil {
		return domain.Run{}, err
	}
	if _, err := workflowSandboxRequirements(e.repo, wf); err != nil {
		return domain.Run{}, err
	}
	now := time.Now().UTC()
	// The random part keeps IDs unique when several runs start in the same
	// clock tick (macOS clocks tick in microseconds): PutRun upserts, so a
	// repeated ID would silently merge two runs.
	id := fmt.Sprintf("run-%d-%s", now.UnixNano(), randomIDSuffix())
	assignWorkBranches(repositories, func() string {
		issueID := strings.TrimSpace(executionContext.IssueID)
		if issueID != "" {
			if issue, ok := e.repo.Issue(issueID); ok {
				return domain.DefaultWorkBranch(issue, now)
			}
		}
		return defaultWorkBranch(executionContext.IssueNumber, issueID, now)
	})
	var firstRepository domain.RepositoryContext
	if len(repositories) > 0 {
		firstRepository = repositories[0]
	}
	executionContext.RunID, executionContext.TraceID, executionContext.WorkflowID, executionContext.WorkflowVersion = id, id, workflowID, wf.Version
	if executionContext.ParentRunID == "" && !executionContext.ExecutionPinned {
		executionContext.ExecutionRunnerID = e.repo.DefaultRunner(executionContext.ResponsibleUserID)
		executionContext.WorkspaceRunID = ""
	}
	if executionContext.ExecutionRunnerID == "" && !executionContext.ExecutionPinned {
		if runner, ok := e.cloudPoolRunner(executionContext.ProjectID); ok {
			executionContext.ExecutionRunnerID = runner.ID
			executionContext.ExecutionPool = domain.ExecutionModeCloud
		} else if e.cloudPoolRequired(executionContext.ProjectID) {
			// The first node binds a pool runner once one is online.
			executionContext.ExecutionPool = domain.ExecutionModeCloud
		}
	}
	if executionContext.ExecutionRunnerID != "" || executionContext.ExecutionPool == domain.ExecutionModeCloud {
		executionContext.ExecutionMode = domain.ExecutionModeRunner
		executionContext.RunnerWorkspaceLayout = domain.RunnerWorkspaceLayoutShared
	} else {
		executionContext.ExecutionMode = domain.ExecutionModeCloud
	}
	if err := e.requireWorkBranchCapabilities(executionContext.ExecutionRunnerID, repositories); err != nil {
		return domain.Run{}, err
	}
	wf.SandboxSnapshot = resolvedSandboxSnapshot(profile, resources)
	r := domain.Run{
		ID: id, WorkflowID: workflowID, WorkflowSnapshot: wf, Status: "running", Input: input, TriggerPayload: domain.RawJSON(firstTrigger(trigger)),
		Repository: firstRepository, ExecutionContext: executionContext, Nodes: map[string]*domain.NodeRun{},
		CreatedAt: now, UpdatedAt: now,
	}
	if len(repositories) > 0 {
		r.Repositories = append([]domain.RepositoryContext(nil), repositories...)
	}
	for _, n := range wf.Nodes {
		r.Nodes[n.ID] = &domain.NodeRun{NodeID: n.ID, Status: "pending"}
	}
	if executionContext.ParentRunID != "" {
		parent, exists := e.repo.RunState(executionContext.ParentRunID)
		if !exists {
			return domain.Run{}, fmt.Errorf("父 SOP 运行不存在")
		}
		if err := inheritSOPHandoff(parent, &r); err != nil {
			return domain.Run{}, err
		}
	}
	if workspace {
		r.Kind = domain.RunKindWorkspace
		r.Status = "waiting"
	}
	if workspace {
		e.event(&r, "", "workspace.created", "对话工作区已创建")
	} else {
		e.event(&r, "", "run.started", "流水线开始执行")
	}
	if executeRuns && !workspace {
		if strings.TrimSpace(instanceID) == "" || ttl <= 0 {
			return domain.Run{}, ErrExecutionDisabled
		}
		r.OwnerInstanceID, r.Generation, r.LeaseUntil = instanceID, 1, now.Add(ttl)
	}
	// Control plane persists an unowned running row. The worker claims it
	// through ResumeInterruptedRuns. Combined instances still insert already
	// leased so another process cannot start a second execute() on the same run.
	if err := e.repo.PutRun(r); err != nil {
		return domain.Run{}, err
	}
	if current, ok := e.repo.RunState(r.ID); ok {
		r = current
	}
	e.publish(r.ID)
	if !executeRuns || r.Status == "queued" || workspace {
		return r, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	if !e.claimRunning(id, cancel) {
		cancel()
		return r, nil
	}
	go e.execute(ctx, id)
	return r, nil
}

func (e *Engine) executes() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.executeRuns && !e.draining
}

func firstTrigger(trigger []json.RawMessage) json.RawMessage {
	if len(trigger) == 0 {
		return nil
	}
	return trigger[0]
}

// randomIDSuffix returns 8 random hex characters.
func randomIDSuffix() string {
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	}
	return hex.EncodeToString(raw)
}
