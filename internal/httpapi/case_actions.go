package httpapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
)

// casesHandlers implements connector.CaseService: the built-in case actions
// of action nodes change cases through the same code as the UI, so their
// changes reach the timeline and fire case triggers.
var _ connector.CaseService = (*casesHandlers)(nil)

// playbookActor is who a playbook's case changes are attributed to; the
// event data names the run and node.
func playbookActor() domain.Actor { return domain.Actor{Kind: domain.ActorSystem} }

func playbookEventData(run connector.RunContext) map[string]any {
	return map[string]any{"runId": run.RunID, "nodeId": run.NodeID}
}

func (h *casesHandlers) runCase(run connector.RunContext) (domain.Case, error) {
	cs, ok := h.repo.Case(run.CaseID)
	if !ok {
		return domain.Case{}, fmt.Errorf("案件 %s 不存在", run.CaseID)
	}
	if cs.ProjectID != run.ProjectID {
		return domain.Case{}, errors.New("案件不属于本运行所在的项目")
	}
	return cs, nil
}

// CaseComment implements connector.CaseService.
func (h *casesHandlers) CaseComment(_ context.Context, run connector.RunContext, body string) error {
	cs, err := h.runCase(run)
	if err != nil {
		return err
	}
	return h.repo.AppendCaseEvents(cs.ID, caseEvent(domain.CaseEventComment, body, playbookActor(), playbookEventData(run), time.Now().UTC()))
}

// CaseUpdate implements connector.CaseService.
func (h *casesHandlers) CaseUpdate(_ context.Context, run connector.RunContext, change connector.CaseChange) (domain.Case, error) {
	cs, err := h.runCase(run)
	if err != nil {
		return domain.Case{}, err
	}
	req := caseUpdate{}
	if change.Status != "" {
		req.Status = &change.Status
	}
	if change.Resolution != "" {
		req.Resolution = &change.Resolution
	}
	if change.Severity != "" {
		req.Severity = &change.Severity
	}
	return h.applyCaseUpdate(cs.ID, req, playbookActor(), playbookEventData(run))
}

// CaseAddIOCs implements connector.CaseService.
func (h *casesHandlers) CaseAddIOCs(_ context.Context, run connector.RunContext, iocs []domain.CaseIOC) (int, error) {
	cs, err := h.runCase(run)
	if err != nil {
		return 0, err
	}
	before, err := h.repo.CaseIOCs(cs.ID)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	for i := range iocs {
		iocs[i].FirstSeen = now
	}
	if len(iocs) == 0 {
		return 0, nil
	}
	if _, err := h.repo.UpdateCase(cs.ID, func(x *domain.Case, _ int) (repo.CaseChange, error) {
		x.UpdatedAt = now
		return repo.CaseChange{IOCs: iocs}, nil
	}); err != nil {
		return 0, err
	}
	after, err := h.repo.CaseIOCs(cs.ID)
	if err != nil {
		return 0, err
	}
	added := len(after) - len(before)
	if added > 0 {
		_ = h.repo.AppendCaseEvents(cs.ID, caseEvent(domain.CaseEventIOCAdded, fmt.Sprintf("SOP 添加了 %d 个 IOC", added), playbookActor(), playbookEventData(run), now))
	}
	return added, nil
}
