package httpapi

import (
	"context"
	"fmt"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
)

// casesHandlers records triage verdicts for the built-in 记录研判结论
// action, so the pilot report can compare them with the analyst's
// resolution.
var _ connector.CaseVerdictService = (*casesHandlers)(nil)

// CaseSetVerdict implements connector.CaseVerdictService. The verdict, its
// confidence, rationale and run replace any earlier verdict;
// AgentVerdictFirstAt keeps the time of the first one, which the pilot
// report uses for alert-to-verdict latency.
func (h *casesHandlers) CaseSetVerdict(_ context.Context, run connector.RunContext, v connector.CaseVerdict) (domain.Case, error) {
	verdict, confidence, rationale, err := domain.NormalizeAgentVerdict(v.Verdict, v.Confidence, v.Rationale)
	if err != nil {
		return domain.Case{}, err
	}
	cs, err := h.runCase(run)
	if err != nil {
		return domain.Case{}, err
	}
	now := time.Now().UTC()
	return h.repo.UpdateCase(cs.ID, func(c *domain.Case, _ int) (repo.CaseChange, error) {
		previous := c.AgentVerdict
		c.AgentVerdict, c.AgentConfidence, c.AgentRationale, c.AgentVerdictRunID = verdict, confidence, rationale, run.RunID
		c.AgentVerdictAt = &now
		if c.AgentVerdictFirstAt == nil {
			c.AgentVerdictFirstAt = &now
		}
		c.UpdatedAt = now
		message := "Agent 研判结论：" + verdict
		if confidence != nil {
			message += fmt.Sprintf("（置信度 %.2f）", *confidence)
		}
		if previous != "" && previous != verdict {
			message += "，此前为 " + previous
		}
		if rationale != "" {
			message += "：" + rationale
		}
		data := playbookEventData(run)
		data["verdict"] = verdict
		if confidence != nil {
			data["confidence"] = *confidence
		}
		return repo.CaseChange{Events: []domain.CaseEvent{caseEvent(domain.CaseEventAgentVerdict, message, playbookActor(), data, now)}}, nil
	})
}
