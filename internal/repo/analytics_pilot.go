package repo

import (
	"encoding/json"
	"sort"
	"time"

	"agentflow/internal/domain"
)

// pilotChunk bounds IN lists so large pilots stay under placeholder limits.
const pilotChunk = 500

// PilotReport computes the shadow-mode pilot report for one project and the
// range [from, to). It only reads: alerts, cases, case timelines, runs,
// webhooks and their delivery log.
func (r *AnalyticsRepo) PilotReport(projectID string, from, to time.Time) (domain.PilotReport, error) {
	rep := domain.PilotReport{ProjectID: projectID, From: from, To: to, GeneratedAt: time.Now().UTC(), Definitions: domain.PilotDefinitions}
	rep.Alerts.Deliveries = map[string]int{}
	rep.Agreement.Matrix = map[string]map[string]int{}

	// Alerts received in the range.
	var alerts []alertRow
	if err := r.DB.Where("project_id = ? AND received_at >= ? AND received_at < ?", projectID, from, to).Find(&alerts).Error; err != nil {
		return rep, err
	}
	runIDs := map[string]bool{}
	for _, row := range alerts {
		rep.Alerts.Admitted++
		var flags struct {
			Duplicate bool `json:"duplicate"`
		}
		_ = json.Unmarshal(row.Payload, &flags)
		if flags.Duplicate {
			rep.Alerts.Deduplicated++
		}
		if row.CaseID != "" {
			rep.Alerts.Cased++
		}
		if row.RunID != "" && !flags.Duplicate {
			runIDs[row.RunID] = true
		}
	}

	// Webhook deliveries of the project's webhooks.
	var hooks []webhookRow
	if err := r.DB.Select("id").Where("project_id = ?", projectID).Find(&hooks).Error; err != nil {
		return rep, err
	}
	rep.Alerts.DeliveriesComplete = true
	for _, h := range hooks {
		var kept int64
		if err := r.DB.Model(&webhookDeliveryRow{}).Where("webhook_id = ?", h.ID).Count(&kept).Error; err != nil {
			return rep, err
		}
		if kept >= webhookDeliveryKeep {
			var oldest webhookDeliveryRow
			if err := r.DB.Select("received_at").Where("webhook_id = ?", h.ID).Order("received_at ASC").Take(&oldest).Error; err == nil && oldest.ReceivedAt.After(from) {
				rep.Alerts.DeliveriesComplete = false
			}
		}
		var rows []webhookDeliveryRow
		if err := r.DB.Where("webhook_id = ? AND received_at >= ? AND received_at < ?", h.ID, from, to).Find(&rows).Error; err != nil {
			return rep, err
		}
		for _, row := range rows {
			var d domain.WebhookDelivery
			if json.Unmarshal(row.Payload, &d) == nil && d.Status != "" {
				rep.Alerts.Deliveries[d.Status]++
			}
		}
	}
	rep.Alerts.RateLimited = rep.Alerts.Deliveries[domain.WebhookDeliveryRateLimited]

	// Cases opened in the range.
	var cases []caseRow
	if err := r.DB.Where("project_id = ? AND created_at >= ? AND created_at < ?", projectID, from, to).Find(&cases).Error; err != nil {
		return rep, err
	}
	rep.Alerts.Cases = len(cases)
	caseIDs := make([]string, 0, len(cases))
	for _, row := range cases {
		caseIDs = append(caseIDs, row.ID)
	}
	// Earliest alert per case, for latency.
	firstAlert := map[string]time.Time{}
	for _, part := range pilotChunks(caseIDs) {
		var raw []alertRow
		if err := r.DB.Select("case_id, received_at").Where("case_id IN ?", part).Find(&raw).Error; err != nil {
			return rep, err
		}
		for _, a := range raw {
			if t, ok := firstAlert[a.CaseID]; !ok || a.ReceivedAt.Before(t) {
				firstAlert[a.CaseID] = a.ReceivedAt
			}
		}
	}
	var latencies []float64
	for _, row := range cases {
		c, err := caseFromRow(row)
		if err != nil {
			return rep, err
		}
		if c.AgentVerdictFirstAt == nil {
			rep.Latency.WithoutVerdict++
		} else {
			start := c.CreatedAt
			if t, ok := firstAlert[c.ID]; ok {
				start = t
			}
			d := c.AgentVerdictFirstAt.Sub(start).Seconds()
			if d < 0 {
				d = 0
			}
			latencies = append(latencies, d)
		}
		if c.Status != domain.CaseStatusClosed {
			if c.AgentVerdict != "" {
				rep.Agreement.OpenWithVerdict++
			}
			continue
		}
		verdict := c.AgentVerdict
		if verdict == "" {
			verdict = "none"
		}
		if rep.Agreement.Matrix[verdict] == nil {
			rep.Agreement.Matrix[verdict] = map[string]int{}
		}
		rep.Agreement.Matrix[verdict][c.Resolution]++
		switch domain.VerdictAgreement(c.AgentVerdict, c.Resolution) {
		case domain.AgreementMatch:
			rep.Agreement.Matched++
		case domain.AgreementMismatch:
			rep.Agreement.Mismatch++
		default:
			rep.Agreement.Excluded++
		}
	}
	rep.Latency.WithVerdict = len(latencies)
	rep.Latency.P50Seconds = domain.Percentile(latencies, 0.50)
	rep.Latency.P95Seconds = domain.Percentile(latencies, 0.95)
	rep.Latency.MaxSeconds = domain.Percentile(latencies, 1)
	if scored := rep.Agreement.Matched + rep.Agreement.Mismatch; scored > 0 {
		rep.Agreement.Rate = float64(rep.Agreement.Matched) / float64(scored)
	}

	// Runs: started by an alert in the range, or linked to a case of the
	// project, and created in the range.
	runStatus := map[string]string{}
	collect := func(rows []runRow) {
		for _, row := range rows {
			if row.Created != nil && !row.Created.Before(from) && row.Created.Before(to) {
				runStatus[row.ID] = row.Status
			}
		}
	}
	ids := make([]string, 0, len(runIDs))
	for id := range runIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, part := range pilotChunks(ids) {
		var rows []runRow
		if err := r.DB.Select("id, status, created_at").Where("id IN ?", part).Find(&rows).Error; err != nil {
			return rep, err
		}
		collect(rows)
	}
	var projectCaseIDs []string
	if err := r.DB.Model(&caseRow{}).Where("project_id = ?", projectID).Pluck("id", &projectCaseIDs).Error; err != nil {
		return rep, err
	}
	for _, part := range pilotChunks(projectCaseIDs) {
		var rows []runRow
		if err := r.DB.Select("id, status, created_at").Where("case_id IN ? AND created_at >= ? AND created_at < ?", part, from, to).Find(&rows).Error; err != nil {
			return rep, err
		}
		collect(rows)
	}
	for _, status := range runStatus {
		rep.Runs.Started++
		switch status {
		case "succeeded":
			rep.Runs.Succeeded++
		case "failed":
			rep.Runs.Failed++
		case "cancelled":
			rep.Runs.Cancelled++
		default:
			rep.Runs.Active++
		}
	}

	// Connector actions executed on the project's cases.
	byConnector := map[string]*domain.PilotActionStat{}
	for _, part := range pilotChunks(projectCaseIDs) {
		var rows []caseEventRow
		if err := r.DB.Where("case_id IN ? AND type = ? AND created_at >= ? AND created_at < ?", part, domain.CaseEventAction, from, to).Find(&rows).Error; err != nil {
			return rep, err
		}
		for _, row := range rows {
			var e domain.CaseEvent
			if json.Unmarshal(row.Payload, &e) != nil {
				continue
			}
			var data struct {
				Connector string `json:"connector"`
				Category  string `json:"category"`
				OK        bool   `json:"ok"`
			}
			if json.Unmarshal([]byte(e.Data), &data) != nil || data.Connector == "" {
				continue
			}
			if data.Category == "response" {
				rep.Actions.ResponseExecuted++
				continue
			}
			stat := byConnector[data.Connector]
			if stat == nil {
				stat = &domain.PilotActionStat{Connector: data.Connector}
				byConnector[data.Connector] = stat
			}
			for _, s := range []*domain.PilotActionStat{stat, &rep.Actions.Overall} {
				s.Total++
				if data.OK {
					s.Succeeded++
				}
			}
			if data.Category == "enrichment" {
				rep.Actions.Enrichment.Total++
				if data.OK {
					rep.Actions.Enrichment.Succeeded++
				}
			}
		}
	}
	rep.Actions.Overall.Connector = "all"
	rep.Actions.Enrichment.Connector = "enrichment"
	rep.Actions.Overall.Finish()
	rep.Actions.Enrichment.Finish()
	rep.Actions.ByConnector = []domain.PilotActionStat{}
	for _, s := range byConnector {
		s.Finish()
		rep.Actions.ByConnector = append(rep.Actions.ByConnector, *s)
	}
	sort.Slice(rep.Actions.ByConnector, func(i, j int) bool {
		return rep.Actions.ByConnector[i].Connector < rep.Actions.ByConnector[j].Connector
	})
	return rep, nil
}

func pilotChunks(ids []string) [][]string {
	var out [][]string
	for len(ids) > 0 {
		n := pilotChunk
		if len(ids) < n {
			n = len(ids)
		}
		out = append(out, ids[:n])
		ids = ids[n:]
	}
	return out
}
