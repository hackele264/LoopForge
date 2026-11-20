package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/repo"

	"github.com/gin-gonic/gin"
)

// casesHandlers owns security alerts, cases, their timelines and the case
// triggers that start playbooks. Webhook ingestion reaches it through
// webhooksHandlers.cases.
type casesHandlers struct{ *deps }

// maxAlertsInTrigger bounds the alert summaries put in a trigger payload.
const maxAlertsInTrigger = 20

// projectReader allows project members of any role, the owner, platform
// administrators and projects without an owner. Security data is not
// readable instance-wide like the rest of the catalog.
func (h *casesHandlers) projectReader(c *gin.Context, projectID string) bool {
	if authRequired() && !h.tokenAllowsProject(c.Request, projectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API Token 无权访问该项目"})
		return false
	}
	if !authRequired() || h.isPlatformAdmin(c.Request) {
		return true
	}
	user, ok := h.requestUser(c.Request, true)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return false
	}
	p, found := h.repo.Project(projectID)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
		return false
	}
	if p.OwnerID == 0 || p.OwnerID == user.ID {
		return true
	}
	for _, m := range p.Members {
		if m.UserID == user.ID {
			return true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "只有项目成员可以查看该项目的告警和案件"})
	return false
}

func caseEvent(kind, message string, actor domain.Actor, data any, at time.Time) domain.CaseEvent {
	e := domain.CaseEvent{Type: kind, Message: message, ActorUserID: actor.UserID, ActorKind: actor.Kind, CreatedAt: at}
	if data != nil {
		if raw, err := json.Marshal(data); err == nil {
			e.Data = domain.RawJSON(raw)
		}
	}
	return e
}

func alertIOCs(a domain.Alert, at time.Time) []domain.CaseIOC {
	var payload any
	if len(a.Payload) > 0 {
		_ = json.Unmarshal([]byte(a.Payload), &payload)
	}
	iocs := domain.ExtractIOCs(payload)
	for i := range iocs {
		iocs[i].AlertID, iocs[i].FirstSeen = a.ID, at
	}
	return iocs
}

// ---------- webhook integration ----------

// alertOutcome is what ingestion did with an alert.
type alertOutcome struct {
	Alert domain.Alert
	Case  *domain.Case
}

// recordAlert stores a webhook alert. A duplicate joins the case its
// fingerprint opened; a new alert opens a case when the webhook asks for it.
// It runs before the playbook starts so the run can carry the case ID.
func (h *casesHandlers) recordAlert(w domain.Webhook, a domain.Alert, duplicateOf *repo.DedupClaim) (alertOutcome, error) {
	actor := domain.Actor{Kind: domain.ActorService, Login: "webhook:" + w.ID}
	now := a.ReceivedAt
	if duplicateOf != nil && duplicateOf.CaseID != "" {
		a.Duplicate, a.RunID = true, duplicateOf.RunID
		updated, err := h.repo.UpdateCase(duplicateOf.CaseID, func(c *domain.Case, _ int) (repo.CaseChange, error) {
			c.UpdatedAt = now
			events := []domain.CaseEvent{caseEvent(domain.CaseEventAlertAdded, fmt.Sprintf("Webhook「%s」收到重复告警：%s", w.Name, a.Title), actor, map[string]any{"alertId": a.ID, "duplicate": true}, now)}
			return repo.CaseChange{Alerts: []domain.Alert{a}, IOCs: alertIOCs(a, now), Events: events}, nil
		})
		if errors.Is(err, repo.ErrCaseNotFound) {
			// The case was deleted under the fingerprint; keep the alert alone.
			return alertOutcome{Alert: a}, h.repo.PutAlert(a)
		}
		if err != nil {
			return alertOutcome{}, err
		}
		a.CaseID = updated.ID
		h.fireCaseTriggers(updated, domain.CaseEventAlertAdded, &a)
		return alertOutcome{Alert: a, Case: &updated}, nil
	}
	if duplicateOf != nil {
		a.Duplicate, a.RunID = true, duplicateOf.RunID
	}
	if !w.OpensCases() || a.Duplicate {
		return alertOutcome{Alert: a}, h.repo.PutAlert(a)
	}
	created, err := h.repo.CreateCase(domain.Case{
		ProjectID: w.ProjectID, Title: a.Title, Severity: a.Severity, Status: domain.CaseStatusNew,
		CreatedBy: w.CreatedBy, CreatedAt: now, UpdatedAt: now,
	}, repo.CaseChange{
		Alerts: []domain.Alert{a},
		IOCs:   alertIOCs(a, now),
		Events: []domain.CaseEvent{caseEvent(domain.CaseEventCreated, fmt.Sprintf("由 Webhook「%s」的告警创建", w.Name), actor, map[string]any{"alertId": a.ID, "webhookId": w.ID}, now)},
	})
	if err != nil {
		return alertOutcome{}, err
	}
	a.CaseID = created.ID
	return alertOutcome{Alert: a, Case: &created}, nil
}

// ---------- triggers ----------

// fireCaseTriggers starts the playbooks subscribed to eventType on c. A
// trigger is skipped while one of its runs for the case is still active or
// once it has started CaseTriggerMaxRunsPerCase runs for the case, so a
// playbook that edits its own case cannot loop.
func (h *casesHandlers) fireCaseTriggers(c domain.Case, eventType string, alert *domain.Alert) {
	triggers, err := h.repo.CaseTriggers(c.ProjectID)
	if err != nil {
		log.Printf("case %s: list triggers: %v", c.ID, err)
		return
	}
	for _, t := range triggers {
		if !t.Matches(eventType, c) {
			continue
		}
		total, active, err := h.repo.CountTriggerRuns(c.ID, t.ID)
		if err != nil {
			log.Printf("case %s: count trigger runs: %v", c.ID, err)
			continue
		}
		now := time.Now().UTC()
		if active > 0 || total >= domain.CaseTriggerMaxRunsPerCase {
			reason := "上一次运行尚未结束"
			if total >= domain.CaseTriggerMaxRunsPerCase {
				reason = fmt.Sprintf("已达到单个案件 %d 次的触发上限", domain.CaseTriggerMaxRunsPerCase)
			}
			_ = h.repo.AppendCaseEvents(c.ID, caseEvent(domain.CaseEventUpdated, fmt.Sprintf("触发器「%s」未启动：%s", t.Name, reason), domain.Actor{Kind: domain.ActorSystem}, map[string]any{"triggerId": t.ID}, now))
			continue
		}
		run, err := h.startCaseRun(c, t.WorkflowID, t.CreatedBy, t.ID, eventType, alert)
		if err != nil {
			_ = h.repo.AppendCaseEvents(c.ID, caseEvent(domain.CaseEventUpdated, fmt.Sprintf("触发器「%s」启动失败：%v", t.Name, err), domain.Actor{Kind: domain.ActorSystem}, map[string]any{"triggerId": t.ID}, now))
			continue
		}
		_ = h.repo.AppendCaseEvents(c.ID, caseEvent(domain.CaseEventRunStarted, fmt.Sprintf("触发器「%s」启动了运行 %s", t.Name, run.ID), domain.Actor{Kind: domain.ActorSystem}, map[string]any{"triggerId": t.ID, "runId": run.ID, "workflowId": t.WorkflowID}, now))
	}
}

// caseTriggerPayload is what a case-started playbook sees as `trigger`.
func (h *casesHandlers) caseTriggerPayload(c domain.Case, eventType string, alert *domain.Alert) ([]byte, error) {
	alerts, err := h.repo.Alerts(repo.AlertFilter{CaseID: c.ID, Limit: maxAlertsInTrigger})
	if err != nil {
		return nil, err
	}
	iocs, err := h.repo.CaseIOCs(c.ID)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"case": c, "event": map[string]any{"type": eventType}, "alerts": alerts, "iocs": iocs}
	if alert != nil {
		payload["alert"] = alert
	}
	return json.Marshal(payload)
}

// startCaseRun starts workflowID on case c as user, linked to the case.
func (h *casesHandlers) startCaseRun(c domain.Case, workflowID string, user int64, triggerID, eventType string, alert *domain.Alert) (domain.Run, error) {
	trigger, err := h.caseTriggerPayload(c, eventType, alert)
	if err != nil {
		return domain.Run{}, err
	}
	input := fmt.Sprintf("案件 #%d：%s", c.Number, c.Title)
	return h.engine.StartWithTrigger(workflowID, input, trigger, nil, domain.TelemetryContext{
		ProjectID: c.ProjectID, ResponsibleUserID: user, CaseID: c.ID, CaseTriggerID: triggerID,
	})
}

// ---------- alerts ----------

// alerts answers GET /api/alerts?projectId=&caseId=&uncased=true.
func (h *casesHandlers) alerts(c *gin.Context) {
	projectID := strings.TrimSpace(c.Query("projectId"))
	if projectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "projectId is required"})
		return
	}
	if !h.projectReader(c, projectID) {
		return
	}
	list, err := h.repo.Alerts(repo.AlertFilter{ProjectID: projectID, CaseID: strings.TrimSpace(c.Query("caseId")), Uncased: c.Query("uncased") == "true", Limit: parsePageLimit(c.Request)})
	if err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusOK, list)
}

// alert answers GET /api/alerts/{id} with the raw payload.
func (h *casesHandlers) alert(c *gin.Context) {
	a, ok := h.repo.Alert(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}
	if !h.projectReader(c, a.ProjectID) {
		return
	}
	c.JSON(http.StatusOK, a)
}

// escalateAlert answers POST /api/alerts/{id}/escalate: open a case from an
// alert, or attach it to an existing case with {"caseId": "..."}.
func (h *casesHandlers) escalateAlert(c *gin.Context) {
	a, ok := h.repo.Alert(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}
	if !h.requireProjectWriter(c, a.ProjectID) {
		return
	}
	var req struct {
		CaseID   string `json:"caseId"`
		Title    string `json:"title"`
		Severity string `json:"severity"`
	}
	if !decode(c, &req) {
		return
	}
	if a.CaseID != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "alert already belongs to a case", "caseId": a.CaseID})
		return
	}
	actor := h.requestActor(c.Request)
	now := time.Now().UTC()
	if strings.TrimSpace(req.CaseID) != "" {
		updated, err := h.repo.UpdateCase(strings.TrimSpace(req.CaseID), func(cs *domain.Case, _ int) (repo.CaseChange, error) {
			if cs.ProjectID != a.ProjectID {
				return repo.CaseChange{}, fmt.Errorf("case belongs to another project")
			}
			cs.UpdatedAt = now
			return repo.CaseChange{Alerts: []domain.Alert{a}, IOCs: alertIOCs(a, now), Events: []domain.CaseEvent{caseEvent(domain.CaseEventAlertAdded, "并入告警："+a.Title, actor, map[string]any{"alertId": a.ID}, now)}}, nil
		})
		if err != nil {
			respondCaseError(c, err)
			return
		}
		h.fireCaseTriggers(updated, domain.CaseEventAlertAdded, &a)
		c.JSON(http.StatusOK, updated)
		return
	}
	severity := strings.TrimSpace(req.Severity)
	if severity == "" {
		severity = a.Severity
	}
	if err := domain.ValidateSeverity(severity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = a.Title
	}
	created, err := h.repo.CreateCase(domain.Case{ProjectID: a.ProjectID, Title: title, Severity: severity, Status: domain.CaseStatusNew, CreatedBy: actor.UserID, CreatedAt: now, UpdatedAt: now},
		repo.CaseChange{Alerts: []domain.Alert{a}, IOCs: alertIOCs(a, now), Events: []domain.CaseEvent{caseEvent(domain.CaseEventCreated, "由告警升级创建："+a.Title, actor, map[string]any{"alertId": a.ID}, now)}})
	if err != nil {
		respond(c, err)
		return
	}
	h.fireCaseTriggers(created, domain.CaseEventCreated, &a)
	c.JSON(http.StatusCreated, created)
}

func respondCaseError(c *gin.Context, err error) {
	if errors.Is(err, repo.ErrCaseNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

// ---------- cases ----------

// cases answers GET (list) and POST (create) /api/cases.
func (h *casesHandlers) cases(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		projectID := strings.TrimSpace(c.Query("projectId"))
		if projectID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "projectId is required"})
			return
		}
		if !h.projectReader(c, projectID) {
			return
		}
		list, err := h.repo.Cases(repo.CaseFilter{ProjectID: projectID, Status: strings.TrimSpace(c.Query("status")), Limit: parsePageLimit(c.Request)})
		if err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, list)
		return
	}
	var req struct {
		ProjectID   string   `json:"projectId"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
		Tags        []string `json:"tags"`
		AlertIDs    []string `json:"alertIds"`
	}
	if !decode(c, &req) {
		return
	}
	req.ProjectID, req.Title = strings.TrimSpace(req.ProjectID), strings.TrimSpace(req.Title)
	if req.Severity == "" {
		req.Severity = domain.SeverityMedium
	}
	if req.ProjectID == "" || req.Title == "" || len(req.Title) > 300 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "projectId and title (at most 300 characters) are required"})
		return
	}
	if err := domain.ValidateSeverity(req.Severity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.requireProjectWriter(c, req.ProjectID) {
		return
	}
	if _, ok := h.repo.Project(req.ProjectID); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project not found"})
		return
	}
	actor := h.requestActor(c.Request)
	now := time.Now().UTC()
	change := repo.CaseChange{Events: []domain.CaseEvent{caseEvent(domain.CaseEventCreated, "手动创建案件", actor, nil, now)}}
	for _, id := range req.AlertIDs {
		a, ok := h.repo.Alert(strings.TrimSpace(id))
		if !ok || a.ProjectID != req.ProjectID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "alert " + id + " not found in the project"})
			return
		}
		if a.CaseID != "" {
			c.JSON(http.StatusConflict, gin.H{"error": "alert " + id + " already belongs to a case"})
			return
		}
		change.Alerts = append(change.Alerts, a)
		change.IOCs = append(change.IOCs, alertIOCs(a, now)...)
	}
	created, err := h.repo.CreateCase(domain.Case{ProjectID: req.ProjectID, Title: req.Title, Description: strings.TrimSpace(req.Description), Severity: req.Severity, Status: domain.CaseStatusNew, Tags: trimTags(req.Tags), CreatedBy: actor.UserID, CreatedAt: now, UpdatedAt: now}, change)
	if err != nil {
		respond(c, err)
		return
	}
	h.fireCaseTriggers(created, domain.CaseEventCreated, nil)
	c.JSON(http.StatusCreated, created)
}

func trimTags(tags []string) []string {
	out := []string{}
	for _, t := range tags {
		if t = strings.TrimSpace(t); t != "" && len(out) < 20 {
			out = append(out, t)
		}
	}
	return out
}

// caseDetail is GET /api/cases/{id}.
type caseDetail struct {
	Case   domain.Case        `json:"case"`
	Alerts []domain.Alert     `json:"alerts"`
	IOCs   []domain.CaseIOC   `json:"iocs"`
	Events []domain.CaseEvent `json:"events"`
	Runs   []repo.CaseRunRef  `json:"runs"`
}

func (h *casesHandlers) loadCase(c *gin.Context, write bool) (domain.Case, bool) {
	cs, ok := h.repo.Case(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return domain.Case{}, false
	}
	if write {
		return cs, h.requireProjectWriter(c, cs.ProjectID)
	}
	return cs, h.projectReader(c, cs.ProjectID)
}

// caseUpdate is the PUT /api/cases/{id} body; absent fields stay unchanged.
type caseUpdate struct {
	Title       *string   `json:"title"`
	Description *string   `json:"description"`
	Severity    *string   `json:"severity"`
	Status      *string   `json:"status"`
	Resolution  *string   `json:"resolution"`
	AssigneeID  *int64    `json:"assigneeId"`
	Tags        *[]string `json:"tags"`
}

// caseByID answers GET and PUT /api/cases/{id}.
func (h *casesHandlers) caseByID(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		cs, ok := h.loadCase(c, false)
		if !ok {
			return
		}
		detail := caseDetail{Case: cs}
		var err error
		if detail.Alerts, err = h.repo.Alerts(repo.AlertFilter{CaseID: cs.ID, Limit: 500}); err == nil {
			if detail.IOCs, err = h.repo.CaseIOCs(cs.ID); err == nil {
				if detail.Events, err = h.repo.CaseEvents(cs.ID, 0); err == nil {
					detail.Runs, err = h.repo.CaseRuns(cs.ID)
				}
			}
		}
		if err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, detail)
		return
	}
	current, ok := h.loadCase(c, true)
	if !ok {
		return
	}
	var req caseUpdate
	if !decode(c, &req) {
		return
	}
	updated, err := h.applyCaseUpdate(current.ID, req, h.requestActor(c.Request), nil)
	if err != nil {
		respondCaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, updated)
}

// applyCaseUpdate changes a case, records each change on its timeline with
// actor (and extra event data, when set) and fires the matching case
// triggers. The UI, the API and playbook actions all go through it.
func (h *casesHandlers) applyCaseUpdate(caseID string, req caseUpdate, actor domain.Actor, extra map[string]any) (domain.Case, error) {
	now := time.Now().UTC()
	var fired []string
	data := func(d map[string]any) any {
		if len(extra) == 0 {
			if d == nil {
				return nil
			}
			return d
		}
		merged := map[string]any{}
		for k, v := range extra {
			merged[k] = v
		}
		for k, v := range d {
			merged[k] = v
		}
		return merged
	}
	updated, err := h.repo.UpdateCase(caseID, func(cs *domain.Case, _ int) (repo.CaseChange, error) {
		var events []domain.CaseEvent
		before := *cs
		if req.Title != nil {
			if t := strings.TrimSpace(*req.Title); t == "" || len(t) > 300 {
				return repo.CaseChange{}, fmt.Errorf("title must be 1 to 300 characters")
			} else if t != cs.Title {
				cs.Title = t
				events = append(events, caseEvent(domain.CaseEventUpdated, "标题改为："+t, actor, data(nil), now))
			}
		}
		if req.Description != nil && strings.TrimSpace(*req.Description) != cs.Description {
			cs.Description = strings.TrimSpace(*req.Description)
			events = append(events, caseEvent(domain.CaseEventUpdated, "更新了描述", actor, data(nil), now))
		}
		if req.Tags != nil {
			cs.Tags = trimTags(*req.Tags)
		}
		if req.Severity != nil && *req.Severity != cs.Severity {
			if err := domain.ValidateSeverity(*req.Severity); err != nil {
				return repo.CaseChange{}, err
			}
			cs.Severity = *req.Severity
			events = append(events, caseEvent(domain.CaseEventSeverityChanged, fmt.Sprintf("严重度 %s → %s", before.Severity, cs.Severity), actor, data(map[string]any{"from": before.Severity, "to": cs.Severity}), now))
			fired = append(fired, domain.CaseEventSeverityChanged)
			if domain.SeverityRank(cs.Severity) > domain.SeverityRank(before.Severity) && domain.SeverityRank(cs.Severity) >= domain.SeverityRank(domain.SeverityHigh) {
				events = append(events, caseEvent(domain.CaseEventEscalated, "案件升级为 "+cs.Severity, actor, data(nil), now))
				fired = append(fired, domain.CaseEventEscalated)
			}
		}
		if req.Status != nil || req.Resolution != nil {
			status, resolution := cs.Status, cs.Resolution
			if req.Status != nil {
				status = *req.Status
				if status != domain.CaseStatusClosed {
					resolution = ""
				}
			}
			if req.Resolution != nil {
				resolution = *req.Resolution
			}
			if err := domain.ValidateCaseStatus(status, resolution); err != nil {
				return repo.CaseChange{}, err
			}
			if status != cs.Status || resolution != cs.Resolution {
				cs.Status, cs.Resolution = status, resolution
				if status == domain.CaseStatusClosed {
					cs.ClosedAt = &now
				} else {
					cs.ClosedAt = nil
				}
				events = append(events, caseEvent(domain.CaseEventStatusChanged, fmt.Sprintf("状态 %s → %s", before.Status, statusLabel(status, resolution)), actor, data(map[string]any{"from": before.Status, "to": status, "resolution": resolution}), now))
				fired = append(fired, domain.CaseEventStatusChanged)
			}
		}
		if req.AssigneeID != nil && *req.AssigneeID != cs.AssigneeID {
			cs.AssigneeID = *req.AssigneeID
			events = append(events, caseEvent(domain.CaseEventAssigned, fmt.Sprintf("负责人改为用户 #%d", cs.AssigneeID), actor, data(map[string]any{"assigneeId": cs.AssigneeID}), now))
		}
		cs.UpdatedAt = now
		return repo.CaseChange{Events: events}, nil
	})
	if err != nil {
		return domain.Case{}, err
	}
	for _, kind := range fired {
		h.fireCaseTriggers(updated, kind, nil)
	}
	return updated, nil
}

func statusLabel(status, resolution string) string {
	if resolution != "" {
		return status + "（" + resolution + "）"
	}
	return status
}

// comment answers POST /api/cases/{id}/comments.
func (h *casesHandlers) comment(c *gin.Context) {
	cs, ok := h.loadCase(c, true)
	if !ok {
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if !decode(c, &req) {
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" || len(body) > 10000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "comment must be 1 to 10000 characters"})
		return
	}
	e := caseEvent(domain.CaseEventComment, body, h.requestActor(c.Request), nil, time.Now().UTC())
	if err := h.repo.AppendCaseEvents(cs.ID, e); err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusCreated, e)
}

// addIOC answers POST /api/cases/{id}/iocs.
func (h *casesHandlers) addIOC(c *gin.Context) {
	cs, ok := h.loadCase(c, true)
	if !ok {
		return
	}
	var req struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if !decode(c, &req) {
		return
	}
	req.Type, req.Value = strings.TrimSpace(req.Type), strings.TrimSpace(req.Value)
	valid := false
	for _, t := range domain.IOCTypes {
		valid = valid || t == req.Type
	}
	if !valid || req.Value == "" || len(req.Value) > 2000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be one of " + strings.Join(domain.IOCTypes, ", ") + " and value is required"})
		return
	}
	now := time.Now().UTC()
	actor := h.requestActor(c.Request)
	if _, err := h.repo.UpdateCase(cs.ID, func(x *domain.Case, _ int) (repo.CaseChange, error) {
		x.UpdatedAt = now
		return repo.CaseChange{IOCs: []domain.CaseIOC{{Type: req.Type, Value: req.Value, FirstSeen: now}}, Events: []domain.CaseEvent{caseEvent(domain.CaseEventIOCAdded, fmt.Sprintf("添加 IOC %s：%s", req.Type, req.Value), actor, nil, now)}}, nil
	}); err != nil {
		respondCaseError(c, err)
		return
	}
	c.JSON(http.StatusCreated, domain.CaseIOC{CaseID: cs.ID, Type: req.Type, Value: req.Value, FirstSeen: now})
}

// runPlaybook answers POST /api/cases/{id}/runs: start an SOP on the case
// by hand, as the requesting user.
func (h *casesHandlers) runPlaybook(c *gin.Context) {
	cs, ok := h.loadCase(c, true)
	if !ok {
		return
	}
	var req struct {
		WorkflowID string `json:"workflowId"`
	}
	if !decode(c, &req) {
		return
	}
	wf, found := h.repo.Workflow(strings.TrimSpace(req.WorkflowID))
	if !found || (!wf.Shared && !wf.Generic && wf.ProjectID != cs.ProjectID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workflow not found in the case's project"})
		return
	}
	actor := h.requestActor(c.Request)
	if !actor.Named() {
		c.JSON(http.StatusForbidden, gin.H{"error": "starting a playbook needs a signed-in user; it runs as that user"})
		return
	}
	run, err := h.startCaseRun(cs, wf.ID, actor.UserID, "", "manual", nil)
	if err != nil {
		respond(c, err)
		return
	}
	_ = h.repo.AppendCaseEvents(cs.ID, caseEvent(domain.CaseEventRunStarted, fmt.Sprintf("手动启动「%s」：%s", wf.Name, run.ID), actor, map[string]any{"runId": run.ID, "workflowId": wf.ID}, time.Now().UTC()))
	c.JSON(http.StatusCreated, gin.H{"runId": run.ID})
}

// ---------- triggers API ----------

// caseTriggers answers GET and POST /api/case-triggers.
func (h *casesHandlers) caseTriggers(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		projectID := strings.TrimSpace(c.Query("projectId"))
		if projectID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "projectId is required"})
			return
		}
		if !h.projectReader(c, projectID) {
			return
		}
		list, err := h.repo.CaseTriggers(projectID)
		if err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, list)
		return
	}
	var t domain.CaseTrigger
	if !decode(c, &t) {
		return
	}
	if err := t.Normalize(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.requireProjectWriter(c, t.ProjectID) || !h.checkTriggerWorkflow(c, t) {
		return
	}
	actor := h.requestActor(c.Request)
	if !actor.Named() {
		c.JSON(http.StatusForbidden, gin.H{"error": "creating a trigger needs a signed-in user; its runs execute as that user"})
		return
	}
	now := time.Now().UTC()
	t.ID, t.CreatedBy, t.CreatedAt, t.UpdatedAt = fmt.Sprintf("ctr-%d", now.UnixNano()), actor.UserID, now, now
	if err := h.repo.PutCaseTrigger(t); err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusCreated, t)
}

func (h *casesHandlers) checkTriggerWorkflow(c *gin.Context, t domain.CaseTrigger) bool {
	wf, ok := h.repo.Workflow(t.WorkflowID)
	if !ok || (!wf.Shared && !wf.Generic && wf.ProjectID != t.ProjectID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workflow not found in the project"})
		return false
	}
	return true
}

// caseTrigger answers PUT and DELETE /api/case-triggers/{id}.
func (h *casesHandlers) caseTrigger(c *gin.Context) {
	current, ok := h.repo.CaseTrigger(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "trigger not found"})
		return
	}
	if !h.requireProjectWriter(c, current.ProjectID) {
		return
	}
	if c.Request.Method == http.MethodDelete {
		if err := h.repo.DeleteCaseTrigger(current.ID); err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
		return
	}
	var next domain.CaseTrigger
	if !decode(c, &next) {
		return
	}
	next.ID, next.ProjectID, next.CreatedBy, next.CreatedAt = current.ID, current.ProjectID, current.CreatedBy, current.CreatedAt
	if err := next.Normalize(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.checkTriggerWorkflow(c, next) {
		return
	}
	next.UpdatedAt = time.Now().UTC()
	if err := h.repo.PutCaseTrigger(next); err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusOK, next)
}
