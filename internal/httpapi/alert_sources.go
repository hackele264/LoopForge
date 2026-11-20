package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"

	"github.com/gin-gonic/gin"
)

// alertSourcesHandlers owns pull alert sources: management under
// /api/alert-sources and the poller that calls each source's connector
// action on its schedule and admits what it returns through the source's
// webhook.
type alertSourcesHandlers struct {
	*deps
	webhooks *webhooksHandlers
	// executor runs the read-only list actions; it has no case service.
	executor *connector.Executor
	owner    string
	wake     chan struct{}

	purgeMu   sync.Mutex
	lastPurge time.Time
}

const (
	// alertSourceTick is how often the poller looks for due sources.
	alertSourceTick = 5 * time.Second
	// alertSourceLease bounds one pass; a poller that dies mid-pass frees
	// the source after this long.
	alertSourceLease = 10 * time.Minute
	// alertSourceParallel caps passes running at once in one process.
	alertSourceParallel = 4
	// alertSourceSeenKeep is how long admitted alert IDs are remembered.
	alertSourceSeenKeep = 30 * 24 * time.Hour
	// alertSourcePreviewItems is how many alerts a preview returns.
	alertSourcePreviewItems = 5
)

func newAlertSourcesHandlers(d *deps, webhooks *webhooksHandlers) *alertSourcesHandlers {
	host, _ := os.Hostname()
	raw := make([]byte, 4)
	_, _ = rand.Read(raw)
	return &alertSourcesHandlers{deps: d, webhooks: webhooks, executor: connector.NewExecutor(nil, nil),
		owner: fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(raw)), wake: make(chan struct{}, 1)}
}

func newAlertSourceID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "as-" + hex.EncodeToString(raw), nil
}

// alertSourceInput is the writable part of a source.
type alertSourceInput struct {
	ProjectID       string            `json:"projectId"`
	WebhookID       string            `json:"webhookId"`
	Name            string            `json:"name"`
	Enabled         *bool             `json:"enabled"`
	ConnectionID    string            `json:"connectionId"`
	Action          string            `json:"action"`
	Inputs          map[string]string `json:"inputs"`
	ItemsField      string            `json:"itemsField"`
	DetailAction    string            `json:"detailAction"`
	DetailInput     string            `json:"detailInput"`
	IDPath          string            `json:"idPath"`
	TimePath        string            `json:"timePath"`
	PollSeconds     int               `json:"pollSeconds"`
	LagSeconds      int               `json:"lagSeconds"`
	WindowSeconds   int               `json:"windowSeconds"`
	PageLimit       int               `json:"pageLimit"`
	LookbackSeconds int               `json:"lookbackSeconds"`
}

func (in alertSourceInput) apply(s *domain.AlertSource) {
	s.Name, s.ConnectionID, s.Action, s.Inputs = in.Name, in.ConnectionID, in.Action, in.Inputs
	s.ItemsField, s.DetailAction, s.DetailInput, s.IDPath, s.TimePath = in.ItemsField, in.DetailAction, in.DetailInput, in.IDPath, in.TimePath
	s.PollSeconds, s.LagSeconds, s.WindowSeconds, s.PageLimit, s.LookbackSeconds = in.PollSeconds, in.LagSeconds, in.WindowSeconds, in.PageLimit, in.LookbackSeconds
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	s.Normalize()
}

// sourcePlan is a source resolved against the catalog and its connection.
type sourcePlan struct {
	webhook    domain.Webhook
	connection domain.Connection
	connector  *connector.Connector
	action     *connector.Action
	detail     *connector.Action
}

// resolve checks a source against its webhook, connection and connector.
// Only read-only actions may list alerts: a source runs without approval.
func (h *alertSourcesHandlers) resolve(s domain.AlertSource) (sourcePlan, error) {
	var p sourcePlan
	if err := s.Validate(); err != nil {
		return p, err
	}
	w, ok := h.repo.Webhook(s.WebhookID)
	if !ok || w.ProjectID != s.ProjectID {
		return p, errors.New("webhook not found in the project")
	}
	conn, ok := h.repo.Connection(s.ConnectionID)
	if !ok || conn.ProjectID != s.ProjectID {
		return p, errors.New("connection not found in the project")
	}
	def, ok := connector.Default().Connector(conn.ConnectorID)
	if !ok || def.Builtin {
		return p, fmt.Errorf("connector %s is not available", conn.ConnectorID)
	}
	a, ok := def.Action(s.Action)
	if !ok {
		return p, fmt.Errorf("connector %s has no action %s", def.ID, s.Action)
	}
	if a.Category == connector.CategoryResponse {
		return p, fmt.Errorf("%s 是响应动作，不能用来拉取告警", connector.Key(def.ID, a.ID))
	}
	declared := map[string]bool{}
	for _, in := range a.Inputs {
		declared[in.Name] = true
	}
	for name := range s.Inputs {
		if !declared[name] {
			return p, fmt.Errorf("action %s has no input %q", a.ID, name)
		}
	}
	if err := connector.CheckSourceInputs(s.Inputs); err != nil {
		return p, err
	}
	p = sourcePlan{webhook: w, connection: conn, connector: def, action: a}
	if s.DetailAction != "" {
		d, ok := def.Action(s.DetailAction)
		if !ok {
			return p, fmt.Errorf("connector %s has no action %s", def.ID, s.DetailAction)
		}
		if d.Category == connector.CategoryResponse {
			return p, fmt.Errorf("%s 是响应动作，不能用来拉取告警", connector.Key(def.ID, d.ID))
		}
		found := false
		for _, in := range d.Inputs {
			found = found || (in.Name == s.DetailInput && in.Type == connector.TypeList)
		}
		if !found {
			return p, fmt.Errorf("action %s has no list input %q", d.ID, s.DetailInput)
		}
		p.detail = d
	}
	return p, nil
}

// alertSources answers GET (list) and POST (create) /api/alert-sources.
func (h *alertSourcesHandlers) alertSources(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		projectID := strings.TrimSpace(c.Query("projectId"))
		if projectID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "projectId is required"})
			return
		}
		if !h.requireProjectWriter(c, projectID) {
			return
		}
		list, err := h.repo.AlertSources(projectID, strings.TrimSpace(c.Query("webhookId")))
		if err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, list)
		return
	}
	var in alertSourceInput
	if !decode(c, &in) {
		return
	}
	s := domain.AlertSource{ProjectID: strings.TrimSpace(in.ProjectID), WebhookID: strings.TrimSpace(in.WebhookID), Enabled: true}
	in.apply(&s)
	if !h.requireProjectWriter(c, s.ProjectID) {
		return
	}
	if _, err := h.resolve(s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, ok := h.requestUser(c.Request, true)
	if !ok || user.ID <= 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "creating an alert source needs a signed-in user"})
		return
	}
	id, err := newAlertSourceID()
	if err != nil {
		respond(c, err)
		return
	}
	now := time.Now().UTC()
	s.ID, s.CreatedBy, s.CreatedAt, s.UpdatedAt = id, user.ID, now, now
	start := now.Add(-time.Duration(s.LookbackSeconds) * time.Second)
	s.State = domain.AlertSourceState{Checkpoint: &start, NextRunAt: &now}
	if err := h.repo.CreateAlertSource(s); err != nil {
		respond(c, err)
		return
	}
	h.kick()
	stored, _ := h.repo.AlertSource(s.ID)
	c.JSON(http.StatusCreated, stored)
}

func (h *alertSourcesHandlers) loadManaged(c *gin.Context) (domain.AlertSource, bool) {
	s, ok := h.repo.AlertSource(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert source not found"})
		return s, false
	}
	if !h.requireProjectWriter(c, s.ProjectID) {
		return s, false
	}
	return s, true
}

// alertSource answers GET, PUT and DELETE /api/alert-sources/{id}.
func (h *alertSourcesHandlers) alertSource(c *gin.Context) {
	current, ok := h.loadManaged(c)
	if !ok {
		return
	}
	switch c.Request.Method {
	case http.MethodGet:
		c.JSON(http.StatusOK, current)
	case http.MethodDelete:
		if err := h.repo.DeleteAlertSource(current.ID); err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	default:
		var in alertSourceInput
		if !decode(c, &in) {
			return
		}
		next := current
		in.apply(&next)
		if _, err := h.resolve(next); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		next.UpdatedAt = time.Now().UTC()
		if err := h.repo.UpdateAlertSourceConfig(next); err != nil {
			respond(c, err)
			return
		}
		if next.Enabled && !current.Enabled {
			_ = h.repo.RequestAlertSourceRun(next.ID, time.Now().UTC())
			h.kick()
		}
		stored, _ := h.repo.AlertSource(next.ID)
		c.JSON(http.StatusOK, stored)
	}
}

// runNow answers POST /api/alert-sources/{id}/run: poll at the next tick.
func (h *alertSourcesHandlers) runNow(c *gin.Context) {
	s, ok := h.loadManaged(c)
	if !ok {
		return
	}
	if !s.Enabled {
		c.JSON(http.StatusConflict, gin.H{"error": "alert source is disabled"})
		return
	}
	if err := h.repo.RequestAlertSourceRun(s.ID, time.Now().UTC()); err != nil {
		respond(c, err)
		return
	}
	h.kick()
	c.JSON(http.StatusAccepted, gin.H{"status": "queued"})
}

type alertSourcePreview struct {
	Since    time.Time        `json:"since"`
	Until    time.Time        `json:"until"`
	Fetched  int              `json:"fetched"`
	Items    []map[string]any `json:"items"`
	IDs      []string         `json:"ids"`
	Titles   []string         `json:"titles"`
	Warning  string           `json:"warning,omitempty"`
	Duration int64            `json:"durationMs"`
}

// preview answers POST /api/alert-sources/preview: fetch the most recent
// window for an unsaved configuration and show what would be admitted,
// without admitting anything.
func (h *alertSourcesHandlers) preview(c *gin.Context) {
	var in alertSourceInput
	if !decode(c, &in) {
		return
	}
	s := domain.AlertSource{ProjectID: strings.TrimSpace(in.ProjectID), WebhookID: strings.TrimSpace(in.WebhookID), Enabled: true}
	in.apply(&s)
	if !h.requireProjectWriter(c, s.ProjectID) {
		return
	}
	plan, err := h.resolve(s)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	until := time.Now().UTC().Add(-time.Duration(s.LagSeconds) * time.Second)
	since := until.Add(-time.Duration(s.WindowSeconds) * time.Second)
	started := time.Now()
	items, err := h.fetch(c.Request.Context(), s, plan, since, until)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	out := alertSourcePreview{Since: since, Until: until, Fetched: len(items), Items: []map[string]any{}, IDs: []string{}, Titles: []string{}, Duration: time.Since(started).Milliseconds()}
	for i, item := range items {
		if i >= alertSourcePreviewItems {
			break
		}
		out.Items = append(out.Items, item)
		out.IDs = append(out.IDs, alertItemID(s, item))
		out.Titles = append(out.Titles, domain.WebhookTitle(plan.webhook, plainJSON(item)))
	}
	if len(items) >= s.PageLimit {
		out.Warning = fmt.Sprintf("返回条数达到上限 %d，实际拉取时会分多轮读完", s.PageLimit)
	}
	c.JSON(http.StatusOK, out)
}

// fetch calls the list action for [since, until) and, when the source has
// a detail action, resolves the listed IDs into alerts.
func (h *alertSourcesHandlers) fetch(ctx context.Context, s domain.AlertSource, p sourcePlan, since, until time.Time) ([]map[string]any, error) {
	inputs, err := connector.EvalSourceInputs(s.Inputs, domain.AlertSourceWindowEnv(since, until, s.PageLimit))
	if err != nil {
		return nil, err
	}
	conn := p.connection
	res, err := h.executor.Execute(ctx, connector.Call{Connector: p.connector, Action: p.action, Connection: &conn, Inputs: inputs, Run: connector.RunContext{ProjectID: s.ProjectID}})
	if err != nil {
		return nil, err
	}
	listed, err := outputList(res.Output, s.ItemsField, p.action.ID)
	if err != nil {
		return nil, err
	}
	if p.detail == nil {
		return asAlertItems(listed), nil
	}
	var items []map[string]any
	for start := 0; start < len(listed); start += domain.AlertSourceDetailBatch {
		end := min(start+domain.AlertSourceDetailBatch, len(listed))
		res, err := h.executor.Execute(ctx, connector.Call{Connector: p.connector, Action: p.detail, Connection: &conn,
			Inputs: map[string]any{s.DetailInput: listed[start:end]}, Run: connector.RunContext{ProjectID: s.ProjectID}})
		if err != nil {
			return nil, err
		}
		got, err := outputList(res.Output, s.ItemsField, p.detail.ID)
		if err != nil {
			return nil, err
		}
		items = append(items, asAlertItems(got)...)
	}
	return items, nil
}

// outputList reads an action's list output; a missing field is no alerts.
func outputList(output map[string]any, field, action string) ([]any, error) {
	v, ok := output[field]
	if !ok || v == nil {
		if output["bodyTruncated"] == true {
			return nil, fmt.Errorf("动作 %s 的响应过大被截断，请调小每次条数", action)
		}
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("动作 %s 的输出 %s 不是列表", action, field)
	}
	return list, nil
}

// asAlertItems turns list entries into alert objects; a scalar becomes
// {"value": x}.
func asAlertItems(list []any) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		} else {
			out = append(out, map[string]any{"value": v})
		}
	}
	return out
}

// plainJSON round-trips an item so paths see float64 numbers, as the
// webhook path does.
func plainJSON(item map[string]any) any {
	raw, err := json.Marshal(item)
	if err != nil {
		return item
	}
	var plain any
	_ = json.Unmarshal(raw, &plain)
	return plain
}

// alertItemID identifies an alert across passes: the value at IDPath, or
// the whole alert when there is none.
func alertItemID(s domain.AlertSource, item map[string]any) string {
	if s.IDPath != "" {
		if v := domain.LookupJSONPath(plainJSON(item), s.IDPath); v != nil {
			if text, ok := v.(string); ok {
				return text
			}
			raw, _ := json.Marshal(v)
			return string(raw)
		}
	}
	raw, _ := json.Marshal(item)
	return string(raw)
}

func alertItemKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// alertItemTime reads the alert time at path: RFC 3339 text, or Unix
// seconds or milliseconds as a number or numeric text.
func alertItemTime(item map[string]any, path string) (time.Time, bool) {
	if path == "" {
		return time.Time{}, false
	}
	switch v := domain.LookupJSONPath(plainJSON(item), path).(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-07:00", "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, v); err == nil {
				return t.UTC(), true
			}
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return unixTime(f), true
		}
	case float64:
		return unixTime(v), true
	}
	return time.Time{}, false
}

func unixTime(f float64) time.Time {
	if f > 1e12 {
		return time.UnixMilli(int64(f)).UTC()
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC()
}

// kick wakes the poller.
func (h *alertSourcesHandlers) kick() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// start runs the poller until ctx ends.
func (h *alertSourcesHandlers) start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(alertSourceTick)
		defer ticker.Stop()
		slots := make(chan struct{}, alertSourceParallel)
		for {
			h.purgeSeen()
			now := time.Now().UTC()
			free := alertSourceParallel - len(slots)
			if free > 0 {
				due, err := h.repo.ClaimDueAlertSources(h.owner, now, alertSourceLease, free)
				if err != nil {
					log.Printf("[ALERT-SOURCE] claim: %v", err)
				}
				for _, s := range due {
					slots <- struct{}{}
					go func(s domain.AlertSource) {
						defer func() { <-slots }()
						h.pass(ctx, s)
					}(s)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-h.wake:
			}
		}
	}()
}

// purgeSeen forgets admitted alert IDs past retention, at most hourly.
func (h *alertSourcesHandlers) purgeSeen() {
	h.purgeMu.Lock()
	if time.Since(h.lastPurge) < time.Hour {
		h.purgeMu.Unlock()
		return
	}
	h.lastPurge = time.Now()
	h.purgeMu.Unlock()
	if n, err := h.repo.PurgeAlertSourceItems(time.Now().UTC().Add(-alertSourceSeenKeep)); err != nil {
		log.Printf("[ALERT-SOURCE] purge: %v", err)
	} else if n > 0 {
		log.Printf("[ALERT-SOURCE] forgot %d admitted alert IDs", n)
	}
}

// pass polls one leased source once and records the outcome.
func (h *alertSourcesHandlers) pass(ctx context.Context, s domain.AlertSource) {
	now := time.Now().UTC()
	state := s.State
	state.LastRunAt = &now
	poll := time.Duration(s.PollSeconds) * time.Second
	fail := func(err error) {
		state.Failures++
		state.LastError = err.Error()
		next := now.Add(domain.AlertSourceBackoff(poll, state.Failures))
		state.NextRunAt = &next
		log.Printf("[ALERT-SOURCE] %s (%s): %v", s.ID, s.Name, err)
		h.finish(s, state)
	}
	plan, err := h.resolve(s)
	if err != nil {
		fail(err)
		return
	}
	if !plan.webhook.Enabled {
		fail(errors.New("所属 Webhook 已停用，暂停拉取"))
		return
	}
	lower := s.CreatedAt
	if state.Checkpoint != nil {
		lower = *state.Checkpoint
	}
	upper := now.Add(-time.Duration(s.LagSeconds) * time.Second)
	if limit := lower.Add(time.Duration(s.WindowSeconds) * time.Second); upper.After(limit) {
		upper = limit
	}
	next := now.Add(poll)
	state.LastWarning = ""
	if !upper.After(lower) {
		state.Failures, state.LastError, state.LastFetched, state.LastAdmitted = 0, "", 0, 0
		state.LastSuccessAt, state.NextRunAt = &now, &next
		h.finish(s, state)
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, alertSourceLease-time.Minute)
	defer cancel()
	items, err := h.fetch(callCtx, s, plan, lower, upper)
	if err != nil {
		fail(err)
		return
	}
	admitted := 0
	origin := fmt.Sprintf("拉取源「%s」", s.Name)
	var failed error
	// deferred is set when the webhook's rate limit stopped the pass: the
	// rest of the window is read again once the budget refills.
	var deferred time.Duration
	for _, item := range items {
		key := alertItemKey(alertItemID(s, item))
		fresh, err := h.repo.MarkAlertSourceItem(s.ID, key, time.Now().UTC())
		if err != nil {
			failed = err
			break
		}
		if !fresh {
			continue
		}
		trigger, err := json.Marshal(item)
		if err != nil || len(trigger) > webhookMaxBody {
			log.Printf("[ALERT-SOURCE] %s: skip alert %s: payload too large or not JSON", s.ID, key[:12])
			continue
		}
		at := time.Now().UTC()
		delivery := domain.WebhookDelivery{WebhookID: plan.webhook.ID, ReceivedAt: at, SourceID: s.ID}
		res := h.webhooks.admitAlert(plan.webhook, trigger, plainJSON(item), at, &delivery, origin)
		if res.err != nil {
			// Nothing was recorded for this alert: let the next pass retry it.
			_ = h.repo.ForgetAlertSourceItem(s.ID, key)
			failed = res.err
			break
		}
		if res.rateLimited {
			// Not admitted: forget it so the next pass, which rereads this
			// window, admits it then.
			_ = h.repo.ForgetAlertSourceItem(s.ID, key)
			deferred = res.retryAfter
			break
		}
		admitted++
	}
	state.LastFetched, state.LastAdmitted = len(items), admitted
	state.TotalAdmitted += int64(admitted)
	if failed != nil {
		fail(fmt.Errorf("告警入库失败：%w", failed))
		return
	}
	if deferred > 0 {
		// Keep the checkpoint: the next pass reads the same window again,
		// skipping alerts already admitted by their IDs. This is not a
		// failure, so the backoff does not grow.
		if deferred < time.Second {
			deferred = time.Second
		}
		retryAt := time.Now().UTC().Add(deferred)
		state.LastWarning = fmt.Sprintf("Webhook 限流：本轮入库 %d 条后达到每分钟 %d 条的上限，其余告警约 %d 秒后重新拉取", admitted, plan.webhook.RateLimitPerMinute, retryAfterSeconds(deferred))
		state.Failures, state.LastError = 0, ""
		state.LastSuccessAt, state.NextRunAt = &now, &retryAt
		h.finish(s, state)
		return
	}
	checkpoint := upper
	if len(items) >= s.PageLimit {
		if latest, ok := latestItemTime(items, s.TimePath); ok && latest.After(lower) && latest.Before(upper) {
			// Read the rest of the window next: alerts at latest already
			// admitted are skipped by their IDs.
			checkpoint = latest
		} else {
			state.LastWarning = fmt.Sprintf("本轮返回 %d 条，达到上限，窗口内可能还有告警没拉到；请设置时间字段或调小窗口", len(items))
		}
	}
	state.Checkpoint = &checkpoint
	if now.Sub(checkpoint) > time.Duration(s.LagSeconds)*time.Second+poll {
		// Behind (a long outage or a full page): catch up without waiting.
		next = now
	}
	state.Failures, state.LastError = 0, ""
	state.LastSuccessAt, state.NextRunAt = &now, &next
	h.finish(s, state)
}

func latestItemTime(items []map[string]any, path string) (time.Time, bool) {
	var latest time.Time
	found := false
	for _, item := range items {
		if t, ok := alertItemTime(item, path); ok && t.After(latest) {
			latest, found = t, true
		}
	}
	return latest, found
}

func (h *alertSourcesHandlers) finish(s domain.AlertSource, state domain.AlertSourceState) {
	held, err := h.repo.FinishAlertSourcePass(s.ID, h.owner, state)
	if err != nil {
		log.Printf("[ALERT-SOURCE] %s: save state: %v", s.ID, err)
	} else if !held && !errors.Is(err, repo.ErrAlertSourceNotFound) {
		log.Printf("[ALERT-SOURCE] %s: lease lost before the pass finished; state not saved", s.ID)
	}
}
