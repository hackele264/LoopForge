package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/engine"

	"github.com/gin-gonic/gin"
)

// webhooksHandlers owns inbound webhooks: management under /api/webhooks and
// the unauthenticated ingress under /api/hooks/{id}/{secret}, which checks
// its own URL secret, method, source address and optional HMAC signature.
type webhooksHandlers struct {
	*deps
	cases *casesHandlers
}

const webhookIngressPrefix = "/api/hooks/"

// webhookMaxBody bounds an inbound alert; it matches the trigger payload cap.
const webhookMaxBody = engine.MaxTriggerPayloadBytes

func newWebhookSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newWebhookID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "wh-" + hex.EncodeToString(raw), nil
}

func webhookIngressPath(id, secret string) string {
	return webhookIngressPrefix + id + "/" + secret
}

// redactWebhookPath hides the secret segment of an ingress URL in logs.
func redactWebhookPath(path string) string {
	if !strings.HasPrefix(path, webhookIngressPrefix) {
		return path
	}
	rest := path[len(webhookIngressPrefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return webhookIngressPrefix + rest[:i] + "/[redacted]"
	}
	return path
}

// webhookView is the API shape: never the secret hash or signing secret.
func webhookView(w domain.Webhook) domain.Webhook {
	w.HasSigningSecret = w.SigningSecret != ""
	w.SigningSecret = ""
	w.SecretHash = ""
	return w
}

type webhookCreated struct {
	Webhook domain.Webhook `json:"webhook"`
	// Secret and Path are returned only when created or rotated.
	Secret string `json:"secret"`
	Path   string `json:"path"`
}

// checkWebhookWorkflow requires the workflow to exist and be runnable from
// the webhook's project.
func (h *webhooksHandlers) checkWebhookWorkflow(c *gin.Context, w domain.Webhook) bool {
	if _, ok := h.repo.Project(w.ProjectID); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project not found"})
		return false
	}
	wf, ok := h.repo.Workflow(w.WorkflowID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workflow not found"})
		return false
	}
	if !wf.Shared && !wf.Generic && wf.ProjectID != w.ProjectID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workflow does not belong to the project"})
		return false
	}
	return true
}

// webhooks answers GET (list) and POST (create) /api/webhooks.
func (h *webhooksHandlers) webhooks(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		projectID := strings.TrimSpace(c.Query("projectId"))
		if projectID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "projectId is required"})
			return
		}
		if !h.requireProjectWriter(c, projectID) {
			return
		}
		list, err := h.repo.WebhooksByProject(projectID, strings.TrimSpace(c.Query("workflowId")))
		if err != nil {
			respond(c, err)
			return
		}
		out := make([]domain.Webhook, 0, len(list))
		for _, w := range list {
			out = append(out, webhookView(w))
		}
		c.JSON(http.StatusOK, out)
		return
	}
	var w domain.Webhook
	if !decode(c, &w) {
		return
	}
	w.Normalize()
	w.HasSigningSecret = false
	if err := w.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.requireProjectWriter(c, w.ProjectID) || !h.checkWebhookWorkflow(c, w) {
		return
	}
	user, ok := h.requestUser(c.Request, true)
	if !ok || user.ID <= 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "creating a webhook needs a signed-in user; its runs execute as that user"})
		return
	}
	id, err := newWebhookID()
	if err != nil {
		respond(c, err)
		return
	}
	secret, err := newWebhookSecret()
	if err != nil {
		respond(c, err)
		return
	}
	now := time.Now().UTC()
	w.ID, w.CreatedBy, w.CreatedAt, w.UpdatedAt = id, user.ID, now, now
	w.SecretHash, w.SecretPrefix = domain.HashWebhookSecret(secret), secret[:6]
	w.LastTriggeredAt = nil
	if err := h.repo.PutWebhook(w); err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusCreated, webhookCreated{Webhook: webhookView(w), Secret: secret, Path: webhookIngressPath(w.ID, secret)})
}

// loadManagedWebhook loads :id and checks the caller may manage its project.
func (h *webhooksHandlers) loadManagedWebhook(c *gin.Context) (domain.Webhook, bool) {
	w, ok := h.repo.Webhook(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook not found"})
		return domain.Webhook{}, false
	}
	if !h.requireProjectWriter(c, w.ProjectID) {
		return domain.Webhook{}, false
	}
	return w, true
}

// webhook answers GET, PUT and DELETE /api/webhooks/{id}.
func (h *webhooksHandlers) webhook(c *gin.Context) {
	current, ok := h.loadManagedWebhook(c)
	if !ok {
		return
	}
	switch c.Request.Method {
	case http.MethodGet:
		c.JSON(http.StatusOK, webhookView(current))
	case http.MethodDelete:
		if err := h.repo.DeleteWebhook(current.ID); err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	default:
		var next domain.Webhook
		if !decode(c, &next) {
			return
		}
		next.Normalize()
		// Identity, secret material and authorship are not editable here.
		next.ID, next.ProjectID, next.CreatedBy, next.CreatedAt = current.ID, current.ProjectID, current.CreatedBy, current.CreatedAt
		next.SecretHash, next.SecretPrefix, next.LastTriggeredAt = current.SecretHash, current.SecretPrefix, current.LastTriggeredAt
		switch {
		case next.SignatureHeader == "":
			next.SigningSecret, next.HasSigningSecret = "", false
		case strings.TrimSpace(next.SigningSecret) == "":
			next.SigningSecret = current.SigningSecret
			next.HasSigningSecret = current.SigningSecret != ""
		default:
			next.HasSigningSecret = true
		}
		if err := next.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !h.checkWebhookWorkflow(c, next) {
			return
		}
		next.UpdatedAt = time.Now().UTC()
		if err := h.repo.PutWebhook(next); err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, webhookView(next))
	}
}

// rotateSecret answers POST /api/webhooks/{id}/rotate; the old URL stops
// working at once.
func (h *webhooksHandlers) rotateSecret(c *gin.Context) {
	w, ok := h.loadManagedWebhook(c)
	if !ok {
		return
	}
	secret, err := newWebhookSecret()
	if err != nil {
		respond(c, err)
		return
	}
	w.SecretHash, w.SecretPrefix, w.UpdatedAt = domain.HashWebhookSecret(secret), secret[:6], time.Now().UTC()
	if err := h.repo.PutWebhook(w); err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusOK, webhookCreated{Webhook: webhookView(w), Secret: secret, Path: webhookIngressPath(w.ID, secret)})
}

// deliveries answers GET /api/webhooks/{id}/deliveries.
func (h *webhooksHandlers) deliveries(c *gin.Context) {
	w, ok := h.loadManagedWebhook(c)
	if !ok {
		return
	}
	list, err := h.repo.WebhookDeliveries(w.ID, 50)
	if err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusOK, list)
}

// webhookClientIP is the caller address checked against the allowlist. The
// first X-Forwarded-For hop is trusted only from a loopback proxy and only
// when AGENTFLOW_WEBHOOK_TRUST_FORWARDED is enabled.
func webhookClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if trustForwarded() && ip != nil && ip.IsLoopback() {
		if first := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); first != "" {
			if forwarded := net.ParseIP(first); forwarded != nil {
				return forwarded
			}
		}
	}
	return ip
}

func trustForwarded() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENTFLOW_WEBHOOK_TRUST_FORWARDED"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// validWebhookSignature checks an HMAC-SHA256 of body, sent as hex with an
// optional "sha256=" prefix.
func validWebhookSignature(secret string, body []byte, header string) bool {
	header = strings.TrimSpace(header)
	header = strings.TrimPrefix(header, "sha256=")
	got, err := hex.DecodeString(header)
	if err != nil || len(got) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// webhookPayload turns the request into the run's trigger object: query
// parameters for GET, otherwise the JSON body; a body that is not an object
// is wrapped as {"body": value}.
func webhookPayload(r *http.Request, body []byte) (map[string]any, error) {
	if r.Method == http.MethodGet {
		out := map[string]any{}
		for key, values := range r.URL.Query() {
			if len(values) == 1 {
				out[key] = values[0]
			} else {
				list := make([]any, len(values))
				for i, v := range values {
					list[i] = v
				}
				out[key] = list
			}
		}
		return out, nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return map[string]any{}, nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("body must be JSON")
	}
	if object, ok := value.(map[string]any); ok {
		return object, nil
	}
	return map[string]any{"body": value}, nil
}

// ingest answers /api/hooks/{id}/{secret}. Unknown hooks and wrong secrets
// get the same 401 so the endpoint does not reveal which IDs exist.
func (h *webhooksHandlers) ingest(c *gin.Context) {
	now := time.Now().UTC()
	w, ok := h.repo.Webhook(c.Param("id"))
	if !ok || subtle.ConstantTimeCompare([]byte(w.SecretHash), []byte(domain.HashWebhookSecret(c.Param("secret")))) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized webhook request"})
		return
	}
	ip := webhookClientIP(c.Request)
	delivery := domain.WebhookDelivery{WebhookID: w.ID, ReceivedAt: now}
	if ip != nil {
		delivery.SourceIP = ip.String()
	}
	reject := func(status int, message string) {
		delivery.Status, delivery.HTTPStatus, delivery.Message = domain.WebhookDeliveryRejected, status, message
		h.recordDelivery(delivery)
		c.JSON(status, gin.H{"error": message})
	}
	if !w.Enabled {
		reject(http.StatusConflict, "webhook is disabled")
		return
	}
	if !w.AllowsMethod(c.Request.Method) {
		reject(http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !w.AllowsIP(ip) {
		reject(http.StatusForbidden, "source address not allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, webhookMaxBody+1))
	if err != nil {
		reject(http.StatusBadRequest, "cannot read body")
		return
	}
	if len(body) > webhookMaxBody {
		reject(http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d bytes", webhookMaxBody))
		return
	}
	if w.SignatureHeader != "" && !validWebhookSignature(w.SigningSecret, body, c.GetHeader(w.SignatureHeader)) {
		reject(http.StatusUnauthorized, "invalid signature")
		return
	}
	payload, err := webhookPayload(c.Request, body)
	if err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	trigger, err := json.Marshal(payload)
	if err != nil {
		reject(http.StatusBadRequest, "payload cannot be encoded")
		return
	}
	// Decode once more without UseNumber so fingerprints and titles see the
	// same float64 values RunIf expressions do.
	var plain any
	_ = json.Unmarshal(trigger, &plain)

	fingerprint := domain.WebhookFingerprint(plain, w.DedupFields)
	delivery.Fingerprint = fingerprint
	alert := domain.Alert{
		ID: newAlertID(now), ProjectID: w.ProjectID, WebhookID: w.ID, Source: w.Name,
		Title: domain.WebhookTitle(w, plain), Severity: domain.WebhookSeverity(w, plain),
		Fingerprint: fingerprint, Payload: domain.RawJSON(trigger), ReceivedAt: now,
	}
	delivery.AlertID = alert.ID
	if fingerprint != "" {
		claim, err := h.repo.ClaimWebhookFingerprint(w.ID, fingerprint, time.Duration(w.DedupWindowSeconds)*time.Second, now)
		if err != nil {
			delivery.Status, delivery.HTTPStatus, delivery.Message = domain.WebhookDeliveryFailed, http.StatusInternalServerError, err.Error()
			h.recordDelivery(delivery)
			respond(c, err)
			return
		}
		if !claim.Claimed {
			outcome, err := h.cases.recordAlert(w, alert, &claim)
			if err != nil {
				log.Printf("webhook %s: record duplicate alert: %v", w.ID, err)
			}
			caseID := ""
			if outcome.Case != nil {
				caseID = outcome.Case.ID
			}
			delivery.Status, delivery.HTTPStatus, delivery.RunID, delivery.CaseID = domain.WebhookDeliveryDeduplicated, http.StatusOK, claim.RunID, caseID
			delivery.Message = fmt.Sprintf("duplicate alert #%d within the dedup window", claim.Hits)
			h.recordDelivery(delivery)
			if claim.RunID != "" {
				h.engine.AppendRunEvent(claim.RunID, "webhook.duplicate", fmt.Sprintf("Webhook「%s」收到重复告警（第 %d 次），未启动新运行", w.Name, claim.Hits))
			}
			c.JSON(http.StatusOK, gin.H{"status": domain.WebhookDeliveryDeduplicated, "runId": claim.RunID, "hits": claim.Hits, "alertId": alert.ID, "caseId": caseID})
			return
		}
	}
	outcome, err := h.cases.recordAlert(w, alert, nil)
	if err != nil {
		if fingerprint != "" {
			_ = h.repo.ReleaseWebhookFingerprint(w.ID, fingerprint)
		}
		delivery.Status, delivery.HTTPStatus, delivery.Message = domain.WebhookDeliveryFailed, http.StatusInternalServerError, "store alert: "+err.Error()
		h.recordDelivery(delivery)
		respond(c, err)
		return
	}
	caseID := ""
	if outcome.Case != nil {
		caseID = outcome.Case.ID
		delivery.CaseID = caseID
		if fingerprint != "" {
			// Keep the fingerprint on the case even if the run fails below, so
			// later duplicates join this case instead of opening another.
			_ = h.repo.SetWebhookFingerprintCase(w.ID, fingerprint, caseID)
		}
	}
	run, err := h.startWebhookRun(w, alert.Title, trigger, caseID)
	if err != nil {
		if fingerprint != "" && caseID == "" {
			_ = h.repo.ReleaseWebhookFingerprint(w.ID, fingerprint)
		}
		if outcome.Case != nil {
			_ = h.repo.AppendCaseEvents(caseID, caseEvent(domain.CaseEventUpdated, fmt.Sprintf("Webhook「%s」的处置流程未能启动：%v", w.Name, err), domain.Actor{Kind: domain.ActorSystem}, nil, time.Now().UTC()))
		}
		delivery.Status, delivery.HTTPStatus, delivery.Message = domain.WebhookDeliveryFailed, http.StatusServiceUnavailable, err.Error()
		h.recordDelivery(delivery)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "run could not start: " + err.Error(), "alertId": alert.ID, "caseId": caseID})
		return
	}
	if fingerprint != "" {
		_ = h.repo.SetWebhookFingerprintRun(w.ID, fingerprint, run.ID)
	}
	if err := h.repo.SetAlertRun(alert.ID, run.ID); err != nil {
		log.Printf("webhook %s: link alert %s to run: %v", w.ID, alert.ID, err)
	}
	h.engine.AppendRunEvent(run.ID, "webhook.received", fmt.Sprintf("由 Webhook「%s」触发", w.Name))
	if outcome.Case != nil {
		_ = h.repo.AppendCaseEvents(caseID, caseEvent(domain.CaseEventRunStarted, fmt.Sprintf("Webhook「%s」启动了运行 %s", w.Name, run.ID), domain.Actor{Kind: domain.ActorSystem}, map[string]any{"runId": run.ID, "workflowId": w.WorkflowID}, time.Now().UTC()))
		alert.RunID, alert.CaseID = run.ID, caseID
		h.cases.fireCaseTriggers(*outcome.Case, domain.CaseEventCreated, &alert)
	}
	delivery.Status, delivery.HTTPStatus, delivery.RunID = domain.WebhookDeliveryStarted, http.StatusAccepted, run.ID
	h.recordDelivery(delivery)
	c.JSON(http.StatusAccepted, gin.H{"status": domain.WebhookDeliveryStarted, "runId": run.ID, "alertId": alert.ID, "caseId": caseID})
}

func newAlertID(now time.Time) string {
	raw := make([]byte, 6)
	_, _ = rand.Read(raw)
	return fmt.Sprintf("alert-%d-%s", now.UnixNano(), hex.EncodeToString(raw))
}

// recordDelivery logs a delivery; a logging failure never changes the
// response the caller already decided on, but it must not vanish silently.
func (h *webhooksHandlers) recordDelivery(d domain.WebhookDelivery) {
	if err := h.repo.RecordWebhookDelivery(d); err != nil {
		log.Printf("webhook %s: record delivery: %v", d.WebhookID, err)
	}
}

// startWebhookRun starts the webhook's SOP as its creator, binding the
// project's default repository for generic workflows like a manual run does.
func (h *webhooksHandlers) startWebhookRun(w domain.Webhook, input string, trigger []byte, caseID string) (domain.Run, error) {
	project, ok := h.repo.Project(w.ProjectID)
	if !ok {
		return domain.Run{}, errors.New("project no longer exists")
	}
	var repositories []domain.RepositoryContext
	if wf, ok := h.repo.Workflow(w.WorkflowID); ok && wf.Generic && strings.TrimSpace(project.DefaultRepositoryID) != "" {
		repoDef, found := h.repo.Repository(strings.TrimSpace(project.DefaultRepositoryID))
		if !found || repoDef.ProjectID != w.ProjectID {
			return domain.Run{}, errors.New("project default repository is invalid")
		}
		repositories = []domain.RepositoryContext{repositoryRunContext(repoDef)}
	}
	return h.engine.StartWithTrigger(w.WorkflowID, input, trigger, repositories, domain.TelemetryContext{ProjectID: w.ProjectID, ResponsibleUserID: w.CreatedBy, CaseID: caseID})
}
