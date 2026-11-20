package httpapi

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/repo"

	"github.com/gin-gonic/gin"
)

// auditHandlers records the platform audit log and serves it to platform
// administrators.
type auditHandlers struct {
	*deps
	purgeMu   sync.Mutex
	lastPurge time.Time
}

// Context keys handlers use to add facts the middleware cannot see.
const (
	auditLoginKey  = "audit.login"
	auditDetailKey = "audit.detail"
)

// authAuditActions names sign-in and token endpoints; their requests are
// recorded whatever the method.
var authAuditActions = map[string]string{
	"POST /api/auth/password":         "auth.login",
	"POST /api/auth/local":            "auth.login.local",
	"POST /api/auth/exchange":         "auth.login.exchange",
	"GET /api/auth/gongfeng/callback": "auth.login.oauth",
	"POST /api/auth/register":         "auth.register",
	"POST /api/auth/setup":            "auth.setup",
	"POST /api/auth/logout":           "auth.logout",
	"POST /api/auth/tokens":           "auth.token.create",
	"DELETE /api/auth/tokens/:id":     "auth.token.revoke",
}

// auditSkipped are paths with their own logs or credentials: webhook
// ingress (delivery log), runner agents, insight ingestion, health.
func auditSkipped(path string) bool {
	return strings.HasPrefix(path, webhookIngressPrefix) || isRunnerAgentPath(path) || path == insightIngestPath || path == "/api/health"
}

// middleware records every API write, every denied API request and every
// sign-in, after the handler ran. It never reads request bodies.
func (h *auditHandlers) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		path := c.Request.URL.Path
		if !strings.HasPrefix(path, "/api/") || auditSkipped(path) {
			return
		}
		route := c.FullPath()
		status := c.Writer.Status()
		action, isAuth := authAuditActions[c.Request.Method+" "+route]
		write := c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions
		denied := status == http.StatusUnauthorized || status == http.StatusForbidden
		auditRead := strings.HasPrefix(path, "/api/audit")
		if !isAuth && !write && !denied && !auditRead {
			return
		}
		if !isAuth {
			if route == "" {
				route = path
			}
			action = "api " + c.Request.Method + " " + route
		}
		e := domain.AuditEvent{Action: action, Method: c.Request.Method, Path: route, Target: path, Status: status, Outcome: domain.AuditOutcome(status), ProjectID: strings.TrimSpace(c.Query("projectId"))}
		if v, ok := c.Get(auditLoginKey); ok {
			e.ActorLogin, _ = v.(string)
		}
		if v, ok := c.Get(auditDetailKey); ok {
			if raw, err := json.Marshal(v); err == nil {
				e.Detail = domain.RawJSON(raw)
			}
		}
		h.record(c.Request, e)
	}
}

// record fills the actor and source address from the request and stores e.
// Failures are logged, never returned: auditing must not break the call.
func (h *auditHandlers) record(r *http.Request, e domain.AuditEvent) {
	if user, ok := h.requestUser(r, true); ok && user != nil {
		e.ActorUserID = user.ID
		if e.ActorLogin == "" {
			e.ActorLogin = user.LoginName
		}
		e.ActorKind = domain.ActorUser
	} else if e.ActorKind == "" {
		e.ActorKind = "anonymous"
	}
	if token, ok := h.requestToken(r); ok {
		e.TokenID = token.ID
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		e.IP = host
	} else {
		e.IP = r.RemoteAddr
	}
	if err := h.repo.AppendAudit(e); err != nil {
		log.Printf("[AUDIT] append %s failed: %v", e.Action, err)
	}
	h.purgeExpired()
}

// auditRetention is how long events are kept; AGENTFLOW_AUDIT_RETENTION_DAYS
// (default 365, 0 keeps everything).
func auditRetention() time.Duration {
	days := 365
	if v := strings.TrimSpace(os.Getenv("AGENTFLOW_AUDIT_RETENTION_DAYS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			days = n
		}
	}
	return time.Duration(days) * 24 * time.Hour
}

// purgeExpired deletes events past retention at most once an hour.
func (h *auditHandlers) purgeExpired() {
	keep := auditRetention()
	if keep <= 0 {
		return
	}
	h.purgeMu.Lock()
	if time.Since(h.lastPurge) < time.Hour {
		h.purgeMu.Unlock()
		return
	}
	h.lastPurge = time.Now()
	h.purgeMu.Unlock()
	if n, err := h.repo.PurgeAuditBefore(time.Now().UTC().Add(-keep)); err != nil {
		log.Printf("[AUDIT] purge failed: %v", err)
	} else if n > 0 {
		log.Printf("[AUDIT] purged %d events older than %s", n, keep)
	}
}

func auditFilterFromQuery(c *gin.Context) (repo.AuditFilter, error) {
	f := repo.AuditFilter{Action: strings.TrimSpace(c.Query("action")), ProjectID: strings.TrimSpace(c.Query("projectId")), Outcome: strings.TrimSpace(c.Query("outcome"))}
	parse := func(name string) (time.Time, error) {
		v := strings.TrimSpace(c.Query(name))
		if v == "" {
			return time.Time{}, nil
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, nil
		}
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s must be RFC 3339 or YYYY-MM-DD", name)
		}
		return t, nil
	}
	var err error
	if f.From, err = parse("from"); err != nil {
		return f, err
	}
	if f.To, err = parse("to"); err != nil {
		return f, err
	}
	if v := strings.TrimSpace(c.Query("actorUserId")); v != "" {
		if f.ActorUserID, err = strconv.ParseInt(v, 10, 64); err != nil {
			return f, fmt.Errorf("actorUserId must be a number")
		}
	}
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if f.Limit, err = strconv.Atoi(v); err != nil {
			return f, fmt.Errorf("limit must be a number")
		}
	}
	return f, nil
}

// events answers GET /api/audit (platform administrators).
func (h *auditHandlers) events(c *gin.Context) {
	if !h.requireAuditReader(c) {
		return
	}
	f, err := auditFilterFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	list, err := h.repo.AuditEvents(f)
	if err != nil {
		respond(c, err)
		return
	}
	c.JSON(http.StatusOK, list)
}

// export answers GET /api/audit/export?format=csv|json with up to 10000
// events as a download.
func (h *auditHandlers) export(c *gin.Context) {
	if !h.requireAuditReader(c) {
		return
	}
	f, err := auditFilterFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if f.Limit <= 0 {
		f.Limit = 10000
	}
	list, err := h.repo.AuditEvents(f)
	if err != nil {
		respond(c, err)
		return
	}
	name := "loopforge-audit-" + time.Now().UTC().Format("20060102-150405")
	if strings.EqualFold(c.Query("format"), "json") {
		c.Header("Content-Disposition", `attachment; filename="`+name+`.json"`)
		c.JSON(http.StatusOK, list)
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	c.Status(http.StatusOK)
	// UTF-8 BOM so spreadsheet tools read Chinese text correctly.
	_, _ = c.Writer.Write([]byte("\xEF\xBB\xBF"))
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"time", "action", "outcome", "status", "actor_user_id", "actor_login", "actor_kind", "token_id", "ip", "project_id", "method", "path", "target", "detail"})
	for _, e := range list {
		_ = w.Write([]string{e.At.Format(time.RFC3339), csvSafe(e.Action), e.Outcome, strconv.Itoa(e.Status), strconv.FormatInt(e.ActorUserID, 10), csvSafe(e.ActorLogin), e.ActorKind, e.TokenID, e.IP, csvSafe(e.ProjectID), e.Method, csvSafe(e.Path), csvSafe(e.Target), csvSafe(string(e.Detail))})
	}
	w.Flush()
}

// csvSafe stops spreadsheet formula injection from user-controlled text.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// requireAuditReader allows platform administrators only. With login off
// the instance has no identities to audit against, so it stays open like
// other administration endpoints.
func (h *auditHandlers) requireAuditReader(c *gin.Context) bool {
	if !authRequired() || h.isPlatformAdmin(c.Request) {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "只有平台管理员可以查看审计日志"})
	return false
}
