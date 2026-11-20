package httpapi

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"agentflow/internal/domain"

	"github.com/gin-gonic/gin"
)

// pilotHandlers serves the shadow-mode pilot report: a read-only summary of
// a project's alerts, runs, connector actions, verdict latency and
// verdict/resolution agreement (docs/pilot.md).
type pilotHandlers struct{ *deps }

// pilotMaxRange bounds one report's time range.
const pilotMaxRange = 92 * 24 * time.Hour

// reportReader allows platform administrators and the project owner. A
// project-limited API token must cover the project.
func (h *pilotHandlers) reportReader(c *gin.Context, projectID string) bool {
	noteAuditProject(c, projectID)
	if !authRequired() {
		return true
	}
	if !h.tokenAllowsProject(c.Request, projectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "API Token 无权访问该项目"})
		return false
	}
	if h.isPlatformAdmin(c.Request) {
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
	if p.OwnerID != 0 && p.OwnerID == user.ID {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "只有项目 Owner 或平台管理员可以查看试点报告"})
	return false
}

// parsePilotTime accepts RFC 3339 or a UTC date (YYYY-MM-DD).
func parsePilotTime(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	return time.Parse("2006-01-02", v)
}

// report answers GET /api/pilot-report?projectId=&from=&to=&format=json|csv.
// from defaults to 14 days before to; to defaults to now; a date-only to
// includes that whole day.
func (h *pilotHandlers) report(c *gin.Context) {
	projectID := strings.TrimSpace(c.Query("projectId"))
	if projectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "projectId is required"})
		return
	}
	if !h.reportReader(c, projectID) {
		return
	}
	to := time.Now().UTC()
	if v := c.Query("to"); v != "" {
		t, err := parsePilotTime(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "to must be RFC 3339 or YYYY-MM-DD"})
			return
		}
		if len(strings.TrimSpace(v)) == len("2006-01-02") {
			t = t.Add(24 * time.Hour)
		}
		to = t
	}
	from := to.Add(-14 * 24 * time.Hour)
	if v := c.Query("from"); v != "" {
		t, err := parsePilotTime(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "from must be RFC 3339 or YYYY-MM-DD"})
			return
		}
		from = t
	}
	if !from.Before(to) || to.Sub(from) > pilotMaxRange {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from must be before to, at most 92 days apart"})
		return
	}
	rep, err := h.repo.PilotReport(projectID, from, to)
	if err != nil {
		respond(c, err)
		return
	}
	if c.Query("format") == "csv" {
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="pilot-report-%s-%s.csv"`, safeFileToken(projectID), from.Format("20060102")))
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Status(http.StatusOK)
		w := csv.NewWriter(c.Writer)
		_ = w.WriteAll(pilotReportRows(rep))
		return
	}
	c.JSON(http.StatusOK, rep)
}

func safeFileToken(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// pilotReportRows flattens a report into metric,value rows.
func pilotReportRows(rep domain.PilotReport) [][]string {
	n := func(v int) string { return strconv.Itoa(v) }
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 4, 64) }
	rows := [][]string{
		{"metric", "value"},
		{"projectId", rep.ProjectID},
		{"from", rep.From.Format(time.RFC3339)},
		{"to", rep.To.Format(time.RFC3339)},
		{"alerts.admitted", n(rep.Alerts.Admitted)},
		{"alerts.deduplicated", n(rep.Alerts.Deduplicated)},
		{"alerts.rateLimited", n(rep.Alerts.RateLimited)},
		{"alerts.deliveriesComplete", strconv.FormatBool(rep.Alerts.DeliveriesComplete)},
		{"cases.opened", n(rep.Alerts.Cases)},
		{"runs.started", n(rep.Runs.Started)},
		{"runs.succeeded", n(rep.Runs.Succeeded)},
		{"runs.failed", n(rep.Runs.Failed)},
		{"runs.cancelled", n(rep.Runs.Cancelled)},
		{"runs.active", n(rep.Runs.Active)},
		{"actions.overall.total", n(rep.Actions.Overall.Total)},
		{"actions.overall.rate", f(rep.Actions.Overall.Rate)},
		{"actions.enrichment.total", n(rep.Actions.Enrichment.Total)},
		{"actions.enrichment.rate", f(rep.Actions.Enrichment.Rate)},
		{"actions.responseExecuted", n(rep.Actions.ResponseExecuted)},
	}
	for _, s := range rep.Actions.ByConnector {
		rows = append(rows, []string{"actions." + s.Connector + ".total", n(s.Total)}, []string{"actions." + s.Connector + ".rate", f(s.Rate)})
	}
	rows = append(rows,
		[]string{"latency.withVerdict", n(rep.Latency.WithVerdict)},
		[]string{"latency.withoutVerdict", n(rep.Latency.WithoutVerdict)},
		[]string{"latency.p50Seconds", f(rep.Latency.P50Seconds)},
		[]string{"latency.p95Seconds", f(rep.Latency.P95Seconds)},
		[]string{"latency.maxSeconds", f(rep.Latency.MaxSeconds)},
		[]string{"agreement.matched", n(rep.Agreement.Matched)},
		[]string{"agreement.mismatched", n(rep.Agreement.Mismatch)},
		[]string{"agreement.excluded", n(rep.Agreement.Excluded)},
		[]string{"agreement.openWithVerdict", n(rep.Agreement.OpenWithVerdict)},
		[]string{"agreement.rate", f(rep.Agreement.Rate)},
	)
	verdicts := make([]string, 0, len(rep.Agreement.Matrix))
	for v := range rep.Agreement.Matrix {
		verdicts = append(verdicts, v)
	}
	sort.Strings(verdicts)
	for _, v := range verdicts {
		resolutions := make([]string, 0, len(rep.Agreement.Matrix[v]))
		for r := range rep.Agreement.Matrix[v] {
			resolutions = append(resolutions, r)
		}
		sort.Strings(resolutions)
		for _, r := range resolutions {
			rows = append(rows, []string{"matrix." + v + "." + r, n(rep.Agreement.Matrix[v][r])})
		}
	}
	return rows
}
