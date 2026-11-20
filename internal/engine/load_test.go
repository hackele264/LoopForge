package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
	"agentflow/internal/runtime"

	"gorm.io/gorm"
)

// TestStateLockLoad measures how far one engine instance carries a burst of
// alerts, and how long run state changes wait for their run's lock. Each alert starts a SOAR-shaped SOP of action
// nodes (no sandbox): extract IOCs, three vendor lookups in parallel against
// a fake vendor with a fixed latency, a join, and two condition branches.
//
// It only runs on request:
//
//	AGENTFLOW_LOAD_TEST=1 go test ./internal/engine -run TestStateLockLoad -v -timeout 30m
//
// AGENTFLOW_LOAD_TEST_DSN   MySQL DSN of a DISPOSABLE database (default: SQLite)
// AGENTFLOW_LOAD_RUNS       alerts in the burst (default 200)
// AGENTFLOW_LOAD_VENDOR_MS  fake vendor latency per call (default 50)
// AGENTFLOW_LOAD_PROJECTS   projects the alerts are spread over (default 1);
//
//	each project admits at most repo.ProjectRunLimit
//	runs at once, so more projects stress the lock
//	itself rather than admission
func TestStateLockLoad(t *testing.T) {
	if os.Getenv("AGENTFLOW_LOAD_TEST") != "1" {
		t.Skip("set AGENTFLOW_LOAD_TEST=1 to run the load test")
	}
	runs := envInt("AGENTFLOW_LOAD_RUNS", 200)
	vendorDelay := time.Duration(envInt("AGENTFLOW_LOAD_VENDOR_MS", 50)) * time.Millisecond
	projects := envInt("AGENTFLOW_LOAD_PROJECTS", 1)

	var s *repo.Store
	var err error
	backend := "sqlite"
	if dsn := os.Getenv("AGENTFLOW_LOAD_TEST_DSN"); dsn != "" {
		backend = "mysql"
		s, err = repo.Open(dsn)
	} else {
		s, err = repo.OpenTest()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	writes := newWriteMeter(t, s.DB)
	stateWriteHook = writes.site
	defer func() { stateWriteHook = nil }()
	e := New(s, runtime.NewManager(filepath.Join(t.TempDir(), "workspaces")))
	// Production starts the claim loop; it also promotes queued runs.
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	e.StartClaimLoop(ctx)

	var callsMu sync.Mutex
	vendorCalls := 0
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(vendorDelay)
		callsMu.Lock()
		vendorCalls++
		callsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v3/"):
			io.WriteString(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"suspicious":0},"reputation":-5}}}`)
		case r.URL.Path == "/api/v2/check":
			io.WriteString(w, `{"data":{"abuseConfidenceScore":87,"totalReports":12}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer vendor.Close()

	base := fmt.Sprintf("load-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	var workflows []domain.WorkflowDefinition
	for p := 0; p < projects; p++ {
		tag := fmt.Sprintf("%s-p%d", base, p)
		project := tag
		if err := s.PutProject(domain.Project{ID: project, Key: fmt.Sprintf("L%d%s", p, base[len(base)-5:]), Name: project}); err != nil {
			t.Fatal(err)
		}
		for _, c := range []domain.Connection{
			{ID: tag + "-vt", ProjectID: project, ConnectorID: "virustotal", Name: "vt", BaseURL: vendor.URL, Secrets: map[string]string{"api_key": "k"}, CreatedAt: now, UpdatedAt: now},
			{ID: tag + "-abuse", ProjectID: project, ConnectorID: "abuseipdb", Name: "abuse", BaseURL: vendor.URL, Secrets: map[string]string{"api_key": "k"}, CreatedAt: now, UpdatedAt: now},
		} {
			if err := s.PutConnection(c); err != nil {
				t.Fatal(err)
			}
		}
		workflows = append(workflows, loadWorkflow(tag, project))
	}
	for _, wf := range workflows {
		if err := validate(wf); err != nil {
			t.Fatal(err)
		}
		if err := s.PutWorkflow(wf); err != nil {
			t.Fatal(err)
		}
	}
	writes.reset()
	before := e.StateLockStats()
	burstStart := time.Now()
	ids := make([]string, runs)
	var startErrs sync.Map
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			trigger := json.RawMessage(fmt.Sprintf(`{"alert":{"title":"beacon %d","src":"203.0.113.%d","url":"http://c2-%d.example/gate"}}`, i, i%250+1, i))
			wf := workflows[i%projects]
			r, err := e.StartWithTrigger(wf.ID, "", trigger, nil, domain.TelemetryContext{ProjectID: wf.ProjectID})
			if err != nil {
				startErrs.Store(i, err)
				return
			}
			ids[i] = r.ID
		}(i)
	}
	wg.Wait()
	startDone := time.Since(burstStart)
	startErrs.Range(func(k, v any) bool { t.Fatalf("start %v: %v", k, v); return false })

	// One summary query per tick, so polling adds little load of its own.
	deadline := time.Now().Add(25 * time.Minute)
	var finished []domain.Run
	lastLog := time.Now()
	for {
		var list []domain.Run
		for _, wf := range workflows {
			part, err := s.RunSummariesFor(domain.AnalyticsFilter{ProjectID: wf.ProjectID}, "")
			if err != nil {
				t.Fatal(err)
			}
			list = append(list, part...)
		}
		finished = finished[:0]
		for _, r := range list {
			if domain.TerminalRunStatus(r.Status) {
				finished = append(finished, r)
			}
		}
		if len(finished) == runs || time.Now().After(deadline) {
			break
		}
		if time.Since(lastLog) > 5*time.Second {
			lastLog = time.Now()
			counts := map[string]int{}
			for _, r := range list {
				counts[r.Status]++
			}
			t.Logf("%s: %d listed, %v", time.Since(burstStart).Round(time.Second), len(list), counts)
		}
		time.Sleep(250 * time.Millisecond)
	}
	wall := time.Since(burstStart)
	after := e.StateLockStats()
	if len(finished) != runs {
		t.Fatalf("only %d of %d runs finished in time", len(finished), runs)
	}

	lat := make([]time.Duration, 0, runs)
	failed := 0
	var lastDone time.Time
	for _, r := range finished {
		if r.Status != "succeeded" {
			failed++
		}
		lat = append(lat, r.UpdatedAt.Sub(r.CreatedAt))
		if r.UpdatedAt.After(lastDone) {
			lastDone = r.UpdatedAt
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration { return lat[int(p*float64(len(lat)-1))] }
	acq := after.Acquisitions - before.Acquisitions
	hold := after.Hold - before.Hold
	wait := after.Wait - before.Wait
	t.Logf("backend=%s projects=%d runs=%d vendor_latency=%s failed=%d vendor_calls=%d", backend, projects, runs, vendorDelay, failed, vendorCalls)
	t.Logf("burst: all %d runs accepted in %s; all finished in %s (%.1f runs/s)", runs, startDone.Round(time.Millisecond), wall.Round(time.Millisecond), float64(runs)/wall.Seconds())
	t.Logf("per-run latency (created to finished): p50=%s p95=%s max=%s", pct(0.5).Round(time.Millisecond), pct(0.95).Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond))
	t.Logf("state lock: %d acquisitions (%.1f per run), avg hold %s, max hold %s, %.1f runs holding their lock on average", acq, float64(acq)/float64(runs), (hold / time.Duration(max64(acq, 1))).Round(time.Microsecond), after.MaxHold.Round(time.Millisecond), hold.Seconds()/wall.Seconds())
	t.Logf("state lock wait: avg %s, max %s, total %s", (wait / time.Duration(max64(acq, 1))).Round(time.Microsecond), after.MaxWait.Round(time.Millisecond), wait.Round(time.Millisecond))
	t.Logf("state lock hold: p50<=%s p95<=%s p99<=%s", after.HoldPercentile(before, 0.5), after.HoldPercentile(before, 0.95), after.HoldPercentile(before, 0.99))
	t.Logf("state changes: %.0f/s over the burst", float64(acq)/wall.Seconds())
	writes.report(t, runs)
}

// writeMeter counts the rows and bound bytes the run store writes, per table,
// and the engine's updateRun calls per call site.
type writeMeter struct {
	mu     sync.Mutex
	rows   map[string]int64
	bytes  map[string]int64
	calls  map[string]int64
	stored map[string]int64
}

func newWriteMeter(t *testing.T, db *gorm.DB) *writeMeter {
	m := &writeMeter{}
	m.reset()
	count := func(tx *gorm.DB) {
		if tx.Error != nil || tx.Statement == nil {
			return
		}
		n := int64(0)
		for _, v := range tx.Statement.Vars {
			n += varBytes(v)
		}
		m.mu.Lock()
		m.rows[tx.Statement.Table]++
		m.bytes[tx.Statement.Table] += n
		m.mu.Unlock()
	}
	if err := db.Callback().Create().After("gorm:create").Register("load:count_create", count); err != nil {
		t.Fatal(err)
	}
	if err := db.Callback().Update().After("gorm:update").Register("load:count_update", count); err != nil {
		t.Fatal(err)
	}
	return m
}

func varBytes(v any) int64 {
	switch x := v.(type) {
	case string:
		return int64(len(x))
	case []byte:
		return int64(len(x))
	case json.RawMessage:
		return int64(len(x))
	case domain.RawJSON:
		return int64(len(x))
	case nil:
		return 0
	default:
		return 8
	}
}

func (m *writeMeter) reset() {
	m.mu.Lock()
	m.rows, m.bytes, m.calls, m.stored = map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}
	m.mu.Unlock()
}

func (m *writeMeter) site(_, site string, wrote bool) {
	m.mu.Lock()
	m.calls[site]++
	if wrote {
		m.stored[site]++
	}
	m.mu.Unlock()
}

func (m *writeMeter) report(t *testing.T, runs int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	per := func(v int64) float64 { return float64(v) / float64(runs) }
	var tables []string
	var totalBytes int64
	for k := range m.rows {
		tables = append(tables, k)
		totalBytes += m.bytes[k]
	}
	sort.Strings(tables)
	t.Logf("writes per run: %.1f run header writes, %.0f bytes bound in all (%.0f KiB total)", per(m.rows["runs"]), per(totalBytes), float64(totalBytes)/1024)
	for _, k := range tables {
		t.Logf("  table %-16s %7.1f rows/run %9.0f bytes/run", k, per(m.rows[k]), per(m.bytes[k]))
	}
	var sites []string
	var calls, stored int64
	for k := range m.calls {
		sites = append(sites, k)
		calls += m.calls[k]
		stored += m.stored[k]
	}
	sort.Slice(sites, func(i, j int) bool { return m.calls[sites[i]] > m.calls[sites[j]] })
	t.Logf("updateRun: %.1f calls/run, %.1f stored/run", per(calls), per(stored))
	for _, k := range sites {
		t.Logf("  %-28s %5.2f calls/run %5.2f stored/run", k, per(m.calls[k]), per(m.stored[k]))
	}
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil && v > 0 {
		return v
	}
	return def
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// loadWorkflow is the SOAR-shaped SOP of the load test, all action nodes.
func loadWorkflow(tag, project string) domain.WorkflowDefinition {
	act := func(id, conn, connectorID, action string, inputs map[string]string, extra func(*domain.WorkflowNode)) domain.WorkflowNode {
		n := domain.WorkflowNode{ID: id, Name: id, Type: connector.NodeType, MaxAttempts: 1, Action: &domain.NodeAction{Connector: connectorID, Action: action, ConnectionID: conn, Inputs: inputs}}
		if extra != nil {
			extra(&n)
		}
		return n
	}
	wf := domain.WorkflowDefinition{ID: tag, Name: "load", SandboxProfileID: "local", ProjectID: project,
		Nodes: []domain.WorkflowNode{
			act("extract", "", connector.BuiltinID, "extract_iocs", map[string]string{"value": "{{ trigger }}"}, nil),
			act("vt_ip", tag+"-vt", "virustotal", "ip_report", map[string]string{"ip": "{{ first(nodes.extract.data.ipv4) }}"}, nil),
			act("vt_url", tag+"-vt", "virustotal", "url_report", map[string]string{"url": "{{ first(nodes.extract.data.url) }}"}, nil),
			act("abuse", tag+"-abuse", "abuseipdb", "check_ip", map[string]string{"ip": "{{ first(nodes.extract.data.ipv4) }}"}, nil),
			act("verdict", "", connector.BuiltinID, "extract_iocs", map[string]string{"value": "{{ nodes.vt_ip.data }}"}, nil),
			act("high", "", connector.BuiltinID, "extract_iocs", map[string]string{"value": "high"}, func(n *domain.WorkflowNode) { n.RunIf = "nodes.vt_ip.data.malicious > 0" }),
			act("low", "", connector.BuiltinID, "extract_iocs", map[string]string{"value": "low"}, func(n *domain.WorkflowNode) { n.RunIf = "nodes.vt_ip.data.malicious == 0" }),
		},
		Edges: []domain.WorkflowEdge{
			{ID: "1", Source: "extract", Target: "vt_ip"}, {ID: "2", Source: "extract", Target: "vt_url"}, {ID: "3", Source: "extract", Target: "abuse"},
			{ID: "4", Source: "vt_ip", Target: "verdict"}, {ID: "5", Source: "vt_url", Target: "verdict"}, {ID: "6", Source: "abuse", Target: "verdict"},
			{ID: "7", Source: "verdict", Target: "high"}, {ID: "8", Source: "verdict", Target: "low"},
		}}
	return wf
}
