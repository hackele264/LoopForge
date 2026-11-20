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
)

// TestStateLockLoad measures how far one engine instance's global state lock
// carries a burst of alerts. Each alert starts a SOAR-shaped SOP of action
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
	t.Logf("state lock: %d acquisitions (%.1f per run), avg hold %s, max hold %s, held %.0f%% of the burst", acq, float64(acq)/float64(runs), (hold / time.Duration(max64(acq, 1))).Round(time.Microsecond), after.MaxHold.Round(time.Millisecond), 100*hold.Seconds()/wall.Seconds())
	t.Logf("state lock wait: avg %s, max %s, total %s", (wait / time.Duration(max64(acq, 1))).Round(time.Microsecond), after.MaxWait.Round(time.Millisecond), wait.Round(time.Millisecond))
	t.Logf("ceiling: %.0f state changes/s → about %.1f runs/s of this SOP", float64(acq)/hold.Seconds(), float64(runs)/hold.Seconds())
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
