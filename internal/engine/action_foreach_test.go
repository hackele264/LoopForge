package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
)

// foreachVendor is a fake VirusTotal: every IP lookup takes a moment so
// concurrent lookups overlap, one IP is unknown (404), and the peak number
// of lookups in flight is recorded.
type foreachVendor struct {
	srv      *httptest.Server
	inFlight atomic.Int32
	peak     atomic.Int32
	calls    atomic.Int32
	mu       sync.Mutex
	seen     []string
	block    chan struct{} // when set, lookups wait for it or the caller
}

func newForeachVendor(t *testing.T, unknown string, block bool) *foreachVendor {
	v := &foreachVendor{}
	if block {
		v.block = make(chan struct{})
	}
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimPrefix(r.URL.Path, "/api/v3/ip_addresses/")
		v.calls.Add(1)
		n := v.inFlight.Add(1)
		defer v.inFlight.Add(-1)
		for {
			p := v.peak.Load()
			if n <= p || v.peak.CompareAndSwap(p, n) {
				break
			}
		}
		v.mu.Lock()
		v.seen = append(v.seen, ip)
		v.mu.Unlock()
		if v.block != nil {
			select {
			case <-v.block:
			case <-r.Context().Done():
				return
			}
		} else {
			time.Sleep(40 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		if ip == unknown {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"code":"NotFoundError"}}`)
			return
		}
		last := ip[strings.LastIndex(ip, ".")+1:]
		fmt.Fprintf(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":%s,"suspicious":0},"country":"NL"}}}`, last)
	}))
	t.Cleanup(v.srv.Close)
	return v
}

var foreachIPs = []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}

func foreachTrigger(ips []string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"alert": map[string]any{"title": "beaconing", "body": "outbound to " + strings.Join(ips, ", ") + " from host-7"}})
	return raw
}

func foreachSetup(t *testing.T, vendor *foreachVendor) (*Engine, *repo.Store) {
	t.Helper()
	e, s := newBranchEngine(t)
	if err := s.PutProject(domain.Project{ID: "sec", Key: "SEC", Name: "sec"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.PutConnection(domain.Connection{ID: "cn-vt", ProjectID: "sec", ConnectorID: "virustotal", Name: "vt", BaseURL: vendor.srv.URL, Secrets: map[string]string{"api_key": "k"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return e, s
}

func foreachLookupNode(mutate func(*domain.WorkflowNode)) domain.WorkflowNode {
	n := domain.WorkflowNode{ID: "vt", Name: "IP 信誉", Type: connector.NodeType, MaxAttempts: 1,
		ForEach: `iocs(trigger, "ipv4")`,
		Action:  &domain.NodeAction{Connector: "virustotal", Action: "ip_report", ConnectionID: "cn-vt", Inputs: map[string]string{"ip": "{{ item }}"}}}
	if mutate != nil {
		mutate(&n)
	}
	return n
}

func foreachStart(t *testing.T, e *Engine, s *repo.Store, wf domain.WorkflowDefinition, ips []string) string {
	t.Helper()
	wf.Name, wf.SandboxProfileID, wf.ProjectID = wf.ID, "local", "sec"
	if err := validate(wf); err != nil {
		t.Fatal(err)
	}
	if err := s.PutWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	r, err := e.StartWithTrigger(wf.ID, "", foreachTrigger(ips), nil, domain.TelemetryContext{ProjectID: "sec"})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func foreachResult(t *testing.T, s *repo.Store, runID, nodeID string) (forEachData, domain.NodeRun) {
	t.Helper()
	r, _ := s.RunState(runID)
	nr := r.Nodes[nodeID]
	var data forEachData
	if err := json.Unmarshal([]byte(nr.Data), &data); err != nil {
		t.Fatalf("node data %q: %v", nr.Data, err)
	}
	return data, *nr
}

// TestActionForEachLooksUpEveryIP: an alert carries five IPs, the action
// node looks each one up with at most two lookups in flight, the unknown IP
// fails without stopping the rest, results keep the alert's order, and a
// downstream condition reads the counts.
func TestActionForEachLooksUpEveryIP(t *testing.T) {
	t.Parallel()
	vendor := newForeachVendor(t, "203.0.113.3", false)
	e, s := foreachSetup(t, vendor)
	wf := domain.WorkflowDefinition{ID: "ip-loop",
		Nodes: []domain.WorkflowNode{
			foreachLookupNode(func(n *domain.WorkflowNode) { n.ForEachConcurrency = 2; n.ForEachFailOn = domain.ForEachFailOnAll }),
			{ID: "review", Name: "review", Type: "approval", MaxAttempts: 1, RunIf: "nodes.vt.data.failed > 0"},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "vt", Target: "review"}}}
	runID := foreachStart(t, e, s, wf, foreachIPs)
	waitFor(t, s, runID, "waiting")

	data, nr := foreachResult(t, s, runID, "vt")
	if nr.Status != "succeeded" || data.Total != 5 || data.Succeeded != 4 || data.Failed != 1 || len(data.Results) != 5 {
		t.Fatalf("status %s data %+v", nr.Status, data)
	}
	for i, res := range data.Results {
		if res.Index != i || res.Item != foreachIPs[i] {
			t.Fatalf("result %d = %+v, want item %s", i, res, foreachIPs[i])
		}
		if i == 2 {
			if res.OK || !strings.Contains(res.Error, "404") || res.Output != nil {
				t.Fatalf("unknown IP result = %+v", res)
			}
			continue
		}
		if !res.OK || res.Output["malicious"] != float64(i+1) || res.Output["country"] != "NL" {
			t.Fatalf("result %d = %+v", i, res)
		}
	}
	if got := vendor.calls.Load(); got != 5 {
		t.Fatalf("vendor calls = %d", got)
	}
	if peak := vendor.peak.Load(); peak != 2 {
		t.Fatalf("peak concurrent lookups = %d, want 2", peak)
	}
	if !strings.Contains(nr.Output, "5 项，成功 4，失败 1") {
		t.Fatalf("summary = %q", nr.Output)
	}
}

// TestActionForEachFailureGoesToErrorEdge: with the default forEachFailOn
// (any) one failed item fails the node, its results stay readable, and the
// error edge takes over.
func TestActionForEachFailureGoesToErrorEdge(t *testing.T) {
	t.Parallel()
	vendor := newForeachVendor(t, "203.0.113.5", false)
	e, s := foreachSetup(t, vendor)
	wf := domain.WorkflowDefinition{ID: "ip-loop-any",
		Nodes: []domain.WorkflowNode{
			foreachLookupNode(nil),
			{ID: "handle", Name: "handle", Type: "approval", MaxAttempts: 1, RunIf: "nodes.vt.data.failed == 1 && nodes.vt.data.succeeded == 4"},
		},
		Edges: []domain.WorkflowEdge{{ID: "1", Source: "vt", Target: "handle", When: domain.EdgeWhenError}}}
	runID := foreachStart(t, e, s, wf, foreachIPs)
	waitFor(t, s, runID, "waiting")
	data, nr := foreachResult(t, s, runID, "vt")
	if nr.Status != "failed" || !nr.ErrorRouted || data.Failed != 1 || data.Succeeded != 4 {
		t.Fatalf("status %s routed %v data %+v", nr.Status, nr.ErrorRouted, data)
	}
	if !strings.Contains(nr.Error, "5 项中 1 项失败，第 5 项") {
		t.Fatalf("error = %q", nr.Error)
	}
	if peak := vendor.peak.Load(); peak > domain.ForEachDefaultConcurrency {
		t.Fatalf("peak %d above the default concurrency", peak)
	}
	r, _ := s.RunState(runID)
	if r.Nodes["handle"].Status != "waiting_approval" {
		t.Fatalf("handle = %s", r.Nodes["handle"].Status)
	}
}

// TestActionForEachEmptyListAndLimit: no IPs succeed with zero items and no
// calls; more items than forEachLimit fail the node before any call.
func TestActionForEachEmptyListAndLimit(t *testing.T) {
	t.Parallel()
	vendor := newForeachVendor(t, "", false)
	e, s := foreachSetup(t, vendor)
	empty := foreachStart(t, e, s, domain.WorkflowDefinition{ID: "ip-loop-empty", Nodes: []domain.WorkflowNode{foreachLookupNode(nil)}}, nil)
	waitFor(t, s, empty, "succeeded")
	data, nr := foreachResult(t, s, empty, "vt")
	if nr.Status != "succeeded" || data.Total != 0 || data.Results == nil || len(data.Results) != 0 {
		t.Fatalf("empty: status %s data %+v", nr.Status, data)
	}
	if !strings.Contains(string(nr.Data), `"results":[]`) {
		t.Fatalf("empty results should be a list: %s", nr.Data)
	}

	limited := foreachStart(t, e, s, domain.WorkflowDefinition{ID: "ip-loop-limit", Nodes: []domain.WorkflowNode{foreachLookupNode(func(n *domain.WorkflowNode) { n.ForEachLimit = 3 })}}, foreachIPs)
	waitFor(t, s, limited, "failed")
	r, _ := s.RunState(limited)
	if !strings.Contains(r.Nodes["vt"].Error, "5 项，超过上限 3") {
		t.Fatalf("limit error = %q", r.Nodes["vt"].Error)
	}

	notList := foreachStart(t, e, s, domain.WorkflowDefinition{ID: "ip-loop-text", Nodes: []domain.WorkflowNode{foreachLookupNode(func(n *domain.WorkflowNode) { n.ForEach = "trigger.alert.title" })}}, foreachIPs)
	waitFor(t, s, notList, "failed")
	r, _ = s.RunState(notList)
	if !strings.Contains(r.Nodes["vt"].Error, "必须得到列表") {
		t.Fatalf("not-a-list error = %q", r.Nodes["vt"].Error)
	}
	if got := vendor.calls.Load(); got != 0 {
		t.Fatalf("vendor calls = %d, want 0", got)
	}
}

// TestActionForEachCancelStopsPendingItems: cancelling the run while the
// first items are in flight aborts them and never starts the rest.
func TestActionForEachCancelStopsPendingItems(t *testing.T) {
	t.Parallel()
	vendor := newForeachVendor(t, "", true)
	e, s := foreachSetup(t, vendor)
	runID := foreachStart(t, e, s, domain.WorkflowDefinition{ID: "ip-loop-cancel", Nodes: []domain.WorkflowNode{foreachLookupNode(func(n *domain.WorkflowNode) { n.ForEachConcurrency = 2 })}}, foreachIPs)
	deadline := time.Now().Add(20 * time.Second)
	for vendor.inFlight.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("lookups never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := e.Cancel(runID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, s, runID, "cancelled")
	time.Sleep(200 * time.Millisecond)
	if got := vendor.calls.Load(); got != 2 {
		t.Fatalf("vendor calls after cancel = %d, want 2", got)
	}
	if r, _ := s.RunState(runID); len(r.Nodes["vt"].Data) > 0 {
		t.Fatalf("a cancelled loop published data: %s", r.Nodes["vt"].Data)
	}
}

func TestBoundForEachDataShrinks(t *testing.T) {
	big := strings.Repeat("x", 4<<10)
	data := forEachData{}
	for i := 0; i < 200; i++ {
		data.Results = append(data.Results, forEachItemResult{Index: i, Item: "10.0.0.1", OK: true, Output: map[string]any{"status": 200.0, "score": 1.0, "body": big}})
	}
	data.Total, data.Succeeded = 200, 200
	raw, err := boundForEachData(&data)
	if err != nil || len(raw) > maxForEachDataBytes || data.Truncated != "bodies" || data.Results[0].Output["score"] != 1.0 || data.Results[0].Output["bodyTruncated"] != true {
		t.Fatalf("bodies: %d bytes, truncated %q, err %v", len(raw), data.Truncated, err)
	}
	for i := range data.Results {
		data.Results[i].Output["score"] = big
	}
	raw, _ = boundForEachData(&data)
	if len(raw) > maxForEachDataBytes || data.Truncated != "outputs" || data.Results[0].Output != nil || data.Results[0].Item != "10.0.0.1" {
		t.Fatalf("outputs: %d bytes, truncated %q", len(raw), data.Truncated)
	}
	for i := range data.Results {
		data.Results[i].Item = big
		data.Results[i].Error = big
	}
	raw, _ = boundForEachData(&data)
	if len(raw) > maxForEachDataBytes || data.Truncated != "items" || data.Results[0].Item != nil || data.Total != 200 {
		t.Fatalf("items: %d bytes, truncated %q", len(raw), data.Truncated)
	}
}
