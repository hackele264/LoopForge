package repo

import (
	"bytes"
	"fmt"
	"reflect"
	"time"

	"agentflow/internal/domain"
)

// runHeaderUpdateColumns are the runs columns a write refreshes on an existing
// row. Lease fields (owner_instance_id, lease_until, execution_generation),
// workspace bindings and the control flags (cancel_requested/pause_requested)
// are owned by their own operations and never written here.
var runHeaderUpdateColumns = []string{
	"kind", "workflow_id", "status", "revision", "input", "human_context", "sandbox_id", "repository", "repositories", "snapshot",
	"execution_context", "usage_json", "tool_calls", "telemetry_sequence",
	"log_sequence", "workspace_cleaned_at", "updated_at", "admission_state", "queue_entered_at", "quota_project_id", "quota_parent_run_id", "quota_exempt", "quota_bucket",
}

// runHeaderLargeColumns are the header columns a planned write leaves out
// when they equal what the writer read. The small columns are always
// written: they cost little and some (workspace_cleaned_at) change without a
// revision bump.
var runHeaderLargeColumns = map[string]bool{
	"input": true, "human_context": true, "repository": true, "repositories": true,
	"snapshot": true, "execution_context": true, "usage_json": true,
}

// RunBase is what RunStateForWrite read, serialized at read time so later
// in-place mutations of the returned Run cannot alias it. PutRunFrom compares
// the mutated Run against it to write only what changed.
type RunBase struct {
	revision  int
	header    map[string]any
	nodes     map[string][]byte
	artifacts map[string]domain.Artifact
	events    int
}

// runWritePlan is a Run's difference from its base: the serialized nodes that
// changed (absent = unchanged) plus what is needed to compare the header and
// artifacts once the write transaction has settled them.
type runWritePlan struct {
	base     *RunBase
	revision int
	nodes    map[string][]byte
}

func newRunBase(run domain.Run) *RunBase {
	b := &RunBase{
		revision:  run.Revision,
		header:    runRowValues(run),
		nodes:     make(map[string][]byte, len(run.Nodes)),
		artifacts: make(map[string]domain.Artifact, len(run.Artifacts)),
		events:    len(run.Events),
	}
	for id, node := range run.Nodes {
		if node != nil {
			b.nodes[id] = mustJSON(node)
		}
	}
	for _, art := range run.Artifacts {
		b.artifacts[artifactKey(art)] = art
	}
	return b
}

func (b *RunBase) plan(run domain.Run) *runWritePlan {
	p := &runWritePlan{base: b, revision: b.revision, nodes: map[string][]byte{}}
	for id, node := range run.Nodes {
		if node == nil {
			continue
		}
		payload := mustJSON(node)
		if old, ok := b.nodes[id]; ok && bytes.Equal(old, payload) {
			continue
		}
		p.nodes[id] = payload
	}
	return p
}

func (p *runWritePlan) sameHeader(col string, value any) bool {
	return runHeaderLargeColumns[col] && reflect.DeepEqual(p.base.header[col], value)
}

func (p *runWritePlan) sameArtifact(art domain.Artifact) bool {
	old, ok := p.base.artifacts[artifactKey(art)]
	return ok && old == art
}

// unchanged reports whether writing run would store nothing new: the header
// differs from base only in its revision and timestamp, no node or artifact
// changed, and no event, telemetry or log record was added.
func (b *RunBase) unchanged(run domain.Run, plan *runWritePlan) bool {
	if len(plan.nodes) > 0 || len(run.Events) != b.events || len(run.Telemetry) > 0 || len(run.Logs) > 0 || len(run.Artifacts) != len(b.artifacts) {
		return false
	}
	for _, art := range run.Artifacts {
		if !plan.sameArtifact(art) {
			return false
		}
	}
	values := runRowValues(run)
	for _, col := range runHeaderUpdateColumns {
		if col == "revision" || col == "updated_at" {
			continue
		}
		if !reflect.DeepEqual(b.header[col], values[col]) {
			return false
		}
	}
	return true
}

// artifactKey identifies an artifact the way the write path names its row.
func artifactKey(art domain.Artifact) string {
	if art.ID != "" {
		return art.ID
	}
	return fmt.Sprintf("\x00%s\x00%d\x00%s", art.NodeID, art.Attempt, art.Name)
}

// RunStateForWrite is RunState for a writer that will store the run back
// with PutRunFrom.
func (r *RunsRepo) RunStateForWrite(id string) (domain.Run, *RunBase, bool) {
	run, ok := r.RunState(id)
	if !ok {
		return domain.Run{}, nil, false
	}
	return run, newRunBase(run), true
}

// PutRunFrom stores a run read with RunStateForWrite. It writes what PutRun
// would, but leaves nodes, artifacts and large header columns that still equal
// base as they are stored, and skips the write entirely (stored=false) when
// nothing changed. A nil base is a plain PutRun.
func (r *RunsRepo) PutRunFrom(v domain.Run, base *RunBase) (stored bool, err error) {
	if base == nil {
		return true, r.PutRun(v)
	}
	plan := base.plan(v)
	if base.unchanged(v, plan) {
		return false, nil
	}
	v.UpdatedAt = time.Now().UTC()
	v.Revision++
	if err := r.writePlannedRun(v, plan); err != nil {
		return false, err
	}
	return true, nil
}
