package repo

import (
	"sort"
	"testing"

	"agentflow/internal/domain"
)

// The claim loop lists live runs every pass, so the listing must leave out
// finished runs however many pile up.
func TestLiveRunsListsOnlyRunningAndWaiting(t *testing.T) {
	t.Parallel()
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, status := range []string{"running", "waiting", "queued", "succeeded", "failed", "cancelled", "paused"} {
		if err := s.PutRun(domain.Run{ID: "r-" + status, Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, r := range s.LiveRuns() {
		got = append(got, r.ID)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "r-running" || got[1] != "r-waiting" {
		t.Fatalf("live runs = %v", got)
	}
	if n := len(s.Runs()); n != 7 {
		t.Fatalf("Runs() = %d runs, want all 7", n)
	}
}
