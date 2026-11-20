package web

import (
	"os"
	"strings"
	"testing"
)

// The narrow-screen settings drawer covers the page, so it must never keep
// a record (a run waiting for approval) out of reach.
func TestNarrowSettingsDrawerGetsOutOfTheWay(t *testing.T) {
	raw, err := os.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, want := range []string{
		"document.addEventListener('pointerdown',event=>{\n    if(!narrowSettingsDrawerOpen()",
		"event.key==='Escape'&&narrowSettingsDrawerOpen())setSettingsSidebarExpanded(false)",
		"const toRecord=routePart(0)===name&&!!routePart(1);",
		"!isSettingsManagementView(previous)&&!toRecord)",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("app.js missing %q", want)
		}
	}
	if strings.Contains(src, "document.addEventListener('click',event=>{\n    if(!narrowSettingsDrawerOpen()") {
		t.Fatal("outside close must use pointerdown: a click that opens the drawer would close it again")
	}
	runs, err := os.ReadFile("app/runs.js")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(runs), "function showRunDetail(")
	if start < 0 || !strings.Contains(string(runs)[start:start+400], "closeNarrowSettingsDrawer()") {
		t.Fatal("opening a run must close the narrow settings drawer")
	}
}
