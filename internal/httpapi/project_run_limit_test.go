package httpapi

import (
	"net/http"
	"testing"

	"agentflow/internal/domain"
	"agentflow/internal/repo"
)

// Project members see the limit; only platform administrators change it.
func TestProjectRunLimitEndpoint(t *testing.T) {
	f := newWebhookFixture(t)
	member := domain.User{ID: 42, LoginName: "analyst"}
	admin := domain.User{ID: 43, LoginName: "platform-ops"}
	for _, u := range []domain.User{member, admin} {
		if err := f.s.PutUser(u); err != nil {
			t.Fatal(err)
		}
	}
	p, _ := f.s.Project("sec")
	p.Members = append(p.Members, domain.ProjectMember{UserID: member.ID, Role: "member"})
	if err := f.s.PutProject(p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GrantPlatformAdmin(admin.LoginName); err != nil {
		t.Fatal(err)
	}

	got := requestJSONAuthed[projectRunLimitView](t, f.h, member, http.MethodGet, "/api/projects/sec/run-limit", nil, http.StatusOK)
	if got.RunLimit != 0 || got.Default != repo.ProjectRunLimit || got.Effective != repo.ProjectRunLimit || got.Max != repo.MaxProjectRunLimit {
		t.Fatalf("default view = %+v", got)
	}
	requestJSONAuthed[map[string]any](t, f.h, f.owner, http.MethodPut, "/api/projects/sec/run-limit", map[string]any{"runLimit": 30}, http.StatusForbidden)
	requestJSONAuthed[map[string]any](t, f.h, member, http.MethodPut, "/api/projects/sec/run-limit", map[string]any{"runLimit": 30}, http.StatusForbidden)
	requestJSONAuthed[map[string]any](t, f.h, admin, http.MethodPut, "/api/projects/sec/run-limit", map[string]any{"runLimit": repo.MaxProjectRunLimit + 1}, http.StatusBadRequest)
	requestJSONAuthed[map[string]any](t, f.h, admin, http.MethodPut, "/api/projects/sec/run-limit", map[string]any{}, http.StatusBadRequest)

	got = requestJSONAuthed[projectRunLimitView](t, f.h, admin, http.MethodPut, "/api/projects/sec/run-limit", map[string]any{"runLimit": 30}, http.StatusOK)
	if got.RunLimit != 30 || got.Effective != 30 {
		t.Fatalf("after set = %+v", got)
	}
	if p, _ := f.s.Project("sec"); p.RunLimit != 30 {
		t.Fatalf("stored limit = %d", p.RunLimit)
	}
	got = requestJSONAuthed[projectRunLimitView](t, f.h, admin, http.MethodPut, "/api/projects/sec/run-limit", map[string]any{"runLimit": 0}, http.StatusOK)
	if got.RunLimit != 0 || got.Effective != repo.ProjectRunLimit {
		t.Fatalf("after reset = %+v", got)
	}
	requestJSONAuthed[map[string]any](t, f.h, admin, http.MethodGet, "/api/projects/nope/run-limit", nil, http.StatusNotFound)
}
