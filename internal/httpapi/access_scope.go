package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"agentflow/internal/domain"
)

type requestTokenContextKey struct{}

// requestToken returns the API token the request authenticated with, if any.
// userAccessAuth stores it on the context; a request it has not seen (an
// exempt path) is resolved from its Authorization header.
func (d deps) requestToken(r *http.Request) (domain.APIToken, bool) {
	if token, ok := r.Context().Value(requestTokenContextKey{}).(domain.APIToken); ok && token.ID != "" {
		return token, true
	}
	raw, ok := bearerToken(r)
	if !ok || d.repo == nil {
		return domain.APIToken{}, false
	}
	sum := sha256.Sum256([]byte(raw))
	return d.repo.ActiveAPITokenByHash(hex.EncodeToString(sum[:]), time.Now().UTC())
}

// tokenAllowsProject reports whether a project-limited token may touch
// projectID. Requests without a token are not limited here.
func (d deps) tokenAllowsProject(r *http.Request, projectID string) bool {
	token, ok := d.requestToken(r)
	return !ok || token.AllowsProject(projectID)
}

// readIsolation reports whether project data (runs, issues, cases, alerts,
// connections) is readable only by project members. It is on whenever login
// is required unless AGENTFLOW_PROJECT_READ_ISOLATION=false.
func readIsolation() bool {
	if !authRequired() {
		return false
	}
	v := strings.TrimSpace(os.Getenv("AGENTFLOW_PROJECT_READ_ISOLATION"))
	if v == "" {
		return true
	}
	on, err := strconv.ParseBool(v)
	return err != nil || on
}

// projectReadable is the read predicate for project data: platform
// administrators, the owner and members of any role (viewer included).
// Ownerless projects are shared. Data outside any project stays readable.
// A project-limited token reads only its projects, whatever the isolation
// setting.
func (d deps) projectReadable(r *http.Request, projectID string) bool {
	if !authRequired() {
		return true
	}
	if !d.tokenAllowsProject(r, projectID) {
		return false
	}
	if !readIsolation() || projectID == "" {
		return true
	}
	user, ok := d.requestUser(r, true)
	if !ok || user == nil || user.ID <= 0 {
		return false
	}
	if d.isPlatformAdmin(r) {
		return true
	}
	return projectMemberReads(d, projectID, user.ID)
}

func projectMemberReads(d deps, projectID string, userID int64) bool {
	p, found := d.repo.Project(projectID)
	if !found {
		return false
	}
	if p.OwnerID == 0 || p.OwnerID == userID {
		return true
	}
	for _, m := range p.Members {
		if m.UserID == userID {
			return true
		}
	}
	return false
}

// projectReadFilter returns a cached predicate for filtering lists.
func (d deps) projectReadFilter(r *http.Request) func(projectID string) bool {
	cache := map[string]bool{}
	return func(projectID string) bool {
		if v, ok := cache[projectID]; ok {
			return v
		}
		v := d.projectReadable(r, projectID)
		cache[projectID] = v
		return v
	}
}
