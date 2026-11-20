package domain

import (
	"fmt"
	"net/http"
	"strings"
)

// API token scopes. A token without scopes keeps its owner's full access
// (tokens created before scopes existed). A scoped token may always read and
// may only make the changes its scopes name; platform administration needs
// TokenScopeAdmin even when the owner is an administrator.
const (
	TokenScopeRead            = "read"
	TokenScopeRunsExecute     = "runs:execute"
	TokenScopeCasesWrite      = "cases:write"
	TokenScopeApprovalsDecide = "approvals:decide"
	TokenScopeConfigWrite     = "config:write"
	TokenScopeAdmin           = "admin"
)

// TokenScopes lists the valid scopes in display order.
var TokenScopes = []string{TokenScopeRead, TokenScopeRunsExecute, TokenScopeCasesWrite, TokenScopeApprovalsDecide, TokenScopeConfigWrite, TokenScopeAdmin}

// ValidateTokenScopes rejects unknown or duplicate scopes.
func ValidateTokenScopes(scopes []string) error {
	seen := map[string]bool{}
	for _, s := range scopes {
		known := false
		for _, k := range TokenScopes {
			known = known || k == s
		}
		if !known {
			return fmt.Errorf("unknown token scope %q", s)
		}
		if seen[s] {
			return fmt.Errorf("duplicate token scope %q", s)
		}
		seen[s] = true
	}
	return nil
}

// Scoped reports whether the token is limited by scopes.
func (t APIToken) Scoped() bool { return len(t.Scopes) > 0 }

// HasScope reports whether the token grants scope. Unscoped tokens grant
// everything; scoped tokens always grant read.
func (t APIToken) HasScope(scope string) bool {
	if !t.Scoped() || scope == "" || scope == TokenScopeRead {
		return true
	}
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ProjectRestricted reports whether the token is limited to some projects.
func (t APIToken) ProjectRestricted() bool { return len(t.ProjectIDs) > 0 }

// AllowsProject reports whether the token may touch projectID. A
// project-restricted token reaches no resource outside a project.
func (t APIToken) AllowsProject(projectID string) bool {
	if !t.ProjectRestricted() {
		return true
	}
	for _, id := range t.ProjectIDs {
		if id == projectID && id != "" {
			return true
		}
	}
	return false
}

// RequiredTokenScope names the scope a request needs. Reads need read;
// the MCP endpoint itself needs nothing because each tool call is dispatched
// again as its own request and checked then.
func RequiredTokenScope(method, path string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return TokenScopeRead
	}
	if path == "/mcp" {
		return ""
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "api" {
		switch parts[1] {
		case "runs":
			if len(parts) == 4 && (parts[3] == "approve" || parts[3] == "reject" || parts[3] == "pass") {
				return TokenScopeApprovalsDecide
			}
			return TokenScopeRunsExecute
		case "cases":
			if len(parts) == 4 && parts[3] == "runs" {
				return TokenScopeRunsExecute
			}
			return TokenScopeCasesWrite
		case "alerts":
			return TokenScopeCasesWrite
		}
	}
	return TokenScopeConfigWrite
}
