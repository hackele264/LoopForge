package domain

import "testing"

func TestRequiredTokenScope(t *testing.T) {
	cases := map[[2]string]string{
		{"GET", "/api/runs/r1"}:             TokenScopeRead,
		{"POST", "/mcp"}:                    "",
		{"POST", "/api/runs"}:               TokenScopeRunsExecute,
		{"POST", "/api/runs/r1/cancel"}:     TokenScopeRunsExecute,
		{"POST", "/api/runs/r1/approve"}:    TokenScopeApprovalsDecide,
		{"POST", "/api/runs/r1/reject"}:     TokenScopeApprovalsDecide,
		{"PUT", "/api/cases/c1"}:            TokenScopeCasesWrite,
		{"POST", "/api/alerts/a1/escalate"}: TokenScopeCasesWrite,
		{"POST", "/api/cases/c1/runs"}:      TokenScopeRunsExecute,
		{"PUT", "/api/workflows"}:           TokenScopeConfigWrite,
		{"POST", "/api/connections"}:        TokenScopeConfigWrite,
		{"DELETE", "/api/case-triggers/t1"}: TokenScopeConfigWrite,
	}
	for in, want := range cases {
		if got := RequiredTokenScope(in[0], in[1]); got != want {
			t.Errorf("%s %s = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestTokenScopeChecks(t *testing.T) {
	legacy := APIToken{}
	if !legacy.HasScope(TokenScopeAdmin) || !legacy.AllowsProject("x") || !legacy.AllowsProject("") {
		t.Fatal("unscoped tokens keep full access")
	}
	scoped := APIToken{Scopes: []string{TokenScopeRead, TokenScopeCasesWrite}, ProjectIDs: []string{"sec"}}
	if !scoped.HasScope(TokenScopeRead) || !scoped.HasScope(TokenScopeCasesWrite) || scoped.HasScope(TokenScopeConfigWrite) || scoped.HasScope(TokenScopeAdmin) {
		t.Fatal("scoped token grants the wrong scopes")
	}
	if !scoped.AllowsProject("sec") || scoped.AllowsProject("other") || scoped.AllowsProject("") {
		t.Fatal("project-limited token reaches the wrong projects")
	}
	if ValidateTokenScopes([]string{"read", "root"}) == nil || ValidateTokenScopes([]string{"read", "read"}) == nil || ValidateTokenScopes([]string{"read", "admin"}) != nil {
		t.Fatal("scope validation")
	}
}
