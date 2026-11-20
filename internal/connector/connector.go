// Package connector runs connector actions: small, declarative HTTP calls to
// security products (threat intelligence, EDR, identity) described by YAML
// templates, plus a few built-in actions on LoopForge's own cases.
//
// A connector template declares its endpoint, how it authenticates, the
// non-secret parameters and secrets a connection must provide, and its
// actions. An action declares typed inputs, one HTTP request whose parts are
// templates, and the output fields it publishes. Templates see only
// `inputs` and `params`; secrets are applied by the authentication step and
// never enter a template, a node configuration or a log line.
//
// The templates in templates/ were written for LoopForge from each vendor's
// public API documentation.
package connector

import (
	"fmt"
	"regexp"
	"strings"

	"agentflow/internal/expr"
)

// Action categories. Response actions change something outside LoopForge
// (isolate a host, disable an account) and may only run after an approval.
const (
	CategoryEnrichment = "enrichment"
	CategoryResponse   = "response"
	CategoryUtility    = "utility"
)

// Authentication types.
const (
	AuthNone                    = "none"
	AuthHeader                  = "header"
	AuthBearer                  = "bearer"
	AuthBasic                   = "basic"
	AuthQuery                   = "query"
	AuthOAuth2ClientCredentials = "oauth2_client_credentials"
)

// Input types.
const (
	TypeString  = "string"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
	TypeList    = "list"
	TypeObject  = "object"
	TypeAny     = "any"
)

// BuiltinID is the connector holding LoopForge's own actions.
const BuiltinID = "loopforge"

// Connector is one vendor template.
type Connector struct {
	ID          string `yaml:"id" json:"id"`
	Title       string `yaml:"title" json:"title"`
	Vendor      string `yaml:"vendor" json:"vendor,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
	Docs        string `yaml:"docs" json:"docs,omitempty"`
	// BaseURL is the default endpoint; a connection may override it.
	BaseURL string   `yaml:"baseUrl" json:"baseUrl,omitempty"`
	Auth    Auth     `yaml:"auth" json:"auth"`
	Params  []Field  `yaml:"params" json:"params,omitempty"`
	Secrets []Field  `yaml:"secrets" json:"secrets,omitempty"`
	Actions []Action `yaml:"actions" json:"actions"`
	// TestAction is a read-only action used by 测试连接.
	TestAction string `yaml:"testAction" json:"testAction,omitempty"`
	// TestInputs fills TestAction's inputs.
	TestInputs map[string]any `yaml:"testInputs" json:"testInputs,omitempty"`
	// Builtin connectors are implemented in Go and need no connection.
	Builtin bool `yaml:"-" json:"builtin,omitempty"`
	// Source is "builtin" for embedded templates or the file name of a
	// deployment template.
	Source string `yaml:"-" json:"source,omitempty"`
}

// Auth describes how requests authenticate. Secret names refer to
// Connector.Secrets.
type Auth struct {
	Type string `yaml:"type" json:"type"`
	// Name is the header or query parameter carrying the secret.
	Name string `yaml:"name" json:"name,omitempty"`
	// Prefix is prepended to a header secret (for example "Token ").
	Prefix string `yaml:"prefix" json:"prefix,omitempty"`
	Secret string `yaml:"secret" json:"secret,omitempty"`
	// Basic authentication.
	Username string `yaml:"username" json:"username,omitempty"`
	Password string `yaml:"password" json:"password,omitempty"`
	// OAuth 2.0 client credentials. TokenURL and Scope are templates over
	// params; ClientID and ClientSecret name secrets.
	TokenURL     string `yaml:"tokenUrl" json:"tokenUrl,omitempty"`
	Scope        string `yaml:"scope" json:"scope,omitempty"`
	ClientID     string `yaml:"clientId" json:"clientId,omitempty"`
	ClientSecret string `yaml:"clientSecret" json:"clientSecret,omitempty"`
}

// Field is a connection parameter or secret.
type Field struct {
	Name        string `yaml:"name" json:"name"`
	Label       string `yaml:"label" json:"label"`
	Description string `yaml:"description" json:"description,omitempty"`
	Required    bool   `yaml:"required" json:"required,omitempty"`
	Default     string `yaml:"default" json:"default,omitempty"`
}

// Action is one operation of a connector.
type Action struct {
	ID          string  `yaml:"id" json:"id"`
	Title       string  `yaml:"title" json:"title"`
	Description string  `yaml:"description" json:"description,omitempty"`
	Category    string  `yaml:"category" json:"category"`
	Inputs      []Input `yaml:"inputs" json:"inputs,omitempty"`
	Request     Request `yaml:"request" json:"-"`
	// Output maps output field names to expressions over `response`
	// (status, headers, body) and `inputs`.
	Output map[string]string `yaml:"output" json:"output,omitempty"`
	// OutputFields lists Output's names in a stable order for the UI.
	OutputFields []string `yaml:"-" json:"outputFields,omitempty"`
	// FailIf is an optional expression over `response` and `inputs`; when
	// true the action fails even though the HTTP status was accepted (APIs
	// that answer 200 with an error code).
	FailIf string `yaml:"failIf" json:"-"`
	// Success lists accepted HTTP statuses; empty accepts 2xx.
	Success        []int `yaml:"success" json:"-"`
	TimeoutSeconds int   `yaml:"timeoutSeconds" json:"-"`
}

// Input is one typed action input.
type Input struct {
	Name        string `yaml:"name" json:"name"`
	Label       string `yaml:"label" json:"label,omitempty"`
	Type        string `yaml:"type" json:"type"`
	Required    bool   `yaml:"required" json:"required,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
	Default     any    `yaml:"default" json:"default,omitempty"`
	// Enum restricts a string input.
	Enum []string `yaml:"enum" json:"enum,omitempty"`
}

// Request is the HTTP call of an action. Path, query, header and form
// values and the strings inside Body are templates over inputs and params.
type Request struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Query   map[string]string `yaml:"query"`
	Headers map[string]string `yaml:"headers"`
	// Body is sent as JSON; Form as application/x-www-form-urlencoded.
	Body any               `yaml:"body"`
	Form map[string]string `yaml:"form"`
}

// Key returns "connector.action".
func Key(connectorID, actionID string) string { return connectorID + "." + actionID }

// Action returns the named action.
func (c *Connector) Action(id string) (*Action, bool) {
	for i := range c.Actions {
		if c.Actions[i].ID == id {
			return &c.Actions[i], true
		}
	}
	return nil, false
}

// Input returns the named input.
func (a *Action) Input(name string) (*Input, bool) {
	for i := range a.Inputs {
		if a.Inputs[i].Name == name {
			return &a.Inputs[i], true
		}
	}
	return nil, false
}

var (
	idPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	outputPattern = regexp.MustCompile(`^[a-zA-Z][A-Za-z0-9_]{0,63}$`)
)

// TemplateRoots are the names connector templates may read.
var TemplateRoots = map[string]bool{"inputs": true, "params": true}

// OutputRoots are the names output mappings may read.
var OutputRoots = map[string]bool{"response": true, "inputs": true}

// reservedOutputs are fields every action result carries.
var reservedOutputs = map[string]bool{"status": true, "body": true, "bodyTruncated": true}

// Validate checks a template for structural mistakes and compiles every
// template and output expression.
func (c *Connector) Validate() error {
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("connector id %q must be lower-case letters, digits and _", c.ID)
	}
	if strings.TrimSpace(c.Title) == "" {
		return fmt.Errorf("connector %s: title is required", c.ID)
	}
	secrets := map[string]bool{}
	for _, f := range c.Secrets {
		if !idPattern.MatchString(f.Name) {
			return fmt.Errorf("connector %s: secret name %q is invalid", c.ID, f.Name)
		}
		secrets[f.Name] = true
	}
	for _, f := range c.Params {
		if !idPattern.MatchString(f.Name) {
			return fmt.Errorf("connector %s: param name %q is invalid", c.ID, f.Name)
		}
	}
	if !c.Builtin {
		if !strings.HasPrefix(c.BaseURL, "https://") && !strings.HasPrefix(c.BaseURL, "http://") && c.BaseURL != "" {
			return fmt.Errorf("connector %s: baseUrl must be http(s)", c.ID)
		}
		if err := c.validateAuth(secrets); err != nil {
			return fmt.Errorf("connector %s: %w", c.ID, err)
		}
	}
	if len(c.Actions) == 0 {
		return fmt.Errorf("connector %s has no actions", c.ID)
	}
	seen := map[string]bool{}
	for i := range c.Actions {
		a := &c.Actions[i]
		if !idPattern.MatchString(a.ID) {
			return fmt.Errorf("connector %s: action id %q is invalid", c.ID, a.ID)
		}
		if seen[a.ID] {
			return fmt.Errorf("connector %s: duplicate action %s", c.ID, a.ID)
		}
		seen[a.ID] = true
		if err := c.validateAction(a); err != nil {
			return fmt.Errorf("action %s: %w", Key(c.ID, a.ID), err)
		}
	}
	if c.TestAction != "" {
		a, ok := c.Action(c.TestAction)
		if !ok {
			return fmt.Errorf("connector %s: testAction %q not found", c.ID, c.TestAction)
		}
		if a.Category == CategoryResponse {
			return fmt.Errorf("connector %s: testAction must not be a response action", c.ID)
		}
	}
	return nil
}

func (c *Connector) validateAuth(secrets map[string]bool) error {
	need := func(names ...string) error {
		for _, n := range names {
			if !secrets[n] {
				return fmt.Errorf("auth refers to undeclared secret %q", n)
			}
		}
		return nil
	}
	switch c.Auth.Type {
	case "", AuthNone:
		return nil
	case AuthHeader, AuthQuery:
		if strings.TrimSpace(c.Auth.Name) == "" {
			return fmt.Errorf("auth %s needs name", c.Auth.Type)
		}
		return need(c.Auth.Secret)
	case AuthBearer:
		return need(c.Auth.Secret)
	case AuthBasic:
		return need(c.Auth.Username, c.Auth.Password)
	case AuthOAuth2ClientCredentials:
		if strings.TrimSpace(c.Auth.TokenURL) == "" {
			return fmt.Errorf("oauth2 auth needs tokenUrl")
		}
		if err := checkTemplate(c.Auth.TokenURL, TemplateRoots); err != nil {
			return fmt.Errorf("tokenUrl: %w", err)
		}
		if err := checkTemplate(c.Auth.Scope, TemplateRoots); err != nil {
			return fmt.Errorf("scope: %w", err)
		}
		return need(defaultName(c.Auth.ClientID, "client_id"), defaultName(c.Auth.ClientSecret, "client_secret"))
	}
	return fmt.Errorf("unsupported auth type %q", c.Auth.Type)
}

func defaultName(name, fallback string) string {
	if strings.TrimSpace(name) == "" {
		return fallback
	}
	return name
}

func (c *Connector) validateAction(a *Action) error {
	switch a.Category {
	case CategoryEnrichment, CategoryResponse, CategoryUtility:
	default:
		return fmt.Errorf("category must be enrichment, response or utility")
	}
	if strings.TrimSpace(a.Title) == "" {
		return fmt.Errorf("title is required")
	}
	names := map[string]bool{}
	for _, in := range a.Inputs {
		if !idPattern.MatchString(in.Name) {
			return fmt.Errorf("input name %q is invalid", in.Name)
		}
		if names[in.Name] {
			return fmt.Errorf("duplicate input %s", in.Name)
		}
		names[in.Name] = true
		switch in.Type {
		case TypeString, TypeNumber, TypeBoolean, TypeList, TypeObject, TypeAny:
		default:
			return fmt.Errorf("input %s has unsupported type %q", in.Name, in.Type)
		}
	}
	if !c.Builtin {
		switch strings.ToUpper(a.Request.Method) {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			return fmt.Errorf("request method %q is not supported", a.Request.Method)
		}
		if !strings.HasPrefix(a.Request.Path, "/") {
			return fmt.Errorf("request path must start with /")
		}
		if a.Request.Body != nil && len(a.Request.Form) > 0 {
			return fmt.Errorf("request has both body and form")
		}
		templates := []string{a.Request.Path}
		for _, m := range []map[string]string{a.Request.Query, a.Request.Headers, a.Request.Form} {
			for _, v := range m {
				templates = append(templates, v)
			}
		}
		templates = append(templates, bodyStrings(a.Request.Body)...)
		for _, t := range templates {
			if err := checkTemplate(t, TemplateRoots); err != nil {
				return err
			}
		}
	}
	for name, src := range a.Output {
		if !outputPattern.MatchString(name) {
			return fmt.Errorf("output name %q is invalid", name)
		}
		if reservedOutputs[name] {
			return fmt.Errorf("output name %q is reserved", name)
		}
		if _, err := expr.CompileWith(src, OutputRoots); err != nil {
			return fmt.Errorf("output %s: %w", name, err)
		}
	}
	if strings.TrimSpace(a.FailIf) != "" {
		if _, err := expr.CompileWith(a.FailIf, OutputRoots); err != nil {
			return fmt.Errorf("failIf: %w", err)
		}
	}
	if a.TimeoutSeconds < 0 || a.TimeoutSeconds > 300 {
		return fmt.Errorf("timeoutSeconds must be 0 to 300")
	}
	return nil
}

// bodyStrings lists every string inside a request body.
func bodyStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case map[string]any:
		var out []string
		for _, x := range t {
			out = append(out, bodyStrings(x)...)
		}
		return out
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, bodyStrings(x)...)
		}
		return out
	}
	return nil
}
