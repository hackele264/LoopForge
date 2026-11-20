package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/expr"
)

const (
	defaultTimeout = 30 * time.Second
	// maxResponseBytes bounds how much of a response is read.
	maxResponseBytes = 4 << 20
	// MaxOutputBytes bounds the stored structured output of one action; a
	// larger result keeps its mapped fields and drops the raw body.
	MaxOutputBytes = 128 << 10
)

// RunContext identifies the run an action executes for.
type RunContext struct {
	RunID     string
	NodeID    string
	ProjectID string
	CaseID    string
	UserID    int64
}

// Call is one action execution.
type Call struct {
	Connector  *Connector
	Action     *Action
	Connection *domain.Connection
	Inputs     map[string]any
	Run        RunContext
}

// Result is what an action published.
type Result struct {
	// Output becomes the node's structured output (nodes.<id>.data).
	Output map[string]any
	// Summary is one human-readable line for the run timeline.
	Summary string
}

// Executor runs actions. The zero value is not usable; use NewExecutor.
type Executor struct {
	client *http.Client
	cases  CaseService
	tokens *tokenCache
}

// NewExecutor returns an executor using client (nil for a default client)
// and cases for the built-in case actions (nil disables them).
func NewExecutor(client *http.Client, cases CaseService) *Executor {
	if client == nil {
		client = &http.Client{}
	}
	// Never follow a redirect to another host: header secrets such as
	// x-apikey are not stripped by net/http the way Authorization is.
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &Executor{client: &c, cases: cases, tokens: &tokenCache{entries: map[string]tokenEntry{}}}
}

// SetCaseService wires the built-in case actions.
func (x *Executor) SetCaseService(cases CaseService) { x.cases = cases }

// Execute validates inputs and runs the action.
func (x *Executor) Execute(ctx context.Context, call Call) (Result, error) {
	if call.Connector == nil || call.Action == nil {
		return Result{}, errors.New("connector action is not set")
	}
	inputs, err := CoerceInputs(call.Action, call.Inputs)
	if err != nil {
		return Result{}, err
	}
	if call.Connector.Builtin {
		return x.executeBuiltin(ctx, call.Action, inputs, call.Run)
	}
	if call.Connection == nil {
		return Result{}, fmt.Errorf("动作 %s 需要选择连接", Key(call.Connector.ID, call.Action.ID))
	}
	if call.Connection.ConnectorID != call.Connector.ID {
		return Result{}, fmt.Errorf("连接 %s 属于连接器 %s，不能用于 %s", call.Connection.Name, call.Connection.ConnectorID, call.Connector.ID)
	}
	secrets := secretValues(call.Connector, call.Connection)
	result, err := x.executeHTTP(ctx, call, inputs)
	if err != nil {
		return Result{}, errors.New(redact(err.Error(), secrets))
	}
	return result, nil
}

// CoerceInputs applies defaults, checks required inputs and converts values
// to the declared types. Unknown inputs are rejected.
func CoerceInputs(a *Action, raw map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for name := range raw {
		if _, ok := a.Input(name); !ok {
			return nil, fmt.Errorf("动作没有输入项 %s", name)
		}
	}
	for _, in := range a.Inputs {
		v, present := raw[in.Name]
		if s, ok := v.(string); ok && strings.TrimSpace(s) == "" && in.Type != TypeString {
			v, present = nil, false
		}
		if s, ok := v.(string); ok && s == "" {
			v, present = nil, false
		}
		if !present || v == nil {
			v = in.Default
		}
		if v == nil {
			if in.Required {
				return nil, fmt.Errorf("输入项 %s 为空", inputLabel(in))
			}
			continue
		}
		cv, err := coerce(in, v)
		if err != nil {
			return nil, fmt.Errorf("输入项 %s：%w", inputLabel(in), err)
		}
		out[in.Name] = cv
	}
	return out, nil
}

func inputLabel(in Input) string {
	if in.Label != "" {
		return in.Label + "（" + in.Name + "）"
	}
	return in.Name
}

func coerce(in Input, v any) (any, error) {
	switch in.Type {
	case TypeString:
		s := expr.Text(v)
		if _, isList := v.([]any); isList {
			return nil, errors.New("需要文本，得到的是列表")
		}
		if len(in.Enum) > 0 {
			for _, e := range in.Enum {
				if e == s {
					return s, nil
				}
			}
			return nil, fmt.Errorf("只能是 %s", strings.Join(in.Enum, "、"))
		}
		return s, nil
	case TypeNumber:
		switch t := v.(type) {
		case float64:
			return t, nil
		case string:
			f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
			if err != nil {
				return nil, errors.New("需要数字")
			}
			return f, nil
		}
		return nil, errors.New("需要数字")
	case TypeBoolean:
		switch t := v.(type) {
		case bool:
			return t, nil
		case string:
			b, err := strconv.ParseBool(strings.TrimSpace(t))
			if err != nil {
				return nil, errors.New("需要 true 或 false")
			}
			return b, nil
		}
		return nil, errors.New("需要 true 或 false")
	case TypeList:
		switch t := v.(type) {
		case []any:
			return t, nil
		case string:
			var list []any
			if json.Unmarshal([]byte(t), &list) == nil {
				return list, nil
			}
			return []any{t}, nil
		}
		return []any{v}, nil
	case TypeObject:
		switch t := v.(type) {
		case map[string]any:
			return t, nil
		case string:
			var obj map[string]any
			if json.Unmarshal([]byte(t), &obj) == nil {
				return obj, nil
			}
		}
		return nil, errors.New("需要 JSON 对象")
	}
	return v, nil
}

// ConnectionParams merges connector defaults with a connection's params.
func ConnectionParams(c *Connector, conn *domain.Connection) map[string]any {
	params := map[string]any{}
	for _, f := range c.Params {
		params[f.Name] = f.Default
	}
	if conn != nil {
		for k, v := range conn.Params {
			if strings.TrimSpace(v) != "" {
				params[k] = v
			}
		}
	}
	return params
}

// MissingConnectionFields lists required params and secrets a connection
// lacks.
func MissingConnectionFields(c *Connector, conn *domain.Connection) []string {
	var missing []string
	params := ConnectionParams(c, conn)
	for _, f := range c.Params {
		if f.Required && strings.TrimSpace(expr.Text(params[f.Name])) == "" {
			missing = append(missing, f.Label)
		}
	}
	for _, f := range c.Secrets {
		if f.Required && (conn == nil || strings.TrimSpace(conn.Secrets[f.Name]) == "") {
			missing = append(missing, f.Label)
		}
	}
	return missing
}

func secretValues(c *Connector, conn *domain.Connection) []string {
	var out []string
	if conn == nil {
		return nil
	}
	for _, v := range conn.Secrets {
		if len(strings.TrimSpace(v)) >= 4 {
			out = append(out, v)
		}
	}
	return out
}

// redact removes secret values (and their URL-escaped forms) from text.
func redact(text string, secrets []string) string {
	for _, s := range secrets {
		if s == "" {
			continue
		}
		text = strings.ReplaceAll(text, s, "[redacted]")
		if esc := url.QueryEscape(s); esc != s {
			text = strings.ReplaceAll(text, esc, "[redacted]")
		}
	}
	return text
}

func (x *Executor) executeHTTP(ctx context.Context, call Call, inputs map[string]any) (Result, error) {
	c, a, conn := call.Connector, call.Action, call.Connection
	if missing := MissingConnectionFields(c, conn); len(missing) > 0 {
		return Result{}, fmt.Errorf("连接 %s 缺少 %s", conn.Name, strings.Join(missing, "、"))
	}
	base := strings.TrimSpace(conn.BaseURL)
	if base == "" {
		base = c.BaseURL
	}
	if base == "" {
		return Result{}, fmt.Errorf("连接 %s 没有设置服务地址", conn.Name)
	}
	env := map[string]any{"inputs": inputs, "params": ConnectionParams(c, conn)}
	path, err := RenderTemplate(a.Request.Path, TemplateRoots, env, url.PathEscape)
	if err != nil {
		return Result{}, err
	}
	target, err := url.Parse(strings.TrimRight(base, "/") + expr.Text(path))
	if err != nil {
		return Result{}, fmt.Errorf("请求地址无效：%w", err)
	}
	query := target.Query()
	for _, name := range sortedKeys(a.Request.Query) {
		v, err := renderText(a.Request.Query[name], TemplateRoots, env)
		if err != nil {
			return Result{}, err
		}
		if v != "" {
			query.Set(name, v)
		}
	}
	var body io.Reader
	contentType := ""
	if a.Request.Body != nil {
		rendered, err := renderValue(a.Request.Body, TemplateRoots, env)
		if err != nil {
			return Result{}, err
		}
		raw, err := json.Marshal(rendered)
		if err != nil {
			return Result{}, err
		}
		body, contentType = bytes.NewReader(raw), "application/json"
	} else if len(a.Request.Form) > 0 {
		form := url.Values{}
		for _, name := range sortedKeys(a.Request.Form) {
			v, err := renderText(a.Request.Form[name], TemplateRoots, env)
			if err != nil {
				return Result{}, err
			}
			form.Set(name, v)
		}
		body, contentType = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
	}
	timeout := defaultTimeout
	if a.TimeoutSeconds > 0 {
		timeout = time.Duration(a.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	headers.Set("User-Agent", "LoopForge-Connector/1")
	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}
	for _, name := range sortedKeys(a.Request.Headers) {
		v, err := renderText(a.Request.Headers[name], TemplateRoots, env)
		if err != nil {
			return Result{}, err
		}
		headers.Set(name, v)
	}
	if err := x.applyAuth(ctx, c, conn, env, headers, query); err != nil {
		return Result{}, err
	}
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(a.Request.Method), target.String(), body)
	if err != nil {
		return Result{}, err
	}
	req.Header = headers
	resp, err := x.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("%s 请求失败：%w", c.Title, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("读取 %s 响应失败：%w", c.Title, err)
	}
	truncated := len(raw) > maxResponseBytes
	if truncated {
		raw = raw[:maxResponseBytes]
	}
	parsed := parseBody(raw, resp.Header.Get("Content-Type"), truncated)
	if !accepted(a.Success, resp.StatusCode) {
		return Result{}, fmt.Errorf("%s 返回 HTTP %d：%s", c.Title, resp.StatusCode, snippet(raw))
	}
	respHeaders := map[string]any{}
	for name, values := range resp.Header {
		if len(values) > 0 {
			respHeaders[strings.ToLower(name)] = values[0]
		}
	}
	outEnv := map[string]any{"inputs": inputs, "response": map[string]any{"status": float64(resp.StatusCode), "headers": respHeaders, "body": parsed}}
	if strings.TrimSpace(a.FailIf) != "" {
		program, err := expr.CompileWith(a.FailIf, OutputRoots)
		if err != nil {
			return Result{}, err
		}
		failed, err := program.Eval(outEnv)
		if err != nil {
			return Result{}, fmt.Errorf("failIf：%w", err)
		}
		if failed == true {
			return Result{}, fmt.Errorf("%s 返回错误：%s", c.Title, snippet(raw))
		}
	}
	output := map[string]any{"status": float64(resp.StatusCode), "body": parsed}
	for _, name := range a.OutputFields {
		program, err := expr.CompileWith(a.Output[name], OutputRoots)
		if err != nil {
			return Result{}, err
		}
		v, err := program.Eval(outEnv)
		if err != nil {
			return Result{}, fmt.Errorf("输出 %s：%w", name, err)
		}
		output[name] = v
	}
	output = boundOutput(output)
	return Result{Output: output, Summary: fmt.Sprintf("%s · %s：HTTP %d", c.Title, a.Title, resp.StatusCode)}, nil
}

// boundOutput drops the raw body when the output would be too large to
// store, keeping the mapped fields.
func boundOutput(output map[string]any) map[string]any {
	raw, err := json.Marshal(output)
	if err == nil && len(raw) <= MaxOutputBytes {
		return output
	}
	output["body"] = nil
	output["bodyTruncated"] = true
	return output
}

func parseBody(raw []byte, contentType string, truncated bool) any {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	if !truncated && (strings.Contains(contentType, "json") || trimmed[0] == '{' || trimmed[0] == '[') {
		var v any
		if json.Unmarshal(trimmed, &v) == nil {
			return v
		}
	}
	return string(trimmed)
}

func accepted(success []int, status int) bool {
	if len(success) == 0 {
		return status >= 200 && status < 300
	}
	for _, s := range success {
		if s == status {
			return true
		}
	}
	return false
}

func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len([]rune(s)) > 300 {
		s = string([]rune(s)[:300]) + "…"
	}
	if s == "" {
		return "(空响应)"
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (x *Executor) applyAuth(ctx context.Context, c *Connector, conn *domain.Connection, env map[string]any, headers http.Header, query url.Values) error {
	secret := func(name string) string { return conn.Secrets[name] }
	switch c.Auth.Type {
	case "", AuthNone:
	case AuthHeader:
		if v := secret(c.Auth.Secret); v != "" {
			headers.Set(c.Auth.Name, c.Auth.Prefix+v)
		}
	case AuthBearer:
		if v := secret(c.Auth.Secret); v != "" {
			headers.Set("Authorization", "Bearer "+v)
		}
	case AuthBasic:
		token := base64.StdEncoding.EncodeToString([]byte(secret(c.Auth.Username) + ":" + secret(c.Auth.Password)))
		headers.Set("Authorization", "Basic "+token)
	case AuthQuery:
		if v := secret(c.Auth.Secret); v != "" {
			query.Set(c.Auth.Name, v)
		}
	case AuthOAuth2ClientCredentials:
		token, err := x.oauthToken(ctx, c, conn, env)
		if err != nil {
			return err
		}
		headers.Set("Authorization", "Bearer "+token)
	default:
		return fmt.Errorf("unsupported auth type %q", c.Auth.Type)
	}
	return nil
}

type tokenEntry struct {
	token   string
	expires time.Time
}

type tokenCache struct {
	mu      sync.Mutex
	entries map[string]tokenEntry
}

func (x *Executor) oauthToken(ctx context.Context, c *Connector, conn *domain.Connection, env map[string]any) (string, error) {
	tokenURL, err := renderText(c.Auth.TokenURL, TemplateRoots, env)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(tokenURL, "/") {
		base := strings.TrimSpace(conn.BaseURL)
		if base == "" {
			base = c.BaseURL
		}
		tokenURL = strings.TrimRight(base, "/") + tokenURL
	}
	scope, err := renderText(c.Auth.Scope, TemplateRoots, env)
	if err != nil {
		return "", err
	}
	clientID := conn.Secrets[defaultName(c.Auth.ClientID, "client_id")]
	clientSecret := conn.Secrets[defaultName(c.Auth.ClientSecret, "client_secret")]
	sum := sha256.Sum256([]byte(tokenURL + "\x00" + scope + "\x00" + clientID + "\x00" + clientSecret))
	key := conn.ID + ":" + base64.RawURLEncoding.EncodeToString(sum[:])
	x.tokens.mu.Lock()
	if e, ok := x.tokens.entries[key]; ok && time.Now().Before(e.expires) {
		x.tokens.mu.Unlock()
		return e.token, nil
	}
	x.tokens.mu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {clientSecret}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("令牌地址无效：%w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := x.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("获取 %s 访问令牌失败：%w", c.Title, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("获取 %s 访问令牌失败：HTTP %d", c.Title, resp.StatusCode)
	}
	var tok struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("获取 %s 访问令牌失败：响应里没有 access_token", c.Title)
	}
	life := time.Duration(tok.ExpiresIn) * time.Second
	if life <= 0 {
		life = 5 * time.Minute
	}
	life -= time.Minute
	if life > 0 {
		x.tokens.mu.Lock()
		x.tokens.entries[key] = tokenEntry{token: tok.AccessToken, expires: time.Now().Add(life)}
		x.tokens.mu.Unlock()
	}
	return tok.AccessToken, nil
}
