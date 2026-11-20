package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
	"agentflow/internal/repo"

	"github.com/gin-gonic/gin"
)

// connectionsHandlers serves the connector catalog and project connections.
type connectionsHandlers struct {
	*deps
	cases *casesHandlers
	// executor runs 测试连接; it has no case service, so built-in case
	// actions are never reachable from here.
	executor *connector.Executor
}

func newConnectionsHandlers(d *deps, cases *casesHandlers) *connectionsHandlers {
	return &connectionsHandlers{deps: d, cases: cases, executor: connector.NewExecutor(nil, nil)}
}

// connectors answers GET /api/connectors: every connector with its actions,
// parameters and secret names (never values).
func (h *connectionsHandlers) connectors(c *gin.Context) {
	c.JSON(http.StatusOK, connector.Default().Connectors())
}

// connectorByID answers GET /api/connectors/{id}.
func (h *connectionsHandlers) connectorByID(c *gin.Context) {
	conn, ok := connector.Default().Connector(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector not found"})
		return
	}
	c.JSON(http.StatusOK, conn)
}

// connectionInput is the create and update body. Secrets: a non-empty value
// sets that secret, an omitted or empty one keeps the stored value;
// clearSecrets removes the named secrets.
type connectionInput struct {
	ProjectID    string            `json:"projectId"`
	ConnectorID  string            `json:"connectorId"`
	Name         string            `json:"name"`
	BaseURL      *string           `json:"baseUrl"`
	Params       map[string]string `json:"params"`
	Secrets      map[string]string `json:"secrets"`
	ClearSecrets []string          `json:"clearSecrets"`
}

func newConnectionID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "cn-" + hex.EncodeToString(raw), nil
}

// connections answers GET (list, project readers) and POST (create,
// project writers) /api/connections.
func (h *connectionsHandlers) connections(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		projectID := strings.TrimSpace(c.Query("projectId"))
		if projectID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "projectId is required"})
			return
		}
		if !h.cases.projectReader(c, projectID) {
			return
		}
		list, err := h.repo.Connections(projectID, strings.TrimSpace(c.Query("connectorId")))
		if err != nil {
			respond(c, err)
			return
		}
		c.JSON(http.StatusOK, list)
		return
	}
	var req connectionInput
	if !decode(c, &req) {
		return
	}
	def, ok := connector.Default().Connector(strings.TrimSpace(req.ConnectorID))
	if !ok || def.Builtin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown connector " + req.ConnectorID})
		return
	}
	if !h.requireProjectWriter(c, strings.TrimSpace(req.ProjectID)) {
		return
	}
	user, _ := h.requestUser(c.Request, true)
	id, err := newConnectionID()
	if err != nil {
		respond(c, err)
		return
	}
	now := time.Now().UTC()
	conn := domain.Connection{ID: id, ProjectID: strings.TrimSpace(req.ProjectID), ConnectorID: def.ID, CreatedBy: user.ID, CreatedAt: now, UpdatedAt: now}
	if err := applyConnectionInput(&conn, def, req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.repo.PutConnection(conn); err != nil {
		respond(c, err)
		return
	}
	stored, _ := h.repo.Connection(conn.ID)
	c.JSON(http.StatusCreated, connectionView(stored))
}

// applyConnectionInput validates and applies a create or update body.
func applyConnectionInput(conn *domain.Connection, def *connector.Connector, req connectionInput) error {
	if strings.TrimSpace(req.Name) != "" || conn.Name == "" {
		conn.Name = strings.TrimSpace(req.Name)
	}
	if req.BaseURL != nil {
		conn.BaseURL = strings.TrimRight(strings.TrimSpace(*req.BaseURL), "/")
	}
	if req.Params != nil {
		params := map[string]string{}
		for name, v := range req.Params {
			known := false
			for _, f := range def.Params {
				known = known || f.Name == name
			}
			if !known {
				return fmt.Errorf("connector %s has no param %q", def.ID, name)
			}
			if v = strings.TrimSpace(v); v != "" {
				params[name] = v
			}
		}
		conn.Params = params
	}
	if conn.Secrets == nil {
		conn.Secrets = map[string]string{}
	}
	known := map[string]bool{}
	for _, f := range def.Secrets {
		known[f.Name] = true
	}
	for name, v := range req.Secrets {
		if !known[name] {
			return fmt.Errorf("connector %s has no secret %q", def.ID, name)
		}
		if v = strings.TrimSpace(v); v != "" {
			if len(v) > 8192 {
				return fmt.Errorf("secret %s is too long", name)
			}
			conn.Secrets[name] = v
		}
	}
	for _, name := range req.ClearSecrets {
		delete(conn.Secrets, name)
	}
	return conn.ValidateConnectionBase()
}

// connectionView strips secret values.
func connectionView(c domain.Connection) domain.Connection {
	c.Secrets = nil
	if c.SecretsSet == nil {
		c.SecretsSet = []string{}
	}
	return c
}

func (h *connectionsHandlers) loadConnection(c *gin.Context, write bool) (domain.Connection, *connector.Connector, bool) {
	conn, ok := h.repo.Connection(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "connection not found"})
		return domain.Connection{}, nil, false
	}
	def, ok := connector.Default().Connector(conn.ConnectorID)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"error": "connector " + conn.ConnectorID + " is no longer installed"})
		return domain.Connection{}, nil, false
	}
	if write {
		return conn, def, h.requireProjectWriter(c, conn.ProjectID)
	}
	return conn, def, h.cases.projectReader(c, conn.ProjectID)
}

// connection answers GET, PUT and DELETE /api/connections/{id}.
func (h *connectionsHandlers) connection(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		conn, _, ok := h.loadConnection(c, false)
		if ok {
			c.JSON(http.StatusOK, connectionView(conn))
		}
		return
	}
	conn, def, ok := h.loadConnection(c, true)
	if !ok {
		return
	}
	if c.Request.Method == http.MethodDelete {
		if err := h.repo.DeleteConnection(conn.ID); err != nil {
			respondConnectionError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
		return
	}
	var req connectionInput
	if !decode(c, &req) {
		return
	}
	if err := applyConnectionInput(&conn, def, req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	conn.UpdatedAt = time.Now().UTC()
	if err := h.repo.PutConnection(conn); err != nil {
		respond(c, err)
		return
	}
	stored, _ := h.repo.Connection(conn.ID)
	c.JSON(http.StatusOK, connectionView(stored))
}

type connectionTestResult struct {
	OK         bool           `json:"ok"`
	Action     string         `json:"action"`
	Summary    string         `json:"summary,omitempty"`
	Error      string         `json:"error,omitempty"`
	Output     map[string]any `json:"output,omitempty"`
	DurationMs int64          `json:"durationMs"`
}

// testConnection answers POST /api/connections/{id}/test: run the
// connector's read-only test action with this connection.
func (h *connectionsHandlers) testConnection(c *gin.Context) {
	conn, def, ok := h.loadConnection(c, true)
	if !ok {
		return
	}
	if def.TestAction == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该连接器没有可用于测试的只读动作"})
		return
	}
	a, _ := def.Action(def.TestAction)
	started := time.Now()
	res, err := h.executor.Execute(c.Request.Context(), connector.Call{Connector: def, Action: a, Connection: &conn, Inputs: def.TestInputs, Run: connector.RunContext{ProjectID: conn.ProjectID}})
	out := connectionTestResult{OK: err == nil, Action: a.Title, DurationMs: time.Since(started).Milliseconds()}
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Summary = res.Summary
		delete(res.Output, "body")
		out.Output = res.Output
	}
	c.JSON(http.StatusOK, out)
}

// respondConnectionError maps repository errors.
func respondConnectionError(c *gin.Context, err error) {
	if err == repo.ErrConnectionNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	respond(c, err)
}
