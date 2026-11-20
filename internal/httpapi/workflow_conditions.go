package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"agentflow/internal/domain"
	"agentflow/internal/engine"
	"agentflow/internal/expr"

	"github.com/gin-gonic/gin"
)

// conditionCheckRequest is a RunIf dry run: an expression plus sample data
// shaped like a run. Workflow and NodeID optionally add the upstream check
// that saving the workflow performs.
type conditionCheckRequest struct {
	Expression string                     `json:"expression"`
	Trigger    json.RawMessage            `json:"trigger,omitempty"`
	Input      string                     `json:"input,omitempty"`
	Nodes      map[string]conditionSample `json:"nodes,omitempty"`
	Workflow   *domain.WorkflowDefinition `json:"workflow,omitempty"`
	NodeID     string                     `json:"nodeId,omitempty"`
}

// conditionSample is one upstream node's state as a condition sees it.
type conditionSample struct {
	Status string          `json:"status,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// checkCondition answers POST /api/workflow-conditions/check. It reads no
// stored data and runs nothing: the expression is evaluated in-process
// against the request's sample values only.
func (h *catalogHandlers) checkCondition(c *gin.Context) {
	var req conditionCheckRequest
	if !decode(c, &req) {
		return
	}
	src := strings.TrimSpace(req.Expression)
	if src == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expression is required"})
		return
	}
	if len(src) > expr.MaxLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expression is too long"})
		return
	}
	sample := domain.Run{ID: "condition-check", Input: req.Input, Nodes: map[string]*domain.NodeRun{}}
	if trigger := strings.TrimSpace(string(req.Trigger)); trigger != "" && trigger != "null" {
		var object map[string]any
		if json.Unmarshal(req.Trigger, &object) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "trigger must be a JSON object"})
			return
		}
		sample.TriggerPayload = domain.RawJSON(trigger)
	}
	for id, node := range req.Nodes {
		status := strings.TrimSpace(node.Status)
		if status == "" {
			status = "succeeded"
		}
		run := &domain.NodeRun{NodeID: id, Status: status}
		if data := strings.TrimSpace(string(node.Data)); data != "" && data != "null" {
			validated, err := domain.ValidateNodeOutput(nil, node.Data)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "nodes." + id + ".data: " + err.Error()})
				return
			}
			run.Data = validated
		}
		sample.Nodes[id] = run
	}
	c.JSON(http.StatusOK, engine.CheckCondition(src, sample, req.Workflow, req.NodeID))
}
