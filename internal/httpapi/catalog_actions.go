package httpapi

import (
	"fmt"
	"strings"

	"agentflow/internal/connector"
	"agentflow/internal/domain"
)

// validateWorkflowActions checks a workflow's action nodes on save: known
// actions, valid inputs, response actions behind an approval, and
// connections that exist in the workflow's project.
func (h *catalogHandlers) validateWorkflowActions(wf domain.WorkflowDefinition) error {
	if err := connector.ValidateWorkflow(wf, connector.Default()); err != nil {
		return err
	}
	for _, n := range wf.Nodes {
		if n.Type != connector.NodeType || n.Action == nil {
			continue
		}
		id := strings.TrimSpace(n.Action.ConnectionID)
		if id == "" {
			continue
		}
		conn, ok := h.repo.Connection(id)
		if !ok {
			return fmt.Errorf("node %s: connection %s not found", n.ID, id)
		}
		if conn.ConnectorID != n.Action.Connector {
			return fmt.Errorf("node %s: connection %s is for connector %s", n.ID, conn.Name, conn.ConnectorID)
		}
		if wf.ProjectID != "" && conn.ProjectID != wf.ProjectID {
			return fmt.Errorf("node %s: connection %s belongs to another project", n.ID, conn.Name)
		}
	}
	return nil
}
