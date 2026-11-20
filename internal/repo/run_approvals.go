package repo

import (
	"encoding/json"

	"agentflow/internal/domain"
)

// ApprovalWait is an approval node waiting with vote/deadline state.
type ApprovalWait struct {
	RunID  string
	NodeID string
	State  *domain.ApprovalState
}

// WaitingApprovals lists approval nodes that are waiting and carry an
// ApprovalState (two-person approval or a deadline). Only the state is read
// from the node payload; the engine re-reads the full run before acting.
func (r *RunsRepo) WaitingApprovals() ([]ApprovalWait, error) {
	var rows []struct {
		RunID   string
		NodeID  string
		Payload []byte
	}
	err := r.DB.Model(&runNodeRow{}).
		Select("run_id, node_id, JSON_EXTRACT(payload, '$.approval') AS payload").
		Where("status = ?", "waiting_approval").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]ApprovalWait, 0, len(rows))
	for _, row := range rows {
		if len(row.Payload) == 0 || string(row.Payload) == "null" {
			continue
		}
		var st domain.ApprovalState
		if json.Unmarshal(row.Payload, &st) != nil {
			continue
		}
		out = append(out, ApprovalWait{RunID: row.RunID, NodeID: row.NodeID, State: &st})
	}
	return out, nil
}
