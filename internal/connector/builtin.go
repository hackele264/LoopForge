package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"agentflow/internal/domain"
)

// CaseService is what the built-in case actions need from the platform. The
// HTTP layer implements it so case changes fire case triggers and land on the
// timeline exactly like changes made in the UI.
type CaseService interface {
	// CaseComment adds a comment to the case timeline.
	CaseComment(ctx context.Context, run RunContext, body string) error
	// CaseUpdate changes status, resolution or severity; empty values stay.
	CaseUpdate(ctx context.Context, run RunContext, change CaseChange) (domain.Case, error)
	// CaseAddIOCs adds indicators and returns how many were new.
	CaseAddIOCs(ctx context.Context, run RunContext, iocs []domain.CaseIOC) (int, error)
}

// CaseVerdictService records a triage verdict on the run's case. It is
// optional: a CaseService without it leaves case_set_verdict unavailable.
type CaseVerdictService interface {
	CaseSetVerdict(ctx context.Context, run RunContext, verdict CaseVerdict) (domain.Case, error)
}

// CaseVerdict is the case_set_verdict action's input.
type CaseVerdict struct {
	Verdict    string
	Confidence *float64
	Rationale  string
}

// CaseChange is the case_update action's input.
type CaseChange struct {
	Status     string
	Resolution string
	Severity   string
}

func builtinConnector() *Connector {
	caseNote := "运行需关联案件（由 Webhook 开案、案件触发器或在案件上手动运行）"
	return &Connector{
		ID:          BuiltinID,
		Title:       "LoopForge 内置动作",
		Description: "在当前运行关联的案件上记录结论、修改状态，以及从任意数据中提取 IOC。不需要连接。",
		Builtin:     true,
		Source:      "builtin",
		Actions: []Action{
			{
				ID: "extract_iocs", Title: "提取 IOC", Category: CategoryUtility,
				Description:  "从任意 JSON 或文本中提取 IP、域名、URL、邮箱、哈希和 CVE，按类型输出列表。",
				Inputs:       []Input{{Name: "value", Label: "数据", Type: TypeAny, Required: true, Description: "例如 {{ trigger }} 或 {{ trigger.alert.body }}"}},
				OutputFields: []string{"count", "cve", "domain", "email", "iocs", "ipv4", "md5", "sha1", "sha256", "url"},
			},
			{
				ID: "case_comment", Title: "案件评论", Category: CategoryUtility,
				Description: "在案件时间线上记一条评论。" + caseNote + "。",
				Inputs:      []Input{{Name: "body", Label: "内容", Type: TypeString, Required: true}},
			},
			{
				ID: "case_update", Title: "更新案件", Category: CategoryUtility,
				Description: "修改案件状态、处置结论或严重度；留空的项不变。关闭案件需要处置结论。" + caseNote + "。",
				Inputs: []Input{
					{Name: "status", Label: "状态", Type: TypeString, Enum: []string{domain.CaseStatusNew, domain.CaseStatusInvestigating, domain.CaseStatusPendingResponse, domain.CaseStatusClosed}},
					{Name: "resolution", Label: "处置结论", Type: TypeString, Enum: []string{domain.CaseResolutionFalsePositive, domain.CaseResolutionResolved, domain.CaseResolutionDuplicate}},
					{Name: "severity", Label: "严重度", Type: TypeString, Enum: []string{domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical}},
				},
				OutputFields: []string{"severity", "status"},
			},
			{
				ID: "case_add_iocs", Title: "案件添加 IOC", Category: CategoryUtility,
				Description:  "把 IOC 列表（如提取 IOC 的 iocs 输出）加到案件。" + caseNote + "。",
				Inputs:       []Input{{Name: "iocs", Label: "IOC 列表", Type: TypeList, Required: true, Description: "[{type, value}] 列表，例如 {{ nodes.extract.data.iocs }}"}},
				OutputFields: []string{"added"},
			},
			{
				ID: "case_set_verdict", Title: "记录研判结论", Category: CategoryUtility,
				Description: "把 Agent 研判结论（malicious / benign / false_positive / needs_review）、置信度和理由记到案件上，用于与分析员关闭案件时的结论对比。" + caseNote + "。",
				Inputs: []Input{
					{Name: "verdict", Label: "结论", Type: TypeString, Required: true, Enum: domain.AgentVerdicts, Description: "例如 {{ nodes.triage.data.verdict }}"},
					{Name: "confidence", Label: "置信度（0–1）", Type: TypeNumber},
					{Name: "rationale", Label: "理由", Type: TypeString},
				},
				OutputFields: []string{"verdict"},
			},
		},
	}
}

func (x *Executor) executeBuiltin(ctx context.Context, a *Action, inputs map[string]any, run RunContext) (Result, error) {
	if a.ID == "extract_iocs" {
		found := domain.ExtractIOCs(inputs["value"])
		out := map[string]any{"count": float64(len(found))}
		var all []any
		for _, t := range domain.IOCTypes {
			out[t] = []any{}
		}
		for _, ioc := range found {
			out[ioc.Type] = append(out[ioc.Type].([]any), ioc.Value)
			all = append(all, map[string]any{"type": ioc.Type, "value": ioc.Value})
		}
		if all == nil {
			all = []any{}
		}
		out["iocs"] = all
		return Result{Output: out, Summary: fmt.Sprintf("提取到 %d 个 IOC", len(found))}, nil
	}
	if x.cases == nil {
		return Result{}, errors.New("案件动作未启用")
	}
	if strings.TrimSpace(run.CaseID) == "" {
		return Result{}, errors.New("运行没有关联案件，无法执行案件动作")
	}
	switch a.ID {
	case "case_comment":
		body := strings.TrimSpace(fmt.Sprint(inputs["body"]))
		if body == "" || len(body) > 10000 {
			return Result{}, errors.New("评论需为 1 到 10000 个字符")
		}
		if err := x.cases.CaseComment(ctx, run, body); err != nil {
			return Result{}, err
		}
		return Result{Output: map[string]any{}, Summary: "已在案件上评论"}, nil
	case "case_update":
		change := CaseChange{}
		change.Status, _ = inputs["status"].(string)
		change.Resolution, _ = inputs["resolution"].(string)
		change.Severity, _ = inputs["severity"].(string)
		if change == (CaseChange{}) {
			return Result{}, errors.New("至少填写状态、处置结论或严重度中的一项")
		}
		updated, err := x.cases.CaseUpdate(ctx, run, change)
		if err != nil {
			return Result{}, err
		}
		return Result{Output: map[string]any{"status": updated.Status, "severity": updated.Severity}, Summary: "已更新案件 #" + fmt.Sprint(updated.Number)}, nil
	case "case_set_verdict":
		svc, ok := x.cases.(CaseVerdictService)
		if !ok {
			return Result{}, errors.New("记录研判结论未启用")
		}
		v := CaseVerdict{}
		v.Verdict, _ = inputs["verdict"].(string)
		v.Rationale, _ = inputs["rationale"].(string)
		if c, ok := inputs["confidence"].(float64); ok {
			v.Confidence = &c
		}
		updated, err := svc.CaseSetVerdict(ctx, run, v)
		if err != nil {
			return Result{}, err
		}
		return Result{Output: map[string]any{"verdict": updated.AgentVerdict}, Summary: fmt.Sprintf("案件 #%d 研判结论：%s", updated.Number, updated.AgentVerdict)}, nil
	case "case_add_iocs":
		var iocs []domain.CaseIOC
		list, _ := inputs["iocs"].([]any)
		for _, item := range list {
			switch t := item.(type) {
			case map[string]any:
				kind, _ := t["type"].(string)
				value, _ := t["value"].(string)
				if kind != "" && value != "" {
					iocs = append(iocs, domain.CaseIOC{Type: kind, Value: value})
				}
			case string:
				// A bare value: classify it the way alert extraction would.
				for _, found := range domain.ExtractIOCs(t) {
					iocs = append(iocs, found)
				}
			}
		}
		for _, ioc := range iocs {
			valid := false
			for _, t := range domain.IOCTypes {
				valid = valid || t == ioc.Type
			}
			if !valid {
				return Result{}, fmt.Errorf("未知 IOC 类型 %q", ioc.Type)
			}
		}
		if len(iocs) > domain.MaxIOCsPerAlert {
			iocs = iocs[:domain.MaxIOCsPerAlert]
		}
		added, err := x.cases.CaseAddIOCs(ctx, run, iocs)
		if err != nil {
			return Result{}, err
		}
		return Result{Output: map[string]any{"added": float64(added)}, Summary: fmt.Sprintf("案件新增 %d 个 IOC", added)}, nil
	}
	return Result{}, fmt.Errorf("未知内置动作 %s", a.ID)
}
