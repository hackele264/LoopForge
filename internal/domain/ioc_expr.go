package domain

import (
	"fmt"

	"agentflow/internal/expr"
)

// iocs(value) lists every indicator found in value (any JSON value) as
// {"type", "value"} objects; iocs(value, "ipv4") lists the values of one type.
func init() {
	expr.RegisterFunction("iocs", func(args []any) (any, error) {
		if len(args) != 1 && len(args) != 2 {
			return nil, fmt.Errorf("iocs takes 1 or 2 arguments, got %d", len(args))
		}
		kind := ""
		if len(args) == 2 {
			s, ok := args[1].(string)
			if !ok {
				return nil, fmt.Errorf("iocs: type must be a string")
			}
			kind = s
			valid := false
			for _, t := range IOCTypes {
				valid = valid || t == kind
			}
			if !valid {
				return nil, fmt.Errorf("iocs: unknown type %q", kind)
			}
		}
		out := []any{}
		for _, ioc := range ExtractIOCs(args[0]) {
			switch {
			case kind == "":
				out = append(out, map[string]any{"type": ioc.Type, "value": ioc.Value})
			case ioc.Type == kind:
				out = append(out, ioc.Value)
			}
		}
		return out, nil
	})
}
