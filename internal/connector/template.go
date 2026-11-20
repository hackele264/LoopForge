package connector

import (
	"fmt"
	"strings"

	"agentflow/internal/expr"
)

// A template is text with "{{ expression }}" parts. A template that is
// exactly one part evaluates to the expression's value with its type; any
// other template evaluates to text.

type templatePart struct {
	text    string
	program *expr.Program
}

func parseTemplate(src string, roots map[string]bool) ([]templatePart, error) {
	var parts []templatePart
	rest := src
	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			if rest != "" {
				parts = append(parts, templatePart{text: rest})
			}
			return parts, nil
		}
		if open > 0 {
			parts = append(parts, templatePart{text: rest[:open]})
		}
		closeAt := strings.Index(rest[open:], "}}")
		if closeAt < 0 {
			return nil, fmt.Errorf("template %q has an unclosed {{", src)
		}
		source := rest[open+2 : open+closeAt]
		program, err := expr.CompileWith(source, roots)
		if err != nil {
			return nil, fmt.Errorf("template %q: %w", src, err)
		}
		parts = append(parts, templatePart{program: program})
		rest = rest[open+closeAt+2:]
	}
}

// checkTemplate compiles a template without evaluating it.
func checkTemplate(src string, roots map[string]bool) error {
	_, err := parseTemplate(src, roots)
	return err
}

// IsTemplate reports whether src contains an expression part.
func IsTemplate(src string) bool { return strings.Contains(src, "{{") }

// RenderTemplate evaluates a template against env. escape, when set,
// transforms each expression's text before it is joined (path escaping).
func RenderTemplate(src string, roots map[string]bool, env map[string]any, escape func(string) string) (any, error) {
	parts, err := parseTemplate(src, roots)
	if err != nil {
		return nil, err
	}
	if len(parts) == 1 && parts[0].program != nil && escape == nil {
		return parts[0].program.Eval(env)
	}
	var b strings.Builder
	for _, p := range parts {
		if p.program == nil {
			b.WriteString(p.text)
			continue
		}
		v, err := p.program.Eval(env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.program.Source(), err)
		}
		text := expr.Text(v)
		if escape != nil {
			text = escape(text)
		}
		b.WriteString(text)
	}
	return b.String(), nil
}

// renderText renders a template and returns text.
func renderText(src string, roots map[string]bool, env map[string]any) (string, error) {
	v, err := RenderTemplate(src, roots, env, nil)
	if err != nil {
		return "", err
	}
	return expr.Text(v), nil
}

// renderValue renders every string inside a JSON-like value.
func renderValue(v any, roots map[string]bool, env map[string]any) (any, error) {
	switch t := v.(type) {
	case string:
		if !IsTemplate(t) {
			return t, nil
		}
		return RenderTemplate(t, roots, env, nil)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			r, err := renderValue(x, roots, env)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(t))
		for _, x := range t {
			r, err := renderValue(x, roots, env)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}
	return v, nil
}

// WorkflowRoots are the names an action node's input templates may read.
var WorkflowRoots = expr.Roots

// CheckNodeInputs compiles an action node's input templates.
func CheckNodeInputs(inputs map[string]string) error {
	for name, src := range inputs {
		if err := checkTemplate(src, WorkflowRoots); err != nil {
			return fmt.Errorf("input %s: %w", name, err)
		}
	}
	return nil
}

// NodeInputRefs lists node IDs read by an action node's input templates.
func NodeInputRefs(inputs map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, src := range inputs {
		parts, err := parseTemplate(src, WorkflowRoots)
		if err != nil {
			continue
		}
		for _, p := range parts {
			if p.program == nil {
				continue
			}
			for _, ref := range p.program.NodeRefs() {
				if !seen[ref] {
					seen[ref] = true
					out = append(out, ref)
				}
			}
		}
	}
	return out
}

// EvalNodeInputs renders an action node's inputs against a run environment
// (trigger, nodes, run).
func EvalNodeInputs(inputs map[string]string, env map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(inputs))
	for name, src := range inputs {
		if !IsTemplate(src) {
			out[name] = src
			continue
		}
		v, err := RenderTemplate(src, WorkflowRoots, env, nil)
		if err != nil {
			return nil, fmt.Errorf("input %s: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}

// SourceRoots are the names an alert source's input templates may read.
var SourceRoots = map[string]bool{"window": true}

// CheckSourceInputs compiles an alert source's input templates.
func CheckSourceInputs(inputs map[string]string) error {
	for name, src := range inputs {
		if err := checkTemplate(src, SourceRoots); err != nil {
			return fmt.Errorf("input %s: %w", name, err)
		}
	}
	return nil
}

// EvalSourceInputs renders an alert source's inputs for one window.
func EvalSourceInputs(inputs map[string]string, window map[string]any) (map[string]any, error) {
	env := map[string]any{"window": window}
	out := make(map[string]any, len(inputs))
	for name, src := range inputs {
		if !IsTemplate(src) {
			out[name] = src
			continue
		}
		v, err := RenderTemplate(src, SourceRoots, env, nil)
		if err != nil {
			return nil, fmt.Errorf("input %s: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}
