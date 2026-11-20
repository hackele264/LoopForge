// Package expr implements the small, read-only expression language used by
// workflow RunIf conditions.
//
// Grammar (lowest precedence first):
//
//	or      = and { "||" and }
//	and     = cmp { "&&" cmp }
//	cmp     = unary [ ("=="|"!="|"<"|"<="|">"|">="|"in") unary ]
//	unary   = ("!"|"-") unary | postfix
//	postfix = primary { "." ident | "[" or "]" | "(" args ")" }
//	primary = number | string | true | false | null | ident | "(" or ")" | "[" list "]"
//
// Expressions have no side effects and see only the values passed to Eval:
// no environment, clock, randomness or I/O, so a rerun evaluates the same way.
// Reading a missing field yields null instead of an error.
package expr

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLength bounds the source of one expression.
const MaxLength = 2000

const maxDepth = 64

// Program is a parsed expression.
type Program struct {
	src  string
	root node
}

// Source returns the expression text.
func (p *Program) Source() string { return p.src }

// NodeRefs lists the node IDs the program reads through nodes["id"] or
// nodes.id, in first-seen order. Dynamic indexes are not listed.
func (p *Program) NodeRefs() []string {
	seen := map[string]bool{}
	var out []string
	var walk func(node)
	walk = func(n node) {
		switch v := n.(type) {
		case *memberNode:
			if id, ok := v.target.(*identNode); ok && id.name == "nodes" {
				if !seen[v.name] {
					seen[v.name] = true
					out = append(out, v.name)
				}
			}
			walk(v.target)
		case *indexNode:
			if id, ok := v.target.(*identNode); ok && id.name == "nodes" {
				if lit, ok := v.index.(*literalNode); ok {
					if s, ok := lit.value.(string); ok && !seen[s] {
						seen[s] = true
						out = append(out, s)
					}
				}
			}
			walk(v.target)
			walk(v.index)
		case *unaryNode:
			walk(v.operand)
		case *binaryNode:
			walk(v.left)
			walk(v.right)
		case *callNode:
			for _, a := range v.args {
				walk(a)
			}
		case *listNode:
			for _, a := range v.items {
				walk(a)
			}
		}
	}
	walk(p.root)
	return out
}

// Roots are the only identifiers an expression may start from.
var Roots = map[string]bool{"trigger": true, "nodes": true, "run": true}

// Compile parses src and checks that it only uses known roots and functions.
func Compile(src string) (*Program, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, fmt.Errorf("expression is empty")
	}
	if len(src) > MaxLength {
		return nil, fmt.Errorf("expression is longer than %d characters", MaxLength)
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	root, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tokEOF {
		return nil, fmt.Errorf("unexpected %q at offset %d", t.text, t.pos)
	}
	if err := checkNames(root); err != nil {
		return nil, err
	}
	return &Program{src: src, root: root}, nil
}

// Eval evaluates the program against env (JSON-like values: map[string]any,
// []any, string, float64, bool, nil).
func (p *Program) Eval(env map[string]any) (any, error) {
	return eval(p.root, env, 0)
}

// EvalBool evaluates the program and requires a boolean result.
func (p *Program) EvalBool(env map[string]any) (bool, error) {
	v, err := p.Eval(env)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expression must produce true or false, got %s", typeName(v))
	}
	return b, nil
}

// ---------- lexer ----------

type tokKind int

const (
	tokEOF tokKind = iota
	tokNumber
	tokString
	tokIdent
	tokOp
)

type token struct {
	kind tokKind
	text string
	num  float64
	pos  int
}

var twoCharOps = []string{"||", "&&", "==", "!=", "<=", ">="}

func lex(src string) ([]token, error) {
	var out []token
	for i := 0; i < len(src); {
		r, size := utf8.DecodeRuneInString(src[i:])
		switch {
		case unicode.IsSpace(r):
			i += size
		case r == '"' || r == '\'':
			s, n, err := lexString(src[i:])
			if err != nil {
				return nil, fmt.Errorf("%v at offset %d", err, i)
			}
			out = append(out, token{kind: tokString, text: s, pos: i})
			i += n
		case r >= '0' && r <= '9':
			j := i
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.') {
				j++
			}
			f, err := strconv.ParseFloat(src[i:j], 64)
			if err != nil {
				return nil, fmt.Errorf("invalid number %q at offset %d", src[i:j], i)
			}
			out = append(out, token{kind: tokNumber, text: src[i:j], num: f, pos: i})
			i = j
		case r == '_' || unicode.IsLetter(r):
			j := i
			for j < len(src) {
				r2, s2 := utf8.DecodeRuneInString(src[j:])
				if r2 != '_' && !unicode.IsLetter(r2) && !unicode.IsDigit(r2) {
					break
				}
				j += s2
			}
			out = append(out, token{kind: tokIdent, text: src[i:j], pos: i})
			i = j
		default:
			matched := false
			for _, op := range twoCharOps {
				if strings.HasPrefix(src[i:], op) {
					out = append(out, token{kind: tokOp, text: op, pos: i})
					i += 2
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			if strings.ContainsRune("!<>.[]()-,", r) {
				out = append(out, token{kind: tokOp, text: string(r), pos: i})
				i += size
				continue
			}
			return nil, fmt.Errorf("unexpected character %q at offset %d", r, i)
		}
	}
	return append(out, token{kind: tokEOF, pos: len(src)}), nil
}

func lexString(src string) (string, int, error) {
	quote := src[0]
	var b strings.Builder
	for i := 1; i < len(src); i++ {
		c := src[i]
		switch c {
		case quote:
			return b.String(), i + 1, nil
		case '\\':
			if i+1 >= len(src) {
				return "", 0, fmt.Errorf("unterminated string")
			}
			i++
			switch src[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(src[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, fmt.Errorf("unterminated string")
}

// ---------- AST ----------

type node interface{}

type literalNode struct{ value any }
type identNode struct{ name string }
type memberNode struct {
	target node
	name   string
}
type indexNode struct{ target, index node }
type unaryNode struct {
	op      string
	operand node
}
type binaryNode struct {
	op          string
	left, right node
}
type callNode struct {
	name string
	args []node
}
type listNode struct{ items []node }

// ---------- parser ----------

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}
func (p *parser) isOp(s string) bool { t := p.peek(); return t.kind == tokOp && t.text == s }
func (p *parser) expect(s string) error {
	if !p.isOp(s) {
		t := p.peek()
		return fmt.Errorf("expected %q at offset %d", s, t.pos)
	}
	p.next()
	return nil
}

func (p *parser) parseOr(depth int) (node, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("expression is nested too deeply")
	}
	left, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}
	for p.isOp("||") {
		p.next()
		right, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		left = &binaryNode{op: "||", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd(depth int) (node, error) {
	left, err := p.parseCmp(depth)
	if err != nil {
		return nil, err
	}
	for p.isOp("&&") {
		p.next()
		right, err := p.parseCmp(depth)
		if err != nil {
			return nil, err
		}
		left = &binaryNode{op: "&&", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseCmp(depth int) (node, error) {
	left, err := p.parseUnary(depth)
	if err != nil {
		return nil, err
	}
	t := p.peek()
	op := ""
	switch {
	case t.kind == tokOp && (t.text == "==" || t.text == "!=" || t.text == "<" || t.text == "<=" || t.text == ">" || t.text == ">="):
		op = t.text
	case t.kind == tokIdent && t.text == "in":
		op = "in"
	}
	if op == "" {
		return left, nil
	}
	p.next()
	right, err := p.parseUnary(depth)
	if err != nil {
		return nil, err
	}
	return &binaryNode{op: op, left: left, right: right}, nil
}

func (p *parser) parseUnary(depth int) (node, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("expression is nested too deeply")
	}
	if p.isOp("!") || p.isOp("-") {
		op := p.next().text
		operand, err := p.parseUnary(depth + 1)
		if err != nil {
			return nil, err
		}
		return &unaryNode{op: op, operand: operand}, nil
	}
	return p.parsePostfix(depth)
}

func (p *parser) parsePostfix(depth int) (node, error) {
	n, err := p.parsePrimary(depth)
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.isOp("."):
			p.next()
			t := p.next()
			if t.kind != tokIdent {
				return nil, fmt.Errorf("expected field name at offset %d", t.pos)
			}
			n = &memberNode{target: n, name: t.text}
		case p.isOp("["):
			p.next()
			idx, err := p.parseOr(depth + 1)
			if err != nil {
				return nil, err
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			n = &indexNode{target: n, index: idx}
		case p.isOp("("):
			id, ok := n.(*identNode)
			if !ok {
				return nil, fmt.Errorf("only named functions can be called (offset %d)", p.peek().pos)
			}
			p.next()
			var args []node
			for !p.isOp(")") {
				a, err := p.parseOr(depth + 1)
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if !p.isOp(",") {
					break
				}
				p.next()
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			n = &callNode{name: id.name, args: args}
		default:
			return n, nil
		}
	}
}

func (p *parser) parsePrimary(depth int) (node, error) {
	t := p.next()
	switch t.kind {
	case tokNumber:
		return &literalNode{value: t.num}, nil
	case tokString:
		return &literalNode{value: t.text}, nil
	case tokIdent:
		switch t.text {
		case "true":
			return &literalNode{value: true}, nil
		case "false":
			return &literalNode{value: false}, nil
		case "null":
			return &literalNode{value: nil}, nil
		}
		return &identNode{name: t.text}, nil
	case tokOp:
		switch t.text {
		case "(":
			n, err := p.parseOr(depth + 1)
			if err != nil {
				return nil, err
			}
			return n, p.expect(")")
		case "[":
			var items []node
			for !p.isOp("]") {
				it, err := p.parseOr(depth + 1)
				if err != nil {
					return nil, err
				}
				items = append(items, it)
				if !p.isOp(",") {
					break
				}
				p.next()
			}
			return &listNode{items: items}, p.expect("]")
		}
	case tokEOF:
		return nil, fmt.Errorf("unexpected end of expression")
	}
	return nil, fmt.Errorf("unexpected %q at offset %d", t.text, t.pos)
}

// checkNames rejects unknown roots and functions at compile time. Function
// names are only valid in call position; bare identifiers must be roots.
func checkNames(n node) error {
	switch v := n.(type) {
	case *identNode:
		if !Roots[v.name] {
			return fmt.Errorf("unknown name %q (use trigger, nodes or run)", v.name)
		}
	case *memberNode:
		return checkNames(v.target)
	case *indexNode:
		if err := checkNames(v.target); err != nil {
			return err
		}
		return checkNames(v.index)
	case *unaryNode:
		return checkNames(v.operand)
	case *binaryNode:
		if err := checkNames(v.left); err != nil {
			return err
		}
		return checkNames(v.right)
	case *callNode:
		if _, ok := functions[v.name]; !ok {
			return fmt.Errorf("unknown function %q", v.name)
		}
		for _, a := range v.args {
			if err := checkNames(a); err != nil {
				return err
			}
		}
	case *listNode:
		for _, a := range v.items {
			if err := checkNames(a); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------- evaluation ----------

func eval(n node, env map[string]any, depth int) (any, error) {
	if depth > maxDepth*2 {
		return nil, fmt.Errorf("expression is nested too deeply")
	}
	switch v := n.(type) {
	case *literalNode:
		return v.value, nil
	case *identNode:
		return env[v.name], nil
	case *memberNode:
		target, err := eval(v.target, env, depth+1)
		if err != nil {
			return nil, err
		}
		if m, ok := target.(map[string]any); ok {
			return m[v.name], nil
		}
		return nil, nil
	case *indexNode:
		target, err := eval(v.target, env, depth+1)
		if err != nil {
			return nil, err
		}
		idx, err := eval(v.index, env, depth+1)
		if err != nil {
			return nil, err
		}
		switch t := target.(type) {
		case map[string]any:
			if s, ok := idx.(string); ok {
				return t[s], nil
			}
		case []any:
			if f, ok := idx.(float64); ok && f == math.Trunc(f) && f >= 0 && int(f) < len(t) {
				return t[int(f)], nil
			}
		}
		return nil, nil
	case *listNode:
		out := make([]any, 0, len(v.items))
		for _, it := range v.items {
			x, err := eval(it, env, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	case *unaryNode:
		x, err := eval(v.operand, env, depth+1)
		if err != nil {
			return nil, err
		}
		if v.op == "!" {
			return !truthy(x), nil
		}
		f, ok := x.(float64)
		if !ok {
			return nil, fmt.Errorf("cannot negate %s", typeName(x))
		}
		return -f, nil
	case *binaryNode:
		return evalBinary(v, env, depth)
	case *callNode:
		args := make([]any, 0, len(v.args))
		for _, a := range v.args {
			x, err := eval(a, env, depth+1)
			if err != nil {
				return nil, err
			}
			args = append(args, x)
		}
		return functions[v.name](args)
	}
	return nil, fmt.Errorf("unsupported expression")
}

func evalBinary(v *binaryNode, env map[string]any, depth int) (any, error) {
	left, err := eval(v.left, env, depth+1)
	if err != nil {
		return nil, err
	}
	switch v.op {
	case "&&":
		if !truthy(left) {
			return false, nil
		}
		right, err := eval(v.right, env, depth+1)
		if err != nil {
			return nil, err
		}
		return truthy(right), nil
	case "||":
		if truthy(left) {
			return true, nil
		}
		right, err := eval(v.right, env, depth+1)
		if err != nil {
			return nil, err
		}
		return truthy(right), nil
	}
	right, err := eval(v.right, env, depth+1)
	if err != nil {
		return nil, err
	}
	switch v.op {
	case "==":
		return equal(left, right), nil
	case "!=":
		return !equal(left, right), nil
	case "in":
		return contains(right, left), nil
	}
	if left == nil || right == nil {
		// Ordering against a missing value is false rather than an error so
		// a condition on an absent field simply does not hold.
		return false, nil
	}
	lf, lok := left.(float64)
	rf, rok := right.(float64)
	if lok && rok {
		return compareOrdered(v.op, lf, rf), nil
	}
	ls, lok := left.(string)
	rs, rok := right.(string)
	if lok && rok {
		return compareOrdered(v.op, strings.Compare(ls, rs), 0), nil
	}
	return nil, fmt.Errorf("cannot compare %s with %s", typeName(left), typeName(right))
}

func compareOrdered[T int | float64](op string, a, b T) bool {
	switch op {
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	}
	return false
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

func equal(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !equal(xv, yv) {
				return false
			}
		}
		return true
	}
	return false
}

func contains(haystack, needle any) bool {
	switch h := haystack.(type) {
	case []any:
		for _, it := range h {
			if equal(it, needle) {
				return true
			}
		}
	case string:
		if s, ok := needle.(string); ok {
			return strings.Contains(h, s)
		}
	case map[string]any:
		if s, ok := needle.(string); ok {
			_, found := h[s]
			return found
		}
	}
	return false
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "list"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// ---------- functions ----------

var functions = map[string]func([]any) (any, error){
	"len": func(a []any) (any, error) {
		if err := arity("len", a, 1); err != nil {
			return nil, err
		}
		switch t := a[0].(type) {
		case nil:
			return 0.0, nil
		case string:
			return float64(utf8.RuneCountInString(t)), nil
		case []any:
			return float64(len(t)), nil
		case map[string]any:
			return float64(len(t)), nil
		}
		return nil, fmt.Errorf("len: unsupported %s", typeName(a[0]))
	},
	"lower": stringFn("lower", strings.ToLower),
	"upper": stringFn("upper", strings.ToUpper),
	"contains": func(a []any) (any, error) {
		return pairFn("contains", a, func(h, n any) bool { return contains(h, n) })
	},
	"startsWith": func(a []any) (any, error) { return stringPair("startsWith", a, strings.HasPrefix) },
	"endsWith":   func(a []any) (any, error) { return stringPair("endsWith", a, strings.HasSuffix) },
	"exists": func(a []any) (any, error) {
		if err := arity("exists", a, 1); err != nil {
			return nil, err
		}
		return a[0] != nil, nil
	},
}

func arity(name string, a []any, n int) error {
	if len(a) != n {
		return fmt.Errorf("%s takes %d argument(s), got %d", name, n, len(a))
	}
	return nil
}

func stringFn(name string, f func(string) string) func([]any) (any, error) {
	return func(a []any) (any, error) {
		if err := arity(name, a, 1); err != nil {
			return nil, err
		}
		if a[0] == nil {
			return nil, nil
		}
		s, ok := a[0].(string)
		if !ok {
			return nil, fmt.Errorf("%s: expected string, got %s", name, typeName(a[0]))
		}
		return f(s), nil
	}
}

func pairFn(name string, a []any, f func(any, any) bool) (any, error) {
	if err := arity(name, a, 2); err != nil {
		return nil, err
	}
	return f(a[0], a[1]), nil
}

func stringPair(name string, a []any, f func(string, string) bool) (any, error) {
	if err := arity(name, a, 2); err != nil {
		return nil, err
	}
	s, ok1 := a[0].(string)
	t, ok2 := a[1].(string)
	if !ok1 || !ok2 {
		return false, nil
	}
	return f(s, t), nil
}
