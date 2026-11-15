package graph

import (
	"fmt"
	"strings"

	"github.com/ioflux-org/armite/internal/directory"
)

// pred keeps an object when it matches a $filter.
type pred func(directory.Object) bool

// parseFilter handles the $filter subset az and Terraform send:
//
//	field eq 'value'            field eq true|false
//	startswith(field,'value')   field/any(c:c eq 'value')
//
// joined by "and". Strings compare case-insensitively, as Graph does
// for these properties. An empty filter keeps everything (nil pred).
func parseFilter(s string) (pred, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	p := &parser{toks: lex(s)}
	keep, err := p.expr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("Invalid filter clause: unexpected %q", p.toks[p.pos].text)
	}
	return keep, nil
}

// A token is an identifier (kind 'i'), a quoted string ('s'), one of
// ( ) , : / ('p'), or a character the grammar has no use for ('?').
type token struct {
	kind byte
	text string
}

func lex(s string) []token {
	var toks []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '\'': // '' inside a string is a quote, as in OData
			var b strings.Builder
			j := i + 1
			closed := false
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					closed = true
					break
				}
				b.WriteByte(s[j])
				j++
			}
			if !closed {
				return append(toks, token{'?', "unterminated string"})
			}
			toks = append(toks, token{'s', b.String()})
			i = j + 1
		case strings.ContainsRune("(),:/", rune(c)):
			toks = append(toks, token{'p', string(c)})
			i++
		default:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '.' || s[j] >= '0' && s[j] <= '9' ||
				s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
				j++
			}
			if j == i {
				return append(toks, token{'?', string(c)})
			}
			toks = append(toks, token{'i', s[i:j]})
			i = j
		}
	}
	return toks
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{}
}

func (p *parser) next() token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) punct(text string) error {
	if t := p.next(); t.kind != 'p' || t.text != text {
		return fmt.Errorf("Invalid filter clause: expected %q, got %q", text, t.text)
	}
	return nil
}

func (p *parser) ident() (string, error) {
	if t := p.next(); t.kind == 'i' {
		return t.text, nil
	} else {
		return "", fmt.Errorf("Invalid filter clause: expected a property, got %q", t.text)
	}
}

func (p *parser) str() (string, error) {
	if t := p.next(); t.kind == 's' {
		return t.text, nil
	} else {
		return "", fmt.Errorf("Invalid filter clause: expected a quoted value, got %q", t.text)
	}
}

// expr := term ("and" term)*
func (p *parser) expr() (pred, error) {
	left, err := p.term()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == 'i' && strings.EqualFold(p.peek().text, "and") {
		p.next()
		right, err := p.term()
		if err != nil {
			return nil, err
		}
		l, r := left, right
		left = func(o directory.Object) bool { return l(o) && r(o) }
	}
	return left, nil
}

// term := startswith(field,'v') | field/any(c:c eq 'v') | field eq 'v' | field eq true|false
func (p *parser) term() (pred, error) {
	field, err := p.ident()
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(field, "startswith") {
		if err := p.punct("("); err != nil {
			return nil, err
		}
		if field, err = p.ident(); err != nil {
			return nil, err
		}
		if err := p.punct(","); err != nil {
			return nil, err
		}
		v, err := p.str()
		if err != nil {
			return nil, err
		}
		if err := p.punct(")"); err != nil {
			return nil, err
		}
		get, err := stringField(field)
		if err != nil {
			return nil, err
		}
		return func(o directory.Object) bool {
			return strings.HasPrefix(strings.ToLower(get(o)), strings.ToLower(v))
		}, nil
	}
	if p.peek().kind == 'p' && p.peek().text == "/" { // field/any(c:c eq 'v')
		p.next()
		if fn, err := p.ident(); err != nil || !strings.EqualFold(fn, "any") {
			return nil, fmt.Errorf("Invalid filter clause: only any() is supported on %s", field)
		}
		if err := p.punct("("); err != nil {
			return nil, err
		}
		v1, err := p.ident()
		if err != nil {
			return nil, err
		}
		if err := p.punct(":"); err != nil {
			return nil, err
		}
		v2, err := p.ident()
		if err != nil {
			return nil, err
		}
		if v1 != v2 {
			return nil, fmt.Errorf("Invalid filter clause: %s is not the lambda variable %s", v2, v1)
		}
		if op, err := p.ident(); err != nil || !strings.EqualFold(op, "eq") {
			return nil, fmt.Errorf("Invalid filter clause: only eq is supported inside any()")
		}
		v, err := p.str()
		if err != nil {
			return nil, err
		}
		if err := p.punct(")"); err != nil {
			return nil, err
		}
		get, err := listField(field)
		if err != nil {
			return nil, err
		}
		return func(o directory.Object) bool {
			for _, s := range get(o) {
				if strings.EqualFold(s, v) {
					return true
				}
			}
			return false
		}, nil
	}
	if op, err := p.ident(); err != nil || !strings.EqualFold(op, "eq") {
		return nil, fmt.Errorf("Invalid filter clause: only eq, startswith and any are supported")
	}
	switch t := p.next(); {
	case t.kind == 's':
		get, err := stringField(field)
		if err != nil {
			return nil, err
		}
		return func(o directory.Object) bool { return strings.EqualFold(get(o), t.text) }, nil
	case t.kind == 'i' && (t.text == "true" || t.text == "false"):
		get, err := boolField(field)
		if err != nil {
			return nil, err
		}
		want := t.text == "true"
		return func(o directory.Object) bool { return get(o) == want }, nil
	default:
		return nil, fmt.Errorf("Invalid filter clause: expected a value after eq, got %q", t.text)
	}
}

// The properties a filter may name, each read from the Object.
func stringField(name string) (func(directory.Object) string, error) {
	switch strings.ToLower(name) {
	case "id":
		return func(o directory.Object) string { return o.ID }, nil
	case "displayname":
		return func(o directory.Object) string { return o.DisplayName }, nil
	case "appid":
		return func(o directory.Object) string { return o.AppID }, nil
	case "userprincipalname":
		return func(o directory.Object) string { return o.UserPrincipalName }, nil
	case "mailnickname":
		return func(o directory.Object) string { return o.MailNickname }, nil
	case "serviceprincipaltype":
		return func(o directory.Object) string { return o.ServicePrincipalType }, nil
	}
	return nil, fmt.Errorf("Invalid filter clause: property %q is not supported", name)
}

func listField(name string) (func(directory.Object) []string, error) {
	if strings.EqualFold(name, "servicePrincipalNames") {
		return func(o directory.Object) []string { return []string{o.AppID} }, nil
	}
	return nil, fmt.Errorf("Invalid filter clause: collection property %q is not supported", name)
}

func boolField(name string) (func(directory.Object) bool, error) {
	switch strings.ToLower(name) {
	case "accountenabled":
		return func(o directory.Object) bool { return o.AccountEnabled }, nil
	case "mailenabled":
		return func(o directory.Object) bool { return o.MailEnabled }, nil
	case "securityenabled":
		return func(o directory.Object) bool { return o.SecurityEnabled }, nil
	}
	return nil, fmt.Errorf("Invalid filter clause: property %q is not a boolean", name)
}
