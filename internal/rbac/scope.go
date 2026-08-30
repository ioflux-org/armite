package rbac

import "strings"

// normalizeScope returns the canonical form of an ARM scope: lowercase,
// no trailing slash. The root scope "/" is preserved. ARM treats scopes
// case-insensitively, so every comparison in this package happens on
// normalized values only.
func normalizeScope(scope string) string {
	s := strings.ToLower(scope)
	s = strings.TrimRight(s, "/")
	if s == "" {
		return "/"
	}
	return s
}

// scopeAtOrAbove reports whether an assignment at assignmentScope applies
// to a request at requestScope: true when the scopes are equal or when
// assignmentScope is an ancestor of requestScope. Inheritance flows
// downward only. Both arguments must already be normalized.
func scopeAtOrAbove(assignmentScope, requestScope string) bool {
	if assignmentScope == requestScope {
		return true
	}
	if assignmentScope == "/" {
		return true
	}
	return strings.HasPrefix(requestScope, assignmentScope+"/")
}
