package rbac

import "strings"

// matchPattern reports whether action matches pattern under Azure RBAC
// wildcard semantics: '*' is the only wildcard and matches any run of
// characters, including '/'; comparison is case-insensitive; a pattern
// without '*' must match exactly (never as a prefix).
func matchPattern(pattern, action string) bool {
	p := strings.ToLower(pattern)
	a := strings.ToLower(action)

	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return a == p
	}

	prefix, suffix := parts[0], parts[len(parts)-1]
	if !strings.HasPrefix(a, prefix) {
		return false
	}
	a = a[len(prefix):]

	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(a, mid)
		if i < 0 {
			return false
		}
		a = a[i+len(mid):]
	}

	return strings.HasSuffix(a, suffix)
}
