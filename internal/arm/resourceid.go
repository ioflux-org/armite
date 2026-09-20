package arm

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrInvalidPath reports a request path that does not follow the ARM
// resource grammar. Details are wrapped onto it with fmt.Errorf and %w;
// callers branch with errors.Is, never on message text.
var ErrInvalidPath = errors.New("invalid resource path")

// A ResourceID is a parsed ARM resource path:
// {scope}/providers/{namespace}/{type}/{name}/... with alternating
// type/name segments. Scope is everything before the LAST providers
// marker and is kept opaque - an invalid scope is not rejected here, it
// simply matches no assignment and no stored resource. Native routes
// (subscriptions, resource groups, tenants) carry no providers marker:
// their namespace is the implicit Microsoft.Resources and their segments
// alternate from the path root.
type ResourceID struct {
	Scope     string   // "" at tenant scope
	Namespace string   // "Microsoft.KeyVault"; "Microsoft.Resources" when Native
	Native    bool     // no /providers/ marker in the path
	Types     []string // type segments, in order
	Names     []string // paired name segments; one shorter when a trailing type is unpaired
}

// IsInstance reports whether the ID addresses a single resource: every
// type segment has a name. The only other legal shape, one trailing
// unpaired type, is a collection on GET and an action name on POST.
func (id ResourceID) IsInstance() bool {
	return len(id.Names) == len(id.Types)
}

// ParseResourceID parses an ARM request path (no query string) into a
// ResourceID. The rule that tames the recursive grammar: split on the
// LAST providers segment; the acting provider is to its right, the scope
// to its left.
func ParseResourceID(path string) (ResourceID, error) {
	if !strings.HasPrefix(path, "/") {
		return ResourceID{}, fmt.Errorf("%w: must start with /", ErrInvalidPath)
	}
	trimmed := strings.TrimSuffix(path[1:], "/")
	if trimmed == "" {
		return ResourceID{}, fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	segs := strings.Split(trimmed, "/")
	for _, s := range segs {
		if s == "" {
			return ResourceID{}, fmt.Errorf("%w: empty segment", ErrInvalidPath)
		}
	}

	last := -1
	for i, s := range segs {
		if strings.EqualFold(s, "providers") {
			last = i
		}
	}

	if last == -1 {
		return parseNative(segs)
	}

	rest := segs[last+1:]
	if len(rest) < 2 {
		return ResourceID{}, fmt.Errorf("%w: providers require a namespace and a type", ErrInvalidPath)
	}
	if !strings.Contains(rest[0], ".") {
		return ResourceID{}, fmt.Errorf("%w: %q is not a provider namespace", ErrInvalidPath, rest[0])
	}

	var scope string
	if last > 0 {
		scope = "/" + strings.Join(segs[:last], "/")
	}
	types, names := splitPairs(rest[1:])
	return ResourceID{Scope: scope, Namespace: rest[0], Types: types, Names: names}, nil
}

// nativeChildren whitelists the providers-free type chains ARM serves
// itself. Keys and values are lowercase; the empty key is the path root.
var nativeChildren = map[string][]string{
	"":               {"subscriptions", "tenants"},
	"subscriptions":  {"resourcegroups", "resources"},
	"resourcegroups": {"resources"},
	"tenants":        {},
}

// nativeCanonical maps lowercase native types to the casing ARM echoes
// in resource IDs. az sends "resourcegroups"; responses say "resourceGroups".
var nativeCanonical = map[string]string{
	"subscriptions":  "subscriptions",
	"resourcegroups": "resourceGroups",
	"tenants":        "tenants",
	"resources":      "resources",
}

// parseNative parses the providers-free routes: the same alternating
// grammar under the implicit Microsoft.Resources namespace. A resource
// group is grammatically ordinary - only its namespace is invisible.
func parseNative(segs []string) (ResourceID, error) {
	types, names := splitPairs(segs)
	parent := ""
	for _, typ := range types {
		lower := strings.ToLower(typ)
		if !slices.Contains(nativeChildren[parent], lower) {
			return ResourceID{}, fmt.Errorf("%w: unknown route %q", ErrInvalidPath, typ)
		}
		parent = lower
	}
	for i, typ := range types {
		types[i] = nativeCanonical[strings.ToLower(typ)]
	}
	return ResourceID{Namespace: "Microsoft.Resources", Native: true, Types: types, Names: names}, nil
}

// splitPairs distributes alternating segments into types (even offsets)
// and names (odd offsets).
func splitPairs(segs []string) (types, names []string) {
	for i, s := range segs {
		if i%2 == 0 {
			types = append(types, s)
		} else {
			names = append(names, s)
		}
	}
	return types, names
}

// String reconstructs the canonical resource ID: scope preserved as
// given, native types in canonical casing, no trailing slash. Parse and
// String round-trip up to segment casing and a trailing slash.
func (id ResourceID) String() string {
	var b strings.Builder
	b.WriteString(id.Scope)
	if !id.Native {
		b.WriteString("/providers/")
		b.WriteString(id.Namespace)
	}
	for i, typ := range id.Types {
		b.WriteString("/")
		b.WriteString(typ)
		if i < len(id.Names) {
			b.WriteString("/")
			b.WriteString(id.Names[i])
		}
	}
	return b.String()
}
