package rbac

import (
	"strings"
	"sync"
)

// AssignmentStore holds role assignments in memory. All state is private
// and every access goes through methods, so the backing storage can be
// swapped for a real database later without touching callers. Safe for
// concurrent use.
type AssignmentStore struct {
	mu          sync.RWMutex
	assignments []RoleAssignment
}

// NewAssignmentStore returns an empty store.
func NewAssignmentStore() *AssignmentStore {
	return &AssignmentStore{}
}

// Add stores a role assignment, canonicalizing it first: scope is
// normalized, principal lowercased, and RoleDefinitionID reduced to the
// bare lowercase GUID (the full ARM path form is accepted too). The error
// is always nil today; it is part of the signature so a database-backed
// store can fail without breaking callers.
func (s *AssignmentStore) Add(a RoleAssignment) error {
	a.PrincipalID = strings.ToLower(a.PrincipalID)
	a.Scope = normalizeScope(a.Scope)
	a.RoleDefinitionID = strings.ToLower(bareGUID(a.RoleDefinitionID))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.assignments = append(s.assignments, a)
	return nil
}

// bareGUID reduces a role definition reference to its final path segment:
// "/providers/.../roleDefinitions/{guid}" and "{guid}" both yield "{guid}".
func bareGUID(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// forPrincipalAtScope returns copies of the assignments that apply to
// principalID at scope: those at the same scope or any ancestor scope.
// Principal GUIDs compare case-insensitively.
func (s *AssignmentStore) forPrincipalAtScope(principalID, scope string) []RoleAssignment {
	principal := strings.ToLower(principalID)
	requestScope := normalizeScope(scope)

	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []RoleAssignment
	for _, a := range s.assignments {
		if a.PrincipalID != principal {
			continue
		}
		if !scopeAtOrAbove(a.Scope, requestScope) {
			continue
		}
		out = append(out, a)
	}
	return out
}
