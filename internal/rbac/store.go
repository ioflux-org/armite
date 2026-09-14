package rbac

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

var (
	// ErrAssignmentNameTaken reports an Add whose Name is already in use.
	// The caller decides whether the existing record is the same
	// assignment (an idempotent create) or a forbidden update.
	ErrAssignmentNameTaken = errors.New("role assignment name already in use")
	// ErrAssignmentExists reports an Add that would grant a principal the
	// same role at the same scope twice under another name: ARM's
	// RoleAssignmentExists.
	ErrAssignmentExists = errors.New("role assignment already exists")
	// ErrAssignmentNotFound reports a lookup for a name the store does
	// not hold.
	ErrAssignmentNotFound = errors.New("role assignment not found")
)

// AssignmentStore holds role assignments in memory, keyed by lowercase
// name. All state is private and every access goes through methods, so
// the backing storage can be swapped for a real database later without
// touching callers. Safe for concurrent use.
type AssignmentStore struct {
	mu     sync.RWMutex
	byName map[string]RoleAssignment
}

// NewAssignmentStore returns an empty store.
func NewAssignmentStore() *AssignmentStore {
	return &AssignmentStore{byName: make(map[string]RoleAssignment)}
}

// Add stores a new assignment, canonicalizing it first: principal and
// role GUID lowercased (the full ARM role path is accepted too), scope
// kept as given minus trailing slashes, name derived when empty, ID
// computed. It refuses a name already in use and a principal/role/scope
// triple already granted under another name.
func (s *AssignmentStore) Add(a RoleAssignment) error {
	a.PrincipalID = strings.ToLower(a.PrincipalID)
	a.RoleDefinitionID = strings.ToLower(bareGUID(a.RoleDefinitionID))
	a.Scope = trimScope(a.Scope)
	if a.PrincipalID == "" || a.RoleDefinitionID == "" {
		return fmt.Errorf("rbac: assignment needs a principal and a role definition: %+v", a)
	}
	if a.Name == "" {
		a.Name = deriveName(a.PrincipalID, a.RoleDefinitionID, normalizeScope(a.Scope))
	}
	a.Name = strings.ToLower(a.Name)
	a.ID = assignmentID(a.Scope, a.Name)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.byName[a.Name]; taken {
		return ErrAssignmentNameTaken
	}
	for _, b := range s.byName {
		if b.PrincipalID == a.PrincipalID && b.RoleDefinitionID == a.RoleDefinitionID &&
			normalizeScope(b.Scope) == normalizeScope(a.Scope) {
			return ErrAssignmentExists
		}
	}
	s.byName[a.Name] = a
	return nil
}

// Get returns the assignment with the given name, compared
// case-insensitively, or ErrAssignmentNotFound.
func (s *AssignmentStore) Get(name string) (RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.byName[strings.ToLower(name)]
	if !ok {
		return RoleAssignment{}, ErrAssignmentNotFound
	}
	return a, nil
}

// Delete removes the assignment with the given name and returns it, so
// the caller can echo what was revoked. A missing name is
// ErrAssignmentNotFound; the caller decides whether that is a 204.
func (s *AssignmentStore) Delete(name string) (RoleAssignment, error) {
	key := strings.ToLower(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byName[key]
	if !ok {
		return RoleAssignment{}, ErrAssignmentNotFound
	}
	delete(s.byName, key)
	return a, nil
}

// List returns the assignments that concern scope, sorted by name: those
// at the scope or above it (inherited) and, unless atScopeOnly, those
// below it too. This is ARM's ListForScope, where $filter=atScope()
// drops the descendants. The result is never nil.
func (s *AssignmentStore) List(scope string, atScopeOnly bool) ([]RoleAssignment, error) {
	request := normalizeScope(scope)

	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RoleAssignment, 0)
	for _, a := range s.byName {
		own := normalizeScope(a.Scope)
		if scopeAtOrAbove(own, request) || (!atScopeOnly && scopeAtOrAbove(request, own)) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(x, y RoleAssignment) int {
		return strings.Compare(x.Name, y.Name)
	})
	return out, nil
}

// bareGUID reduces a role definition reference to its final path segment:
// "/providers/.../roleDefinitions/{guid}" and "{guid}" both yield "{guid}".
func bareGUID(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// trimScope keeps a scope's casing - ARM echoes it as given - and drops
// trailing slashes; the root scope stays "/". Comparisons use
// normalizeScope, never the stored form.
func trimScope(scope string) string {
	s := strings.TrimRight(scope, "/")
	if s == "" {
		return "/"
	}
	return s
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
	for _, a := range s.byName {
		if a.PrincipalID != principal {
			continue
		}
		if !scopeAtOrAbove(normalizeScope(a.Scope), requestScope) {
			continue
		}
		out = append(out, a)
	}
	return out
}
