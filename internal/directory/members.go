package directory

import (
	"slices"
	"strings"
)

// Group membership. A group's Members are object ids of users, service
// principals and other groups. Nesting is allowed, cycles included (a
// in b, b in a): every walk below marks what it has seen, so a cycle
// ends it instead of spinning.

// AddMember makes memberID a direct member of the group.
func (s *Store) AddMember(groupID, memberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[key(groupID)]
	if !ok || g.Kind != KindGroup {
		return ErrNotFound
	}
	m, ok := s.byID[key(memberID)]
	if !ok || m.Kind == KindApplication {
		return ErrNotFound // applications are not principals: nothing to be a member with
	}
	if key(m.ID) == key(g.ID) {
		return ErrSelfMember
	}
	if hasMember(g, m.ID) {
		return ErrConflict
	}
	g = g.clone()
	g.Members = append(g.Members, m.ID)
	return s.commitLocked(g)
}

// RemoveMember ends a direct membership; ErrNotFound when there is none.
func (s *Store) RemoveMember(groupID, memberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.byID[key(groupID)]
	if !ok || g.Kind != KindGroup || !hasMember(g, memberID) {
		return ErrNotFound
	}
	g = g.clone()
	g.Members = slices.DeleteFunc(g.Members, func(id string) bool { return key(id) == key(memberID) })
	return s.commitLocked(g)
}

func hasMember(g Object, id string) bool {
	return slices.ContainsFunc(g.Members, func(m string) bool { return key(m) == key(id) })
}

// Members returns what a group contains, in the order added: its direct
// members, or with transitive set, also everything inside the groups
// among them, each object once. ok is false when groupID is not a group.
func (s *Store) Members(groupID string, transitive bool) (members []Object, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, found := s.byID[key(groupID)]
	if !found || g.Kind != KindGroup {
		return nil, false
	}
	members = make([]Object, 0)
	seen := map[string]bool{key(g.ID): true}
	for queue := []Object{g}; len(queue) > 0; queue = queue[1:] {
		for _, id := range queue[0].Members {
			m, exists := s.byID[key(id)]
			if !exists || seen[key(id)] {
				continue // gone from the configuration, or already listed
			}
			seen[key(id)] = true
			members = append(members, m.clone())
			if transitive && m.Kind == KindGroup {
				queue = append(queue, m)
			}
		}
	}
	return members, true
}

// GroupsOf returns the groups id is a member of: directly, or with
// transitive set, also the groups those are in, and so on up. Sorted
// by creation time then id, like every listing.
func (s *Store) GroupsOf(id string, transitive bool) []Object {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Object, 0)
	seen := map[string]bool{key(id): true}
	for level := []string{id}; len(level) > 0; {
		var next []string
		for _, g := range s.byID {
			if g.Kind != KindGroup || seen[key(g.ID)] {
				continue
			}
			if slices.ContainsFunc(level, func(m string) bool { return hasMember(g, m) }) {
				seen[key(g.ID)] = true
				out = append(out, g.clone())
				next = append(next, g.ID)
			}
		}
		if !transitive {
			break
		}
		level = next
	}
	slices.SortFunc(out, func(a, b Object) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// TransitiveGroupIDs is GroupsOf for RBAC: the ids of every group a
// principal belongs to, at any depth. An assignment to any of them is
// an assignment to the principal.
func (s *Store) TransitiveGroupIDs(principalID string) []string {
	groups := s.GroupsOf(principalID, true)
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return ids
}

// dropMembersLocked takes deleted objects (lowercase ids) out of every
// group that listed them, journaling each group it changes.
func (s *Store) dropMembersLocked(gone []string) error {
	for _, g := range s.byID {
		if g.Kind != KindGroup || !slices.ContainsFunc(gone, func(id string) bool { return hasMember(g, id) }) {
			continue
		}
		g = g.clone()
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return slices.Contains(gone, key(m)) })
		if err := s.commitLocked(g); err != nil {
			return err
		}
	}
	return nil
}
