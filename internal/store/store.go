package store

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
)

// ErrNotFound reports a lookup for a resource ID the store does not hold.
var ErrNotFound = errors.New("resource not found")

// Resource is the envelope every ARM resource shares on the wire.
// Identity, placement and tags are common to all of them; Properties is
// the provider-specific body, kept as raw JSON so the store stays
// generic - it never needs to understand a vault to hold one.
type Resource struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Location   string            `json:"location,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties json.RawMessage   `json:"properties,omitempty"`
}

// clone returns a deep copy of r. The map and the byte slice inside a
// Resource are references; nothing the store holds may be reachable
// from outside it, in either direction.
func (r Resource) clone() Resource {
	r.Tags = maps.Clone(r.Tags)
	r.Properties = slices.Clone(r.Properties)
	return r
}

// Store holds ARM resources in memory, keyed by lowercase resource ID:
// ARM looks resources up case-insensitively but echoes the casing it was
// given. All state is private, copies cross the boundary both ways, and
// every method returns an error even where memory cannot fail, so a
// database can replace the map without touching callers. Safe for
// concurrent use.
type Store struct {
	mu   sync.RWMutex
	byID map[string]Resource
}

// New returns an empty store.
func New() *Store {
	return &Store{byID: make(map[string]Resource)}
}

// key is the map key for an ID or scope: lowercase, no trailing slash.
func key(id string) string {
	return strings.ToLower(strings.TrimSuffix(id, "/"))
}

// Put creates or replaces the resource with r.ID - PUT semantics. It
// reports whether the resource was created rather than replaced, which
// is the difference between ARM's 201 and 200.
func (s *Store) Put(r Resource) (created bool, err error) {
	if r.ID == "" {
		return false, errors.New("store: resource has no ID")
	}
	k := key(r.ID)

	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.byID[k]
	s.byID[k] = r.clone()
	return !exists, nil
}

// Get returns a copy of the resource with the given ID, or ErrNotFound.
func (s *Store) Get(id string) (Resource, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byID[key(id)]
	if !ok {
		return Resource{}, ErrNotFound
	}
	return r.clone(), nil
}

// List returns copies of every resource whose ID lies strictly below
// scope, at any depth, sorted by ID: those of type typ, or all of them
// when typ is "". Both comparisons are case-insensitive. An empty result
// is a non-nil empty slice so it encodes as [] rather than null.
func (s *Store) List(scope, typ string) ([]Resource, error) {
	prefix := key(scope) + "/"

	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k, r := range s.byID {
		if strings.HasPrefix(k, prefix) && (typ == "" || strings.EqualFold(r.Type, typ)) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	out := make([]Resource, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.byID[k].clone())
	}
	return out, nil
}

// Delete removes the resource with the given ID and reports whether it
// existed. A missing resource is not an error here: the provider decides
// whether that is a 204 or a 404.
func (s *Store) Delete(id string) (deleted bool, err error) {
	k := key(id)

	s.mu.Lock()
	defer s.mu.Unlock()
	_, deleted = s.byID[k]
	delete(s.byID, k)
	return deleted, nil
}
