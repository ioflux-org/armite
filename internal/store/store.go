package store

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/ioflux-org/provisio/internal/state"
)

// ErrNotFound reports a lookup for a resource ID the store does not hold.
var ErrNotFound = errors.New("resource not found")

// storeName names this store's records in the journal.
const storeName = "resources"

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
// every method returns an error even where memory cannot fail. Every
// change is journaled through log after it is made: the map is the
// truth a snapshot captures, the journal is how it survives a restart.
// Safe for concurrent use.
type Store struct {
	log  *state.Log // nil: memory only
	mu   sync.RWMutex
	byID map[string]Resource
}

// Compile-time proof that the store can be attached to a state.Log.
var _ state.Store = (*Store)(nil)

// New returns an empty store that journals through log, registered with
// it under the store's name so Replay and compaction find it; a nil log
// keeps the store in memory only. The store attaches itself because the
// name and the record format are its own.
func New(log *state.Log) *Store {
	s := &Store{log: log, byID: make(map[string]Resource)}
	log.Attach(storeName, s)
	return s
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
	value, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	return !exists, s.log.Append(state.Record{Store: storeName, Key: k, Value: value})
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
	if _, ok := s.byID[k]; !ok {
		return false, nil
	}
	delete(s.byID, k)
	return true, s.log.Append(state.Record{Store: storeName, Key: k, Deleted: true})
}

// Restore applies one journaled change during replay, before the store
// serves: the resource under its key, or its removal.
func (s *Store) Restore(rec state.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.Deleted {
		delete(s.byID, rec.Key)
		return nil
	}
	var r Resource
	if err := json.Unmarshal(rec.Value, &r); err != nil {
		return err
	}
	s.byID[rec.Key] = r
	return nil
}

// Dump emits every resource for a snapshot, under the read lock so the
// snapshot is one consistent moment of the store.
func (s *Store) Dump(emit func(state.Record) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, r := range s.byID {
		value, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if err := emit(state.Record{Store: storeName, Key: k, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
