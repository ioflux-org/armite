package keyvault

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/ioflux-org/provisio/internal/state"
)

// storeName names this store's records in the journal.
const storeName = "secrets"

var (
	errSecretNotFound  = errors.New("secret not found")
	errSecretDeleted   = errors.New("secret is soft-deleted")
	errVersionNotFound = errors.New("secret version not found")
)

// Times are Unix seconds: the data plane's wire format ("created": 1789000000).
type secretVersion struct {
	Version     string
	Value       string
	ContentType string
	Tags        map[string]string
	Enabled     bool
	NotBefore   *int64
	Expires     *int64
	Created     int64
	Updated     int64
}

func (v secretVersion) clone() secretVersion {
	v.Tags = maps.Clone(v.Tags)
	if v.NotBefore != nil {
		v.NotBefore = new(*v.NotBefore)
	}
	if v.Expires != nil {
		v.Expires = new(*v.Expires)
	}
	return v
}

// secret is one named secret in a vault: its versions, oldest first,
// and its soft-delete state.
type secret struct {
	Name     string          // casing as first created
	Versions []secretVersion // oldest first; the last one is current
	Deleted  *int64          // nil while live; Unix seconds of the soft-delete
}

func (s secret) clone() secret {
	s.Versions = slices.Clone(s.Versions)
	for i := range s.Versions {
		s.Versions[i] = s.Versions[i].clone()
	}
	if s.Deleted != nil {
		s.Deleted = new(*s.Deleted)
	}
	return s
}

// latest is the current version.
func (s secret) latest() secretVersion {
	return s.Versions[len(s.Versions)-1]
}

// secretStore holds every vault's secrets in memory, keyed by lowercase
// vault name and then lowercase secret name. Same rules as the resource
// store: private state, copies both ways, an error on every method, and
// every change journaled after it is made. A journal record is one
// whole secret, versions included, under the key "vault/name".
type secretStore struct {
	log    *state.Log // nil: memory only
	mu     sync.RWMutex
	vaults map[string]map[string]*secret
}

// Compile-time proof that the store can be attached to a state.Log.
var _ state.Store = (*secretStore)(nil)

func newSecretStore(log *state.Log) *secretStore {
	st := &secretStore{log: log, vaults: map[string]map[string]*secret{}}
	log.Attach(storeName, st)
	return st
}

func lower(s string) string {
	return strings.ToLower(s)
}

// lookup finds a secret; a nil map for an unknown vault reads as empty.
func (st *secretStore) lookup(vault, name string) (*secret, bool) {
	s, ok := st.vaults[lower(vault)][lower(name)]
	return s, ok
}

// Set appends a version to the named secret, creating the secret on
// first use, and returns the secret (with its canonical name) and the
// stored version. A soft-deleted secret cannot be written to.
func (st *secretStore) Set(vault, name string, v secretVersion) (secret, secretVersion, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	m, ok := st.vaults[lower(vault)]
	if !ok {
		m = map[string]*secret{}
		st.vaults[lower(vault)] = m
	}
	s, ok := m[lower(name)]
	if !ok {
		s = &secret{Name: name}
		m[lower(name)] = s
	}
	if s.Deleted != nil {
		return secret{}, secretVersion{}, errSecretDeleted
	}
	s.Versions = append(s.Versions, v.clone())
	if err := st.journal(vault, name, s); err != nil {
		return secret{}, secretVersion{}, err
	}
	return s.clone(), v.clone(), nil
}

// Get returns a live secret and one of its versions: the named one, or
// the current one when version is "".
func (st *secretStore) Get(vault, name, version string) (secret, secretVersion, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s, ok := st.lookup(vault, name)
	if !ok || s.Deleted != nil {
		return secret{}, secretVersion{}, errSecretNotFound
	}
	if version == "" {
		return s.clone(), s.latest().clone(), nil
	}
	for _, v := range s.Versions {
		if strings.EqualFold(v.Version, version) {
			return s.clone(), v.clone(), nil
		}
	}
	return secret{}, secretVersion{}, errVersionNotFound
}

// Update applies fn to one version of a live secret (the current one
// when version is "") and returns the result.
func (st *secretStore) Update(vault, name, version string,
	fn func(*secretVersion)) (secret, secretVersion, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.lookup(vault, name)
	if !ok || s.Deleted != nil {
		return secret{}, secretVersion{}, errSecretNotFound
	}
	i := len(s.Versions) - 1
	if version != "" {
		i = slices.IndexFunc(s.Versions, func(v secretVersion) bool {
			return strings.EqualFold(v.Version, version)
		})
		if i < 0 {
			return secret{}, secretVersion{}, errVersionNotFound
		}
	}
	fn(&s.Versions[i])
	if err := st.journal(vault, name, s); err != nil {
		return secret{}, secretVersion{}, err
	}
	return s.clone(), s.Versions[i].clone(), nil
}

// List returns a vault's secrets, live or soft-deleted, sorted by name.
// The result is never nil.
func (st *secretStore) List(vault string, deleted bool) ([]secret, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]secret, 0)
	for _, s := range st.vaults[lower(vault)] {
		if (s.Deleted != nil) == deleted {
			out = append(out, s.clone())
		}
	}
	slices.SortFunc(out, func(a, b secret) int {
		return strings.Compare(lower(a.Name), lower(b.Name))
	})
	return out, nil
}

// Delete soft-deletes a live secret at now and returns it.
func (st *secretStore) Delete(vault, name string, now int64) (secret, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.lookup(vault, name)
	if !ok || s.Deleted != nil {
		return secret{}, errSecretNotFound
	}
	s.Deleted = new(now)

	if err := st.journal(vault, name, s); err != nil {
		return secret{}, err
	}
	return s.clone(), nil
}

// GetDeleted returns a soft-deleted secret.
func (st *secretStore) GetDeleted(vault, name string) (secret, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s, ok := st.lookup(vault, name)
	if !ok || s.Deleted == nil {
		return secret{}, errSecretNotFound
	}
	return s.clone(), nil
}

// Recover brings a soft-deleted secret back, every version included.
func (st *secretStore) Recover(vault, name string) (secret, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.lookup(vault, name)
	if !ok || s.Deleted == nil {
		return secret{}, errSecretNotFound
	}
	s.Deleted = nil

	if err := st.journal(vault, name, s); err != nil {
		return secret{}, err
	}
	return s.clone(), nil
}

// Purge removes a soft-deleted secret for good.
func (st *secretStore) Purge(vault, name string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.lookup(vault, name)
	if !ok || s.Deleted == nil {
		return errSecretNotFound
	}
	delete(st.vaults[lower(vault)], lower(name))
	return st.journal(vault, name, nil)
}

// DropVault forgets everything stored for a vault: on vault delete, and
// on vault create, so a reused name starts empty. Each secret is
// journaled as removed on its own; the journal has no "whole vault"
// record because a record is one key.
func (st *secretStore) DropVault(vault string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for name := range st.vaults[lower(vault)] {
		if err := st.journal(vault, name, nil); err != nil {
			return err
		}
	}
	delete(st.vaults, lower(vault))
	return nil
}

// journal records the secret's current state, or its removal when s is
// nil. Called under the write lock, after the change.
func (st *secretStore) journal(vault, name string, s *secret) error {
	key := lower(vault) + "/" + lower(name)
	rec := state.Record{Store: storeName, Key: key, Deleted: s == nil}
	if s != nil {
		value, err := json.Marshal(s)
		if err != nil {
			return err
		}
		rec.Value = value
	}
	return st.log.Append(rec)
}

// Restore applies one journaled change during replay.
func (st *secretStore) Restore(rec state.Record) error {
	vault, name, ok := strings.Cut(rec.Key, "/")
	if !ok {
		return errors.New("secret record key is not vault/name: " + rec.Key)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if rec.Deleted {
		delete(st.vaults[vault], name)
		return nil
	}
	var s secret
	if err := json.Unmarshal(rec.Value, &s); err != nil {
		return err
	}
	m, ok := st.vaults[vault]
	if !ok {
		m = map[string]*secret{}
		st.vaults[vault] = m
	}
	m[name] = &s
	return nil
}

// Dump emits every secret of every vault for a snapshot.
func (st *secretStore) Dump(emit func(state.Record) error) error {
	st.mu.RLock()
	defer st.mu.RUnlock()
	for vault, m := range st.vaults {
		for name, s := range m {
			value, err := json.Marshal(s)
			if err != nil {
				return err
			}
			rec := state.Record{Store: storeName, Key: vault + "/" + name, Value: value}
			if err := emit(rec); err != nil {
				return err
			}
		}
	}
	return nil
}
