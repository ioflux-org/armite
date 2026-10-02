package storage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"maps"
	"sync"
	"time"

	"github.com/ioflux-org/provisio/internal/state"
)

// storeName names the key store's records in the journal.
const storeName = "storageKeys"

// accountKeys are a storage account's two access keys, as Azure hands
// them out through listKeys and Azurite takes them at start-up.
type accountKeys struct {
	Key1    string    `json:"key1"`
	Key2    string    `json:"key2"`
	Created time.Time `json:"created"`
}

// keyStore holds the keys of every storage account, keyed by lowercase
// account name, journaled like the other stores. In managed mode the
// keys are generated here; in byo mode they come from the configuration
// and nothing is journaled.
type keyStore struct {
	log  *state.Log // nil: memory only
	mu   sync.RWMutex
	keys map[string]accountKeys
}

// Compile-time proof that the store can be attached to a state.Log.
var _ state.Store = (*keyStore)(nil)

func newKeyStore(log *state.Log) *keyStore {
	s := &keyStore{log: log, keys: map[string]accountKeys{}}
	log.Attach(storeName, s)
	return s
}

// newAccountKey is 64 random bytes in base64, the shape of an Azure
// account key.
func newAccountKey() string {
	key := make([]byte, 64)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// Set stores keys for account and journals them.
func (s *keyStore) Set(account string, k accountKeys) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[lower(account)] = k
	value, err := json.Marshal(k)
	if err != nil {
		return err
	}
	return s.log.Append(state.Record{Store: storeName, Key: lower(account), Value: value})
}

// Get returns the keys of account.
func (s *keyStore) Get(account string) (accountKeys, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[lower(account)]
	return k, ok
}

// Delete forgets account's keys.
func (s *keyStore) Delete(account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[lower(account)]; !ok {
		return nil
	}
	delete(s.keys, lower(account))
	return s.log.Append(state.Record{Store: storeName, Key: lower(account), Deleted: true})
}

// All returns every account's keys, as Azurite wants them: name to
// "key1:key2".
func (s *keyStore) All() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.keys))
	for name, k := range s.keys {
		out[name] = k.Key1 + ":" + k.Key2
	}
	return out
}

// Restore applies one journaled change during replay.
func (s *keyStore) Restore(rec state.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.Deleted {
		delete(s.keys, rec.Key)
		return nil
	}
	var k accountKeys
	if err := json.Unmarshal(rec.Value, &k); err != nil {
		return err
	}
	s.keys[rec.Key] = k
	return nil
}

// Dump emits every account's keys for a snapshot.
func (s *keyStore) Dump(emit func(state.Record) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for name, k := range maps.Clone(s.keys) {
		value, err := json.Marshal(k)
		if err != nil {
			return err
		}
		if err := emit(state.Record{Store: storeName, Key: name, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
