// Package directory is Armite's Entra directory: the applications,
// service principals, users and groups that Microsoft Graph creates and
// that tokens and role assignments refer to. One journaled store, keyed
// by object id, with the lookups the other planes need: the token
// endpoint verifies a client secret here, the authorization provider
// asks whether a principal exists here, the Graph plane serves it all.
package directory

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/state"
)

const storeName = "directory"

// Kinds of directory object. Graph's @odata.type is "#microsoft.graph." + kind.
const (
	KindApplication      = "application"
	KindServicePrincipal = "servicePrincipal"
	KindUser             = "user"
	KindGroup            = "group"
	kdfName              = "pbkdf2-sha256"
	kdfIters             = 100_000
)

var (
	ErrNotFound = errors.New("directory: object not found")
	ErrConflict = errors.New("directory: an object with that key already exists")
	ErrSeeded   = errors.New("directory: the object comes from the configuration")
	// ErrSelfMember refuses the one nesting that is always a mistake.
	ErrSelfMember = errors.New("directory: a group cannot be a member of itself")
)

// Object is one directory object as the store holds it: the fields
// Graph returns for every kind, the kind-specific ones, and what Graph
// never returns (password hashes). The Graph plane decides what goes
// on the wire.
type Object struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	DisplayName string    `json:"displayName"`
	Created     time.Time `json:"createdDateTime"`

	// application and servicePrincipal
	AppID string `json:"appId,omitempty"`
	// servicePrincipal: "Application" or "ManagedIdentity"
	ServicePrincipalType string `json:"servicePrincipalType,omitempty"`
	AccountEnabled       bool   `json:"accountEnabled"`
	// user; the password is kept as a hash, like a client secret
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	MailNickname      string `json:"mailNickname,omitempty"`
	PasswordHash      string `json:"passwordHash,omitempty"`
	// group
	Description     string   `json:"description,omitempty"`
	MailEnabled     bool     `json:"mailEnabled"`
	SecurityEnabled bool     `json:"securityEnabled"`
	Members         []string `json:"members,omitempty"` // object ids, in the order added

	Passwords []Password `json:"passwordCredentials,omitempty"`

	// Seeded objects come from the configuration: rebuilt at every
	// boot, never journaled or dumped, not deletable. A change through
	// Graph clears the flag: the object is journaled and yours from then on.
	Seeded bool `json:"seeded,omitempty"`
}

// Password is one client secret: its metadata as Graph lists it and
// the salted hash Armite verifies against. The secret itself is shown
// once, by AddPassword, and never stored.
type Password struct {
	KeyID       string    `json:"keyId"`
	DisplayName string    `json:"displayName,omitempty"`
	Start       time.Time `json:"startDateTime"`
	End         time.Time `json:"endDateTime"`
	Hint        string    `json:"hint,omitempty"`
	Hash        string    `json:"hash"`
}

// Lookup is what the other planes need from the directory.
type Lookup interface {
	// PrincipalByID returns a user, group or service principal by object id.
	PrincipalByID(id string) (Object, bool)
	// Authenticate returns the service principal for appID when secret
	// is one of its current passwords (on its application or itself).
	Authenticate(appID, secret string) (Object, bool)
}

// Store holds the directory in memory and journals every change.
// Copies cross the boundary both ways (Members and Passwords are
// slices). Safe for concurrent use.
type Store struct {
	log  *state.Log
	mu   sync.RWMutex
	byID map[string]Object // lowercase id
}

var _ state.Store = (*Store)(nil)
var _ Lookup = (*Store)(nil)

// New returns an empty directory that journals through log; a nil log
// keeps it in memory only.
func New(log *state.Log) *Store {
	s := &Store{log: log, byID: make(map[string]Object)}
	log.Attach(storeName, s)
	return s
}

func key(id string) string { return strings.ToLower(id) }

func (o Object) clone() Object {
	o.Members = slices.Clone(o.Members)
	o.Passwords = slices.Clone(o.Passwords)
	return o
}

// seedTime is the createdDateTime of every seeded object: fixed, so a
// listing is stable across boots.
var seedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Seed puts the configuration's identities in the directory: for each
// client an application and a service principal, the client's secret
// becoming the application's password (where az create-for-rbac puts
// it); for the managed identity a service principal. Call it before
// Replay, so journaled changes to a seed win.
func (s *Store) Seed(cfg config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range cfg.Clients {
		hash, err := hashSecret(c.Secret)
		if err != nil {
			return err
		}
		name := "armite-client-" + short(c.ID)
		s.setLocked(Object{
			ID: derivedID("application", c.ObjectID), Kind: KindApplication, DisplayName: name,
			Created: seedTime, AppID: c.ID, AccountEnabled: true, Seeded: true,
			Passwords: []Password{{KeyID: derivedID("password", c.ObjectID), DisplayName: "armite.yaml",
				Start: seedTime, End: seedTime.AddDate(100, 0, 0), Hint: hint(c.Secret), Hash: hash}},
		})
		s.setLocked(Object{
			ID: c.ObjectID, Kind: KindServicePrincipal, DisplayName: name, Created: seedTime,
			AppID: c.ID, ServicePrincipalType: "Application", AccountEnabled: true, Seeded: true,
		})
	}
	if mi := cfg.ManagedIdentity; mi.ObjectID != "" {
		s.setLocked(Object{
			ID: mi.ObjectID, Kind: KindServicePrincipal, DisplayName: "armite-managed-identity",
			Created: seedTime, AppID: mi.ClientID, ServicePrincipalType: "ManagedIdentity",
			AccountEnabled: true, Seeded: true,
		})
	}
	return nil
}

// setLocked stores o in memory only; the caller holds the lock.
func (s *Store) setLocked(o Object) { s.byID[key(o.ID)] = o.clone() }

// commitLocked stores o and journals it. A seeded object that changes
// stops being a seed: from now on the journal, not the file, holds it.
func (s *Store) commitLocked(o Object) error {
	o.Seeded = false
	s.byID[key(o.ID)] = o.clone()
	value, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return s.log.Append(state.Record{Store: storeName, Key: key(o.ID), Value: value})
}

// Create stores a new object, assigning its id and creation time, and
// refuses the keys Graph keeps unique: appId for applications and
// service principals, userPrincipalName for users.
func (s *Store) Create(o Object) (Object, error) {
	if o.Kind == "" || o.DisplayName == "" {
		return Object{}, errors.New("directory: kind and displayName are required")
	}
	o.ID = newID()
	o.Created = time.Now().UTC().Truncate(time.Second)
	o.Members, o.Passwords, o.Seeded = nil, nil, false
	if o.Kind != KindUser {
		o.PasswordHash = ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch o.Kind {
	case KindApplication:
		if o.AppID == "" {
			o.AppID = newID()
		}
		if _, ok := s.byAppIDLocked(KindApplication, o.AppID); ok {
			return Object{}, ErrConflict
		}
	case KindServicePrincipal:
		if o.AppID == "" {
			return Object{}, errors.New("directory: a service principal needs an appId")
		}
		if _, ok := s.byAppIDLocked(KindServicePrincipal, o.AppID); ok {
			return Object{}, ErrConflict
		}
		if o.ServicePrincipalType == "" {
			o.ServicePrincipalType = "Application"
		}
	case KindUser:
		if o.UserPrincipalName == "" {
			return Object{}, errors.New("directory: a user needs a userPrincipalName")
		}
		if _, ok := s.byUPNLocked(o.UserPrincipalName); ok {
			return Object{}, ErrConflict
		}
	}
	return o.clone(), s.commitLocked(o)
}

// Get returns the object with the given id.
func (s *Store) Get(id string) (Object, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.byID[key(id)]
	return o.clone(), ok
}

// ByAppID returns the application or service principal (kind) for appID.
func (s *Store) ByAppID(kind, appID string) (Object, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byAppIDLocked(kind, appID)
}

func (s *Store) byAppIDLocked(kind, appID string) (Object, bool) {
	for _, o := range s.byID {
		if o.Kind == kind && strings.EqualFold(o.AppID, appID) {
			return o.clone(), true
		}
	}
	return Object{}, false
}

// ByUPN returns the user with that userPrincipalName.
func (s *Store) ByUPN(upn string) (Object, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byUPNLocked(upn)
}

func (s *Store) byUPNLocked(upn string) (Object, bool) {
	for _, o := range s.byID {
		if o.Kind == KindUser && strings.EqualFold(o.UserPrincipalName, upn) {
			return o.clone(), true
		}
	}
	return Object{}, false
}

// List returns the objects of one kind that keep accepts (nil keeps
// all), sorted by creation time then id, so listings are stable.
func (s *Store) List(kind string, keep func(Object) bool) []Object {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Object, 0)
	for _, o := range s.byID {
		if o.Kind == kind && (keep == nil || keep(o)) {
			out = append(out, o.clone())
		}
	}
	slices.SortFunc(out, func(a, b Object) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// Update applies fn to the object with id and journals the result.
func (s *Store) Update(id string, fn func(*Object) error) (Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.byID[key(id)]
	if !ok {
		return Object{}, ErrNotFound
	}
	o = o.clone()
	if err := fn(&o); err != nil {
		return Object{}, err
	}
	return o.clone(), s.commitLocked(o)
}

// Delete removes the object with id. A seed cannot be deleted; an
// application takes its service principals with it, as Entra does, and
// whatever is deleted leaves the groups it was in.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.byID[key(id)]
	if !ok {
		return ErrNotFound
	}
	if o.Seeded {
		return ErrSeeded
	}
	victims := []string{key(o.ID)}
	if o.Kind == KindApplication {
		for k, sp := range s.byID {
			if sp.Kind == KindServicePrincipal && strings.EqualFold(sp.AppID, o.AppID) && !sp.Seeded {
				victims = append(victims, k)
			}
		}
	}
	for _, k := range victims {
		delete(s.byID, k)
		if err := s.log.Append(state.Record{Store: storeName, Key: k, Deleted: true}); err != nil {
			return err
		}
	}
	return s.dropMembersLocked(victims)
}

// AddPassword adds a client secret to an application or service
// principal and returns the secret, which is never stored.
func (s *Store) AddPassword(id, displayName string, start, end time.Time) (secret string, p Password, err error) {
	secret, err = newSecret()
	if err != nil {
		return "", Password{}, err
	}
	hash, err := hashSecret(secret)
	if err != nil {
		return "", Password{}, err
	}
	p = Password{KeyID: newID(), DisplayName: displayName, Start: start, End: end, Hint: hint(secret), Hash: hash}
	_, err = s.Update(id, func(o *Object) error {
		if o.Kind != KindApplication && o.Kind != KindServicePrincipal {
			return fmt.Errorf("directory: %s objects have no passwords", o.Kind)
		}
		o.Passwords = append(o.Passwords, p)
		return nil
	})
	return secret, p, err
}

// newSecret is 256 random bits as 64 hex characters: nothing a shell,
// a YAML file or a command line can misread. A base64url secret starts
// with "-" once in 64, and "az login -p -abc" then fails as an unknown
// option.
func newSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// RemovePassword removes the credential with keyID.
func (s *Store) RemovePassword(id, keyID string) error {
	_, err := s.Update(id, func(o *Object) error {
		n := len(o.Passwords)
		o.Passwords = slices.DeleteFunc(o.Passwords, func(p Password) bool { return p.KeyID == keyID })
		if len(o.Passwords) == n {
			return ErrNotFound
		}
		return nil
	})
	return err
}

// CreateUser stores a new user. The password is kept only as a hash:
// nothing reads it back, and it is there for the day users can sign in.
func (s *Store) CreateUser(o Object, password string) (Object, error) {
	if password == "" {
		return Object{}, errors.New("directory: a user needs a password")
	}
	hash, err := hashSecret(password)
	if err != nil {
		return Object{}, err
	}
	o.Kind, o.PasswordHash = KindUser, hash
	return s.Create(o)
}

// SetUserPassword replaces a user's password.
func (s *Store) SetUserPassword(id, password string) error {
	hash, err := hashSecret(password)
	if err != nil {
		return err
	}
	_, err = s.Update(id, func(o *Object) error {
		if o.Kind != KindUser {
			return fmt.Errorf("directory: %s objects have no password profile", o.Kind)
		}
		o.PasswordHash = hash
		return nil
	})
	return err
}

// PrincipalByID implements Lookup: users, groups and service principals
// are principals; applications are not.
func (s *Store) PrincipalByID(id string) (Object, bool) {
	o, ok := s.Get(id)
	if !ok || o.Kind == KindApplication {
		return Object{}, false
	}
	return o, true
}

// Authenticate implements Lookup: the enabled service principal for
// appID whose application or own passwords include secret, unexpired.
func (s *Store) Authenticate(appID, secret string) (Object, bool) {
	sp, ok := s.ByAppID(KindServicePrincipal, appID)
	if !ok || !sp.AccountEnabled {
		return Object{}, false
	}
	candidates := sp.Passwords
	if app, ok := s.ByAppID(KindApplication, appID); ok {
		candidates = append(candidates, app.Passwords...)
	}
	now := time.Now()
	for _, p := range candidates {
		if now.Before(p.Start) || now.After(p.End) {
			continue
		}
		if verifySecret(p.Hash, secret) {
			return sp, true
		}
	}
	return Object{}, false
}

// Restore applies one journaled change during replay. A journaled
// object replaces a seed of the same id: the change made through Graph
// wins over the file.
func (s *Store) Restore(rec state.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.Deleted {
		delete(s.byID, rec.Key)
		return nil
	}
	var o Object
	if err := json.Unmarshal(rec.Value, &o); err != nil {
		return err
	}
	s.byID[rec.Key] = o
	return nil
}

// Dump emits every non-seeded object for a snapshot: seeds are rebuilt
// from the file at boot and must not come back from a snapshot after
// the file changed.
func (s *Store) Dump(emit func(state.Record) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, o := range s.byID {
		if o.Seeded {
			continue
		}
		value, err := json.Marshal(o)
		if err != nil {
			return err
		}
		if err := emit(state.Record{Store: storeName, Key: k, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

// hashSecret derives a key from the secret with PBKDF2-HMAC-SHA256 and
// a random salt and returns "pbkdf2-sha256$iterations$salt$key". A
// password hash must be slow on purpose: a plain SHA-256 of a secret is
// a dictionary attack away from the secret, and the journal is a file
// on disk. The parameters travel with the hash, so they can change.
func hashSecret(secret string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, secret, salt, kdfIters, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", kdfName, kdfIters,
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(key)), nil
}

// verifySecret re-derives the key with the stored parameters and
// compares in constant time, so a wrong secret takes as long as a
// right one.
func verifySecret(stored, secret string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != kdfName {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters < 1 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	key, err := pbkdf2.Key(sha256.New, secret, salt, iters, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, want) == 1
}

// hint is the first three characters, as Graph shows for a credential.
func hint(secret string) string {
	if len(secret) < 3 {
		return secret
	}
	return secret[:3]
}

func short(id string) string {
	if len(id) < 8 {
		return id
	}
	return id[:8]
}

// newID is a random UUID v4 in the canonical form Graph uses.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // the system's random source failing is not recoverable here
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return format(b)
}

// derivedID is a stable UUID for a seed's companion objects (the
// application behind a configured client, its password credential), so
// ids do not change between boots.
func derivedID(kind, objectID string) string {
	sum := sha256.Sum256([]byte(kind + ":" + strings.ToLower(objectID)))
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return format(b)
}

func format(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
