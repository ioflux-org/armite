package directory

import (
	"bytes"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/state"
)

var testKey = bytes.Repeat([]byte{9}, 32)

func open(t *testing.T, dir string) (*state.Log, *Store) {
	return openWith(t, dir, config.Default())
}

func openWith(t *testing.T, dir string, cfg config.Config) (*state.Log, *Store) {
	t.Helper()
	log, err := state.Open(dir, testKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	s := New(log)
	if err := s.Seed(cfg); err != nil {
		t.Fatal(err)
	}
	if err := log.Replay(); err != nil {
		t.Fatal(err)
	}
	return log, s
}

func TestSeedsLogInAndAreNotJournaled(t *testing.T) {
	cfg := config.Default()
	client := cfg.Clients[0]
	_, s := open(t, t.TempDir())
	sp, ok := s.Authenticate(client.ID, client.Secret)
	if !ok || sp.ID != client.ObjectID || sp.Kind != KindServicePrincipal {
		t.Fatalf("seeded client cannot log in: %+v %v", sp, ok)
	}
	if _, ok := s.Authenticate(client.ID, "wrong"); ok {
		t.Error("a wrong secret logged in")
	}
	if _, ok := s.PrincipalByID(cfg.ManagedIdentity.ObjectID); !ok {
		t.Error("the managed identity is not a principal")
	}
	if err := s.Delete(client.ObjectID); !errors.Is(err, ErrSeeded) {
		t.Errorf("deleting a seed: %v, want ErrSeeded", err)
	}
	n := 0
	if err := s.Dump(func(state.Record) error { n++; return nil }); err != nil || n != 0 {
		t.Errorf("a snapshot would hold %d seeded objects, want 0 (%v)", n, err)
	}
}

func TestCreateKeepsKeysUnique(t *testing.T) {
	_, s := open(t, t.TempDir())
	app, err := s.Create(Object{Kind: KindApplication, DisplayName: "demo"})
	if err != nil || app.AppID == "" || app.ID == "" {
		t.Fatalf("create application: %+v %v", app, err)
	}
	if _, err := s.Create(Object{Kind: KindApplication, DisplayName: "demo", AppID: app.AppID}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate appId: %v", err)
	}
	sp, err := s.Create(Object{Kind: KindServicePrincipal, DisplayName: "demo", AppID: app.AppID})
	if err != nil || sp.ServicePrincipalType != "Application" {
		t.Fatalf("create sp: %+v %v", sp, err)
	}
	if _, err := s.Create(Object{Kind: KindServicePrincipal, DisplayName: "demo", AppID: app.AppID}); !errors.Is(err, ErrConflict) {
		t.Errorf("second sp for one app: %v", err)
	}
	if _, err := s.Create(Object{Kind: KindUser, DisplayName: "u", UserPrincipalName: "u@armite.local"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(Object{Kind: KindUser, DisplayName: "u2", UserPrincipalName: "U@ARMITE.LOCAL"}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate UPN (case-insensitive): %v", err)
	}
	if got := s.List(KindServicePrincipal, nil); len(got) != 3 { // two seeds + demo
		t.Errorf("service principals = %d, want 3", len(got))
	}
}

func TestPasswordsAreShownOnceAndVerified(t *testing.T) {
	_, s := open(t, t.TempDir())
	app, _ := s.Create(Object{Kind: KindApplication, DisplayName: "demo"})
	sp, _ := s.Create(Object{Kind: KindServicePrincipal, DisplayName: "demo", AppID: app.AppID, AccountEnabled: true})
	now := time.Now()
	secret, cred, err := s.AddPassword(app.ID, "rbac", now, now.Add(24*time.Hour))
	if err != nil || secret == "" || cred.KeyID == "" || cred.Hint != secret[:3] {
		t.Fatalf("addPassword: %q %+v %v", secret, cred, err)
	}
	got, _ := s.Get(app.ID)
	if got.Passwords[0].Hash == secret || got.Passwords[0].Hash == "" {
		t.Error("the secret or nothing was stored; want a salted hash")
	}
	if p, ok := s.Authenticate(app.AppID, secret); !ok || p.ID != sp.ID {
		t.Errorf("login with the application's password: %+v %v", p, ok)
	}
	if err := s.RemovePassword(app.ID, cred.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate(app.AppID, secret); ok {
		t.Error("a removed password still logs in")
	}
	expired, _, _ := s.AddPassword(sp.ID, "old", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if _, ok := s.Authenticate(app.AppID, expired); ok {
		t.Error("an expired password logged in")
	}
	if !strings.HasPrefix(got.Passwords[0].Hash, "pbkdf2-sha256$") {
		t.Errorf("hash = %q, want a pbkdf2-sha256 string with its parameters", got.Passwords[0].Hash)
	}
}

func TestDeletingAnApplicationRemovesItsServicePrincipals(t *testing.T) {
	_, s := open(t, t.TempDir())
	app, _ := s.Create(Object{Kind: KindApplication, DisplayName: "demo"})
	sp, _ := s.Create(Object{Kind: KindServicePrincipal, DisplayName: "demo", AppID: app.AppID})
	if err := s.Delete(app.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(sp.ID); ok {
		t.Error("the service principal outlived its application")
	}
}

func TestCreatedObjectsAndChangedSeedsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	log, s := open(t, dir)
	user, _ := s.Create(Object{Kind: KindUser, DisplayName: "u", UserPrincipalName: "u@armite.local"})
	seedApp, _ := s.ByAppID(KindApplication, cfg.Clients[0].ID)
	secret, _, err := s.AddPassword(seedApp.ID, "extra", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	log.Close()

	log2, s2 := open(t, dir)
	if _, ok := s2.ByUPN(user.UserPrincipalName); !ok {
		t.Error("the user did not survive the restart")
	}
	if _, ok := s2.Authenticate(cfg.Clients[0].ID, secret); !ok {
		t.Error("the password added to the seed did not survive the restart")
	}
	if _, ok := s2.Authenticate(cfg.Clients[0].ID, cfg.Clients[0].Secret); !ok {
		t.Error("the file's credential was part of the journaled object and must still work")
	}
	log2.Close()

	// The journal holds the seed now: a secret rotated in the file does
	// not reach it, and the journaled credential keeps working.
	rotated := cfg
	rotated.Clients = slices.Clone(cfg.Clients)
	rotated.Clients[0].Secret = "rotated-in-the-file"
	_, s3 := openWith(t, dir, rotated)
	if _, ok := s3.Authenticate(cfg.Clients[0].ID, "rotated-in-the-file"); ok {
		t.Error("the rotated file secret works although the journal holds the seed; expected the journal to win")
	}
	if _, ok := s3.Authenticate(cfg.Clients[0].ID, cfg.Clients[0].Secret); !ok {
		t.Error("the journaled credential stopped working after the file changed")
	}
}

func TestSecretsAreSafeToPaste(t *testing.T) {
	safe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	seen := map[string]bool{}
	for range 200 {
		s, err := newSecret()
		if err != nil {
			t.Fatal(err)
		}
		if !safe.MatchString(s) {
			t.Fatalf("secret %q is not 64 hex characters", s)
		}
		if seen[s] {
			t.Fatalf("secret %q came out twice", s)
		}
		seen[s] = true
	}
}

// mk creates an object or fails the test.
func mk(t *testing.T, s *Store, o Object) Object {
	t.Helper()
	if o.Kind == KindUser {
		created, err := s.CreateUser(o, "P@ssw0rd!")
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	created, err := s.Create(o)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func ids(objs []Object) []string {
	out := make([]string, len(objs))
	for i, o := range objs {
		out[i] = o.ID
	}
	return out
}

// sameSet compares without order: groups created in the same second
// sort by their random ids.
func sameSet(got []string, want ...string) bool {
	got, want = slices.Clone(got), slices.Clone(want)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

func TestGroupsNestAndACycleEndsTheWalk(t *testing.T) {
	_, s := open(t, t.TempDir())
	user := mk(t, s, Object{Kind: KindUser, DisplayName: "u", UserPrincipalName: "u@armite.local"})
	app := mk(t, s, Object{Kind: KindApplication, DisplayName: "app"})
	sp := mk(t, s, Object{Kind: KindServicePrincipal, DisplayName: "app", AppID: app.AppID, AccountEnabled: true})
	a := mk(t, s, Object{Kind: KindGroup, DisplayName: "a"})
	b := mk(t, s, Object{Kind: KindGroup, DisplayName: "b"})
	c := mk(t, s, Object{Kind: KindGroup, DisplayName: "c"})
	// a holds the user and b; b holds the service principal and c; c holds a: a cycle.
	for _, pair := range [][2]string{{a.ID, user.ID}, {a.ID, b.ID}, {b.ID, sp.ID}, {b.ID, c.ID}, {c.ID, a.ID}} {
		if err := s.AddMember(pair[0], pair[1]); err != nil {
			t.Fatalf("AddMember(%s, %s): %v", pair[0], pair[1], err)
		}
	}

	direct, ok := s.Members(a.ID, false)
	if !ok || !slices.Equal(ids(direct), []string{user.ID, b.ID}) {
		t.Errorf("direct members of a = %v, want the user then b, in the order added", ids(direct))
	}
	all, _ := s.Members(a.ID, true)
	if !slices.Equal(ids(all), []string{user.ID, b.ID, sp.ID, c.ID}) {
		t.Errorf("transitive members of a = %v, want user, b, sp, c - and not a itself", ids(all))
	}
	if _, ok := s.Members(user.ID, false); ok {
		t.Error("Members of a user must report that it is not a group")
	}

	if got := ids(s.GroupsOf(sp.ID, false)); !sameSet(got, b.ID) {
		t.Errorf("direct groups of the service principal = %v, want b", got)
	}
	if got := s.TransitiveGroupIDs(sp.ID); !sameSet(got, a.ID, b.ID, c.ID) {
		t.Errorf("transitive groups of the service principal = %v, want a, b and c", got)
	}
	if got := s.TransitiveGroupIDs(a.ID); !sameSet(got, b.ID, c.ID) {
		t.Errorf("transitive groups of a = %v, want b and c - a group is not in itself, even around a cycle", got)
	}
	if got := s.TransitiveGroupIDs(app.ID); len(got) != 0 {
		t.Errorf("an application is in no group, got %v", got)
	}
}

func TestMembershipRules(t *testing.T) {
	_, s := open(t, t.TempDir())
	user := mk(t, s, Object{Kind: KindUser, DisplayName: "u", UserPrincipalName: "u@armite.local"})
	app := mk(t, s, Object{Kind: KindApplication, DisplayName: "app"})
	g := mk(t, s, Object{Kind: KindGroup, DisplayName: "g"})
	if err := s.AddMember(g.ID, strings.ToUpper(user.ID)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		what          string
		group, member string
		want          error
	}{
		{"a member twice", g.ID, user.ID, ErrConflict},
		{"the group itself", g.ID, g.ID, ErrSelfMember},
		{"an unknown member", g.ID, "00000000-0000-0000-0000-000000000000", ErrNotFound},
		{"an application", g.ID, app.ID, ErrNotFound},
		{"a user as the group", user.ID, g.ID, ErrNotFound},
	} {
		if err := s.AddMember(tc.group, tc.member); !errors.Is(err, tc.want) {
			t.Errorf("AddMember, %s: %v, want %v", tc.what, err, tc.want)
		}
	}
	if err := s.RemoveMember(g.ID, app.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("RemoveMember of a non-member: %v, want ErrNotFound", err)
	}
	if err := s.RemoveMember(g.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.Members(g.ID, false); len(m) != 0 {
		t.Errorf("after RemoveMember: %v", ids(m))
	}
}

func TestDeletedObjectsLeaveTheirGroupsAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	log, s := openWith(t, dir, cfg)
	user := mk(t, s, Object{Kind: KindUser, DisplayName: "u", UserPrincipalName: "u@armite.local"})
	app := mk(t, s, Object{Kind: KindApplication, DisplayName: "app"})
	sp := mk(t, s, Object{Kind: KindServicePrincipal, DisplayName: "app", AppID: app.AppID, AccountEnabled: true})
	inner := mk(t, s, Object{Kind: KindGroup, DisplayName: "inner"})
	outer := mk(t, s, Object{Kind: KindGroup, DisplayName: "outer"})
	seed := cfg.Clients[0].ObjectID
	for _, m := range []string{user.ID, sp.ID, inner.ID, seed} {
		if err := s.AddMember(outer.ID, m); err != nil {
			t.Fatal(err)
		}
	}
	// A user, an application (taking its service principal) and a group go.
	for _, id := range []string{user.ID, app.ID, inner.ID} {
		if err := s.Delete(id); err != nil {
			t.Fatal(err)
		}
	}
	if m, _ := s.Members(outer.ID, false); !slices.Equal(ids(m), []string{seed}) {
		t.Fatalf("members after the deletes = %v, want only the configured principal", ids(m))
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	_, s = openWith(t, dir, cfg)
	if m, _ := s.Members(outer.ID, false); !slices.Equal(ids(m), []string{seed}) {
		t.Errorf("members after a restart = %v, want only the configured principal", ids(m))
	}
	if got := s.TransitiveGroupIDs(seed); !sameSet(got, outer.ID) {
		t.Errorf("groups of the configured principal after a restart = %v", got)
	}
}

func TestAMemberRemovedFromTheConfigurationIsSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	log, s := openWith(t, dir, cfg)
	g := mk(t, s, Object{Kind: KindGroup, DisplayName: "g"})
	if err := s.AddMember(g.ID, cfg.Clients[0].ObjectID); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Clients = nil // the client is gone from armite.yaml
	_, s = openWith(t, dir, cfg)
	if m, ok := s.Members(g.ID, true); !ok || len(m) != 0 {
		t.Errorf("members = %v, want none: the id no longer names anything", ids(m))
	}
}

func TestUserPasswordsAreKeptAsHashes(t *testing.T) {
	_, s := open(t, t.TempDir())
	u, err := s.CreateUser(Object{DisplayName: "Ada", UserPrincipalName: "ada@armite.local"}, "P@ssw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if u.Kind != KindUser || strings.Contains(u.PasswordHash, "P@ssw0rd!") || !verifySecret(u.PasswordHash, "P@ssw0rd!") {
		t.Errorf("created user = %+v, want a user with a verifiable hash", u)
	}
	if _, err := s.CreateUser(Object{DisplayName: "Ada again", UserPrincipalName: "ADA@armite.local"}, "x"); !errors.Is(err, ErrConflict) {
		t.Errorf("a second user with the same userPrincipalName: %v, want ErrConflict", err)
	}
	if _, err := s.CreateUser(Object{DisplayName: "Bob", UserPrincipalName: "bob@armite.local"}, ""); err == nil {
		t.Error("a user without a password was accepted")
	}
	if err := s.SetUserPassword(u.ID, "N3w-secret"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(u.ID)
	if verifySecret(got.PasswordHash, "P@ssw0rd!") || !verifySecret(got.PasswordHash, "N3w-secret") {
		t.Error("SetUserPassword did not replace the password")
	}
	g := mk(t, s, Object{Kind: KindGroup, DisplayName: "g", PasswordHash: "leftover"})
	if g.PasswordHash != "" {
		t.Error("only users keep a password hash")
	}
	if err := s.SetUserPassword(g.ID, "x"); err == nil {
		t.Error("a group was given a password")
	}
}
