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
