package azurite

import (
	"net"
	"strings"
	"testing"
)

func TestAccountsEnv(t *testing.T) {
	got := accountsEnv(map[string]string{"zeta": "k2", "alpha": "k1"})
	if got != "alpha:k1;zeta:k2" {
		t.Errorf("accountsEnv = %q, want names sorted, name:key joined by ;", got)
	}
	empty := accountsEnv(nil)
	if !strings.HasPrefix(empty, "placeholder:") || len(empty) < len("placeholder:")+80 {
		t.Errorf("no accounts must yield a placeholder with a random key, got %q", empty)
	}
	if accountsEnv(nil) == empty {
		t.Error("the placeholder key must differ between calls")
	}
}

func TestStartRefusesAPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	m := New("no-such-command", t.TempDir(), port)
	err = m.Start(nil)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("Start with the port taken = %v, want 'already in use'", err)
	}
}
