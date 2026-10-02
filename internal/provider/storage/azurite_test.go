package storage

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/azurite"
)

// azuriteCommand is the azurite-blob executable the integration tests
// drive; without it they are skipped.
func azuriteCommand(t *testing.T) string {
	t.Helper()
	cmd := os.Getenv("PROVISIO_AZURITE")
	if cmd == "" {
		t.Skip("set PROVISIO_AZURITE to the azurite-blob executable to run this test")
	}
	return cmd
}

func newKey() string {
	key := make([]byte, 64)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// signedStatus performs a Shared Key request host-style against the
// local Azurite: the account is the first label of the Host header.
func signedStatus(t *testing.T, addr, method, account, key, path string) int {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(key)
	r, _ := http.NewRequest(method, "http://"+addr+path, nil)
	r.Host = account + ".blob.localhost"
	r.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	r.Header.Set("x-ms-version", "2025-07-05")
	signSharedKey(r, account, raw)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAzuriteStartRestartStop(t *testing.T) {
	m := azurite.New(azuriteCommand(t), t.TempDir(), 10900)
	defer m.Stop()
	k1, k2 := newKey(), newKey()

	started := time.Now()
	if err := m.Start(map[string]string{"one": k1}); err != nil {
		t.Fatal(err)
	}
	t.Logf("cold start: %v", time.Since(started))
	const cont = "/cont1?restype=container"
	if got := signedStatus(t, m.Addr(), http.MethodPut, "one", k1, cont); got != 201 {
		t.Errorf("create container as 'one' = %d, want 201", got)
	}
	if got := signedStatus(t, m.Addr(), http.MethodGet, "two", k2, "/?comp=list"); got == 200 {
		t.Error("account 'two' must not exist yet")
	}

	started = time.Now()
	if err := m.Start(map[string]string{"one": k1, "two": k2}); err != nil {
		t.Fatal(err)
	}
	t.Logf("restart with a new account: %v", time.Since(started))
	if got := signedStatus(t, m.Addr(), http.MethodGet, "two", k2, "/?comp=list"); got != 200 {
		t.Errorf("list as 'two' after restart = %d, want 200", got)
	}
	if got := signedStatus(t, m.Addr(), http.MethodGet, "one", k1, cont); got != 200 {
		t.Errorf("container of 'one' must survive the restart, got %d", got)
	}
	// Same set again: no restart, same process.
	if err := m.Start(map[string]string{"one": k1, "two": k2}); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get("http://" + m.Addr() + "/"); err == nil {
		t.Error("after Stop the port must be closed")
	}
}
