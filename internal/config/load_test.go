package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// testStateKey is 32 zero bytes, base64.
const testStateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provisio.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsOnly(t *testing.T) {
	got, err := Load("")
	if err != nil || got.TenantID != Default().TenantID {
		t.Fatalf("Load(\"\") = %+v, %v", got.TenantID, err)
	}
}

func TestLoadOverlaysTheFile(t *testing.T) {
	path := writeYAML(t, `
tenant_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
vault_host: kv.local
clients:
- id: 33333333-3333-3333-3333-333333333333
  secret: changed
  object_id: 44444444-4444-4444-4444-444444444444
managed_identity:
  client_id: 99999999-9999-9999-9999-999999999999
`)
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" || got.VaultHost != "kv.local" {
		t.Errorf("scalars not overlaid: %+v", got)
	}
	if got.SubscriptionID != Default().SubscriptionID || got.ARMHost != "management.localhost" {
		t.Errorf("absent keys must keep defaults: %+v", got)
	}
	if len(got.Clients) != 1 || got.Clients[0].Secret != "changed" {
		t.Errorf("a present list replaces the default list: %+v", got.Clients)
	}
	mi := got.ManagedIdentity
	if mi.ClientID != "99999999-9999-9999-9999-999999999999" ||
		mi.ObjectID != Default().ManagedIdentity.ObjectID {
		t.Errorf("nested struct must overlay field by field: %+v", mi)
	}
	if got.IssuerURL() != "https://login.localhost:8443/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/v2.0" {
		t.Errorf("derived values must follow: %s", got.IssuerURL())
	}
}

func TestLoadEnvAfterFile(t *testing.T) {
	path := writeYAML(t, "listener_addr: 127.0.0.1:9443\nstate:\n  dir: /tmp/a\n")
	t.Setenv("PROVISIO_LISTEN_ADDR", "0.0.0.0:9443")
	t.Setenv("PROVISIO_STATE_DIR", "/tmp/b")
	t.Setenv("PROVISIO_STATE_KEY", testStateKey)
	got, err := Load(path)
	if err != nil || got.ListenerAddr != "0.0.0.0:9443" {
		t.Errorf("env must win over the file: %q, %v", got.ListenerAddr, err)
	}
	if got.State.Dir != "/tmp/b" || got.State.Key != testStateKey {
		t.Errorf("state env must win over the file: %+v", got.State)
	}
}

func TestValidateNamesEveryProblem(t *testing.T) {
	bad := Default()
	bad.TenantID = "not-a-guid"
	bad.VaultHost = "vault.localhost:8443"
	bad.LoginHost = bad.ARMHost
	bad.Clients[0].Secret = ""
	bad.RoleAssignments = append(bad.RoleAssignments, SeedAssignment{
		PrincipalID: "77777777-7777-7777-7777-777777777777", RoleDefinitionID: "x", Scope: "sub"})
	bad.State.CompactAfterMB = -1
	bad.State.Key = "not-a-key"
	bad.BlobHost = "storage.localhost"
	bad.Azurite = Azurite{Mode: "byo", Upstream: "azurite:10000",
		Accounts: []StorageAccount{{Name: "Bad-Name", Key: "not base64!"}}}
	err := bad.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"tenant_id", "vault_host", "arm_host/login_host/vault_host",
		"clients[0].secret", "role_assignments[2].principal_id", "role_assignments[2].role_definition_id",
		"role_assignments[2].scope", "state.compact_after_mb", "state.key", "blob_host",
		"azurite.upstream", "azurite.accounts[0].name", "azurite.accounts[0].key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %s:\n%v", want, err)
		}
	}
	if Default().Validate() != nil {
		t.Errorf("the defaults must validate: %v", Default().Validate())
	}
	good := Default()
	good.State = State{Dir: "", CompactAfterMB: 0, Key: testStateKey}
	good.Azurite = Azurite{Mode: "byo", Upstream: "http://azurite:10000",
		Accounts: []StorageAccount{{Name: "devstoreaccount1", Key: testStateKey}}}
	if err := good.Validate(); err != nil {
		t.Errorf("memory only, never compact, a real key, a byo azurite: %v", err)
	}
	good.Azurite = Azurite{Mode: "nope"}
	if err := good.Validate(); err == nil || !strings.Contains(err.Error(), "azurite.mode") {
		t.Errorf("an unknown azurite mode must be named: %v", err)
	}
	same := Default()
	same.BlobHost = "blob.localhost"
	same.VaultHost = "blob.localhost"
	if err := same.Validate(); err == nil || !strings.Contains(err.Error(), "four different") {
		t.Errorf("two planes on one hostname must be refused: %v", err)
	}
}

func TestRedactedAndYAMLRoundTrip(t *testing.T) {
	out, err := Default().YAML()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(writeYAML(t, string(out)))
	if err != nil {
		t.Fatalf("YAML() must be loadable: %v", err)
	}
	if got.Clients[0].Secret != "provisio-secret" {
		t.Error("round trip lost the secret")
	}
	withKey := Default()
	withKey.State.Key = testStateKey
	red, _ := withKey.Redacted().YAML()
	if strings.Contains(string(red), "provisio-secret") ||
		strings.Contains(string(red), testStateKey) || strings.Count(string(red), "***") != 2 {
		t.Errorf("Redacted must mask the client secret and the state key:\n%s", red)
	}
	if red, _ = Default().Redacted().YAML(); !strings.Contains(string(red), `key: ""`) {
		t.Errorf("an empty state key has nothing to mask:\n%s", red)
	}
}

// Changing a principal's object id without touching role_assignments
// leaves the default seeds pointing at a principal that no longer
// exists; Load must say so rather than seed a dangling assignment.
func TestLoadRejectsSeedsForUnknownPrincipal(t *testing.T) {
	path := writeYAML(t, "managed_identity:\n  object_id: 99999999-9999-9999-9999-999999999999\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "role_assignments[1].principal_id") {
		t.Errorf("want the dangling seed named, got: %v", err)
	}
}

func TestTemplateIsCommentedAndLoadable(t *testing.T) {
	out, err := Template()
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	wants := []string{"# Provisio configuration", "# Owner", "# Contributor", "role_assignments:",
		"# Where resources, role assignments and secrets persist", "compact_after_mb: 8",
		"blob_host: blob.localhost", "# The blob store behind storage accounts", "mode: managed"}
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("template lacks %q:\n%s", want, text)
		}
	}
	got, err := Load(writeYAML(t, text))
	if err != nil {
		t.Fatalf("the template must load unchanged: %v", err)
	}
	if got.TenantID != Default().TenantID || len(got.RoleAssignments) != 2 {
		t.Errorf("template round trip changed the defaults: %+v", got)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := writeYAML(t, "tenant_id: 11111111-1111-1111-1111-111111111111\nvault_hots: x\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "line 2: field vault_hots not found") ||
		!strings.Contains(err.Error(), "2 | vault_hots: x") || strings.Contains(err.Error(), "in type") {
		t.Errorf("unknown key must be named with its line and source, got: %v", err)
	}
}

func TestLoadRejectsBadYAMLAndMissingFile(t *testing.T) {
	_, err := Load(writeYAML(t, "tenant_id: x\nclients: [\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2:") {
		t.Errorf("malformed YAML must fail with its line, got: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("a missing file named explicitly must fail")
	}
	if _, err := Load(writeYAML(t, "")); err != nil {
		t.Errorf("an empty file is defaults: %v", err)
	}
}

func TestAnnotateRejectsUnknownPath(t *testing.T) {
	var doc yaml.Node
	if err := doc.Encode(Default()); err != nil {
		t.Fatal(err)
	}
	if err := annotate(&doc, "clients.0.secret", "", "change me"); err != nil {
		t.Errorf("known path: %v", err)
	}
	for _, path := range []string{"no_such_key", "clients.7.secret", "clients.x"} {
		if err := annotate(&doc, path, "h", ""); err == nil {
			t.Errorf("annotate(%q) must fail: a renamed key must not drop its comment", path)
		}
	}
}
