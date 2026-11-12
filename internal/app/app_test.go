package app_test

import (
	"strings"
	"testing"

	"github.com/ioflux-org/armite/internal/app/apptest"
	"github.com/ioflux-org/armite/internal/config"
)

const (
	sub            = "/subscriptions/22222222-2222-2222-2222-222222222222"
	client, secret = "33333333-3333-3333-3333-333333333333", "armite-secret"
	ownerObject    = "44444444-4444-4444-4444-444444444444"
	secretsOfficer = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7" // Key Vault Secrets Officer
	armScope       = "https://management.azure.com/.default"
	// what az keyvault create --enable-rbac-authorization sends
	vaultBody = `{"location":"eastus","properties":{"tenantId":"11111111-1111-1111-1111-111111111111",` +
		`"sku":{"name":"standard","family":"A"},"accessPolicies":[],"enableRbacAuthorization":true,` +
		`"enableSoftDelete":true,"softDeleteRetentionInDays":90}}`
)

// The hero flow: Owner creates the vault, is refused a secret, is
// granted the data role, and the same request succeeds. Every hop is a
// real HTTPS request to the real hostnames.
func TestOwnerIsRefusedASecretUntilGranted(t *testing.T) {
	s := apptest.Start(t)
	cfg := s.App.Config
	arm := cfg.ARMBaseURL()
	armTok := s.Token(client, secret, armScope)

	if st, body := s.Do("PUT", arm+sub+"/resourcegroups/kv-rg?api-version=2021-04-01", armTok,
		`{"location":"eastus"}`); st != 201 {
		t.Fatalf("create group: %d %s", st, body)
	}
	vaultID := sub + "/resourceGroups/kv-rg/providers/Microsoft.KeyVault/vaults/kv-demo"
	if st, body := s.Do("PUT", arm+vaultID+"?api-version=2025-05-01", armTok, vaultBody); st/100 != 2 {
		t.Fatalf("create vault: %d %s", st, body)
	}

	vaultTok := s.Token(client, secret, cfg.VaultAudience()+"/.default")
	secretURL := cfg.VaultURI("kv-demo") + "secrets/db-pass?api-version=7.4"
	st, body := s.Do("PUT", secretURL, vaultTok, `{"value":"hunter2"}`)
	if st != 403 || !strings.Contains(body, "ForbiddenByRbac") {
		t.Fatalf("Owner setting a secret: %d %s, want 403 ForbiddenByRbac", st, body)
	}

	grant := arm + vaultID + "/providers/Microsoft.Authorization/roleAssignments/" +
		"0f0f0f0f-0000-4000-8000-000000000001?api-version=2022-04-01"
	grantBody := `{"properties":{"roleDefinitionId":"` + sub +
		"/providers/Microsoft.Authorization/roleDefinitions/" + secretsOfficer +
		`","principalId":"` + ownerObject + `","principalType":"ServicePrincipal"}}`
	if st, body := s.Do("PUT", grant, armTok, grantBody); st != 201 {
		t.Fatalf("grant: %d %s", st, body)
	}

	if st, body := s.Do("PUT", secretURL, vaultTok, `{"value":"hunter2"}`); st != 200 {
		t.Fatalf("set after the grant: %d %s", st, body)
	}
	if st, body := s.Do("GET", secretURL, vaultTok, ""); st != 200 || !strings.Contains(body, "hunter2") {
		t.Fatalf("get after the grant: %d %s", st, body)
	}
}

// What was created survives a restart of the same home and state
// directory: the journal replays, the CA and keys are the same.
func TestStateSurvivesARestart(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	cfg := config.Default()
	cfg.ListenerAddr, cfg.IMDSAddr = "127.0.0.1:0", "127.0.0.1:0"
	cfg.State.Dir, cfg.Azurite.Mode = dir, "off"

	s := apptest.StartWith(t, cfg, home)
	group := sub + "/resourcegroups/kept?api-version=2021-04-01"
	if st, body := s.Do("PUT", s.App.Config.ARMBaseURL()+group, s.Token(client, secret, armScope),
		`{"location":"eastus"}`); st != 201 {
		t.Fatalf("create: %d %s", st, body)
	}
	s.Stop()

	s2 := apptest.StartWith(t, cfg, home)
	if st, body := s2.Do("GET", s2.App.Config.ARMBaseURL()+group, s2.Token(client, secret, armScope),
		""); st != 200 || !strings.Contains(body, `"kept"`) {
		t.Fatalf("after restart: %d %s", st, body)
	}
}
