package app_test

import (
	"encoding/json"
	"net/url"
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

// The directory answers on the graph host with a Graph token: the way
// az ad sp show finds a principal.
func TestGraphListsTheSeededPrincipal(t *testing.T) {
	s := apptest.Start(t)
	cfg := s.App.Config
	tok := s.Token(client, secret, cfg.GraphAudience()+"/.default")
	q := url.Values{"$filter": {"servicePrincipalNames/any(c:c eq '" + client + "')"}}
	st, body := s.Do("GET", cfg.GraphBaseURL()+"/v1.0/servicePrincipals?"+q.Encode(), tok, "")
	if st != 200 || !strings.Contains(body, ownerObject) {
		t.Fatalf("graph list: %d %s", st, body)
	}
}

// field is the string property name of a JSON object.
func field(t *testing.T, body, name string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("not a JSON object: %s", body)
	}
	v, _ := m[name].(string)
	if v == "" {
		t.Fatalf("no %q in %s", name, body)
	}
	return v
}

// newServicePrincipal does what az ad sp create-for-rbac does through
// Graph: an application, a secret on it, a service principal for it.
func newServicePrincipal(t *testing.T, s *apptest.Server, graphTok, name string) (appID, secret, object string) {
	t.Helper()
	graph := s.App.Config.GraphBaseURL() + "/v1.0"
	st, body := s.Do("POST", graph+"/applications", graphTok, `{"displayName":"`+name+`","keyCredentials":[]}`)
	if st != 201 {
		t.Fatalf("create application: %d %s", st, body)
	}
	appObject, appID := field(t, body, "id"), field(t, body, "appId")
	st, body = s.Do("POST", graph+"/applications/"+appObject+"/addPassword", graphTok,
		`{"passwordCredential":{"displayName":"rbac"}}`)
	if st != 200 {
		t.Fatalf("addPassword: %d %s", st, body)
	}
	secret = field(t, body, "secretText")
	st, body = s.Do("POST", graph+"/servicePrincipals", graphTok, `{"appId":"`+appID+`","accountEnabled":true}`)
	if st != 201 {
		t.Fatalf("create service principal: %d %s", st, body)
	}
	return appID, secret, field(t, body, "id")
}

// The az ad sp create-for-rbac flow over real HTTPS: a service
// principal created through Graph a moment ago logs in with the secret
// Graph showed once, is refused by ARM until a role is assigned, gets
// the role on the first try, and is then allowed exactly what the role
// allows.
func TestAServicePrincipalCreatedThroughGraph(t *testing.T) {
	s := apptest.Start(t)
	cfg := s.App.Config
	arm := cfg.ARMBaseURL()
	graphTok := s.Token(client, secret, cfg.GraphAudience()+"/.default")
	ownerTok := s.Token(client, secret, armScope)

	appID, newSecret, spObject := newServicePrincipal(t, s, graphTok, "ci-app")

	// It logs in at once, and has no role yet.
	spTok := s.Token(appID, newSecret, armScope)
	groups := arm + sub + "/resourcegroups?api-version=2021-04-01"
	if st, body := s.Do("GET", groups, spTok, ""); st != 403 || !strings.Contains(body, "AuthorizationFailed") ||
		!strings.Contains(body, spObject) {
		t.Fatalf("before any role: %d %s, want 403 AuthorizationFailed naming the new principal", st, body)
	}

	// Owner grants Reader; no principalType sent, the directory supplies it.
	grant := arm + sub + "/providers/Microsoft.Authorization/roleAssignments/" +
		"0f0f0f0f-0000-4000-8000-000000000002?api-version=2022-04-01"
	grantBody := `{"properties":{"roleDefinitionId":"` + sub + "/providers/Microsoft.Authorization/roleDefinitions/" +
		config.ReaderRoleID + `","principalId":"` + spObject + `"}}`
	if st, body := s.Do("PUT", grant, ownerTok, grantBody); st != 201 || !strings.Contains(body, `"principalType":"ServicePrincipal"`) {
		t.Fatalf("grant Reader: %d %s", st, body)
	}

	// Reader reads and cannot write.
	if st, body := s.Do("GET", groups, spTok, ""); st != 200 {
		t.Fatalf("list as Reader: %d %s", st, body)
	}
	if st, body := s.Do("PUT", arm+sub+"/resourcegroups/nope?api-version=2021-04-01", spTok,
		`{"location":"eastus"}`); st != 403 || !strings.Contains(body, "AuthorizationFailed") {
		t.Fatalf("create as Reader: %d %s, want 403", st, body)
	}
}

// A role given to a group reaches a member two groups down, on the
// token it already holds, and stops reaching it on the next request
// after the nesting is undone.
func TestAGroupsRoleReachesItsMembers(t *testing.T) {
	s := apptest.Start(t)
	cfg := s.App.Config
	graph, arm := cfg.GraphBaseURL()+"/v1.0", cfg.ARMBaseURL()
	graphTok := s.Token(client, secret, cfg.GraphAudience()+"/.default")
	ownerTok := s.Token(client, secret, armScope)

	appID, newSecret, spObject := newServicePrincipal(t, s, graphTok, "member-app")
	spTok := s.Token(appID, newSecret, armScope)
	group := func(name string) string {
		t.Helper()
		st, body := s.Do("POST", graph+"/groups", graphTok,
			`{"displayName":"`+name+`","mailNickname":"`+name+`","mailEnabled":false,"securityEnabled":true}`)
		if st != 201 {
			t.Fatalf("create group %s: %d %s", name, st, body)
		}
		return field(t, body, "id")
	}
	add := func(groupID, memberID string) {
		t.Helper()
		st, body := s.Do("POST", graph+"/groups/"+groupID+"/members/$ref", graphTok,
			`{"@odata.id":"`+graph+`/directoryObjects/`+memberID+`"}`)
		if st != 204 {
			t.Fatalf("add member: %d %s", st, body)
		}
	}
	readers, team := group("readers"), group("team")
	add(team, spObject) // the service principal is in team

	// Reader goes to the group readers, which nobody is in yet.
	grant := arm + sub + "/providers/Microsoft.Authorization/roleAssignments/" +
		"0f0f0f0f-0000-4000-8000-000000000003?api-version=2022-04-01"
	grantBody := `{"properties":{"roleDefinitionId":"` + sub + "/providers/Microsoft.Authorization/roleDefinitions/" +
		config.ReaderRoleID + `","principalId":"` + readers + `"}}`
	if st, body := s.Do("PUT", grant, ownerTok, grantBody); st != 201 || !strings.Contains(body, `"principalType":"Group"`) {
		t.Fatalf("grant Reader to the group: %d %s", st, body)
	}
	groups := arm + sub + "/resourcegroups?api-version=2021-04-01"
	if st, body := s.Do("GET", groups, spTok, ""); st != 403 {
		t.Fatalf("before team is in readers: %d %s, want 403", st, body)
	}

	add(readers, team) // team is in readers: the role now reaches the service principal
	if st, body := s.Do("GET", groups, spTok, ""); st != 200 {
		t.Fatalf("through two groups: %d %s, want 200", st, body)
	}
	if st, body := s.Do("PUT", arm+sub+"/resourcegroups/nope?api-version=2021-04-01", spTok,
		`{"location":"eastus"}`); st != 403 {
		t.Fatalf("Reader through a group still cannot write: %d %s", st, body)
	}
	// What is assigned to the principal, groups included.
	list := arm + sub + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&" +
		url.Values{"$filter": {"assignedTo('" + spObject + "')"}}.Encode()
	if st, body := s.Do("GET", list, ownerTok, ""); st != 200 || !strings.Contains(body, readers) {
		t.Fatalf("assignedTo: %d %s, want the assignment to readers", st, body)
	}

	// Undo the nesting: the same token is refused on the next request.
	if st, body := s.Do("DELETE", graph+"/groups/"+readers+"/members/"+team+"/$ref", graphTok, ""); st != 204 {
		t.Fatalf("remove team from readers: %d %s", st, body)
	}
	if st, body := s.Do("GET", groups, spTok, ""); st != 403 || !strings.Contains(body, "AuthorizationFailed") {
		t.Fatalf("after leaving the group: %d %s, want 403", st, body)
	}
}
