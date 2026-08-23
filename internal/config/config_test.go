package config

import (
	"net"
	"regexp"
	"testing"
)

var guidRe = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
)

func TestDefaultIdentitiesAreGUIDs(t *testing.T) {
	config := Default()
	if !guidRe.MatchString(config.TenantID) {
		t.Errorf("TenantID = %q, not a valid/lowercase GUID", config.TenantID)
	}
	if !guidRe.MatchString(config.SubscriptionID) {
		t.Errorf("SubscriptionID = %q, not a valid/lowercase GUID", config.SubscriptionID)
	}
}

func TestDefaultHasNoEmptyFields(t *testing.T) {
	config := Default()

	fields := map[string]string{
		"TenantID":                 config.TenantID,
		"SubscriptionID":           config.SubscriptionID,
		"DefaultResourceGroup":     config.DefaultResourceGroup,
		"ListenerAddr":             config.ListenerAddr,
		"ARMHost":                  config.ARMHost,
		"LoginHost":                config.LoginHost,
		"Clients[0].ID":            config.Clients[0].ID,
		"Clients[0].Secret":        config.Clients[0].Secret,
		"Clients[0].ObjectID":      config.Clients[0].ObjectID,
		"IMDAddr":                  config.IMDSAddr,
		"ManagedIdentiy.ClientID":  config.ManagedIdentity.ClientID,
		"ManagedIdentity.ObjectID": config.ManagedIdentity.ObjectID,
	}
	for name, val := range fields {
		if val == "" {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestDefaultListenerAddrIsHostPort(t *testing.T) {
	config := Default()

	if _, _, err := net.SplitHostPort(config.ListenerAddr); err != nil {
		t.Errorf("ListenerAddr = %q, not a valid host:port: %v", config.ListenerAddr, err)
	}

	if _, _, err := net.SplitHostPort(config.IMDSAddr); err != nil {
		t.Errorf("IMDAddr = %q, not a valid host:port: %v", config.IMDSAddr, err)
	}
}

func TestLoginBaseURL(t *testing.T) {
	got := Default().LoginBaseURL()
	want := "https://login.localhost:8443"
	if got != want {
		t.Errorf("LoginBaseURL = %q, want %q", got, want)
	}
}

func TestFindClient(t *testing.T) {
	cfg := Default()
	if len(cfg.Clients) == 0 {
		t.Fatal("Default() has no clients")
	}
	want := cfg.Clients[0]
	got, ok := cfg.FindClient(want.ID)
	if !ok || got != want {
		t.Errorf("FindClient(%q) = %+v, %v; want %+v, true", want.ID, got, ok, want)
	}
	if _, ok := cfg.FindClient("nope"); ok {
		t.Errorf("FindClient(nope) found something")
	}
	if want.ID == want.ObjectID {
		t.Errorf("client ID and ObjectID must differ (appid vs oid)")
	}
}

func TestManagedIdentityIsDistinctPrincipal(t *testing.T) {
	cfg := Default()
	mi := cfg.ManagedIdentity
	if mi.ClientID == mi.ObjectID {
		t.Errorf("managed Identity ClientID and ObjectID mmust differ (appid vs oid)")
	}
	for _, cl := range cfg.Clients {
		if cl.ObjectID == mi.ObjectID || cl.ID == mi.ClientID {
			t.Errorf("managed identity collides with client %q", cl.ID)
		}
	}
}
