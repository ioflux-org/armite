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
		"TenantID":             config.TenantID,
		"SubscriptionID":       config.SubscriptionID,
		"DefaultResourceGroup": config.DefaultResourceGroup,
		"ListenerAddr":         config.ListenerAddr,
		"ARMHost":              config.ARMHost,
		"LoginHost":            config.LoginHost,
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
}
