package config

import "net"

// Built-in role definition GUIDs are globally fixed across Azure: the same
// values appear in every tenant's `az role definition list` and in the
// embedded seed.
const (
	OwnerRoleID       = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	ContributorRoleID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	ReaderRoleID      = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
)

// SeedAssignment is a role assignment granted at boot - the answer to
// "who assigns the first role". Real Azure grants the account owner at
// subscription creation, out of band; Provisio grants from config.
type SeedAssignment struct {
	PrincipalID      string `yaml:"principal_id"`
	RoleDefinitionID string `yaml:"role_definition_id"` // bare GUID or full ARM path
	Scope            string `yaml:"scope"`
}

type Client struct {
	ID       string `yaml:"id"`
	Secret   string `yaml:"secret"`
	ObjectID string `yaml:"object_id"`
}

// ManagedIdentity is the system-assigned managed identity IMDS issues tokens
// for. It is a service principal like Client - ObjectID is the RBAC principal,
// ClientID is what callers may pass as client_id - but it has no secret: the
// platform (here, the IMDS listener) is the credential.
type ManagedIdentity struct {
	ClientID string `json:"client_id"`
	ObjectID string `json:"object_id"`
}

type Config struct {
	TenantID             string           `yaml:"tenant_id"`
	SubscriptionID       string           `yaml:"subscription_id"`
	DefaultResourceGroup string           `yaml:"default_resource_group"`
	ListenerAddr         string           `yaml:"listener_addr"`
	ARMHost              string           `yaml:"arm_host"`
	LoginHost            string           `yaml:"login_host"`
	ARMAudience          string           `yaml:"arm_audience"`
	Clients              []Client         `yaml:"clients"`
	IMDSAddr             string           `yaml:"imds_addr"`
	ManagedIdentity      ManagedIdentity  `yaml:"managed_identity"`
	RoleAssignments      []SeedAssignment `yaml:"role_assignments"`
}

func Default() Config {
	config := Config{
		TenantID:             "11111111-1111-1111-1111-111111111111",
		SubscriptionID:       "22222222-2222-2222-2222-222222222222",
		DefaultResourceGroup: "default-rg",
		ListenerAddr:         "127.0.0.1:8443",
		ARMHost:              "management.localhost",
		LoginHost:            "login.localhost",
		ARMAudience:          "https://management.azure.com",
		Clients: []Client{{
			ID:       "33333333-3333-3333-3333-333333333333",
			Secret:   "provisio-secret",
			ObjectID: "44444444-4444-4444-4444-444444444444",
		}},
		IMDSAddr: "127.0.0.1:8081",
		ManagedIdentity: ManagedIdentity{
			ClientID: "55555555-5555-5555-5555-555555555555",
			ObjectID: "66666666-6666-6666-6666-666666666666",
		},
	}
	sub := "/subscriptions/" + config.SubscriptionID
	config.RoleAssignments = []SeedAssignment{
		{PrincipalID: config.Clients[0].ObjectID, RoleDefinitionID: OwnerRoleID, Scope: sub},
		{PrincipalID: config.ManagedIdentity.ObjectID, RoleDefinitionID: ContributorRoleID, Scope: sub},
	}

	return config
}

func (c Config) LoginBaseURL() string {
	_, port, err := net.SplitHostPort(c.ListenerAddr)
	if err != nil {
		return "https://" + c.LoginHost
	}
	return "https://" + c.LoginHost + ":" + port
}

// IssuerURL is the tenant's OIDC issuer: minted into every token's iss
// claim, published by discovery, and demanded by the gateway. One
// definition keeps the three from drifting apart.
func (c Config) IssuerURL() string {
	return c.LoginBaseURL() + "/" + c.TenantID + "/v2.0"
}

func (c Config) FindClient(id string) (Client, bool) {
	for _, cl := range c.Clients {
		if cl.ID == id {
			return cl, true
		}
	}
	return Client{}, false
}
