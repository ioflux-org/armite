package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Built-in role definition GUIDs are globally fixed across Azure: the same
// values appear in every tenant's `az role definition list` and in the
// embedded seed.
const (
	OwnerRoleID       = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	ContributorRoleID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	ReaderRoleID      = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
)

// StorageAudience is the token audience the blob data plane demands:
// Azure's own, which every client asks for by default.
const StorageAudience = "https://storage.azure.com"

// SeedAssignment is a role assignment granted at boot - the answer to
// "who assigns the first role". Real Azure grants the account owner at
// subscription creation, out of band; Armite grants from config.
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
	ClientID string `yaml:"client_id"`
	ObjectID string `yaml:"object_id"`
}

// State is where resources, role assignments and secrets persist across
// restarts: a journal and a snapshot in Dir, sealed with Key. Dir is
// DataDir by default; a relative path is resolved from the working
// directory, which is how a project keeps its own data next to its own
// files; empty keeps everything in memory. CompactAfterMB bounds the
// journal: past it, the journal is folded into the snapshot; 0 never
// compacts.
// Key is a base64 32-byte AES key; empty means one is generated into the
// certificate directory on first boot, next to the CA key.
type State struct {
	Dir            string `yaml:"dir"`
	CompactAfterMB int    `yaml:"compact_after_mb"`
	Key            string `yaml:"key"`
}

type Config struct {
	TenantID             string           `yaml:"tenant_id"`
	SubscriptionID       string           `yaml:"subscription_id"`
	DefaultResourceGroup string           `yaml:"default_resource_group"`
	SubscriptionName     string           `yaml:"subscription_name"`
	TenantName           string           `yaml:"tenant_name"`
	ListenerAddr         string           `yaml:"listener_addr"`
	ARMHost              string           `yaml:"arm_host"`
	LoginHost            string           `yaml:"login_host"`
	VaultHost            string           `yaml:"vault_host"`
	BlobHost             string           `yaml:"blob_host"`
	ARMAudience          string           `yaml:"arm_audience"`
	Clients              []Client         `yaml:"clients"`
	IMDSAddr             string           `yaml:"imds_addr"`
	ManagedIdentity      ManagedIdentity  `yaml:"managed_identity"`
	RoleAssignments      []SeedAssignment `yaml:"role_assignments"`
	State                State            `yaml:"state"`
	Azurite              Azurite          `yaml:"azurite"`
	Log                  Log              `yaml:"log"`
}

// Azurite is the blob store behind the storage data plane. In managed
// mode Armite starts Command itself, with the accounts it has created,
// and restarts it when an account is created or deleted; in byo mode it
// forwards to Upstream, an Azurite the user runs, whose accounts (and
// keys) are listed here because that Azurite was started with them. Off
// disables the Microsoft.Storage provider.
type Azurite struct {
	Mode     string           `yaml:"mode"` // managed, byo or off
	Command  string           `yaml:"command"`
	Port     int              `yaml:"port"`
	Upstream string           `yaml:"upstream"`
	Accounts []StorageAccount `yaml:"accounts"`
}

// StorageAccount is an account a bring-your-own Azurite knows: the name
// and the base64 key it was started with.
type StorageAccount struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

// Log is how the server writes its log: Format "text" is one line per
// message, for a terminal; "json" is one object per line, for a
// collector. Either way every request gets one line, with its id.
type Log struct {
	Format string `yaml:"format"`
}

// Home is the directory Armite keeps its identity in - the CA, the
// leaf certificate, the signing key, the state key - and the optional
// configuration file: ARMITE_HOME, else ~/.armite, like ~/.ssh or
// ~/.aws. One per machine, so a server started from any directory is
// the same server to every client that trusted its CA. The data lives
// elsewhere, see DataDir.
func Home() string {
	if v := os.Getenv("ARMITE_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".armite" // no home directory: the working directory
	}
	return filepath.Join(home, ".armite")
}

// DataDir is where the state lives by default: the user's data
// directory for the platform - $XDG_DATA_HOME or ~/.local/share on
// Linux, ~/Library/Application Support on macOS, %LOCALAPPDATA% on
// Windows - plus "armite". Data grows (Azurite's blobs are in it) and
// is disposable, which a dot directory of keys is not; deleting the
// data directory starts over, with the same CA. When ARMITE_HOME is
// set explicitly, the data goes under it instead, so one variable gives
// a container or a second instance a self-contained directory.
func DataDir() string {
	if v := os.Getenv("ARMITE_HOME"); v != "" {
		return filepath.Join(v, "state")
	}
	home, err := os.UserHomeDir()
	switch {
	case runtime.GOOS == "windows" && os.Getenv("LOCALAPPDATA") != "":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "armite")
	case runtime.GOOS == "darwin" && err == nil:
		return filepath.Join(home, "Library", "Application Support", "armite")
	case os.Getenv("XDG_DATA_HOME") != "":
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "armite")
	case err == nil:
		return filepath.Join(home, ".local", "share", "armite")
	}
	return filepath.Join(Home(), "state")
}

// ConfigFile is the configuration file Home holds, when it exists.
const ConfigFile = "armite.yaml"

func Default() Config {
	config := Config{
		TenantID:             "11111111-1111-1111-1111-111111111111",
		SubscriptionID:       "22222222-2222-2222-2222-222222222222",
		DefaultResourceGroup: "default-rg",
		SubscriptionName:     "Armite Subscription",
		TenantName:           "Armite",
		ListenerAddr:         "127.0.0.1:8443",
		ARMHost:              "management.localhost",
		LoginHost:            "login.localhost",
		VaultHost:            "vault.localhost",
		BlobHost:             "blob.core.localhost",
		ARMAudience:          "https://management.azure.com",
		Clients: []Client{{
			ID:       "33333333-3333-3333-3333-333333333333",
			Secret:   "armite-secret",
			ObjectID: "44444444-4444-4444-4444-444444444444",
		}},
		IMDSAddr: "127.0.0.1:8081",
		ManagedIdentity: ManagedIdentity{
			ClientID: "55555555-5555-5555-5555-555555555555",
			ObjectID: "66666666-6666-6666-6666-666666666666",
		},
		State:   State{Dir: DataDir(), CompactAfterMB: 8},
		Azurite: Azurite{Mode: "managed", Command: "azurite-blob", Port: 10000},
		Log:     Log{Format: "text"},
	}
	sub := "/subscriptions/" + config.SubscriptionID
	config.RoleAssignments = []SeedAssignment{
		{PrincipalID: config.Clients[0].ObjectID, RoleDefinitionID: OwnerRoleID, Scope: sub},
		{PrincipalID: config.ManagedIdentity.ObjectID, RoleDefinitionID: ContributorRoleID, Scope: sub},
	}

	return config
}

func (c Config) LoginBaseURL() string {
	return c.baseURL(c.LoginHost)
}

// ARMBaseURL is the management-plane origin clients register as their
// resource manager endpoint. Published by /metadata/endpoints, so az and
// Terraform learn it from one place.
func (c Config) ARMBaseURL() string {
	return c.baseURL(c.ARMHost)
}

func (c Config) baseURL(host string) string {
	_, port, err := net.SplitHostPort(c.ListenerAddr)
	if err != nil {
		return "https://" + host
	}
	return "https://" + host + ":" + port
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

// VaultDNSSuffix is what a client appends to a vault name to reach its
// data plane, published as suffixes.keyVaultDns in the endpoints
// document. It carries the listener's port because az builds the URL by
// concatenation and never consults vaultUri.
func (c Config) VaultDNSSuffix() string {
	_, port, err := net.SplitHostPort(c.ListenerAddr)
	if err != nil {
		return c.VaultHost
	}
	return c.VaultHost + ":" + port
}

// VaultURI is the data-plane origin of the named vault, as ARM reports
// it in properties.vaultUri: one hostname per vault.
func (c Config) VaultURI(name string) string {
	return "https://" + name + "." + c.VaultDNSSuffix() + "/"
}

// VaultAudience is the token audience the data plane demands and the
// resource its challenge advertises. It is the vault host itself, not
// https://vault.azure.net, because SDKs verify that the vault they are
// calling is a subdomain of the challenge resource.
func (c Config) VaultAudience() string {
	return "https://" + c.VaultDNSSuffix()
}

// StorageSuffix is what clients append to "{account}.blob." to reach a
// storage account, published as suffixes.storage: az, the SDKs and
// Terraform all build the URL that way, so the blob host must be
// "blob." followed by this suffix. The listener's port is part of it,
// as for vaults.
func (c Config) StorageSuffix() string {
	suffix := strings.TrimPrefix(c.BlobHost, "blob.")
	_, port, err := net.SplitHostPort(c.ListenerAddr)
	if err != nil {
		return suffix
	}
	return suffix + ":" + port
}

// BlobURI is the data-plane origin of a storage account's blob service,
// as ARM reports it in properties.primaryEndpoints.blob.
func (c Config) BlobURI(account string) string {
	return "https://" + account + ".blob." + c.StorageSuffix() + "/"
}

// QueueHost and TableHost are the queue and table services' hostname
// suffixes, "queue." and "table." in place of "blob.". Nothing serves
// queues or tables, but Terraform probes both endpoints when it creates
// an account and must be told so quickly, not by a timeout.
func (c Config) QueueHost() string {
	return "queue." + strings.TrimPrefix(c.BlobHost, "blob.")
}

func (c Config) TableHost() string {
	return "table." + strings.TrimPrefix(c.BlobHost, "blob.")
}

// AzuriteURL is the upstream the blob data plane forwards to: the
// configured one in byo mode, the managed process otherwise.
func (c Config) AzuriteURL() string {
	if c.Azurite.Mode == "byo" {
		return c.Azurite.Upstream
	}
	return fmt.Sprintf("http://127.0.0.1:%d", c.Azurite.Port)
}

// FromEnv returns Default with the environment applied: the listen
// addresses ARMITE_LISTEN_ADDR (ARM, login and the vaults) and
// ARMITE_IMDS_ADDR - the defaults bind the loopback interface, which
// a container's published ports cannot reach, so the image sets both to
// 0.0.0.0 - the state directory and key, ARMITE_STATE_DIR and
// ARMITE_STATE_KEY, and the log format, ARMITE_LOG_FORMAT. The home
// directory itself is ARMITE_HOME, read by Home and DataDir. Hostnames
// and the port clients use are unchanged.
func FromEnv() Config {
	cfg := Default()
	applyEnv(&cfg)
	return cfg
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("ARMITE_LISTEN_ADDR"); v != "" {
		cfg.ListenerAddr = v
	}
	if v := os.Getenv("ARMITE_IMDS_ADDR"); v != "" {
		cfg.IMDSAddr = v
	}
	if v := os.Getenv("ARMITE_STATE_DIR"); v != "" {
		cfg.State.Dir = v
	}
	if v := os.Getenv("ARMITE_STATE_KEY"); v != "" {
		cfg.State.Key = v
	}
	if v := os.Getenv("ARMITE_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
}

// IMDSURL is the address clients set as AZURE_POD_IDENTITY_AUTHORITY_HOST.
// When IMDS binds every interface (a container), that is the loopback
// address of the port, since the client is outside.
func (c Config) IMDSURL() string {
	host, port, err := net.SplitHostPort(c.IMDSAddr)
	if err != nil {
		return "http://" + c.IMDSAddr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}
