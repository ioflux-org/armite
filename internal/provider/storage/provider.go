// Package storage is the Microsoft.Storage provider: storage accounts as
// ARM resources, their keys, and a blob data plane that authorizes by
// RBAC and forwards to Azurite, which holds the data.
package storage

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/azurite"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/state"
	"github.com/ioflux-org/provisio/internal/store"
)

// Provider serves the Microsoft.Storage namespace.
type Provider struct {
	cfg      config.Config
	store    *store.Store      // accounts, next to the resource groups they live in
	keys     *keyStore         // each account's access keys (managed mode)
	byo      map[string]string // byo mode: configured account name -> "key1:key2"
	azurite  *azurite.Manager  // managed mode; nil in byo mode
	upstream *upstream
	now      func() time.Time

	delegationSeed []byte // the secret user delegation keys derive from
}

// New builds the provider. In managed mode m runs Azurite and the keys
// are generated and journaled; in byo mode m is nil and the accounts
// come from the configuration. seed is the secret user delegation keys
// are derived from; it must be stable across restarts (the state key).
func New(cfg config.Config, st *store.Store, journal *state.Log,
	m *azurite.Manager, seed []byte) (*Provider, error) {
	p := &Provider{cfg: cfg, store: st, keys: newKeyStore(journal), azurite: m, now: time.Now,
		delegationSeed: seed}
	if cfg.Azurite.Mode == "byo" {
		p.byo = map[string]string{}
		for _, a := range cfg.Azurite.Accounts {
			p.byo[lower(a.Name)] = a.Key
		}
	}
	up, err := newUpstream(cfg.AzuriteURL(), p.keyFor)
	if err != nil {
		return nil, err
	}
	p.upstream = up
	return p, nil
}

// Start brings Azurite up with the accounts replayed from the journal.
// Call it after Replay and before serving.
func (p *Provider) Start() error {
	if p == nil || p.azurite == nil {
		return nil
	}
	return p.azurite.Start(p.keys.All())
}

// Stop ends the managed Azurite, if any.
func (p *Provider) Stop() error {
	if p == nil || p.azurite == nil {
		return nil
	}
	return p.azurite.Stop()
}

// keyFor returns the primary key Azurite knows account by.
func (p *Provider) keyFor(account string) ([]byte, bool) {
	if p.byo != nil {
		k, ok := p.byo[lower(account)]
		if !ok {
			return nil, false
		}
		first, _, _ := strings.Cut(k, ":")
		return decodeKey(first)
	}
	k, ok := p.keys.Get(account)
	if !ok {
		return nil, false
	}
	return decodeKey(k.Key1)
}

// syncAzurite restarts the managed Azurite when the account set changed.
func (p *Provider) syncAzurite() error {
	if p.azurite == nil {
		return nil
	}
	return p.azurite.Start(p.keys.All())
}

// ResourceTypes lists what this provider serves, for the catalogue.
func (p *Provider) ResourceTypes() []gateway.ResourceType {
	versions := []string{"2025-08-01", "2024-01-01", "2023-05-01", "2023-01-01", "2022-09-01"}
	return []gateway.ResourceType{
		{Type: "storageAccounts", APIVersions: versions},
		{Type: "storageAccounts/blobServices", APIVersions: versions},
		{Type: "storageAccounts/blobServices/containers", APIVersions: versions},
		{Type: "storageAccounts/fileServices", APIVersions: versions},
		{Type: "storageAccounts/queueServices", APIVersions: versions},
		{Type: "storageAccounts/tableServices", APIVersions: versions},
		{Type: "checkNameAvailability", APIVersions: versions},
	}
}

// ServeHTTP dispatches on the type chain RouteRequest parsed.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, ok := gateway.RouteFromContext(r.Context())
	if !ok {
		azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
			"The request was not routed before dispatch.")
		return
	}
	chain := strings.ToLower(strings.Join(rt.ID.Types, "/"))
	switch chain {
	case "storageaccounts":
		if rt.ID.IsInstance() {
			p.serveAccount(w, r, rt.ID)
		} else {
			p.serveAccounts(w, r, rt.ID)
		}
	case "storageaccounts/listkeys":
		p.listKeys(w, r, rt.ID)
	case "storageaccounts/regeneratekey":
		p.regenerateKey(w, r, rt.ID)
	case "checknameavailability":
		p.checkNameAvailability(w, r, rt.ID)
	case "storageaccounts/blobservices":
		if rt.ID.IsInstance() {
			p.serveBlobService(w, r, rt.ID)
		} else {
			p.serveBlobServices(w, r, rt.ID)
		}
	case "storageaccounts/blobservices/containers":
		if rt.ID.IsInstance() {
			p.serveContainer(w, r, rt.ID)
		} else {
			p.serveContainers(w, r, rt.ID)
		}
	case "storageaccounts/fileservices", "storageaccounts/queueservices",
		"storageaccounts/tableservices":
		// Terraform reads every service's properties when it refreshes an
		// account. Nothing serves files, queues or tables; the defaults
		// are answered so a refresh succeeds, and a PUT is accepted and
		// echoed, never enforced.
		p.serveOtherService(w, r, rt.ID, rt.ID.Types[1])
	default:
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeInvalidResourceType,
			"The resource type '"+chain+"' could not be found in the namespace "+
				"'Microsoft.Storage' for api version '"+rt.APIVersion+"'.")
	}
}

func lower(s string) string { return strings.ToLower(s) }

// internalError is the provider's own failure: logged with detail, told
// to the client without it.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("storage: %v", err)
	azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
		"An internal error occurred in the Microsoft.Storage provider.")
}
