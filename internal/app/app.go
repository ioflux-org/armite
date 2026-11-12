// Package app assembles one Armite: identity from the home directory,
// state from the data directory, every plane behind one TLS listener
// and IMDS behind a plain one. main builds an App from the
// configuration and serves it until a signal; tests build one on
// ephemeral ports and drive it with real HTTP clients.
package app

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ioflux-org/armite/internal/azurite"
	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/entra"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/httplog"
	"github.com/ioflux-org/armite/internal/pki"
	"github.com/ioflux-org/armite/internal/provider/authorization"
	"github.com/ioflux-org/armite/internal/provider/keyvault"
	"github.com/ioflux-org/armite/internal/provider/resources"
	"github.com/ioflux-org/armite/internal/provider/storage"
	"github.com/ioflux-org/armite/internal/rbac"
	"github.com/ioflux-org/armite/internal/router"
	"github.com/ioflux-org/armite/internal/state"
	"github.com/ioflux-org/armite/internal/store"
)

// App is one assembled server. Config carries the addresses actually
// bound: a configuration with port 0 reads back with the real port.
type App struct {
	Config config.Config
	CACert string // the CA certificate clients must trust

	ln, imdsLn   net.Listener
	server, imds *http.Server
	certFile     string
	keyFile      string
	accounts     *storage.Provider
	journal      *state.Log
}

// New binds the listeners, builds the identity under home, opens the
// state and assembles the planes. Nothing is served until Serve.
func New(cfg config.Config, home string) (a *App, err error) {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	// Listeners first: a port of 0 becomes a real port here, and every
	// URL the planes publish is computed from cfg.ListenerAddr after.
	ln, err := net.Listen("tcp", cfg.ListenerAddr)
	if err != nil {
		return nil, err
	}
	imdsLn, err := net.Listen("tcp", cfg.IMDSAddr)
	if err != nil {
		ln.Close()
		return nil, err
	}
	defer func() { // nothing half-built keeps a port
		if err != nil {
			ln.Close()
			imdsLn.Close()
		}
	}()
	cfg.ListenerAddr, cfg.IMDSAddr = ln.Addr().String(), imdsLn.Addr().String()

	caCert, caKey, err := pki.EnsureCA(home)
	if err != nil {
		return nil, err
	}
	hosts := []string{cfg.ARMHost, cfg.LoginHost, "*." + cfg.VaultHost, "*." + cfg.BlobHost,
		"*." + cfg.QueueHost(), "*." + cfg.TableHost(), "localhost", "127.0.0.1", "::1"}
	certFile, keyFile, err := pki.IssueLeaf(caCert, caKey, hosts, home)
	if err != nil {
		return nil, err
	}
	signingKey, err := pki.EnsureSigningKey(home)
	if err != nil {
		return nil, err
	}
	// The state key is loaded even when nothing persists: it is also the
	// secret storage user delegation keys are derived from.
	stateKey, err := state.LoadKey(home, cfg.State.Key)
	if err != nil {
		return nil, err
	}
	var journal *state.Log
	if cfg.State.Dir != "" {
		journal, err = state.Open(cfg.State.Dir, stateKey, int64(cfg.State.CompactAfterMB)<<20)
		if err != nil {
			return nil, err
		}
		log.Printf("Persisting state in %s", cfg.State.Dir)
	}

	defs, err := rbac.LoadBuiltinRoles()
	if err != nil {
		return nil, err
	}
	// The stores attach themselves to the journal as they are built;
	// Replay then rebuilds them, before the seeds and before anything
	// serves.
	assignments := rbac.NewAssignmentStore(journal)
	resourceStore := store.New(journal)
	vaults := keyvault.New(cfg, resourceStore, journal)
	var accounts *storage.Provider
	if cfg.Azurite.Mode == "managed" {
		path, err := azurite.Find(cfg.Azurite.Command, azurite.InstallDir())
		if err != nil {
			log.Printf("Microsoft.Storage disabled: %v; or point azurite.mode: byo at an Azurite you run", err)
			cfg.Azurite.Mode = "off"
		} else {
			cfg.Azurite.Command = path
		}
	}
	if cfg.Azurite.Mode != "off" {
		var manager *azurite.Manager
		if cfg.Azurite.Mode == "managed" {
			manager = azurite.New(cfg.Azurite.Command,
				filepath.Join(cmp.Or(cfg.State.Dir, os.TempDir()), "azurite"), cfg.Azurite.Port)
		}
		accounts, err = storage.New(cfg, resourceStore, journal, manager, stateKey)
		if err != nil {
			return nil, err
		}
	}
	if err := journal.Replay(); err != nil {
		return nil, fmt.Errorf("%w (to start over: armite reset)", err)
	}
	if err := accounts.Start(); err != nil {
		return nil, err
	}
	if err := rbac.Seed(assignments, defs, gateway.SeedAssignments(cfg)); err != nil {
		return nil, err
	}
	checker := rbac.NewChecker(defs, assignments)
	login := entra.New(cfg, signingKey)

	registry := gateway.NewRegistry()
	registry.Register("Microsoft.Resources", resources.New(cfg, resourceStore, registry.Catalog))
	registry.Register("Microsoft.KeyVault", vaults)
	registry.Register("Microsoft.Authorization", authorization.New(cfg, defs, assignments, time.Now))
	// Every plane is wrapped the same way: a request id on the response
	// and one log line per request. A nil blob plane stays nil - that is
	// how the router knows storage is off.
	var blobPlane http.Handler
	if accounts != nil {
		registry.Register("Microsoft.Storage", accounts)
		blobPlane = httplog.Wrap("blob", accounts.DataPlane(&signingKey.PublicKey, time.Now, checker))
	} else {
		registry.Disable("Microsoft.Storage")
	}
	arm := httplog.Wrap("arm", gateway.New(cfg, &signingKey.PublicKey, time.Now, checker, registry))
	dataPlane := httplog.Wrap("vault", vaults.DataPlane(&signingKey.PublicKey, time.Now, checker))

	return &App{
		Config:   cfg,
		CACert:   filepath.Join(home, pki.CACertFile),
		ln:       ln,
		imdsLn:   imdsLn,
		certFile: certFile,
		keyFile:  keyFile,
		server:   &http.Server{Handler: router.New(cfg, httplog.Wrap("entra", login), arm, dataPlane, blobPlane)},
		imds:     &http.Server{Handler: httplog.Wrap("imds", entra.NewIMDS(cfg, signingKey))},
		accounts: accounts,
		journal:  journal,
	}, nil
}

// Serve runs until ctx is done or a listener fails, then stops in the
// order that loses nothing: listeners closed and in-flight requests
// finished (five seconds), Azurite ended politely, the journal closed.
// A clean stop returns nil.
func (a *App) Serve(ctx context.Context) error {
	errc := make(chan error, 2)
	go func() { errc <- a.server.ServeTLS(a.ln, a.certFile, a.keyFile) }()
	go func() { errc <- a.imds.Serve(a.imdsLn) }()
	var err error
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	a.stop()
	return err
}

func (a *App) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range []*http.Server{a.server, a.imds} {
		if err := s.Shutdown(ctx); err != nil {
			log.Printf("stopping: %v", err)
		}
	}
	if err := a.accounts.Stop(); err != nil {
		log.Printf("stopping azurite: %v", err)
	}
	if err := a.journal.Close(); err != nil {
		log.Printf("closing the journal: %v", err)
	}
}
