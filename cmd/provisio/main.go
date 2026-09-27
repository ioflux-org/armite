package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/entra"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/pki"
	"github.com/ioflux-org/provisio/internal/provider/authorization"
	"github.com/ioflux-org/provisio/internal/provider/keyvault"
	"github.com/ioflux-org/provisio/internal/provider/resources"
	"github.com/ioflux-org/provisio/internal/rbac"
	"github.com/ioflux-org/provisio/internal/router"
	"github.com/ioflux-org/provisio/internal/store"
)

func main() {
	cfg := config.FromEnv()
	// certDir holds the CA, the leaf certificate and the signing key; in
	// the container it is the mounted volume clients read ca.pem from.
	certDir := os.Getenv("PROVISIO_CERT_DIR")
	if certDir == "" {
		certDir = "certs"
	}

	caCert, caKey, err := pki.EnsureCA(certDir)
	if err != nil {
		log.Fatal(err)
	}
	hosts := []string{cfg.ARMHost, cfg.LoginHost, "*." + cfg.VaultHost,
		"localhost", "127.0.0.1", "::1"}
	certFile, keyFile, err := pki.IssueLeaf(caCert, caKey, hosts, certDir)
	if err != nil {
		log.Fatal(err)
	}

	signingKey, err := pki.EnsureSigningKey(certDir)
	if err != nil {
		log.Fatal(err)
	}

	defs, err := rbac.LoadBuiltinRoles()
	if err != nil {
		log.Fatal(err)
	}
	assignments := rbac.NewAssignmentStore()
	if err := rbac.Seed(assignments, defs, gateway.SeedAssignments(cfg)); err != nil {
		log.Fatal(err)
	}
	checker := rbac.NewChecker(defs, assignments)

	login := entra.New(cfg, signingKey)

	registry := gateway.NewRegistry()
	resourceStore := store.New()
	vaults := keyvault.New(cfg, resourceStore)
	registry.Register("Microsoft.Resources", resources.New(cfg, resourceStore, registry.Catalog))
	registry.Register("Microsoft.KeyVault", vaults)
	registry.Register("Microsoft.Authorization", authorization.New(cfg, defs, assignments, time.Now))

	arm := gateway.New(cfg, &signingKey.PublicKey, time.Now, checker, registry)
	dataPlane := vaults.DataPlane(&signingKey.PublicKey, time.Now, checker)
	server := &http.Server{
		Addr:    cfg.ListenerAddr,
		Handler: router.New(cfg, login, arm, dataPlane),
	}
	imds := &http.Server{
		Addr:    cfg.IMDSAddr,
		Handler: entra.NewIMDS(cfg, signingKey),
	}

	// Each server blocks its own goroutine; the first one to fail stops the
	// process. The buffer lets the second sender finish without a receiver.
	errc := make(chan error, 2)
	go func() {
		log.Printf("Serving %s (listening on %s)", cfg.ARMBaseURL(), cfg.ListenerAddr)
		log.Printf("Trust the CA: curl --cacert %s %s/",
			filepath.Join(certDir, pki.CACertFile), cfg.ARMBaseURL())
		errc <- server.ListenAndServeTLS(certFile, keyFile)
	}()
	go func() {
		log.Printf("Serving IMDS (listening on %s; SDKs: AZURE_POD_IDENTITY_AUTHORITY_HOST=%s)",
			cfg.IMDSAddr, cfg.IMDSURL())
		errc <- imds.ListenAndServe()
	}()
	log.Fatal(<-errc)
}
