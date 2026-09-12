package main

import (
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/entra"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/pki"
	"github.com/ioflux-org/provisio/internal/provider/resources"
	"github.com/ioflux-org/provisio/internal/rbac"
	"github.com/ioflux-org/provisio/internal/router"
	"github.com/ioflux-org/provisio/internal/store"
)

const certDir = "certs"

func main() {
	cfg := config.Default()

	caCert, caKey, err := pki.EnsureCA(certDir)
	if err != nil {
		log.Fatal(err)
	}
	hosts := []string{cfg.ARMHost, cfg.LoginHost, "localhost", "127.0.0.1", "::1"}
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
	registry.Register("Microsoft.Resources", resources.New(store.New()))

	arm := gateway.New(cfg, &signingKey.PublicKey, time.Now, checker, registry)
	server := &http.Server{
		Addr:    cfg.ListenerAddr,
		Handler: router.New(cfg, login, arm),
	}
	imds := &http.Server{
		Addr:    cfg.IMDSAddr,
		Handler: entra.NewIMDS(cfg, signingKey),
	}

	// Each server blocks its own goroutine; the first one to fail stops the
	// process. The buffer lets the second sender finish without a receiver.
	errc := make(chan error, 2)
	go func() {
		log.Printf("Starting server on https://%s", cfg.ListenerAddr)
		log.Printf("Trust the CA: curl --cacert %s https://%s/", filepath.Join(certDir, pki.CACertFile), cfg.ListenerAddr)
		errc <- server.ListenAndServeTLS(certFile, keyFile)
	}()
	go func() {
		log.Printf("Starting IMDS on http://%s (SDKs: AZURE_POD_IDENTITY_AUTHORITY_HOST=http://%s)", cfg.IMDSAddr, cfg.IMDSAddr)
		errc <- imds.ListenAndServe()
	}()
	log.Fatal(<-errc)
}
