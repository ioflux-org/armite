package main

import (
	"cmp"
	"fmt"
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
	"github.com/ioflux-org/provisio/internal/state"
	"github.com/ioflux-org/provisio/internal/store"
)

// configPath is PROVISIO_CONFIG, else ./provisio.yaml when it exists,
// else "" (defaults only): zero files to run, one file to tweak.
func configPath() string {
	if p := os.Getenv("PROVISIO_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat("provisio.yaml"); err == nil {
		return "provisio.yaml"
	}
	return ""
}

func main() {
	path := configPath()
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 {
		runCommand(cfg, path, os.Args[1:])
		return
	}
	if path != "" {
		log.Printf("Loaded configuration from %s", path)
	}
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

	// The journal every store writes through. Its key lives next to the
	// CA key, so the state directory alone cannot be read; a nil journal
	// (state.dir empty) keeps everything in memory. Nothing is closed at
	// exit: every append is already on disk, which is what lets the
	// process be killed at any moment.
	var journal *state.Log
	if cfg.State.Dir != "" {
		key, err := state.LoadKey(certDir, cfg.State.Key)
		if err != nil {
			log.Fatal(err)
		}
		journal, err = state.Open(cfg.State.Dir, key, int64(cfg.State.CompactAfterMB)<<20)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Persisting state in %s", cfg.State.Dir)
	}

	defs, err := rbac.LoadBuiltinRoles()
	if err != nil {
		log.Fatal(err)
	}
	// The stores attach themselves to the journal as they are built;
	// Replay then rebuilds them, before the seeds (which may already be
	// there, replayed) and before anything serves.
	assignments := rbac.NewAssignmentStore(journal)
	resourceStore := store.New(journal)
	vaults := keyvault.New(cfg, resourceStore, journal)
	if err := journal.Replay(); err != nil {
		log.Fatalf("%v (to start over, delete %s)", err, cfg.State.Dir)
	}
	if err := rbac.Seed(assignments, defs, gateway.SeedAssignments(cfg)); err != nil {
		log.Fatal(err)
	}
	checker := rbac.NewChecker(defs, assignments)

	login := entra.New(cfg, signingKey)

	registry := gateway.NewRegistry()
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

// runCommand serves the subcommands: "config init [file]" writes a
// commented provisio.yaml of the defaults, "config show [--secrets]"
// prints the effective configuration, "config check" only validates
// (the Load above already did, so reaching here means it passed).
func runCommand(cfg config.Config, path string, args []string) {
	if args[0] == "config" && len(args) > 1 {
		switch args[1] {
		case "init":
			target := "provisio.yaml"
			if len(args) > 2 {
				target = args[2]
			}
			body, err := config.Template()
			if err != nil {
				log.Fatal(err)
			}
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				log.Fatalf("config init: %v (delete the file first to regenerate it)", err)
			}
			defer f.Close()
			if _, err := f.Write(body); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("wrote %s\n", target)
			return
		case "show":
			out := cfg.Redacted()
			if len(args) > 2 && args[2] == "--secrets" {
				out = cfg
			}
			body, err := out.YAML()
			if err != nil {
				log.Fatal(err)
			}
			os.Stdout.Write(body)
			return
		case "check":
			fmt.Printf("%s: ok\n", cmp.Or(path, "defaults"))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "usage: provisio [config init [file] | config show [--secrets] | config check]\n")
	os.Exit(2)
}
