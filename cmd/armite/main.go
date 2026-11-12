package main

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/ioflux-org/armite/internal/app"
	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/pki"
	"github.com/ioflux-org/armite/internal/state"
	"github.com/ioflux-org/armite/internal/store"
)

// configPath is ARMITE_CONFIG, else ./armite.yaml when it exists
// (a project's own, like a .env), else the home directory's when it
// exists, else "" (defaults only): zero files to run, one file to tweak.
func configPath() string {
	if p := os.Getenv("ARMITE_CONFIG"); p != "" {
		return p
	}
	for _, p := range []string{config.ConfigFile, filepath.Join(config.Home(), config.ConfigFile)} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// version is set by the release build (-ldflags "-X main.version=v1.2.3").
// A "go install …@v1.2.3" build has no ldflags but records the module
// version in the binary, which buildVersion falls back to; a plain go
// build from a clone prints "dev".
var version = "dev"

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" &&
		info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func main() {
	// "armite version" must work without a configuration file, and
	// without a valid one, so it is answered before anything is loaded.
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("armite " + buildVersion())
		return
	}
	path := configPath()
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 {
		runCommand(cfg, path, os.Args[1:])
		return
	}
	// slog's default handler writes through the log package, so text
	// mode keeps log's own format; json installs a handler of its own,
	// and SetDefault routes the log package through it too, so every
	// line, from either API, comes out as JSON.
	if cfg.Log.Format == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	}
	if path != "" {
		log.Printf("Loaded configuration from %s", path)
	}
	home := config.Home()
	a, err := app.New(cfg, home)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Serving %s (listening on %s); IMDS at %s (listening on %s)",
		a.Config.ARMBaseURL(), a.Config.ListenerAddr, a.Config.IMDSURL(), a.Config.IMDSAddr)
	for _, line := range nextSteps(a.Config, home) {
		log.Print(line)
	}
	// Ctrl-C and SIGTERM (kill, docker stop, systemd) cancel the context
	// and Serve stops cleanly. stop() restores the default behaviour as
	// soon as the first signal lands, so a second Ctrl-C while stopping
	// ends the process at once.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	if err := a.Serve(ctx); err != nil {
		log.Fatal(err)
	}
	log.Print("Stopped")
}

// nextSteps is what the boot log owes a first run: the three things
// every client needs, phrased for where the server is. The Docker image
// sets ARMITE_CONTAINER, and there the CA has to be copied out before
// anything can trust it.
func nextSteps(cfg config.Config, home string) []string {
	ca := filepath.Join(home, pki.CACertFile)
	trust := "Trust the CA " + ca + ": curl --cacert, REQUESTS_CA_BUNDLE (az), " +
		"NODE_EXTRA_CA_CERTS, SSL_CERT_FILE (Terraform)"
	if os.Getenv("ARMITE_CONTAINER") != "" {
		trust = "Trust the CA: docker cp <container>:" + ca + " ./ca.pem, then pass ./ca.pem as " +
			"--cacert, REQUESTS_CA_BUNDLE (az), NODE_EXTRA_CA_CERTS or SSL_CERT_FILE (Terraform); " +
			"publish 8081 too for managed-identity clients"
	}
	return []string{
		"Next: 1. " + cfg.ARMHost + ", " + cfg.LoginHost + ", *." + cfg.VaultHost + " and *." +
			cfg.BlobHost + " must resolve to this machine - `armite hosts` prints the " +
			"/etc/hosts lines; Linux with systemd-resolved needs nothing (see docs/dns.md)",
		"      2. " + trust,
		"      3. az cloud register -n Armite --endpoint-resource-manager " + cfg.ARMBaseURL() +
			" - the demo and the rest: https://armite.cloud/getting-started",
	}
}

// runCommand serves the subcommands: "config init [file]" writes a
// commented armite.yaml of the defaults into the home directory,
// "config show [--secrets]" prints the effective configuration, "config
// check" only validates (the Load above already did, so reaching here
// means it passed), "hosts" prints the /etc/hosts lines for every
// hostname the server answers to.
func runCommand(cfg config.Config, path string, args []string) {
	switch args[0] {
	case "hosts":
		if err := printHosts(cfg); err != nil {
			log.Fatal(err)
		}
		return
	case "doctor":
		runDoctor(cfg, path)
		return
	case "reset":
		runReset(cfg, args[1:])
		return
	case "azurite":
		runAzurite(args[1:])
		return
	}
	if args[0] == "config" && len(args) > 1 {
		switch args[1] {
		case "init":
			target := filepath.Join(config.Home(), config.ConfigFile)
			if len(args) > 2 {
				target = args[2]
			}
			body, err := config.Template()
			if err != nil {
				log.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
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
			fmt.Printf("# home: %s\n# data: %s\n# file: %s\n", config.Home(),
				cmp.Or(cfg.State.Dir, "none (in memory)"), cmp.Or(path, "none (defaults)"))
			os.Stdout.Write(body)
			return
		case "check":
			fmt.Printf("%s: ok\n", cmp.Or(path, "defaults"))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "usage: armite [config init [file] | config show [--secrets] | "+
		"azurite install [version] | config check | hosts | doctor | reset [-y] | version]\n")
	os.Exit(2)
}

// hostNames is every hostname the server answers to: the fixed two,
// then one per vault and per storage account in the state (the queue
// and table twins included, for Terraform), read without touching the
// files so it works beside a running server.
func hostNames(cfg config.Config) ([]string, error) {
	names := []string{cfg.ARMHost, cfg.LoginHost}
	if _, err := os.Stat(cfg.State.Dir); cfg.State.Dir != "" && err == nil {
		key, err := state.LoadKey(config.Home(), cfg.State.Key)
		if err != nil {
			return nil, err
		}
		journal, err := state.OpenReadOnly(cfg.State.Dir, key)
		if err != nil {
			return nil, err
		}
		resources := store.New(journal)
		if err := journal.Replay(); err != nil {
			return nil, err
		}
		vaults, _ := resources.List("/", "Microsoft.KeyVault/vaults")
		for _, v := range vaults {
			names = append(names, strings.ToLower(v.Name)+"."+cfg.VaultHost)
		}
		accounts, _ := resources.List("/", "Microsoft.Storage/storageAccounts")
		for _, a := range accounts {
			name := strings.ToLower(a.Name)
			names = append(names, name+"."+cfg.BlobHost, name+"."+cfg.QueueHost(),
				name+"."+cfg.TableHost())
		}
	}
	return names, nil
}

// printHosts prints one /etc/hosts line per name. Nothing else goes to
// stdout, so the output can be appended to the hosts file as it is.
func printHosts(cfg config.Config) error {
	names, err := hostNames(cfg)
	if err != nil {
		return err
	}
	fmt.Println("# armite hosts: append to /etc/hosts, or see docs/dns.md for a resolver fix")
	for _, n := range names {
		fmt.Printf("127.0.0.1  %s\n", n)
	}
	return nil
}
