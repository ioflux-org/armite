package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/azurite"
	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/pki"
)

// A finding is one line of the doctor's report: what was examined, how
// it went and, when it went badly, what to do about it.
type finding struct {
	status string // "ok", "warn" or "fail"
	name   string
	detail string
}

// stateEntries is everything the server writes into the data
// directory; reset removes exactly these and refuses a directory that
// holds anything else, except the cache, which it keeps.
var stateEntries = []string{"journal", "journal.tmp", "snapshot", "snapshot.tmp", "azurite"}

// runDoctor examines what a first run trips over - the home and data
// directories, the hostnames, the ports, Azurite - and exits 1 when a
// check failed. Warnings are information, not problems.
func runDoctor(cfg config.Config, path string) {
	home := config.Home()
	findings := []finding{configFinding(path), homeFinding(home), dataFinding(cfg)}

	names, err := hostNames(cfg)
	if err != nil {
		findings = append(findings, finding{"warn", "state", "could not read the state for hostnames: " + err.Error()})
		names = []string{cfg.ARMHost, cfg.LoginHost}
	}
	for _, n := range names {
		findings = append(findings, hostFinding(n, false))
	}
	for _, n := range []string{"probe." + cfg.VaultHost, "probe." + cfg.BlobHost} {
		findings = append(findings, hostFinding(n, true))
	}

	listener, running := listenerFinding(cfg, home)
	findings = append(findings, listener,
		portFinding("port "+cfg.IMDSAddr+" (IMDS)", cfg.IMDSAddr, running),
		azuriteFinding(cfg, running))

	failed := 0
	for _, f := range findings {
		fmt.Printf("%-5s %-34s %s\n", f.status, f.name, f.detail)
		if f.status == "fail" {
			failed++
		}
	}
	if failed > 0 {
		fmt.Printf("%d problem(s); fix them and run `armite doctor` again\n", failed)
		os.Exit(1)
	}
	fmt.Println("all good")
}

func configFinding(path string) finding {
	if path == "" {
		return finding{"ok", "config", "defaults, no file (armite config init writes one)"}
	}
	return finding{"ok", "config", path + " loads"} // Load validated it before we got here
}

func homeFinding(home string) finding {
	ca := filepath.Join(home, pki.CACertFile)
	if _, err := os.Stat(ca); err != nil {
		return finding{"warn", "home " + home, "no CA yet; the first start creates it"}
	}
	return finding{"ok", "home " + home, "CA at " + ca}
}

func dataFinding(cfg config.Config) finding {
	dir := cfg.State.Dir
	if dir == "" {
		return finding{"ok", "data", "in memory (state.dir is empty); nothing survives a restart"}
	}
	if _, err := os.Stat(dir); err != nil {
		return finding{"ok", "data " + dir, "not there yet; the first start creates it"}
	}
	f, err := os.CreateTemp(dir, ".doctor-*")
	if err != nil {
		return finding{"fail", "data " + dir, "not writable: " + err.Error()}
	}
	f.Close()
	os.Remove(f.Name())
	return finding{"ok", "data " + dir, "writable"}
}

// hostFinding resolves one name the way every client will, through the
// system resolver, and expects this machine back. A wildcard probe that
// fails is a warning: hosts-file setups have no wildcard, and each new
// vault or account needs its own line.
func hostFinding(name string, wildcardProbe bool) finding {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil {
		if wildcardProbe {
			return finding{"warn", name, "no wildcard: every new vault or storage account needs a hosts line (`armite hosts`), or a resolver rule (docs/dns.md)"}
		}
		return finding{"fail", name, "does not resolve: `armite hosts` prints the /etc/hosts line (docs/dns.md)"}
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.IsLoopback() {
			return finding{"ok", name, a}
		}
	}
	return finding{"fail", name, "resolves to " + strings.Join(addrs, ", ") + ", not to this machine"}
}

// listenerFinding tells a free port from Armite from a stranger: ours
// completes a TLS handshake under our CA and serves the ARM metadata
// document. The dial is pinned to the port, so the check works even
// when the hostnames do not resolve yet.
func listenerFinding(cfg config.Config, home string) (finding, bool) {
	addr := cfg.ListenerAddr
	name := "port " + addr + " (ARM, Entra, data planes)"
	conn, err := net.DialTimeout("tcp", loopback(addr), 500*time.Millisecond)
	if err != nil {
		return finding{"ok", name, "free"}, false
	}
	conn.Close()
	pem, err := os.ReadFile(filepath.Join(home, pki.CACertFile))
	if err != nil {
		return finding{"warn", name, "in use, and no CA yet to tell whether it is Armite"}, false
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: cfg.ARMHost},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, loopback(addr))
		},
	}}
	resp, err := client.Get(cfg.ARMBaseURL() + "/metadata/endpoints?api-version=2022-09-01")
	if err != nil {
		return finding{"fail", name, "in use by something that is not Armite: " + err.Error()}, false
	}
	resp.Body.Close()
	return finding{"ok", name, "Armite is running here (CA verified)"}, true
}

func portFinding(name, addr string, running bool) finding {
	conn, err := net.DialTimeout("tcp", loopback(addr), 500*time.Millisecond)
	if err != nil {
		return finding{"ok", name, "free"}
	}
	conn.Close()
	if running {
		return finding{"ok", name, "in use by the running Armite"}
	}
	return finding{"warn", name, "in use by another program; stop it before starting Armite"}
}

func azuriteFinding(cfg config.Config, running bool) finding {
	switch cfg.Azurite.Mode {
	case "off":
		return finding{"ok", "azurite", "off by configuration; storage accounts are disabled"}
	case "byo":
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(cfg.Azurite.Upstream)
		if err != nil {
			return finding{"fail", "azurite " + cfg.Azurite.Upstream, "does not answer: " + err.Error()}
		}
		resp.Body.Close()
		return finding{"ok", "azurite " + cfg.Azurite.Upstream, "answers"}
	}
	path, err := azurite.Find(cfg.Azurite.Command, azuriteInstallDir())
	if err != nil {
		return finding{"fail", "azurite", err.Error()}
	}
	port := fmt.Sprintf("127.0.0.1:%d", cfg.Azurite.Port)
	if conn, err := net.DialTimeout("tcp", port, 500*time.Millisecond); err == nil {
		conn.Close()
		if running {
			return finding{"ok", "azurite", path + ", serving on " + port}
		}
		return finding{"warn", "azurite", path + "; " + port + " is in use (an Azurite from an earlier run? the server refuses to start on top of it)"}
	}
	return finding{"ok", "azurite", path}
}

// loopback swaps an unspecified bind address (0.0.0.0, [::], :port) for
// one a client can dial.
func loopback(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

// runReset deletes the data directory - resources, role assignments,
// secrets, blobs - and keeps the identity: the CA, the leaf and the
// signing key stay, so every client keeps trusting the next server.
func runReset(cfg config.Config, args []string) {
	dir := cfg.State.Dir
	if dir == "" {
		fmt.Println("state is in memory (state.dir is empty): nothing to reset")
		return
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%s does not exist: nothing to reset\n", dir)
		return
	}
	if conn, err := net.DialTimeout("tcp", loopback(cfg.ListenerAddr), 500*time.Millisecond); err == nil {
		conn.Close()
		log.Fatalf("something is listening on %s - stop the server first", cfg.ListenerAddr)
	}
	if err := looksLikeState(dir); err != nil {
		log.Fatalf("refusing to delete %s: %v", dir, err)
	}
	if !slices.Contains(args, "-y") && !slices.Contains(args, "--yes") {
		fmt.Printf("Delete everything under %s? Resources, assignments, secrets and blobs go; "+
			"the CA and keys in %s stay. [y/N] ", dir, config.Home())
		var answer string
		fmt.Scanln(&answer)
		if !strings.EqualFold(answer, "y") {
			fmt.Println("kept")
			return
		}
	}
	for _, name := range stateEntries {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("removed the state under %s; the next start begins empty, with the same CA "+
		"(and the Azurite copy, if any, stays)\n", dir)
}

// looksLikeState refuses anything that is not Armite's data directory:
// a typo in state.dir must never delete a project. Armite's directory
// holds only its journal, its snapshot, their temporaries and Azurite's
// folder.
func looksLikeState(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == "cache" || slices.Contains(stateEntries, e.Name()) {
			continue
		}
		return fmt.Errorf("it holds %q, which Armite did not create", e.Name())
	}
	return nil
}
