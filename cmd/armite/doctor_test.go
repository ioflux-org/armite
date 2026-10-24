package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLoopback(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:8443":   "127.0.0.1:8443",
		"[::]:8443":      "127.0.0.1:8443",
		":8443":          "127.0.0.1:8443",
		"127.0.0.1:8443": "127.0.0.1:8443",
		"10.0.0.5:8443":  "10.0.0.5:8443",
	} {
		if got := loopback(in); got != want {
			t.Errorf("loopback(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeState(t *testing.T) {
	dir := t.TempDir()
	if err := looksLikeState(dir); err != nil {
		t.Errorf("empty directory: %v", err)
	}
	for _, name := range []string{"journal", "snapshot", "azurite"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := looksLikeState(dir); err != nil {
		t.Errorf("Armite's files: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := looksLikeState(dir); err != nil {
		t.Errorf("the cache beside the state must be accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := looksLikeState(dir); err == nil {
		t.Error("a directory with a stranger's file was accepted")
	}
}

func TestHostFindingLoopback(t *testing.T) {
	if f := hostFinding("localhost", false); f.status != "ok" {
		t.Errorf("localhost: %+v", f)
	}
	if f := hostFinding("no-such-host.invalid", true); f.status != "warn" {
		t.Errorf("unresolvable wildcard probe should warn: %+v", f)
	}
}

func TestPortFinding(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if f := portFinding("p", addr, false); f.status != "warn" {
		t.Errorf("port in use by a stranger: %+v", f)
	}
	if f := portFinding("p", addr, true); f.status != "ok" {
		t.Errorf("port in use by the running Armite: %+v", f)
	}
	ln.Close()
	if f := portFinding("p", addr, false); f.status != "ok" {
		t.Errorf("free port: %+v", f)
	}
}
