package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCAIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	first, _, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}
	second, _, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Errorf("CA serial changed across boots: %v then %v", first.SerialNumber, second.SerialNumber)
	}
}

func TestEnsureCARefusesPartialState(t *testing.T) {
	dir := t.TempDir()
	_, _, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, caKeyFile)); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	if _, _, err := EnsureCA(dir); err == nil {
		t.Errorf("EnsureCA with cert but no key = nil error, want refusal")
	}
}

func TestLeafVerifiesForConfiguredHosts(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	certPath, _, err := IssueLeaf(caCert, caKey, hosts, dir)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	leaf := readCert(t, certPath)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	for _, host := range hosts {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("Verify(%q) = %v, want nil", host, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "evil.example.com"}); err == nil {
		t.Errorf("Verify(evil.example.com) = nil, want hostname mismatch")
	}
}

func TestPrivateKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	_, leafKeyPath, err := IssueLeaf(caCert, caKey, []string{"localhost"}, dir)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	for _, path := range []string{filepath.Join(dir, caKeyFile), leafKeyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %o, want 600", path, perm)
		}
	}
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cert
}
