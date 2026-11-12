// Package apptest boots an App for tests: ephemeral ports, a temporary
// home, in-memory state, Azurite off, and a client that trusts the CA
// and dials every hostname to the TLS listener, so tests use the real
// URLs (https://management.localhost:<port>/...) exactly as az would,
// with nothing to resolve and nothing to edit in /etc/hosts.
package apptest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ioflux-org/armite/internal/app"
	"github.com/ioflux-org/armite/internal/config"
)

// Server is a running App and a client that trusts it.
type Server struct {
	App    *app.App
	Client *http.Client

	t      *testing.T
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

// Start boots a default configuration on ephemeral ports with a fresh
// home; tweak functions adjust the configuration first.
func Start(t *testing.T, tweak ...func(*config.Config)) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.ListenerAddr, cfg.IMDSAddr = "127.0.0.1:0", "127.0.0.1:0"
	cfg.State.Dir = ""
	cfg.Azurite.Mode = "off"
	for _, f := range tweak {
		f(&cfg)
	}
	return StartWith(t, cfg, t.TempDir())
}

// StartWith boots cfg with the identity under home. A second call with
// the same home and state directory is a restart: same CA, same keys,
// replayed state.
func StartWith(t *testing.T, cfg config.Config, home string) *Server {
	t.Helper()
	a, err := app.New(cfg, home)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{App: a, t: t, cancel: cancel, done: make(chan error, 1)}
	go func() { s.done <- a.Serve(ctx) }()
	t.Cleanup(s.Stop)

	pem, err := os.ReadFile(a.CACert)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	tlsAddr := a.Config.ListenerAddr
	s.Client = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// A hostname goes to the TLS listener whatever it is; an IP
			// (IMDS) dials as it is. TLS still verifies the hostname
			// against the leaf's wildcards, exactly as a client would.
			if host, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) == nil {
				addr = tlsAddr
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	return s
}

// Stop ends the server and reports a failed Serve; safe to call twice.
func (s *Server) Stop() {
	s.once.Do(func() {
		s.cancel()
		if err := <-s.done; err != nil {
			s.t.Errorf("serve: %v", err)
		}
	})
}

// Token gets a client-credentials token for scope from the login host.
func (s *Server) Token(clientID, secret, scope string) string {
	s.t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID},
		"client_secret": {secret}, "scope": {scope}}
	resp, err := s.Client.PostForm(s.App.Config.LoginBaseURL()+"/"+s.App.Config.TenantID+
		"/oauth2/v2.0/token", form)
	if err != nil {
		s.t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.AccessToken == "" {
		s.t.Fatalf("token: status %d, %s %v", resp.StatusCode, body.Error, err)
	}
	return body.AccessToken
}

// Do sends one JSON request with a bearer token and returns the status
// and the body as text.
func (s *Server) Do(method, rawURL, token, body string) (int, string) {
	s.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
