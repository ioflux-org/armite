package router

import (
	"net"
	"net/http"
	"strings"

	"github.com/ioflux-org/provisio/internal/config"
)

// Router dispatches by hostname: one TLS listener, three planes. It owns no
// handler construction - main builds the planes and injects them.
type Router struct {
	cfg   config.Config
	login http.Handler
	arm   http.Handler
	vault http.Handler
}

// New returns a Router sending cfg.LoginHost to login, any subdomain of
// cfg.VaultHost (one hostname per vault) to vault, and everything else,
// unknown hosts included, to arm.
func New(cfg config.Config, login, arm, vault http.Handler) *Router {
	return &Router{cfg: cfg, login: login, arm: arm, vault: vault}
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)
	switch {
	case host == rt.cfg.ARMHost:
		rt.arm.ServeHTTP(w, r)
	case host == rt.cfg.LoginHost:
		rt.login.ServeHTTP(w, r)
	case strings.HasSuffix(host, "."+rt.cfg.VaultHost):
		rt.vault.ServeHTTP(w, r)
	default:
		rt.arm.ServeHTTP(w, r)
	}
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
