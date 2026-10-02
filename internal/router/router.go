package router

import (
	"net"
	"net/http"
	"strings"

	"github.com/ioflux-org/provisio/internal/config"
)

// Router dispatches by hostname: one TLS listener, four planes. It owns no
// handler construction - main builds the planes and injects them.
type Router struct {
	cfg   config.Config
	login http.Handler
	arm   http.Handler
	vault http.Handler
	blob  http.Handler
}

// New returns a Router sending cfg.LoginHost to login, any subdomain of
// cfg.VaultHost (one hostname per vault) to vault, any subdomain of
// cfg.BlobHost (one per storage account) to blob - the queue and table
// hosts too, which blob answers for - and everything else, unknown
// hosts included, to arm. A nil blob handler means storage is off: its
// hosts fall through to arm.
func New(cfg config.Config, login, arm, vault, blob http.Handler) *Router {
	return &Router{cfg: cfg, login: login, arm: arm, vault: vault, blob: blob}
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
	case rt.blob != nil && rt.isStorageHost(host):
		rt.blob.ServeHTTP(w, r)
	default:
		rt.arm.ServeHTTP(w, r)
	}
}

// isStorageHost reports whether host is a subdomain of the blob, queue
// or table host: an account's endpoints, all served by the blob plane.
func (rt *Router) isStorageHost(host string) bool {
	for _, suffix := range []string{rt.cfg.BlobHost, rt.cfg.QueueHost(), rt.cfg.TableHost()} {
		if strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
