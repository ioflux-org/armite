package router

import (
	"net"
	"net/http"

	"github.com/ioflux-org/provisio/internal/config"
)

// Router dispatches by hostname: one TLS listener, two planes. It owns no
// handler construction - main builds the planes and injects them.
type Router struct {
	cfg   config.Config
	login http.Handler
	arm   http.Handler
}

// New returns a Router sending cfg.LoginHost to login and everything
// else, unknown hosts included, to arm.
func New(cfg config.Config, login, arm http.Handler) *Router {
	return &Router{cfg: cfg, login: login, arm: arm}
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch stripPort(r.Host) {
	case rt.cfg.ARMHost:
		rt.arm.ServeHTTP(w, r)
	case rt.cfg.LoginHost:
		rt.login.ServeHTTP(w, r)
	default:
		rt.arm.ServeHTTP(w, r)
	}
}

// func (rt *Router) serveARM(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("WWW-Authenticate",
// 		fmt.Sprintf("Bearer authorization_uri=%q", rt.cfg.LoginBaseURL()+"/"+rt.cfg.TenantID))
// 	azerr.WriteError(w, http.StatusUnauthorized, azerr.CodeAuthenticationFailed, "Authentication failed. The Authorization header is missing or invalid.")
// }

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
