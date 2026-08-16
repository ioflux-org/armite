package router

import (
	"fmt"
	"net"
	"net/http"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/entra"
)

type Router struct {
	cfg   config.Config
	login http.Handler
}

func New(cfg config.Config) *Router {
	return &Router{cfg: cfg, login: entra.New(cfg)}
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch stripPort(r.Host) {
	case rt.cfg.ARMHost:
		rt.serveARM(w, r)
	case rt.cfg.LoginHost:
		rt.login.ServeHTTP(w, r)
	default:
		rt.serveARM(w, r)
	}
}

func (rt *Router) serveARM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf("Bearer authorization_uri=%q", rt.cfg.LoginBaseURL()+"/"+rt.cfg.TenantID))
	azerr.WriteError(w, http.StatusUnauthorized, azerr.CodeAuthenticationFailed, "Authentication failed. The Authorization header is missing or invalid.")
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
