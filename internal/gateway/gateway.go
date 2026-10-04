package gateway

import (
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/rbac"
)

// Gateway is the management-plane handler: the ARM request pipeline,
// authentication -> routing -> authorization -> provider dispatch, plus
// the one path ARM serves anonymously, /metadata/endpoints.
type Gateway struct {
	handler http.Handler
}

// New assembles the pipeline: Authenticate -> RouteRequest -> Authorize ->
// terminal. Handlers wrap innermost-first, so the chain is built in
// the reverse of the order it runs. The terminal is injected - main passes
// the provider Registry, tests pass spies - so this package never
// imports a provider, and providers may import it for Route. The
// endpoints document is mounted beside the pipeline, not inside it:
// clients read it before they hold any token.
func New(
	cfg config.Config, pub *rsa.PublicKey, now func() time.Time,
	checker *rbac.Checker, terminal http.Handler,
) *Gateway {
	pipeline := terminal
	pipeline = NewAuthorizer(checker).Authorize(pipeline)
	pipeline = RouteRequest(pipeline)
	pipeline = NewAuthenticator(cfg, pub, now).Authenticate(pipeline)

	mux := http.NewServeMux()
	mux.Handle("/metadata/endpoints", serveEndpoints(cfg))
	mux.Handle("/", pipeline)
	return &Gateway{handler: mux}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.handler.ServeHTTP(w, r)
}
