package gateway

import (
	"crypto/rsa"
	"log"
	"net/http"
	"time"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/rbac"
)

// Gateway is the management-plane handler: the ARM request pipeline. In
// M3b the pipeline is authentication followed by a placeholder; later
// steps insert parsing, authorization and provider dispatch between them.
type Gateway struct {
	pipeline http.Handler
}

// New assembles the pipeline: Authenticate -> RouteRequest -> Authorize ->
// placeholder. Handlers wrap innermost-first, so the chain is built in
// the reverse of the order it runs.
func New(cfg config.Config, pub *rsa.PublicKey, now func() time.Time, checker *rbac.Checker) *Gateway {
	var pipeline http.Handler = http.HandlerFunc(notYetImplemented)
	pipeline = NewAuthorizer(checker).Authorize(pipeline)
	pipeline = RouteRequest(pipeline)
	pipeline = NewAuthenticator(cfg, pub, now).Authenticate(pipeline)
	return &Gateway{pipeline: pipeline}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("arm: %s %s", r.Method, r.URL.RequestURI())
	g.pipeline.ServeHTTP(w, r)
}

// notYetImplemented stands in for the rest of the pipeline. Reaching it
// proves authentication passed; it answers 404 the way ARM does for a
// path no provider serves.
func notYetImplemented(w http.ResponseWriter, r *http.Request) {
	azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
		"Provisio has no handler for '"+r.URL.Path+"' yet.")
}
