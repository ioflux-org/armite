package gateway

import (
	"context"
	"net/http"
	"regexp"

	"github.com/ioflux-org/armite/internal/arm"
	"github.com/ioflux-org/armite/internal/azerr"
)

// Route is what the pipeline learned about a request from its URL and
// method: the parsed resource ID, the api-version, and the RBAC action
// and scope derived from them. Providers read it from the context.
type Route struct {
	ID         arm.ResourceID
	APIVersion string
	Action     string
	Scope      string
}

type routeKey struct{}

func withRoute(ctx context.Context, rt Route) context.Context {
	return context.WithValue(ctx, routeKey{}, rt)
}

// RouteFromContext returns the Route stored by RouteRequest, and false
// for a request that was not routed.
func RouteFromContext(ctx context.Context) (Route, bool) {
	rt, ok := ctx.Value(routeKey{}).(Route)
	return rt, ok
}

// apiVersionRe accepts ARM's date-based versions, with or without a
// suffix such as -preview. Any well-formed version passes: Armite keeps
// no per-provider version matrix.
var apiVersionRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(-[a-z]+)?$`)

// RouteRequest wraps next: it enforces api-version, parses the path and
// derives the RBAC action, storing the result as a Route in the context.
// api-version is checked before the path so a missing version is
// reported the way real ARM reports it, whatever the path.
func RouteRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := r.URL.Query().Get("api-version")
		if version == "" {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeMissingApiVersionParameter,
				"The api-version query parameter (?api-version=) is required for all requests.")
			return
		}
		if !apiVersionRe.MatchString(version) {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidApiVersionParameter,
				"The api-version '"+version+"' is invalid. The supported format is yyyy-MM-dd, "+
					"optionally followed by a suffix such as -preview.")
			return
		}
		id, err := arm.ParseResourceID(r.URL.Path)
		if err != nil {
			azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
				"The request path '"+r.URL.Path+"' is not a valid resource identifier.")
			return
		}
		action, scope, err := arm.DeriveAction(r.Method, id)
		if err != nil {
			azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
				"The method '"+r.Method+"' is not allowed on '"+r.URL.Path+"'.")
			return
		}
		rt := Route{ID: id, APIVersion: version, Action: action, Scope: scope}
		next.ServeHTTP(w, r.WithContext(withRoute(r.Context(), rt)))
	})
}
