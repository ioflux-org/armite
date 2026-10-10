package gateway

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/rbac"
)

// Authorizer answers "may this principal do this" with the M2 evaluator.
type Authorizer struct {
	checker *rbac.Checker
}

// NewAuthorizer returns an Authorizer evaluating against checker.
func NewAuthorizer(checker *rbac.Checker) *Authorizer {
	return &Authorizer{checker: checker}
}

// discoveryActions are the tenant-root listings every authenticated
// caller may perform. Real ARM does not authorize these at scope "/"
// either - it returns the subset the caller can access. Armite has one
// subscription and one tenant; M3f decides whether to filter.
var discoveryActions = map[string]bool{
	"microsoft.resources/subscriptions/read": true,
	"microsoft.resources/tenants/read":       true,
}

// Authorize wraps next: it requires the Principal (from Authenticate) and
// the Route (from RouteRequest) already in the context, evaluates RBAC,
// and answers 403 on deny. It runs BEFORE any store lookup on purpose:
// real ARM refuses unauthorized callers without revealing whether the
// resource exists.
func (a *Authorizer) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			// A pipeline wired without Authenticate is a programming error;
			// fail closed rather than evaluate an empty principal.
			azerr.WriteError(w, http.StatusUnauthorized, azerr.CodeAuthenticationFailed,
				"Authentication failed. No principal on the request.")
			return
		}
		rt, ok := RouteFromContext(r.Context())
		if !ok {
			azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
				"The request was not routed before authorization.")
			return
		}
		if rt.Scope == "/" && discoveryActions[strings.ToLower(rt.Action)] {
			next.ServeHTTP(w, r)
			return
		}
		allowed, err := a.checker.Check(p.ObjectID, rt.Action, rt.Scope, false)
		if err != nil {
			log.Printf("arm: rbac check for %s: %v", p.ObjectID, err)
			azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
				"An error occurred while evaluating authorization.")
			return
		}
		if !allowed {
			msg := fmt.Sprintf("The client '%s' with object id '%s' does not have authorization "+
				"to perform action '%s' over scope '%s' or the scope is invalid. "+
				"If access was recently granted, please refresh your credentials.",
				p.AppID, p.ObjectID, rt.Action, rt.Scope)
			azerr.WriteError(w, http.StatusForbidden, azerr.CodeAuthorizationFailed, msg)
			return
		}
		next.ServeHTTP(w, r)
	})
}
