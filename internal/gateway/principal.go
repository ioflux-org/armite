package gateway

import "context"

// Principal is the authenticated caller, as established by the
// Authenticator from the token's claims. ObjectID is the RBAC principal
// that M3c hands to Checker.Check.
type Principal struct {
	ObjectID string
	AppID    string
	TenantID string
}

// principalKey is the context key for the Principal. An unexported struct
// type means no other package can forge or collide with it: a Principal
// in the context was put there by this package.
type principalKey struct{}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the Principal the Authenticator stored on the
// request, and false for a request that did not pass authentication.
func FronContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

