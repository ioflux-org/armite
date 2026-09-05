package gateway

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/entra"
)

// Authenticator turns a bearer token into a Principal, or answers 401.
// entra.VerifyToken settles whether the token is genuine; the checks here
// settle whether it is acceptable - unexpired, minted by our tenant, for
// our audience - each with the error code real ARM uses.
type Authenticator struct {
	pub       *rsa.PublicKey
	issuer    string
	audience  string
	challenge string
	now       func() time.Time
}

// NewAuthenticator builds an Authenticator for cfg's tenant and audience.
// now is injected so tests move the clock instead of waiting on it.
func NewAuthenticator(cfg config.Config, pub *rsa.PublicKey, now func() time.Time) *Authenticator {
	return &Authenticator{
		pub:       pub,
		issuer:    cfg.IssuerURL(),
		audience:  strings.TrimSuffix(cfg.ARMAudience, "/"),
		challenge: fmt.Sprintf("Bearer authorization_uri=%q", cfg.LoginBaseURL()+"/"+cfg.TenantID),
		now:       now,
	}
}

// Authenticate wraps next: requests reach it only with a verified token,
// carrying the Principal in their context.
func (a *Authenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			a.unauthorized(w, azerr.CodeAuthenticationFailed, "Authentication failed. The 'Authorization' header is missing or is not a Bearer token.")
			return
		}
		c, err := entra.VerifyToken(a.pub, token)
		if err != nil {
			a.unauthorized(w, azerr.CodeInvalidAuthenticationToken, "the access token is invalid.")
			return
		}
		now := a.now()
		if exp := time.Unix(c.ExpiresAt, 0); !now.Before(exp) {
			a.unauthorized(w, azerr.CodeExpiredAuthenticationToken,
				fmt.Sprintf("The access token expiry UTC time is '%s' is earlier than the current UTC time '%s'.",
					exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)))
			return
		}
		if now.Before(time.Unix(c.NotBefore, 0)) {
			a.unauthorized(w, azerr.CodeInvalidAuthenticationToken, "The access token is not yet valid.")
			return
		}
		if c.Issuer != a.issuer {
			a.unauthorized(w, azerr.CodeInvalidAuthenticationTokenTenant,
				fmt.Sprintf("The access token is for the wrong issuer '%s'. It must match the tenant issuer '%s'.", c.Issuer, a.issuer))
			return
		}
		if strings.TrimSuffix(c.Audience, "/") != a.audience {
			a.unauthorized(w, azerr.CodeInvalidAuthenticationTokenAudience,
				fmt.Sprintf("The access token has been obtained for wrong audience '%s'. It should exactly match the allowed audience '%s'", c.Audience, a.audience))
			return
		}
		if c.ObjectID == "" {
			a.unauthorized(w, azerr.CodeInvalidAuthenticationToken,
				"The received access token is not valid: the claim 'oid' should be present")
			return
		}
		p := Principal{ObjectID: c.ObjectID, AppID: c.AppID, TenantID: c.TenantID}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// bearerToken extracts the token from an Authorization header value. The
// scheme compares case-insensitively (RFC 9110); the token is not inspected.
func bearerToken(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// unauthorized writes the ARM 401 envelope plus the Bearer challenge that
// tells clients which authority to obtain a token from.
func (a *Authenticator) unauthorized(w http.ResponseWriter, code, errMessage string) {
	w.Header().Set("WWW-Authenticate", a.challenge)
	azerr.WriteError(w, http.StatusUnauthorized, code, errMessage)
}
