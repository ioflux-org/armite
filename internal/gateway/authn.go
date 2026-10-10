package gateway

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/entra"
)

// Authenticator turns a bearer token into a Principal, or answers 401.
// entra.VerifyToken settles whether the token is genuine; the checks here
// settle whether it is acceptable - unexpired, minted by our tenant, for
// our audience - each with the error code real ARM uses.
type Authenticator struct {
	pub       *rsa.PublicKey
	issuer    string
	audiences []string
	challenge string
	now       func() time.Time
}

// Failure says why a bearer token was refused: the ARM error code and
// message. The zero Failure means the token was accepted.
type Failure struct {
	Code    string
	Message string
}

// NewAuthenticator builds an Authenticator for cfg's tenant and the ARM
// audience. now is injected so tests move the clock instead of waiting.
func NewAuthenticator(cfg config.Config, pub *rsa.PublicKey, now func() time.Time) *Authenticator {
	return NewAuthenticatorFor(cfg, pub, now, cfg.ARMAudience, cfg.ARMBaseURL())
}

// NewAuthenticatorFor builds an Authenticator demanding a specific
// audience. The Key Vault data plane uses it with the vault audience;
// everything else about a token - signature, expiry, issuer, oid - is
// judged the same way on both planes.
func NewAuthenticatorFor(cfg config.Config, pub *rsa.PublicKey, now func() time.Time,
	audiences ...string) *Authenticator {
	accepted := make([]string, 0, len(audiences))
	for _, a := range audiences {
		accepted = append(accepted, strings.TrimSuffix(a, "/"))
	}
	return &Authenticator{
		pub:       pub,
		issuer:    cfg.IssuerURL(),
		audiences: accepted,
		challenge: fmt.Sprintf("Bearer authorization_uri=%q", cfg.LoginBaseURL()+"/"+cfg.TenantID),
		now:       now,
	}
}

// Authenticate wraps next: requests reach it only with a verified token,
// carrying the Principal in their context.
func (a *Authenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, fail := a.Verify(r.Header.Get("Authorization"))
		if fail.Code != "" {
			a.unauthorized(w, fail.Code, fail.Message)
			return
		}
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

// Verify checks an Authorization header value and returns the Principal
// it identifies, or the Failure to report. It is the pure core of
// Authenticate, shared with the Key Vault data plane, which reports the
// same failures in Key Vault's own envelope.
func (a *Authenticator) Verify(authorization string) (Principal, Failure) {
	token, ok := bearerToken(authorization)
	if !ok {
		return Principal{}, Failure{azerr.CodeAuthenticationFailed,
			"Authentication failed. The 'Authorization' header is missing or is not a Bearer token."}
	}
	c, err := entra.VerifyToken(a.pub, token)
	if err != nil {
		return Principal{}, Failure{azerr.CodeInvalidAuthenticationToken, "The access token is invalid."}
	}
	now := a.now()
	if exp := time.Unix(c.ExpiresAt, 0); !now.Before(exp) {
		return Principal{}, Failure{azerr.CodeExpiredAuthenticationToken,
			fmt.Sprintf("The access token expiry UTC time '%s' is earlier than the current UTC time '%s'.",
				exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))}
	}
	if now.Before(time.Unix(c.NotBefore, 0)) {
		return Principal{}, Failure{azerr.CodeInvalidAuthenticationToken,
			"The access token is not yet valid."}
	}
	if c.Issuer != a.issuer {
		return Principal{}, Failure{azerr.CodeInvalidAuthenticationTokenTenant,
			fmt.Sprintf("The access token is from the wrong issuer '%s'. "+
				"It must match the tenant issuer '%s'.", c.Issuer, a.issuer)}
	}
	if !slices.Contains(a.audiences, strings.TrimSuffix(c.Audience, "/")) {
		return Principal{}, Failure{azerr.CodeInvalidAuthenticationTokenAudience,
			fmt.Sprintf("The access token has been obtained for wrong audience '%s'. "+
				"It should exactly match the allowed audience '%s'.", c.Audience,
				strings.Join(a.audiences, "' or '"))}
	}
	if c.ObjectID == "" {
		return Principal{}, Failure{azerr.CodeInvalidAuthenticationToken,
			"The received access token is not valid: the claim 'oid' should be present."}
	}
	return Principal{ObjectID: c.ObjectID, AppID: c.AppID, TenantID: c.TenantID}, Failure{}
}
