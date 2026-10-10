package entra

import (
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/config"
)

const imdsTokenPath = "/metadata/identity/oauth2/token"

// imdsTokenResponse mirrors IMDS's legacy wire format: every numeric field is
// a decimal STRING. SDKs parse them as such; emitting JSON numbers breaks them.
type imdsTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ClientID     string `json:"client_id"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	ExtExpiresIn string `json:"ext_expires_in"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

// IMDS serves the Instance Metadata Service's managed-identity token endpoint.
// It is plain HTTP and addressed by IP, so it gets its own listener and mux
// rather than a slot in the host-based plane router.
type IMDS struct {
	cfg        config.Config
	signingKey *rsa.PrivateKey
	mux        *http.ServeMux
}

func NewIMDS(cfg config.Config, signingKey *rsa.PrivateKey) *IMDS {
	s := &IMDS{
		cfg:        cfg,
		signingKey: signingKey,
		mux:        http.NewServeMux(),
	}
	s.mux.HandleFunc("GET "+imdsTokenPath, s.serveToken)

	// MSAL Node canonicalizes the endpoint to ".../token/". {$} matches only
	// the end of the path; a plain trailing-slash pattern would match the
	// whole subtree below it.
	s.mux.HandleFunc("GET "+imdsTokenPath+"/{$}", s.serveToken)

	return s
}

func (s *IMDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *IMDS) serveToken(w http.ResponseWriter, r *http.Request) {
	// Checked before anything else: the SDK's availability probe sends no
	// header and no query and relies on getting exactly this 400 back.
	if r.Header.Get("MetaData") != "true" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Required metadata header not specified")
		return
	}
	q := r.URL.Query()
	// IMDS versions are additive; presence is the contract, not the value.
	if q.Get("api-version") == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Required query variable 'api-version' is missing")
		return
	}
	resource := q.Get("resource")
	if resource == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Required query variable 'resource' is missing")
		return
	}
	mi := s.cfg.ManagedIdentity
	// client_id selects a user-assigned identity; we only have the one.
	if id := q.Get("client_id"); id != "" && id != mi.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Identity not found")
		return
	}

	c := newAppClaims(s.cfg, strings.TrimSuffix(resource, "/"), mi.ObjectID, mi.ClientID, time.Now())
	token, err := signJWT(s.signingKey, c)
	if err != nil {
		log.Printf("imds: signing token: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token singing failed")
		return
	}

	expiresIn := strconv.FormatInt(int64(tokenLifetime.Seconds())-1, 10)
	w.Header().Set("Content-Type", "application/json")
	resp := imdsTokenResponse{
		AccessToken:  token,
		ClientID:     mi.ClientID,
		ExpiresIn:    expiresIn,
		ExpiresOn:    strconv.FormatInt(c.ExpiresAt, 10),
		ExtExpiresIn: expiresIn,
		NotBefore:    strconv.FormatInt(c.NotBefore, 10),
		Resource:     resource,
		TokenType:    "Bearer",
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("imds: encoding token response: %v", err)
	}
}
