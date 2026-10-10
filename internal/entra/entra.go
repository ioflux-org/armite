package entra

import (
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"

	"github.com/ioflux-org/armite/internal/config"
)

type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type Handler struct {
	cfg        config.Config
	signingKey *rsa.PrivateKey
	mux        *http.ServeMux
}

func New(cfg config.Config, signingKey *rsa.PrivateKey) *Handler {
	h := &Handler{cfg: cfg, signingKey: signingKey, mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", h.serveDiscovery)
	h.mux.HandleFunc("GET /{tenant}/discovery/v2.0/keys", h.serveJWKS)
	h.mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", h.serveToken)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	if tenant != h.cfg.TenantID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "AADSTS90002: Tenant '"+tenant+"' not found.")
		return
	}
	base := h.cfg.LoginBaseURL() + "/" + tenant
	doc := discoveryDocument{
		Issuer:                            h.cfg.IssuerURL(),
		AuthorizationEndpoint:             base + "/oauth2/v2.0/authorize",
		TokenEndpoint:                     base + "/oauth2/v2.0/token",
		JWKSURI:                           base + "/discovery/v2.0/keys",
		ResponseTypesSupported:            []string{"code", "id_token", "token"},
		SubjectTypesSupported:             []string{"pairwise"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		log.Printf("entra: encoding discovery document: %v", err)
	}
}
