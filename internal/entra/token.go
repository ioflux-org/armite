package entra

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/config"
)

const tokenLifetime = time.Hour

type tokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
}

func (h *Handler) serveToken(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	if tenant != h.cfg.TenantID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "AADSTS90002: Tenant '"+tenant+"' not found.")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "AADSTS900144: The request body must contain a URL-encoded form.")
		return
	}
	if gt := r.PostFormValue("grant_type"); gt != "client_credentials" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "AADSTS70003: The app requested an unsupported grant type '"+gt+"'.")
		return
	}
	aud, ok := audienceFromScope(r.PostFormValue("scope"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "AADSTS900144: The request body must contain the following parameter: 'scope'.")
		return
	}
	clientID := r.PostFormValue("client_id")
	client, ok := h.cfg.FindClient(clientID)
	if !ok {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized_client", "AADSTS700016: Application with identifier '"+clientID+"' was not found in the directory.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(r.PostFormValue("client_secret"))) != 1 {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "AADSTS7000215: Invalid client secret provided.")
		return
	}

	c := newAppClaims(h.cfg, aud, client.ObjectID, client.ID, time.Now())

	token, err := signJWT(h.signingKey, c)
	if err != nil {
		log.Printf("entra: signing token: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	resp := tokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    int64(tokenLifetime.Seconds()) - 1,
		ExtExpiresIn: int64(tokenLifetime.Seconds()) - 1,
		AccessToken:  token,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("entra: encoding token response: %v", err)
	}
}

func audienceFromScope(scope string) (string, bool) {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return "", false
	}
	return strings.TrimSuffix(fields[0], "/.default"), true
}

// newAppClaims builds the claims for an application (service principal) token.
// Both token sources - client credentials and IMDS - mint the same shape; only
// who (objectID/appID) and for what (aud) differ.
func newAppClaims(cfg config.Config, aud, objectID, appID string, now time.Time) Claims {
	return Claims{
		Issuer:    cfg.IssuerURL(),
		Subject:   objectID,
		Audience:  aud,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(tokenLifetime).Unix(),
		TenantID:  cfg.TenantID,
		ObjectID:  objectID,
		AppID:     appID,
		IDType:    "app",
		Version:   "2.0",
	}
}
