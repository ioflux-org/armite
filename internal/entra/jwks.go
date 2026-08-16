package entra

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
)

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func keyID(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func publicJWK(pub *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: keyID(pub),
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (h *Handler) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tenant") != h.cfg.TenantID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"AADSTS90002: Tenant '"+r.PathValue("tenant")+"' not found.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=86400, private")
	if err := json.NewEncoder(w).Encode(jwks{Keys: []jwk{publicJWK(&h.signingKey.PublicKey)}}); err != nil {
		log.Printf("entra: encoding jwks: %v", err)
	}
}
