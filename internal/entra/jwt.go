package entra

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	ExpiresAt int64  `json:"exp"`
	TenantID  string `json:"tid"`
	ObjectID  string `json:"oid"`
	AppID     string `json:"appid"`
	IDType    string `json:"idtyp"`
	Version   string `json:"ver"`
}

type jwtHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func signJWT(key *rsa.PrivateKey, c claims) (string, error) {
	hdr, err := json.Marshal(jwtHeader{Typ: "JWT", Alg: "RS256", Kid: keyID(&key.PublicKey)})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func verifyJWT(pub *rsa.PublicKey, token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, errMalformedToken
	}
	enc := base64.RawURLEncoding
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return claims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return claims{}, err
	}
	body, err := enc.DecodeString(parts[1])
	if err != nil {
		return claims{}, err
	}
	var c claims
	if err := json.Unmarshal(body, &c); err != nil {
		return claims{}, err
	}
	return c, nil
}
