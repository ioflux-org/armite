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

// Claims is the payload of a Provisio-issued token. Exported so the
// gateway can read the identity claims after verification.
type Claims struct {
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

func signJWT(key *rsa.PrivateKey, c Claims) (string, error) {
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

// VerifyToken checks the RS256 signature against pub and decodes the
// claims. It settles whether the token is genuine and nothing more:
// expiry, issuer and audience are the relying party's policy, so the
// gateway judges those with its own clock and its own error codes.
func VerifyToken(pub *rsa.PublicKey, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errMalformedToken
	}
	enc := base64.RawURLEncoding
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return Claims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return Claims{}, err
	}
	body, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return Claims{}, err
	}
	return c, nil
}
