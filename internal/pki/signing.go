package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"path/filepath"
)

const signingKeyFile = "signing.key"

func EnsureSigningKey(dir string) (*rsa.PrivateKey, error) {
	path := filepath.Join(dir, signingKeyFile)
	exists, err := fileExists(path)
	if err != nil {
		return nil, err
	}
	if exists {
		parsed, err := readKey(path)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("pki: %s holds a %T, want *rsa.PrivateKey", path, parsed)
		}
		return key, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := writeKey(path, key); err != nil {
		return nil, err
	}
	return key, nil
}
