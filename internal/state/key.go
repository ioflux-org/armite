package state

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const keyName = "state.key"

// LoadKey returns the 32-byte sealing key: the configured value (base64)
// when given, else the key file in dir, generated on first use with mode
// 0600, like the CA key in certs/. A key that lives beside the data
// stops casual reading and accidental commits; a configured key stops
// more.
func LoadKey(dir, configured string) ([]byte, error) {
	if configured != "" {
		key, err := base64.StdEncoding.DecodeString(configured)
		if err != nil || len(key) != 32 {
			return nil, errors.New("state: key must be 32 bytes, base64-encoded")
		}
		return key, nil
	}
	path := filepath.Join(dir, keyName)
	if data, err := os.ReadFile(path); err == nil {
		key, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("state: %s is not a 32-byte base64 key", path)
		}
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	return key, nil
}
