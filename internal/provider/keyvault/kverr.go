package keyvault

import (
	"encoding/json"
	"log"
	"net/http"
)

// Data-plane error codes. SecretNotFound and Forbidden with the
// ForbiddenByRbac inner code are pinned from observed Key Vault
// responses; the others are recalled and logged as such.
const (
	kvSecretNotFound   = "SecretNotFound"
	kvBadParameter     = "BadParameter"
	kvUnauthorized     = "Unauthorized"
	kvForbidden        = "Forbidden"
	kvForbiddenByRbac  = "ForbiddenByRbac"
	kvSecretDisabled   = "SecretDisabled"
	kvConflict         = "Conflict"
	kvNotFound         = "NotFound"
	kvVaultNotFound    = "VaultNotFound"
	kvMethodNotAllowed = "MethodNotAllowed"
)

// Key Vault's data plane has its own error envelope, narrower than
// ARM's: no details array, an optional innererror carrying only a code.
// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/KeyVaultError
type kvError struct {
	Error kvErrorBody `json:"error"`
}
type kvErrorBody struct {
	Code       string       `json:"code"`
	Message    string       `json:"message,omitempty"`
	InnerError *kvErrorBody `json:"innererror,omitempty"`
}

// kvFailure is an error decided while parsing a request, before any
// handler runs.
type kvFailure struct {
	status  int
	code    string
	message string
}

// writeKVError writes a data-plane error; inner is the innererror code,
// or "" for none.
func writeKVError(w http.ResponseWriter, status int, code, message, inner string) {
	body := kvError{Error: kvErrorBody{Code: code, Message: message}}
	if inner != "" {
		body.Error.InnerError = &kvErrorBody{Code: inner}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("keyvault: encoding error response: %v", err)
	}
}

// kvInternalError is the data plane's 500: logged in full, reported
// without the details.
func kvInternalError(w http.ResponseWriter, err error) {
	log.Printf("keyvault: internal error: %v", err)
	writeKVError(w, http.StatusInternalServerError, "InternalServerError",
		"An internal error occurred.", "")
}

// writeKVJSON writes a data-plane response body. Marshal comes first so
// an encoding failure can still become a 500 instead of a torn 200.
func writeKVJSON(w http.ResponseWriter, status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		kvInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(raw)
}
