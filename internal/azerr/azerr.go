package azerr

import (
	"encoding/json"
	"log"
	"net/http"
)

const (
	CodeAuthenticationFailed               = "AuthenticationFailed"
	CodeAuthorizationFailed                = "AuthorizationFailed"
	CodeResourceNotFound                   = "ResourceNotFound"
	CodeInvalidApiVersionParameter         = "InvalidApiVersionParameter"
	CodeInvalidAuthenticationToken         = "InvalidAuthenticationToken"
	CodeExpiredAuthenticationToken         = "ExpiredAuthenticationToken"
	CodeInvalidAuthenticationTokenAudience = "InvalidAuthenticationTokenAudience"
	CodeInvalidAuthenticationTokenTenant   = "InvalidAuthenticationTokenTenant"
)

type ErrorInfo struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details []ErrorInfo `json:"details"`
}

type envelope struct {
	Error ErrorInfo `json:"error"`
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	env := envelope{
		Error: ErrorInfo{
			Code:    code,
			Message: message,
			Details: []ErrorInfo{},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-ms-error-code", code)
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(env); err != nil {
		log.Printf("azerr: failed to encode error response: %v", err)
	}
}
