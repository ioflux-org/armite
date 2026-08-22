package entra

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

var errMalformedToken = errors.New("entra: malformed token")

type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(oauthError{Error: code, ErrorDescription: description}); err != nil {
		log.Printf("entra: encoding oauth error: %v", err)
	}
}
