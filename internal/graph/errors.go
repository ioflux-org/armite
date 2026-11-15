package graph

import (
	"encoding/json"
	"net/http"
	"time"
)

// Graph's error envelope: a code and a message, plus innerError with
// the request id, which here is the x-ms-request-id the log line
// carries (set on the response by httplog before the handler runs).
type graphError struct {
	Error graphErrorBody `json:"error"`
}

type graphErrorBody struct {
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	InnerError map[string]string `json:"innerError"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	id := w.Header().Get("x-ms-request-id")
	body := graphError{Error: graphErrorBody{Code: code, Message: message, InnerError: map[string]string{
		"date": time.Now().UTC().Format(time.RFC3339), "request-id": id, "client-request-id": id}}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body) //nolint:errcheck // the client went away
}

func notFound(w http.ResponseWriter, what string) {
	writeError(w, http.StatusNotFound, "Request_ResourceNotFound",
		"Resource '"+what+"' does not exist or one of its queried reference-property objects are not present.")
}
