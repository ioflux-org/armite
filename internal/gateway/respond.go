package gateway

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ioflux-org/provisio/internal/azerr"
)

// WriteJSON writes v as the JSON body of a response with the given
// status. Providers use it for every success response; errors keep going
// through azerr.WriteError so the envelope and the x-ms-error-code header
// stay in one place. The body is encoded BEFORE the header goes out: once
// WriteHeader has run the status is final, so encoding first keeps the
// option of answering 500 when v cannot be encoded.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		log.Printf("gateway: encoding response: %v", err)
		azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
			"The response could not be encoded.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// A failed write means the client went away; nothing is left to tell it.
	w.Write(body)
}
