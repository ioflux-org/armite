package azerr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()

	WriteError(rec, http.StatusNotFound, CodeResourceNotFound, "vault 'my-vault' was not found")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	if got := rec.Header().Get("x-ms-error-code"); got != CodeResourceNotFound {
		t.Errorf("x-ms-error-code = %q, want %q", got, CodeResourceNotFound)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"details":[]`) {
		t.Errorf("body must contain %q, got: %s", `"details":[]`, body)
	}

	var env envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if env.Error.Code != CodeResourceNotFound {
		t.Errorf("error.code = %q, want %q", env.Error.Code, CodeResourceNotFound)
	}
	if env.Error.Message == "" {
		t.Error("error.message is empty")
	}
}
