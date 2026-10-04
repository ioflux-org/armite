package httplog

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// captureLog routes slog's default logger into a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestWrapIDsAndLine(t *testing.T) {
	buf := captureLog(t)
	var seen string
	h := Wrap("arm", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = w.Header().Get("x-ms-request-id") // what a handler reads
		w.Header().Set("x-ms-error-code", "AuthorizationFailed")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{}}`))
	}))
	req := httptest.NewRequest(http.MethodGet,
		"https://management.localhost:8443/subscriptions?api-version=2022-12-01", nil)
	req.Header.Set("x-ms-client-request-id", "client-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	id := rec.Header().Get("x-ms-request-id")
	if !guidRe.MatchString(id) {
		t.Errorf("x-ms-request-id = %q, want a version 4 GUID", id)
	}
	if seen != id {
		t.Errorf("the handler saw %q, the client %q", seen, id)
	}
	if rec.Header().Get("x-ms-client-request-id") != "client-1" {
		t.Error("x-ms-client-request-id must be echoed")
	}
	line := buf.String()
	for _, want := range []string{"msg=request", "id=" + id, "plane=arm", "method=GET",
		"host=management.localhost:8443", `path="/subscriptions?api-version=2022-12-01"`,
		"status=403", "bytes=12", "duration=", "error=AuthorizationFailed",
		"client_request_id=client-1"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %q:\n%s", want, line)
		}
	}
}

func TestWrapDefaultsAndUpstreamID(t *testing.T) {
	buf := captureLog(t)
	// A proxied response: the upstream's id arrives as a second value
	// (the proxy copies headers with Add); the client must see ours only.
	h := Wrap("blob", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("x-ms-request-id", "upstream")
		r.URL.RawQuery = ""   // the blob plane strips a SAS before forwarding
		w.Write([]byte("ok")) // no WriteHeader: 200 implied
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"https://stdemo.blob.core.localhost:8443/demo/hello.txt?sv=2026-04-06&sig=SECRET", nil))
	if ids := rec.Header().Values("x-ms-request-id"); len(ids) != 1 || !guidRe.MatchString(ids[0]) {
		t.Errorf("x-ms-request-id = %q, want exactly our GUID", ids)
	}
	line := buf.String()
	if !strings.Contains(line, "status=200") || !strings.Contains(line, "bytes=2") ||
		strings.Contains(line, "error=") {
		t.Errorf("an implicit 200 must log as such:\n%s", line)
	}
	if strings.Contains(line, "SECRET") || !strings.Contains(line, "sig=REDACTED") {
		t.Errorf("a SAS signature must not reach the log, the query as received must:\n%s", line)
	}
}

func TestWrapFlushesThroughUnwrap(t *testing.T) {
	captureLog(t)
	h := Wrap("vault", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("partial"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush through the wrapper: %v", err)
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !rec.Flushed {
		t.Error("the recorder was not flushed: Unwrap is missing")
	}
}

func TestNewIDIsRandom(t *testing.T) {
	if a, b := NewID(), NewID(); a == b || !guidRe.MatchString(a) {
		t.Errorf("NewID = %q, %q", a, b)
	}
}
