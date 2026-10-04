// Package httplog gives every request an id and one log line.
//
// Azure answers every call with an x-ms-request-id, the handle a client
// quotes when something went wrong and the one thing that ties its error
// to a line in the service's log. Provisio does the same: the id is
// minted before the handler runs and sits on the response from the
// start, and when the handler returns, one structured line records what
// happened to the request - plane, method, path, status, duration and the
// error code, if any - under that id.
package httplog

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Wrap returns next with a request id and an access log line. The id is
// set as x-ms-request-id on the response before next runs, so a handler
// that wants it reads w.Header(); a client's x-ms-client-request-id is
// echoed back, as the services do. The line is written with log/slog
// after next returns, at Info, with the x-ms-error-code header the
// handler set, if any, as "error".
func Wrap(plane string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		path := redact(r.URL) // as received: a handler may rewrite the query
		ww := &writer{ResponseWriter: w, id: NewID(), status: http.StatusOK,
			client: r.Header.Get("x-ms-client-request-id")}
		ww.setIDs()
		next.ServeHTTP(ww, r)

		attrs := []any{"id", ww.id, "plane", plane, "method", r.Method, "host", r.Host,
			"path", path, "status", ww.status, "bytes", ww.bytes,
			"duration", time.Since(start)}
		if code := w.Header().Get("x-ms-error-code"); code != "" {
			attrs = append(attrs, "error", code)
		}
		if ww.client != "" {
			attrs = append(attrs, "client_request_id", ww.client)
		}
		slog.Info("request", attrs...)
	})
}

// NewID returns a random GUID, the x-ms-request-id shape: a version 4
// UUID, 122 random bits with the version and variant bits fixed.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// writer is the ResponseWriter the handler sees: it records the status
// and the size, which the real one does not report, and pins the ids on
// the headers at the moment they are sent - a proxied response arrives
// with the upstream's own x-ms-request-id, and the one the client reads
// must be the one in the log.
type writer struct {
	http.ResponseWriter
	id     string
	client string
	status int
	bytes  int
	wrote  bool
}

func (w *writer) setIDs() {
	w.Header().Set("x-ms-request-id", w.id)
	if w.client != "" {
		w.Header().Set("x-ms-client-request-id", w.client)
	}
}

func (w *writer) WriteHeader(status int) {
	if !w.wrote {
		w.wrote, w.status = true, status
		w.setIDs()
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *writer) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Unwrap exposes the real writer to http.ResponseController, which is
// how net/http (the reverse proxy included) reaches Flush and the other
// optional interfaces through a wrapper.
func (w *writer) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// redact is the request URI with a SAS signature masked: the query is
// worth logging (api-version, restype, comp), the secret in it is not.
func redact(u *url.URL) string {
	if !strings.Contains(u.RawQuery, "sig=") {
		return u.RequestURI()
	}
	q := u.Query()
	q.Set("sig", "REDACTED")
	return u.EscapedPath() + "?" + q.Encode()
}
