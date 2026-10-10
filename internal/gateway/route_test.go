package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ioflux-org/armite/internal/azerr"
)

func TestRouteRequest(t *testing.T) {
	const (
		rgs     = "/subscriptions/sub-1/resourceGroups"
		rg      = rgs + "/dev"
		v       = "?api-version=2022-12-01"
		rgWrite = "Microsoft.Resources/subscriptions/resourceGroups/write"
		rgRead  = "Microsoft.Resources/subscriptions/resourceGroups/read"
	)
	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int // 0: next must be reached
		wantCode   string
		wantAction string
		wantScope  string
	}{
		{"missing api-version", http.MethodGet, rg, 400, azerr.CodeMissingApiVersionParameter, "", ""},
		{"malformed api-version", http.MethodGet, rg + "?api-version=latest", 400, azerr.CodeInvalidApiVersionParameter, "", ""},
		{"truncated api-version", http.MethodGet, rg + "?api-version=2022-12", 400, azerr.CodeInvalidApiVersionParameter, "", ""},
		{"missing version wins over bad path", http.MethodGet, "/blobs/b1", 400, azerr.CodeMissingApiVersionParameter, "", ""},
		{"bad path", http.MethodGet, "/blobs/b1" + v, 404, azerr.CodeResourceNotFound, "", ""},
		{"options", http.MethodOptions, rg + v, 405, azerr.CodeMethodNotAllowed, "", ""},
		{"put on a collection", http.MethodPut, rgs + v, 405, azerr.CodeMethodNotAllowed, "", ""},
		{"group write", http.MethodPut, rg + v, 0, "", rgWrite, rg},
		{"preview api-version", http.MethodGet, rg + "?api-version=2023-07-01-preview", 0, "", rgRead, rg},
	}
	for _, tc := range tests {
		var got Route
		reached := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, reached = RouteFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(tc.method, tc.target, nil)
		rec := httptest.NewRecorder()
		RouteRequest(next).ServeHTTP(rec, req)

		if tc.wantStatus == 0 {
			wantVersion := req.URL.Query().Get("api-version")
			if !reached || got.Action != tc.wantAction || got.Scope != tc.wantScope || got.APIVersion != wantVersion {
				t.Errorf("%s: reached = %v, route = %+v; want action %q scope %q version %q",
					tc.name, reached, got, tc.wantAction, tc.wantScope, wantVersion)
			}
			continue
		}
		if reached {
			t.Errorf("%s: reached next, want %d %s", tc.name, tc.wantStatus, tc.wantCode)
			continue
		}
		code := rec.Header().Get("x-ms-error-code")
		if rec.Code != tc.wantStatus || code != tc.wantCode {
			t.Errorf("%s: status %d code %q, want %d %s", tc.name, rec.Code, code, tc.wantStatus, tc.wantCode)
		}
	}
}
