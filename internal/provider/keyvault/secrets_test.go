package keyvault

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

const vaultHost = "kv-demo.vault.localhost:8443"

var (
	clock     = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	testVault = vaultContext{Name: "kv-demo", ID: rg + vaults + "/kv-demo",
		URI: "https://kv-demo.vault.localhost:8443/", Location: "eastus"}
	versionRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// serveSecret parses and serves a data-plane request directly, skipping
// authentication and authorization: the API alone, at a fixed clock.
func serveSecret(t *testing.T, p *Provider, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	p.now = func() time.Time { return clock }
	target := "https://" + vaultHost + path
	if !strings.Contains(path, "?") {
		target += "?api-version=2025-07-01"
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	rec := httptest.NewRecorder()
	op, fail := p.secretOperation(req)
	if fail != nil {
		writeKVError(rec, fail.status, fail.code, fail.message, "")
		return rec
	}
	op.serve(rec, testVault)
	return rec
}

// kvCode returns error.code and error.innererror.code from a KV error body.
func kvCode(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var e kvError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("body is not a KV error: %v\n%s", err, rec.Body.String())
	}
	inner := ""
	if e.Error.InnerError != nil {
		inner = e.Error.InnerError.Code
	}
	return e.Error.Code, inner
}

func decodeBundle(t *testing.T, rec *httptest.ResponseRecorder) secretBundle {
	t.Helper()
	var b secretBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body is not a secret bundle: %v\n%s", err, rec.Body.String())
	}
	return b
}

func TestSecretOperations(t *testing.T) {
	p := newProvider(t)
	tests := []struct {
		name, method, path string
		wantAction         string // suffix under Microsoft.KeyVault/vaults/secrets/
		wantScope          string
		wantStatus         int // when the request is refused at parse time
	}{
		{"list", http.MethodGet, "/secrets", "readMetadata/action", "", 0},
		{"get", http.MethodGet, "/secrets/db", "getSecret/action", "/secrets/db", 0},
		{"get version", http.MethodGet, "/secrets/db/abc", "getSecret/action", "/secrets/db", 0},
		{"set", http.MethodPut, "/secrets/db", "setSecret/action", "/secrets/db", 0},
		{"update", http.MethodPatch, "/secrets/db/abc", "update/action", "/secrets/db", 0},
		{"update latest", http.MethodPatch, "/secrets/db", "update/action", "/secrets/db", 0},
		{"update latest, SDK form", http.MethodPatch, "/secrets/db/", "update/action", "/secrets/db", 0},
		{"delete", http.MethodDelete, "/secrets/db", "delete", "/secrets/db", 0},
		{"versions", http.MethodGet, "/secrets/db/versions", "readMetadata/action", "/secrets/db", 0},
		{"list deleted", http.MethodGet, "/deletedsecrets", "readMetadata/action", "", 0},
		{"get deleted", http.MethodGet, "/deletedsecrets/db", "getSecret/action", "/secrets/db", 0},
		{"purge", http.MethodDelete, "/deletedsecrets/db", "purge/action", "/secrets/db", 0},
		{"recover", http.MethodPost, "/deletedsecrets/db/recover", "recover/action", "/secrets/db", 0},
		{"post on a secret", http.MethodPost, "/secrets/db", "", "", 405},
		{"backup unsupported", http.MethodPost, "/secrets/db/backup", "", "", 405},
		{"bad name", http.MethodGet, "/secrets/bad_name", "", "", 400},
		{"unknown collection", http.MethodGet, "/keys/k", "", "", 404},
		{"missing api-version", http.MethodGet, "/secrets?x=1", "", "", 400},
	}
	for _, tt := range tests {
		target := "https://" + vaultHost + tt.path
		if !strings.Contains(tt.path, "?") {
			target += "?api-version=7.4"
		}
		op, fail := p.secretOperation(httptest.NewRequest(tt.method, target, nil))
		if tt.wantStatus != 0 {
			if fail == nil || fail.status != tt.wantStatus {
				t.Errorf("%s: fail = %+v, want status %d", tt.name, fail, tt.wantStatus)
			}
			continue
		}
		if fail != nil {
			t.Errorf("%s: refused: %+v", tt.name, fail)
			continue
		}
		if op.action != actionPrefix+tt.wantAction || op.scope != tt.wantScope {
			t.Errorf("%s: action %q scope %q, want %q %q", tt.name, op.action, op.scope,
				actionPrefix+tt.wantAction, tt.wantScope)
		}
	}
}

func TestSecretLifecycle(t *testing.T) {
	p := newProvider(t)
	now := clock.Unix()

	body := `{"value":"one","contentType":"text/plain","tags":{"env":"dev"}}`
	rec := serveSecret(t, p, http.MethodPut, "/secrets/Db-Pass", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("set: status = %d %s", rec.Code, rec.Body.String())
	}
	b := decodeBundle(t, rec)
	prefix := testVault.URI + "secrets/Db-Pass/"
	if !strings.HasPrefix(b.ID, prefix) || !versionRe.MatchString(strings.TrimPrefix(b.ID, prefix)) {
		t.Errorf("set id = %q, want %s<32 hex>", b.ID, prefix)
	}
	version1 := strings.TrimPrefix(b.ID, prefix)
	a := b.Attributes
	if b.Value != "one" || b.ContentType != "text/plain" || b.Tags["env"] != "dev" {
		t.Errorf("set bundle = %+v", b)
	}
	if a.Enabled == nil || !*a.Enabled || a.Created != now || a.Updated != now ||
		a.RecoveryLevel != recoveryLevel || a.RecoverableDays != secretRetentionDays {
		t.Errorf("set attributes = %+v", a)
	}

	rec = serveSecret(t, p, http.MethodPut, "/secrets/db-pass", `{"value":"two"}`)
	if b2 := decodeBundle(t, rec); rec.Code != http.StatusOK || b2.ID == b.ID {
		t.Errorf("second set: status = %d id %q, want a new version", rec.Code, b2.ID)
	}
	rec = serveSecret(t, p, http.MethodGet, "/secrets/db-pass", "")
	got := decodeBundle(t, rec)
	if rec.Code != http.StatusOK || got.Value != "two" || !strings.Contains(got.ID, "/Db-Pass/") {
		t.Errorf("get latest = %d %+v, want value two under the canonical name", rec.Code, got)
	}
	rec = serveSecret(t, p, http.MethodGet, "/secrets/db-pass/"+version1, "")
	if got := decodeBundle(t, rec); rec.Code != http.StatusOK || got.Value != "one" {
		t.Errorf("get by version = %d %+v", rec.Code, got)
	}

	rec = serveSecret(t, p, http.MethodGet, "/secrets/db-pass/versions", "")
	var list secretListResult
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Value) != 2 {
		t.Fatalf("versions = %d items, %v", len(list.Value), err)
	}
	raw := rec.Body.String()
	if !strings.Contains(raw, `"nextLink":null`) || strings.Contains(raw, `"value":"`) {
		t.Errorf("versions body must carry nextLink:null and no secret values: %s", raw)
	}
	rec = serveSecret(t, p, http.MethodGet, "/secrets", "")
	err := json.Unmarshal(rec.Body.Bytes(), &list)
	if err != nil || len(list.Value) != 1 || list.Value[0].ID != testVault.URI+"secrets/Db-Pass" {
		t.Errorf("list = %+v, %v; want one item with an unversioned id", list.Value, err)
	}

	rec = serveSecret(t, p, http.MethodPatch, "/secrets/db-pass/", `{"contentType":"text/x-latest"}`)
	got = decodeBundle(t, rec)
	if rec.Code != http.StatusOK || got.ContentType != "text/x-latest" ||
		!strings.HasSuffix(got.ID, "/Db-Pass/"+latestVersion(t, p)) {
		t.Errorf("update latest via trailing slash = %d %+v", rec.Code, got)
	}
	rec = serveSecret(t, p, http.MethodPatch, "/secrets/db-pass/"+version1,
		`{"attributes":{"enabled":false}}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"value"`) {
		t.Errorf("update: status = %d body %s; want 200 without the value", rec.Code, rec.Body.String())
	}
	rec = serveSecret(t, p, http.MethodGet, "/secrets/db-pass/"+version1, "")
	code, inner := kvCode(t, rec)
	if rec.Code != http.StatusForbidden || code != kvForbidden || inner != kvSecretDisabled {
		t.Errorf("get disabled: %d %s/%s, want 403 Forbidden/SecretDisabled", rec.Code, code, inner)
	}

	rec = serveSecret(t, p, http.MethodDelete, "/secrets/db-pass", "")
	var d deletedSecretBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("delete: status = %d, %v", rec.Code, err)
	}
	if d.RecoveryID != testVault.URI+"deletedsecrets/Db-Pass" || d.DeletedDate != now ||
		d.ScheduledPurgeDate != now+secretRetentionDays*daySeconds || d.Value != "two" {
		t.Errorf("deleted bundle = %+v", d)
	}
	rec = serveSecret(t, p, http.MethodGet, "/secrets/db-pass", "")
	code, _ = kvCode(t, rec)
	if rec.Code != http.StatusNotFound || code != kvSecretNotFound ||
		!strings.Contains(rec.Body.String(), "recover") {
		t.Errorf("get after delete: %d %s", rec.Code, rec.Body.String())
	}
	rec = serveSecret(t, p, http.MethodPut, "/secrets/db-pass", `{"value":"three"}`)
	if code, _ := kvCode(t, rec); rec.Code != http.StatusConflict || code != kvConflict {
		t.Errorf("set while deleted: %d %s, want 409 Conflict", rec.Code, code)
	}
	rec = serveSecret(t, p, http.MethodGet, "/deletedsecrets/db-pass", "")
	if rec.Code != http.StatusOK {
		t.Errorf("get deleted: status = %d", rec.Code)
	}
	rec = serveSecret(t, p, http.MethodGet, "/deletedsecrets", "")
	var dl deletedSecretListResult
	err = json.Unmarshal(rec.Body.Bytes(), &dl)
	if err != nil || len(dl.Value) != 1 || dl.Value[0].RecoveryID != d.RecoveryID {
		t.Errorf("list deleted = %+v, %v", dl.Value, err)
	}

	rec = serveSecret(t, p, http.MethodPost, "/deletedsecrets/db-pass/recover", "")
	if got := decodeBundle(t, rec); rec.Code != http.StatusOK || got.Value != "two" {
		t.Errorf("recover = %d %+v", rec.Code, got)
	}
	if rec = serveSecret(t, p, http.MethodGet, "/secrets/db-pass", ""); rec.Code != http.StatusOK {
		t.Errorf("get after recover: status = %d", rec.Code)
	}
	serveSecret(t, p, http.MethodDelete, "/secrets/db-pass", "")
	rec = serveSecret(t, p, http.MethodDelete, "/deletedsecrets/db-pass", "")
	if rec.Code != http.StatusNoContent {
		t.Errorf("purge: status = %d, want 204", rec.Code)
	}
	rec = serveSecret(t, p, http.MethodGet, "/deletedsecrets/db-pass", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("get deleted after purge: status = %d, want 404", rec.Code)
	}
	rec = serveSecret(t, p, http.MethodPut, "/secrets/db-pass", `{"value":"four"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("set after purge: status = %d, want 200 (name reusable)", rec.Code)
	}
}

func TestSetSecretRejections(t *testing.T) {
	p := newProvider(t)
	for _, body := range []string{"", "not json", `{}`, `{"value":""}`} {
		rec := serveSecret(t, p, http.MethodPut, "/secrets/db", body)
		if code, _ := kvCode(t, rec); rec.Code != http.StatusBadRequest || code != kvBadParameter {
			t.Errorf("body %q: %d %s, want 400 BadParameter", body, rec.Code, code)
		}
	}
}

// latestVersion returns the current version id of Db-Pass in p.
func latestVersion(t *testing.T, p *Provider) string {
	t.Helper()
	_, ver, err := p.secrets.Get("kv-demo", "db-pass", "")
	if err != nil {
		t.Fatal(err)
	}
	return ver.Version
}
