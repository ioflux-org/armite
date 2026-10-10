package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ioflux-org/armite/internal/config"
)

// fakeAzurite is the slice of the Blob service the management plane
// needs: container create, properties, metadata, ACL, list and delete,
// each checked for a host-style URL and a Shared Key signature.
type fakeAzurite struct {
	t          *testing.T
	key        []byte
	containers map[string]bool
	calls      []string
}

func (f *fakeAzurite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	if r.Host != "stdemo.blob.localhost" {
		f.t.Errorf("upstream Host = %q, want the account host-style", r.Host)
	}
	want := r.Clone(r.Context())
	signSharedKey(want, "stdemo", f.key)
	if got := r.Header.Get("Authorization"); got != want.Header.Get("Authorization") {
		f.t.Errorf("upstream Authorization = %q, want a Shared Key signature for stdemo", got)
	}
	name := strings.Trim(r.URL.Path, "/")
	q := r.URL.Query()
	switch {
	case name == "" && q.Get("comp") == "list":
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><EnumerationResults>`+
			`<Containers><Container><Name>alpha</Name><Properties>`+
			`<Last-Modified>Fri, 02 Oct 2026 10:00:00 GMT</Last-Modified><Etag>"0x1"</Etag>`+
			`<LeaseStatus>unlocked</LeaseStatus><LeaseState>available</LeaseState>`+
			`<PublicAccess>blob</PublicAccess></Properties><Metadata><owner>me</owner></Metadata>`+
			`</Container></Containers></EnumerationResults>`)
	case q.Get("restype") != "container":
		http.Error(w, "unexpected", http.StatusBadRequest)
	case r.Method == http.MethodPut && q.Get("comp") == "":
		if f.containers[name] {
			w.Header().Set("x-ms-error-code", "ContainerAlreadyExists")
			w.WriteHeader(http.StatusConflict)
			return
		}
		f.containers[name] = true
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPut: // metadata, acl
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet:
		if !f.containers[name] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("x-ms-blob-public-access", "blob")
		w.Header().Set("x-ms-lease-status", "unlocked")
		w.Header().Set("x-ms-lease-state", "available")
		w.Header().Set("x-ms-meta-owner", "me")
		w.Header().Set("Last-Modified", "Fri, 02 Oct 2026 10:00:00 GMT")
		w.Header().Set("ETag", `"0x1"`)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodDelete:
		if !f.containers[name] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.containers, name)
		w.WriteHeader(http.StatusAccepted)
	}
}

func TestContainersThroughUpstream(t *testing.T) {
	key := []byte(strings.Repeat("k", 64))
	fake := &fakeAzurite{t: t, key: key, containers: map[string]bool{}}
	ts := httptest.NewServer(fake)
	defer ts.Close()
	cfg := config.Default()
	cfg.Azurite = config.Azurite{Mode: "byo", Upstream: ts.URL, Accounts: []config.StorageAccount{
		{Name: "stdemo", Key: base64.StdEncoding.EncodeToString(key)}}}
	p := newProvider(t, cfg)
	id := rg + accounts + "/stdemo"
	if rec := serve(t, p, http.MethodPut, id, azBody); rec.Code != http.StatusOK {
		t.Fatalf("create account: %d %s", rec.Code, rec.Body.String())
	}
	cont := id + "/blobServices/default/containers/alpha"

	rec := serve(t, p, http.MethodPut, cont,
		`{"properties":{"publicAccess":"Blob","metadata":{"owner":"me"}}}`)
	var got container
	json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != http.StatusCreated || got.ID != cont || got.Type != containerType ||
		got.Properties.PublicAccess != "Blob" || got.Properties.Metadata["owner"] != "me" ||
		got.Properties.LeaseState != "Available" ||
		got.Properties.LastModifiedTime != "2026-10-02T10:00:00Z" {
		t.Errorf("create container: status %d, %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodPut, cont, `{"properties":{"publicAccess":"None"}}`)
	if rec.Code != http.StatusOK {
		t.Errorf("second PUT is an update: status %d, %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodGet, cont, "")
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"leaseStatus":"Unlocked"`) {
		t.Errorf("get container: status %d, %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodGet, id+"/blobServices/default/containers", "")
	var list struct{ Value []container }
	json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != http.StatusOK || len(list.Value) != 1 || list.Value[0].Name != "alpha" ||
		list.Value[0].Properties.PublicAccess != "Blob" ||
		list.Value[0].Properties.Metadata["owner"] != "me" {
		t.Errorf("list containers: status %d, %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodGet, id+"/blobServices/default/containers/missing", "")
	if rec.Code != http.StatusNotFound || code(rec) != "ContainerNotFound" {
		t.Errorf("get missing container: status %d %s", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodDelete, cont, "")
	if rec.Code != http.StatusOK {
		t.Errorf("delete container: status %d", rec.Code)
	}
	rec = serve(t, p, http.MethodDelete, cont, "")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete again: status %d, want 204", rec.Code)
	}
	// Create reads the container back for the response; the second PUT
	// hits 409 and becomes metadata + ACL updates, then the read.
	wantCalls := []string{"PUT /alpha?restype=container", "GET /alpha?restype=container",
		"PUT /alpha?restype=container", "PUT /alpha?restype=container&comp=metadata",
		"PUT /alpha?restype=container&comp=acl", "GET /alpha?restype=container"}
	for i, want := range wantCalls {
		if i >= len(fake.calls) || fake.calls[i] != want {
			t.Errorf("upstream call %d = %q, want %q", i, fake.calls[i], want)
		}
	}
}
