package storage

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/arm"
	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/store"
)

// The management plane's view of containers and the blob service is
// served from Azurite: a container exists there or nowhere, so every
// ARM call here becomes a data-plane call upstream, signed with the
// account key.

const (
	blobServiceType = "Microsoft.Storage/storageAccounts/blobServices"
	containerType   = "Microsoft.Storage/storageAccounts/blobServices/containers"
)

// accountOf resolves the account an ARM child resource belongs to.
func (p *Provider) accountOf(w http.ResponseWriter, id arm.ResourceID) (store.Resource, bool) {
	accountID := arm.ResourceID{Scope: id.Scope, Namespace: id.Namespace,
		Types: id.Types[:1], Names: id.Names[:1]}
	res, err := p.store.Get(accountID.String())
	if err != nil {
		accountLookupError(w, accountID, err)
		return store.Resource{}, false
	}
	return res, true
}

// blobServiceProperties is what GET .../blobServices/default returns
// until a PUT changes it; nothing here is enforced upstream.
func blobServiceDefaults() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"cors": raw(map[string]any{"corsRules": []any{}}),
		"deleteRetentionPolicy": raw(map[string]any{
			"enabled": false, "allowPermanentDelete": false}),
		"containerDeleteRetentionPolicy": raw(map[string]any{"enabled": false}),
		"isVersioningEnabled":            raw(false),
		"changeFeed":                     raw(map[string]any{"enabled": false}),
		"restorePolicy":                  raw(map[string]any{"enabled": false}),
		"lastAccessTimeTrackingPolicy":   raw(map[string]any{"enable": false}),
	}
}

type blobService struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Type       string                     `json:"type"`
	Sku        sku                        `json:"sku"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func (p *Provider) blobServiceOf(res store.Resource) (blobService, error) {
	var st stored
	if err := json.Unmarshal(res.Properties, &st); err != nil {
		return blobService{}, err
	}
	props := blobServiceDefaults()
	if st.BlobService != nil {
		for k, v := range st.BlobService {
			props[k] = v
		}
	}
	return blobService{ID: res.ID + "/blobServices/default", Name: "default", Type: blobServiceType,
		Sku: st.Sku, Properties: props}, nil
}

// serveBlobServices lists the one blob service every account has.
func (p *Provider) serveBlobServices(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on the blob service collection.")
		return
	}
	res, ok := p.accountOf(w, id)
	if !ok {
		return
	}
	bs, err := p.blobServiceOf(res)
	if err != nil {
		internalError(w, err)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []blobService `json:"value"`
	}{[]blobService{bs}})
}

// serveBlobService answers GET and PUT of .../blobServices/default: the
// properties are kept with the account and echoed back.
func (p *Provider) serveBlobService(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	res, ok := p.accountOf(w, id)
	if !ok {
		return
	}
	if !strings.EqualFold(id.Names[1], "default") {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			"The blob service '"+id.Names[1]+"' does not exist; the only one is 'default'.")
		return
	}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPut, http.MethodPatch:
		var body struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if !readBody(w, r, &body) {
			return
		}
		var st stored
		if err := json.Unmarshal(res.Properties, &st); err != nil {
			internalError(w, err)
			return
		}
		if st.BlobService == nil {
			st.BlobService = map[string]json.RawMessage{}
		}
		for k, v := range body.Properties {
			st.BlobService[k] = v
		}
		res.Properties = raw(st)
		if _, err := p.store.Put(res); err != nil {
			internalError(w, err)
			return
		}
	default:
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on the blob service.")
		return
	}
	bs, err := p.blobServiceOf(res)
	if err != nil {
		internalError(w, err)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, bs)
}

// container is the ARM shape of a container.
type container struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Type       string              `json:"type"`
	Etag       string              `json:"etag,omitempty"`
	Properties containerProperties `json:"properties"`
}

type containerProperties struct {
	PublicAccess          string            `json:"publicAccess"`
	LeaseStatus           string            `json:"leaseStatus"`
	LeaseState            string            `json:"leaseState"`
	LastModifiedTime      string            `json:"lastModifiedTime,omitempty"`
	Metadata              map[string]string `json:"metadata"`
	HasImmutabilityPolicy bool              `json:"hasImmutabilityPolicy"`
	HasLegalHold          bool              `json:"hasLegalHold"`
	Deleted               bool              `json:"deleted"`
}

// publicAccessARM maps the data plane's x-ms-blob-public-access value to
// ARM's enum, and back.
func publicAccessARM(v string) string {
	switch strings.ToLower(v) {
	case "blob":
		return "Blob"
	case "container":
		return "Container"
	}
	return "None"
}

func publicAccessHeader(v string) string {
	switch strings.ToLower(v) {
	case "blob", "container":
		return strings.ToLower(v)
	}
	return ""
}

// capitalize turns Azurite's "unlocked" into ARM's "Unlocked".
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func containerID(accountID, name string) string {
	return accountID + "/blobServices/default/containers/" + name
}

// containerFromHeaders builds the ARM shape from a container's
// properties response upstream.
func containerFromHeaders(accountID, name string, h http.Header) container {
	meta := map[string]string{}
	for k, v := range h {
		if lower := strings.ToLower(k); strings.HasPrefix(lower, "x-ms-meta-") {
			meta[lower[len("x-ms-meta-"):]] = strings.Join(v, ",")
		}
	}
	modified := ""
	if t, err := http.ParseTime(h.Get("Last-Modified")); err == nil {
		modified = t.UTC().Format(time.RFC3339)
	}
	return container{
		ID: containerID(accountID, name), Name: name, Type: containerType, Etag: h.Get("ETag"),
		Properties: containerProperties{
			PublicAccess:     publicAccessARM(h.Get("x-ms-blob-public-access")),
			LeaseStatus:      capitalize(h.Get("x-ms-lease-status")),
			LeaseState:       capitalize(h.Get("x-ms-lease-state")),
			LastModifiedTime: modified,
			Metadata:         meta,
		},
	}
}

// upstreamError relays an Azurite failure as an ARM error.
func upstreamError(w http.ResponseWriter, resp *http.Response) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	code := resp.Header.Get("x-ms-error-code")
	if code == "" {
		code = azerr.CodeInternalServerError
	}
	status := resp.StatusCode
	if status == http.StatusNotFound {
		code = azerr.CodeResourceNotFound
	}
	azerr.WriteError(w, status, code, "The blob service answered: "+strings.TrimSpace(string(body)))
}

// serveContainers lists an account's containers from upstream.
func (p *Provider) serveContainers(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on the container collection.")
		return
	}
	res, ok := p.accountOf(w, id)
	if !ok {
		return
	}
	resp, err := p.upstream.do(r.Context(), res.Name, http.MethodGet,
		"/?comp=list&include=metadata", nil, nil)
	if err != nil {
		internalError(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		upstreamError(w, resp)
		return
	}
	var listing struct {
		Containers []struct {
			Name       string `xml:"Name"`
			Properties struct {
				LastModified string `xml:"Last-Modified"`
				Etag         string `xml:"Etag"`
				LeaseStatus  string `xml:"LeaseStatus"`
				LeaseState   string `xml:"LeaseState"`
				PublicAccess string `xml:"PublicAccess"`
			} `xml:"Properties"`
			Metadata struct {
				Items []struct {
					XMLName xml.Name
					Value   string `xml:",chardata"`
				} `xml:",any"`
			} `xml:"Metadata"`
		} `xml:"Containers>Container"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&listing); err != nil {
		internalError(w, fmt.Errorf("list containers: %w", err))
		return
	}
	out := make([]container, 0, len(listing.Containers))
	for _, c := range listing.Containers {
		meta := map[string]string{}
		for _, item := range c.Metadata.Items {
			meta[strings.ToLower(item.XMLName.Local)] = item.Value
		}
		modified := ""
		if t, err := http.ParseTime(c.Properties.LastModified); err == nil {
			modified = t.UTC().Format(time.RFC3339)
		}
		out = append(out, container{
			ID: containerID(res.ID, c.Name), Name: c.Name, Type: containerType,
			Etag: c.Properties.Etag,
			Properties: containerProperties{
				PublicAccess:     publicAccessARM(c.Properties.PublicAccess),
				LeaseStatus:      capitalize(c.Properties.LeaseStatus),
				LeaseState:       capitalize(c.Properties.LeaseState),
				LastModifiedTime: modified, Metadata: meta,
			},
		})
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []container `json:"value"`
	}{out})
}

// serveContainer handles one container through the management plane:
// PUT creates (or updates metadata and public access), GET reads,
// DELETE removes; each is one or two calls upstream.
func (p *Provider) serveContainer(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	res, ok := p.accountOf(w, id)
	if !ok {
		return
	}
	name := id.Names[2]
	path := "/" + url.PathEscape(name) + "?restype=container"
	switch r.Method {
	case http.MethodPut, http.MethodPatch:
		var body struct {
			Properties struct {
				PublicAccess string            `json:"publicAccess"`
				Metadata     map[string]string `json:"metadata"`
			} `json:"properties"`
		}
		if !readBody(w, r, &body) {
			return
		}
		h := http.Header{}
		if access := publicAccessHeader(body.Properties.PublicAccess); access != "" {
			h.Set("x-ms-blob-public-access", access)
		}
		for k, v := range body.Properties.Metadata {
			h.Set("x-ms-meta-"+k, v)
		}
		resp, err := p.upstream.do(r.Context(), res.Name, http.MethodPut, path, h, nil)
		if err != nil {
			internalError(w, err)
			return
		}
		resp.Body.Close()
		status := http.StatusCreated
		switch resp.StatusCode {
		case http.StatusCreated:
		case http.StatusConflict:
			// Exists: ARM's PUT replaces metadata and public access.
			status = http.StatusOK
			for _, update := range []string{"&comp=metadata", "&comp=acl"} {
				resp, err := p.upstream.do(r.Context(), res.Name, http.MethodPut,
					path+update, h, nil)
				if err != nil {
					internalError(w, err)
					return
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					upstreamError(w, resp)
					return
				}
			}
		default:
			upstreamError(w, resp)
			return
		}
		c, ok := p.getContainer(w, r, res, name, path)
		if !ok {
			return
		}
		gateway.WriteJSON(w, status, c)
	case http.MethodGet:
		c, ok := p.getContainer(w, r, res, name, path)
		if !ok {
			return
		}
		gateway.WriteJSON(w, http.StatusOK, c)
	case http.MethodDelete:
		resp, err := p.upstream.do(r.Context(), res.Name, http.MethodDelete, path, nil, nil)
		if err != nil {
			internalError(w, err)
			return
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusAccepted:
			w.WriteHeader(http.StatusOK)
		case http.StatusNotFound:
			w.WriteHeader(http.StatusNoContent)
		default:
			upstreamError(w, resp)
		}
	default:
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not supported on containers.")
	}
}

func (p *Provider) getContainer(w http.ResponseWriter, r *http.Request, res store.Resource,
	name, path string) (container, bool) {
	resp, err := p.upstream.do(r.Context(), res.Name, http.MethodGet, path, nil, nil)
	if err != nil {
		internalError(w, err)
		return container{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		azerr.WriteError(w, http.StatusNotFound, "ContainerNotFound",
			"The specified container does not exist.")
		return container{}, false
	}
	if resp.StatusCode != http.StatusOK {
		upstreamError(w, resp)
		return container{}, false
	}
	return containerFromHeaders(res.ID, name, resp.Header), true
}

// wipeContainers deletes every container of an account upstream, best
// effort, before the account itself goes: Azurite keeps data by account
// name, and a re-created account must not inherit it.
func (p *Provider) wipeContainers(r *http.Request, account string) {
	resp, err := p.upstream.do(r.Context(), account, http.MethodGet, "/?comp=list", nil, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var listing struct {
		Names []string `xml:"Containers>Container>Name"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return
	}
	for _, name := range listing.Names {
		resp, err := p.upstream.do(r.Context(), account, http.MethodDelete,
			"/"+url.PathEscape(name)+"?restype=container", nil, nil)
		if err == nil {
			resp.Body.Close()
		}
	}
}

// serveOtherService answers for the file, queue and table services of an
// account - services Armite does not serve - so that clients reading
// every service's properties (Terraform does, on every refresh) get a
// consistent "nothing configured" instead of a 404.
func (p *Provider) serveOtherService(w http.ResponseWriter, r *http.Request,
	id arm.ResourceID, kind string) {
	res, ok := p.accountOf(w, id)
	if !ok {
		return
	}
	kind = strings.ToLower(kind)
	typ := "Microsoft.Storage/storageAccounts/" + kind
	props := map[string]any{"cors": map[string]any{"corsRules": []any{}}}
	if kind == "fileservices" {
		props["shareDeleteRetentionPolicy"] = map[string]any{"enabled": false}
		props["protocolSettings"] = map[string]any{"smb": map[string]any{}}
	}
	if r.Method == http.MethodPut || r.Method == http.MethodPatch {
		var body struct {
			Properties map[string]any `json:"properties"`
		}
		if !readBody(w, r, &body) {
			return
		}
		for k, v := range body.Properties {
			props[k] = v
		}
	} else if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on "+kind+".")
		return
	}
	item := map[string]any{"id": res.ID + "/" + kind + "/default", "name": "default", "type": typ,
		"properties": props}
	if id.IsInstance() {
		gateway.WriteJSON(w, http.StatusOK, item)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, map[string]any{"value": []any{item}})
}
