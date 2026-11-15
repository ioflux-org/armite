// Package graph serves the Microsoft Graph subset Armite's directory
// needs: what az ad, az role assignment and the azuread Terraform
// provider send. One plane behind the graph host, every request with a
// token for the Graph audience. This file routes and answers reads.
package graph

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/directory"
	"github.com/ioflux-org/armite/internal/gateway"
)

// collections maps a Graph collection segment to the directory kind.
var collections = map[string]string{
	"applications":      directory.KindApplication,
	"servicePrincipals": directory.KindServicePrincipal,
	"users":             directory.KindUser,
	"groups":            directory.KindGroup,
}

// Plane is the Graph handler over the directory.
type Plane struct {
	cfg  config.Config
	dir  *directory.Store
	auth *gateway.Authenticator
	mux  *http.ServeMux
}

// New returns the plane. Tokens must carry the Graph audience Armite
// publishes; https://graph.microsoft.com is accepted too, for clients
// that hardcode it.
func New(cfg config.Config, dir *directory.Store, pub *rsa.PublicKey, now func() time.Time) *Plane {
	p := &Plane{cfg: cfg, dir: dir, mux: http.NewServeMux(),
		auth: gateway.NewAuthenticatorFor(cfg, pub, now, cfg.GraphAudience(), "https://graph.microsoft.com")}
	p.mux.HandleFunc("GET /v1.0/me", p.serveMe)
	p.mux.HandleFunc("POST /v1.0/directoryObjects/getByIds", p.serveGetByIds)
	p.mux.HandleFunc("GET /v1.0/{collection}", p.serveList)
	p.mux.HandleFunc("GET /v1.0/{collection}/{key}", p.serveGet)
	p.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Request_ResourceNotFound",
			"Resource not found for the segment '"+strings.Trim(r.URL.Path, "/")+"'.")
	})
	return p
}

// ServeHTTP authenticates, then routes. No Graph permission model: any
// principal with a token for this audience may use the directory
// (Azure would demand application permissions; see docs/divergences.md).
func (p *Plane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, fail := p.auth.Verify(r.Header.Get("Authorization")); fail.Code != "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="", authorization_uri="`+
			p.cfg.LoginBaseURL()+"/"+p.cfg.TenantID+`"`)
		writeError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", fail.Message)
		return
	}
	p.mux.ServeHTTP(w, r)
}

func (p *Plane) serveList(w http.ResponseWriter, r *http.Request) {
	segment := r.PathValue("collection")
	kind, ok := collections[segment]
	if !ok {
		notFound(w, segment)
		return
	}
	keep, err := parseFilter(r.URL.Query().Get("$filter"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Request_UnsupportedQuery", err.Error())
		return
	}
	objs := p.dir.List(kind, keep)
	out := make([]map[string]any, 0, len(objs))
	for _, o := range objs {
		out = append(out, wire(o))
	}
	gateway.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context": p.cfg.GraphBaseURL() + "/v1.0/$metadata#" + segment,
		"value":          out,
	})
}

func (p *Plane) serveGet(w http.ResponseWriter, r *http.Request) {
	kind, ok := collections[r.PathValue("collection")]
	if !ok {
		notFound(w, r.PathValue("collection"))
		return
	}
	o, ok := p.lookup(kind, r.PathValue("key"))
	if !ok {
		notFound(w, r.PathValue("key"))
		return
	}
	gateway.WriteJSON(w, http.StatusOK, wire(o))
}

// lookup resolves a key the way Graph does: an object id for every
// kind, a userPrincipalName for users.
func (p *Plane) lookup(kind, key string) (directory.Object, bool) {
	if o, ok := p.dir.Get(key); ok && o.Kind == kind {
		return o, true
	}
	if kind == directory.KindUser && strings.Contains(key, "@") {
		return p.dir.ByUPN(key)
	}
	return directory.Object{}, false
}

// serveGetByIds is how az names principals in a role assignment
// listing: object ids in, directory objects with their type out,
// unknown ids silently left out.
func (p *Plane) serveGetByIds(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Request_BadRequest", "The request body could not be read: "+err.Error())
		return
	}
	out := make([]map[string]any, 0, len(body.IDs))
	for _, id := range body.IDs {
		if o, ok := p.dir.PrincipalByID(id); ok {
			m := wire(o)
			m["@odata.type"] = "#microsoft.graph." + o.Kind
			out = append(out, m)
		}
	}
	gateway.WriteJSON(w, http.StatusOK, map[string]any{"value": out})
}

// serveMe answers as Graph does for an application token: /me needs a
// signed-in user, and client credentials have none.
func (p *Plane) serveMe(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusBadRequest, "BadRequest",
		"/me request is only valid with delegated authentication flow.")
}

// wire is the object as Graph returns it: the common fields, the
// kind's own, and credentials without their hashes.
func wire(o directory.Object) map[string]any {
	m := map[string]any{"id": o.ID, "displayName": o.DisplayName,
		"createdDateTime": o.Created.UTC().Format(time.RFC3339)}
	switch o.Kind {
	case directory.KindApplication:
		m["appId"] = o.AppID
		m["signInAudience"] = "AzureADMyOrg"
		m["passwordCredentials"] = credentials(o.Passwords)
		m["keyCredentials"] = []any{}
	case directory.KindServicePrincipal:
		m["appId"] = o.AppID
		m["appDisplayName"] = o.DisplayName
		m["accountEnabled"] = o.AccountEnabled
		m["servicePrincipalType"] = o.ServicePrincipalType
		m["servicePrincipalNames"] = []string{o.AppID}
		m["passwordCredentials"] = credentials(o.Passwords)
	case directory.KindUser:
		m["userPrincipalName"] = o.UserPrincipalName
		m["mailNickname"] = o.MailNickname
		m["accountEnabled"] = o.AccountEnabled
		m["userType"] = "Member"
	case directory.KindGroup:
		m["mailNickname"] = o.MailNickname
		m["mailEnabled"] = o.MailEnabled
		m["securityEnabled"] = o.SecurityEnabled
		m["groupTypes"] = []any{}
	}
	return m
}

func credentials(ps []directory.Password) []map[string]any {
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, map[string]any{
			"keyId": p.KeyID, "displayName": p.DisplayName, "hint": p.Hint,
			"startDateTime": p.Start.UTC().Format(time.RFC3339), "endDateTime": p.End.UTC().Format(time.RFC3339),
			"secretText": nil, "customKeyIdentifier": nil,
		})
	}
	return out
}
