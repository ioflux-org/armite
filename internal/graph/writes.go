package graph

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/directory"
	"github.com/ioflux-org/armite/internal/gateway"
)

// decode reads a JSON body into v. A missing body is an empty object,
// as Graph treats it; anything unreadable is answered here with 400.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v)
	if err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "Request_BadRequest",
			"Unable to read JSON request payload: "+err.Error())
		return false
	}
	return true
}

// target resolves {collection}/{key} to a directory object, or answers
// 404 itself.
func (p *Plane) target(w http.ResponseWriter, r *http.Request) (directory.Object, bool) {
	kind, ok := collections[r.PathValue("collection")]
	if !ok {
		notFound(w, r.PathValue("collection"))
		return directory.Object{}, false
	}
	o, ok := p.lookup(kind, r.PathValue("key"))
	if !ok {
		notFound(w, r.PathValue("key"))
		return directory.Object{}, false
	}
	return o, true
}

// serveCreate is POST on a collection: an application (az sends a
// displayName; the appId is ours to assign) or the service principal
// of an existing application (az sends the appId; the name comes from
// the application). Users and groups are not served yet.
func (p *Plane) serveCreate(w http.ResponseWriter, r *http.Request) {
	segment := r.PathValue("collection")
	kind, ok := collections[segment]
	if !ok {
		notFound(w, segment)
		return
	}
	var body struct {
		DisplayName    string `json:"displayName"`
		AppID          string `json:"appId"`
		AccountEnabled *bool  `json:"accountEnabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	o := directory.Object{Kind: kind, DisplayName: body.DisplayName, AccountEnabled: true}
	if body.AccountEnabled != nil {
		o.AccountEnabled = *body.AccountEnabled
	}
	conflict := "Another object with the same value for property appId already exists."
	switch kind {
	case directory.KindApplication:
		if body.DisplayName == "" {
			writeError(w, http.StatusBadRequest, "Request_BadRequest",
				"A value is required for property 'displayName' of resource 'Application'.")
			return
		}
	case directory.KindServicePrincipal:
		app, ok := p.dir.ByAppID(directory.KindApplication, body.AppID)
		if body.AppID == "" || !ok {
			writeError(w, http.StatusBadRequest, "Request_BadRequest",
				"The appId '"+body.AppID+"' of the service principal does not reference a valid application object.")
			return
		}
		o.AppID, o.DisplayName = app.AppID, app.DisplayName
		conflict = "The service principal cannot be created, updated, or restored because the " +
			"service principal name " + app.AppID + " is already in use."
	default:
		writeError(w, http.StatusNotImplemented, "NotImplemented",
			"Creating "+segment+" is not supported yet; see https://armite.cloud/divergences.")
		return
	}
	created, err := p.dir.Create(o)
	switch {
	case errors.Is(err, directory.ErrConflict):
		writeError(w, http.StatusConflict, "Request_MultipleObjectsWithSameKeyValue", conflict)
	case err != nil:
		internalError(w, err)
	default:
		gateway.WriteJSON(w, http.StatusCreated, wire(created))
	}
}

// serveUpdate is PATCH: only the properties the body names change,
// which is why the fields are pointers - nil means "not mentioned",
// and false or "" would otherwise be indistinguishable from it.
func (p *Plane) serveUpdate(w http.ResponseWriter, r *http.Request) {
	o, ok := p.target(w, r)
	if !ok {
		return
	}
	var body struct {
		DisplayName    *string `json:"displayName"`
		AccountEnabled *bool   `json:"accountEnabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.DisplayName != nil && *body.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "Request_BadRequest", "The displayName cannot be empty.")
		return
	}
	_, err := p.dir.Update(o.ID, func(o *directory.Object) error {
		if body.DisplayName != nil {
			o.DisplayName = *body.DisplayName
		}
		if body.AccountEnabled != nil {
			o.AccountEnabled = *body.AccountEnabled
		}
		return nil
	})
	if err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// serveDelete removes an object; an application takes its service
// principal with it. The identities armite.yaml declares are the way
// back in after any mistake, so Graph may change them but not delete
// them.
func (p *Plane) serveDelete(w http.ResponseWriter, r *http.Request) {
	o, ok := p.target(w, r)
	if !ok {
		return
	}
	if p.configured(o) {
		writeError(w, http.StatusForbidden, "Authorization_RequestDenied",
			"'"+o.DisplayName+"' is declared in the Armite configuration and cannot be deleted through Graph; remove it from armite.yaml.")
		return
	}
	if err := p.dir.Delete(o.ID); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// configured reports whether o belongs to an identity the configuration
// declares: a client's application or service principal, or the managed
// identity.
func (p *Plane) configured(o directory.Object) bool {
	if o.AppID == "" {
		return false
	}
	for _, c := range p.cfg.Clients {
		if strings.EqualFold(c.ID, o.AppID) {
			return true
		}
	}
	return strings.EqualFold(p.cfg.ManagedIdentity.ClientID, o.AppID)
}

// credentialTarget is target for the two kinds that have passwords.
func (p *Plane) credentialTarget(w http.ResponseWriter, r *http.Request, action string) (directory.Object, bool) {
	o, ok := p.target(w, r)
	if !ok {
		return directory.Object{}, false
	}
	if o.Kind != directory.KindApplication && o.Kind != directory.KindServicePrincipal {
		writeError(w, http.StatusBadRequest, "BadRequest", "Resource not found for the segment '"+action+"'.")
		return directory.Object{}, false
	}
	return o, true
}

// serveAddPassword creates a client secret and shows it, once: the
// response is the only place secretText ever appears. Without dates the
// credential starts now and lasts two years, Graph's default.
func (p *Plane) serveAddPassword(w http.ResponseWriter, r *http.Request) {
	o, ok := p.credentialTarget(w, r, "addPassword")
	if !ok {
		return
	}
	var body struct {
		PasswordCredential struct {
			DisplayName   string     `json:"displayName"`
			StartDateTime *time.Time `json:"startDateTime"`
			EndDateTime   *time.Time `json:"endDateTime"`
		} `json:"passwordCredential"`
	}
	if !decode(w, r, &body) {
		return
	}
	start := p.now().UTC().Truncate(time.Second)
	if t := body.PasswordCredential.StartDateTime; t != nil {
		start = t.UTC()
	}
	end := start.AddDate(2, 0, 0)
	if t := body.PasswordCredential.EndDateTime; t != nil {
		end = t.UTC()
	}
	if !end.After(start) {
		writeError(w, http.StatusBadRequest, "Request_BadRequest",
			"The endDateTime of a password credential must be after its startDateTime.")
		return
	}
	secret, cred, err := p.dir.AddPassword(o.ID, body.PasswordCredential.DisplayName, start, end)
	if err != nil {
		internalError(w, err)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context":      p.cfg.GraphBaseURL() + "/v1.0/$metadata#microsoft.graph.passwordCredential",
		"customKeyIdentifier": nil,
		"displayName":         cred.DisplayName,
		"endDateTime":         cred.End.UTC().Format(time.RFC3339),
		"hint":                cred.Hint,
		"keyId":               cred.KeyID,
		"secretText":          secret,
		"startDateTime":       cred.Start.UTC().Format(time.RFC3339),
	})
}

// serveRemovePassword deletes one credential by its keyId.
func (p *Plane) serveRemovePassword(w http.ResponseWriter, r *http.Request) {
	o, ok := p.credentialTarget(w, r, "removePassword")
	if !ok {
		return
	}
	var body struct {
		KeyID string `json:"keyId"`
	}
	if !decode(w, r, &body) {
		return
	}
	err := p.dir.RemovePassword(o.ID, body.KeyID)
	switch {
	case errors.Is(err, directory.ErrNotFound): // the object exists: it is the key that does not
		writeError(w, http.StatusBadRequest, "Request_BadRequest",
			"No password credential found with keyId '"+body.KeyID+"'.")
	case err != nil:
		internalError(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// internalError is the plane's own failure: logged with detail, told to
// the client without it.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("graph: %v", err)
	writeError(w, http.StatusInternalServerError, "Service_InternalServerError",
		"An internal error occurred in the directory.")
}
