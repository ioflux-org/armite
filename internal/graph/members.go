package graph

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ioflux-org/armite/internal/directory"
	"github.com/ioflux-org/armite/internal/gateway"
)

// group resolves groups/{key}, or answers 404 itself.
func (p *Plane) group(w http.ResponseWriter, r *http.Request) (directory.Object, bool) {
	g, ok := p.lookup(directory.KindGroup, r.PathValue("key"))
	if !ok {
		notFound(w, r.PathValue("key"))
	}
	return g, ok
}

// serveMembers lists what a group contains: members is the direct
// list, transitiveMembers also opens the groups inside it.
func (p *Plane) serveMembers(w http.ResponseWriter, r *http.Request) {
	g, ok := p.group(w, r)
	if !ok {
		return
	}
	members, _ := p.dir.Members(g.ID, strings.HasSuffix(r.URL.Path, "/transitiveMembers"))
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		out = append(out, typed(m))
	}
	gateway.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context": p.cfg.GraphBaseURL() + "/v1.0/$metadata#directoryObjects",
		"value":          out,
	})
}

// serveAddMember is POST members/$ref: the body names the new member by
// URL, {"@odata.id": ".../directoryObjects/{id}"}, and only the last
// segment matters.
func (p *Plane) serveAddMember(w http.ResponseWriter, r *http.Request) {
	g, ok := p.group(w, r)
	if !ok {
		return
	}
	var body struct {
		Ref string `json:"@odata.id"`
	}
	if !decode(w, r, &body) {
		return
	}
	ref := strings.TrimRight(body.Ref, "/")
	id := ref[strings.LastIndexByte(ref, '/')+1:]
	if id == "" {
		writeError(w, http.StatusBadRequest, "Request_BadRequest",
			"The request body must name the member: {\"@odata.id\": \".../directoryObjects/{id}\"}.")
		return
	}
	err := p.dir.AddMember(g.ID, id)
	switch {
	case errors.Is(err, directory.ErrNotFound): // the group exists: it is the member that does not
		notFound(w, id)
	case errors.Is(err, directory.ErrConflict):
		writeError(w, http.StatusBadRequest, "Request_BadRequest",
			"One or more added object references already exist for the following modified properties: 'members'.")
	case errors.Is(err, directory.ErrSelfMember):
		writeError(w, http.StatusBadRequest, "Request_BadRequest", "A group cannot be added as a member of itself.")
	case err != nil:
		internalError(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// serveRemoveMember is DELETE members/{id}/$ref.
func (p *Plane) serveRemoveMember(w http.ResponseWriter, r *http.Request) {
	g, ok := p.group(w, r)
	if !ok {
		return
	}
	err := p.dir.RemoveMember(g.ID, r.PathValue("member"))
	switch {
	case errors.Is(err, directory.ErrNotFound):
		notFound(w, r.PathValue("member"))
	case err != nil:
		internalError(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// principal resolves {collection}/{key} to a user, a group or a service
// principal for a membership question; directoryObjects/{id} names any
// of them. Applications are in no group: for them the action does not
// exist, which is how Graph puts it.
func (p *Plane) principal(w http.ResponseWriter, r *http.Request, action string) (directory.Object, bool) {
	segment, key := r.PathValue("collection"), r.PathValue("key")
	if segment == "directoryObjects" {
		o, ok := p.dir.PrincipalByID(key)
		if !ok {
			notFound(w, key)
		}
		return o, ok
	}
	kind, known := collections[segment]
	switch {
	case !known:
		notFound(w, segment)
	case kind == directory.KindApplication:
		writeError(w, http.StatusBadRequest, "BadRequest", "Resource not found for the segment '"+action+"'.")
	default:
		o, ok := p.lookup(kind, key)
		if !ok {
			notFound(w, key)
		}
		return o, ok
	}
	return directory.Object{}, false
}

// serveCheckMemberGroups answers which of the given groups the
// principal is in, through any depth of nesting.
func (p *Plane) serveCheckMemberGroups(w http.ResponseWriter, r *http.Request) {
	o, ok := p.principal(w, r, "checkMemberGroups")
	if !ok {
		return
	}
	var body struct {
		GroupIDs []string `json:"groupIds"`
	}
	if !decode(w, r, &body) {
		return
	}
	in := make(map[string]bool)
	for _, id := range p.dir.TransitiveGroupIDs(o.ID) {
		in[strings.ToLower(id)] = true
	}
	out := make([]string, 0)
	for _, id := range body.GroupIDs {
		if in[strings.ToLower(id)] {
			out = append(out, id)
		}
	}
	p.writeIDs(w, out)
}

// serveGetMemberGroups lists every group the principal is in, through
// any depth of nesting; securityEnabledOnly keeps the security groups.
func (p *Plane) serveGetMemberGroups(w http.ResponseWriter, r *http.Request) {
	o, ok := p.principal(w, r, "getMemberGroups")
	if !ok {
		return
	}
	var body struct {
		SecurityEnabledOnly bool `json:"securityEnabledOnly"`
	}
	if !decode(w, r, &body) {
		return
	}
	out := make([]string, 0)
	for _, g := range p.dir.GroupsOf(o.ID, true) {
		if g.SecurityEnabled || !body.SecurityEnabledOnly {
			out = append(out, g.ID)
		}
	}
	p.writeIDs(w, out)
}

func (p *Plane) writeIDs(w http.ResponseWriter, ids []string) {
	gateway.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context": p.cfg.GraphBaseURL() + "/v1.0/$metadata#Collection(Edm.String)",
		"value":          ids,
	})
}
