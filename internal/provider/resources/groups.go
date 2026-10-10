package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ioflux-org/armite/internal/arm"
	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/store"
)

const (
	groupType = "Microsoft.Resources/resourceGroups"

	// provisioned is the only provisioningState a synchronous provider
	// ever shows: by the time the response is written, the work is done.
	provisioned = `{"provisioningState":"Succeeded"}`

	// maxBodyBytes bounds a PUT body. A resource group is a location and
	// some tags; anything near this size is not a resource group.
	maxBodyBytes = 1 << 20
)

// groupNameRe is ARM's rule for resource group names: letters, digits,
// underscore, hyphen, period and parentheses, at most 90 characters.
// "Must not end in a period" is checked separately.
var groupNameRe = regexp.MustCompile(`^[-\p{L}\p{N}_.()]{1,90}$`)

func validGroupName(name string) bool {
	return groupNameRe.MatchString(name) && !strings.HasSuffix(name, ".")
}

// groupBody is what a client sends on PUT or PATCH. Unknown fields
// (properties, managedBy) are ignored, as real ARM ignores what it does
// not model. Tags is a pointer so a PATCH can tell "no tags field" (keep
// them) from "tags": {} (remove them all).
type groupBody struct {
	Location string             `json:"location"`
	Tags     *map[string]string `json:"tags"`
}

// serveGroup handles one resource group: PUT, PATCH, GET, HEAD, DELETE.
// POST never arrives - DeriveAction rejects it on an instance.
func (p *Provider) serveGroup(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	switch r.Method {
	case http.MethodPut:
		p.putGroup(w, r, id)
	case http.MethodPatch:
		p.patchGroup(w, r, id)
	case http.MethodGet:
		p.getGroup(w, id)
	case http.MethodHead:
		p.headGroup(w, id)
	case http.MethodDelete:
		p.deleteGroup(w, id)
	default:
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not supported on resource groups yet.")
	}
}

// serveGroups handles the collection: GET lists the subscription's groups.
func (p *Provider) serveGroups(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on the resource group collection.")
		return
	}
	groups, err := p.store.List("/subscriptions/"+id.Names[0], groupType)
	if err != nil {
		internalError(w, err)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []store.Resource `json:"value"`
	}{groups})
}

// putGroup creates or replaces a group: 201 on create, 200 on replace.
// Real ARM keeps the name casing from creation and refuses to move a
// group to another location; both are honored here. PUT replaces the
// whole group, so tags omitted from the body are tags removed.
func (p *Provider) putGroup(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	name := id.Names[1]
	if !validGroupName(name) {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidResourceGroupName,
			fmt.Sprintf("Resource group name '%s' is invalid. Valid names consist of letters, "+
				"digits, underscores, hyphens, periods, and parentheses, must not end in a "+
				"period, and may be up to 90 characters long.", name))
		return
	}
	var body groupBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&body); err != nil {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid and could not be deserialized: "+err.Error())
		return
	}
	if body.Location == "" {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeLocationRequired,
			"The location property is required for this definition.")
		return
	}

	res := store.Resource{
		ID:         id.String(),
		Name:       name,
		Type:       groupType,
		Location:   body.Location,
		Properties: json.RawMessage(provisioned),
	}
	if body.Tags != nil {
		res.Tags = *body.Tags
	}

	existing, err := p.store.Get(res.ID)
	switch {
	case err == nil:
		if !strings.EqualFold(existing.Location, body.Location) {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidResourceGroupLocation,
				fmt.Sprintf("Invalid resource group location '%s'. The Resource group already "+
					"exists in location '%s'.", body.Location, existing.Location))
			return
		}
		res.ID, res.Name, res.Location = existing.ID, existing.Name, existing.Location

	case errors.Is(err, store.ErrNotFound):
		// First PUT: create.
	default:
		internalError(w, err)
		return
	}
	created, err := p.store.Put(res)
	if err != nil {
		internalError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	gateway.WriteJSON(w, status, res)
}

// patchGroup updates a group in place: a field in the body replaces the
// group's, a field absent from the body is kept - ARM's rule for
// resource groups, and what Terraform does for a tag change (PATCH with
// the full tag set, nothing else). The location cannot change; one sent
// in the body is ignored. The group must exist: PATCH never creates.
func (p *Provider) patchGroup(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	res, err := p.store.Get(id.String())
	if err != nil {
		groupLookupError(w, id, err)
		return
	}
	var body groupBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&body); err != nil {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid and could not be deserialized: "+err.Error())
		return
	}
	if body.Tags != nil {
		res.Tags = *body.Tags
	}
	if _, err := p.store.Put(res); err != nil {
		internalError(w, err)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, res)
}

func (p *Provider) getGroup(w http.ResponseWriter, id arm.ResourceID) {
	res, err := p.store.Get(id.String())
	if err != nil {
		groupLookupError(w, id, err)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, res)
}

// headGroup is ARM's existence check: 204 when the group exists, 404
// when it does not, never a body.
func (p *Provider) headGroup(w http.ResponseWriter, id arm.ResourceID) {
	_, err := p.store.Get(id.String())
	if err != nil {
		groupLookupError(w, id, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteGroup answers synchronously and takes the group's contents with
// it, as real ARM does. Real ARM returns 202 and a Location header to
// poll; SDK and az pollers treat an immediate 200 as done.
func (p *Provider) deleteGroup(w http.ResponseWriter, id arm.ResourceID) {
	children, err := p.store.List(id.String(), "")
	if err != nil {
		internalError(w, err)
		return
	}
	for _, child := range children {
		if _, err := p.store.Delete(child.ID); err != nil {
			internalError(w, err)
			return
		}
	}
	deleted, err := p.store.Delete(id.String())
	if !deleted {
		groupLookupError(w, id, store.ErrNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// groupLookupError maps a store error on a group lookup to the ARM
// response: ErrNotFound is the client's 404, anything else is ours.
func groupLookupError(w http.ResponseWriter, id arm.ResourceID, err error) {
	if errors.Is(err, store.ErrNotFound) {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceGroupNotFound,
			fmt.Sprintf("Resource group '%s' could not be found.", id.Names[1]))
		return
	}
	internalError(w, err)
}
