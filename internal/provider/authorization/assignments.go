package authorization

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/rbac"
)

// maxBodyBytes bounds a PUT body: three properties, never more.
const maxBodyBytes = 1 << 20

// assignmentRequest is the PUT body az and the SDKs send.
type assignmentRequest struct {
	Properties struct {
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		PrincipalType    string `json:"principalType"`
	} `json:"properties"`
}

// assignment is the Role Assignments API resource (api-version 2022-04-01).
type assignment struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Type       string               `json:"type"`
	Properties assignmentProperties `json:"properties"`
}

type assignmentProperties struct {
	RoleDefinitionID string    `json:"roleDefinitionId"`
	PrincipalID      string    `json:"principalId"`
	PrincipalType    string    `json:"principalType"`
	Scope            string    `json:"scope"`
	CreatedOn        time.Time `json:"createdOn"`
	UpdatedOn        time.Time `json:"updatedOn"`
}

// toAssignment maps a stored assignment to the wire. Assignments are
// immutable, so updatedOn is createdOn; both are emitted in UTC, as real
// ARM does, whatever clock stamped them.
func toAssignment(a rbac.RoleAssignment) assignment {
	return assignment{
		ID:   a.ID,
		Name: a.Name,
		Type: "Microsoft.Authorization/roleAssignments",
		Properties: assignmentProperties{
			RoleDefinitionID: definitionID(a.Scope, a.RoleDefinitionID),
			PrincipalID:      a.PrincipalID,
			PrincipalType:    a.PrincipalType,
			Scope:            a.Scope,
			CreatedOn:        a.CreatedOn.UTC(),
			UpdatedOn:        a.CreatedOn.UTC(),
		},
	}
}

// serveAssignments handles the collection (GET with $filter) and one
// assignment (PUT, GET, DELETE).
func (p *Provider) serveAssignments(w http.ResponseWriter, r *http.Request, rt gateway.Route) {
	id := rt.ID
	if !id.IsInstance() {
		if r.Method != http.MethodGet {
			azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
				"The method '"+r.Method+"' is not allowed on the role assignment collection.")
			return
		}
		p.listAssignments(w, r, id.Scope)
		return
	}
	name := id.Names[0]
	switch r.Method {
	case http.MethodPut:
		p.putAssignment(w, r, id.Scope, name)
	case http.MethodGet:
		a, err := p.store.Get(name)
		if err != nil || !sameScope(a.Scope, id.Scope) {
			p.assignmentLookupError(w, name, err)
			return
		}
		gateway.WriteJSON(w, http.StatusOK, toAssignment(a))
	case http.MethodDelete:
		p.deleteAssignment(w, id.Scope, name)
	default:
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on a role assignment.")
	}
}

// putAssignment creates an assignment named by the client. Assignments
// are immutable: a second PUT with the same name and properties is the
// same assignment (201 again); with different properties it is refused.
// The same grant under another name is ARM's 409.
func (p *Provider) putAssignment(w http.ResponseWriter, r *http.Request, scope, name string) {
	var body assignmentRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&body); err != nil {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid and could not be deserialized: "+err.Error())
		return
	}
	props := body.Properties
	if props.RoleDefinitionID == "" || props.PrincipalID == "" {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid: properties.roleDefinitionId and "+
				"properties.principalId are required.")
		return
	}
	guid := strings.ToLower(lastSegment(props.RoleDefinitionID))
	if _, ok := p.defs[guid]; !ok {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeRoleDefinitionDoesNotExist,
			"The specified role definition with ID '"+props.RoleDefinitionID+"' does not exist.")
		return
	}
	if !p.knownPrincipal(props.PrincipalID) {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodePrincipalNotFound,
			"Principal "+props.PrincipalID+" does not exist in the directory "+p.cfg.TenantID+".")
		return
	}
	principalType := props.PrincipalType
	if principalType == "" {
		principalType = "ServicePrincipal"
	}

	a := rbac.RoleAssignment{
		Name:             name,
		PrincipalID:      props.PrincipalID,
		PrincipalType:    principalType,
		RoleDefinitionID: guid,
		Scope:            scope,
		CreatedOn:        p.now().UTC(),
	}
	err := p.store.Add(a)
	switch {
	case err == nil:
		// Created. Read it back: Add canonicalized it and set its ID.
	case errors.Is(err, rbac.ErrAssignmentNameTaken):
		existing, gerr := p.store.Get(name)
		if gerr != nil {
			internalError(w, gerr)
			return
		}
		same := strings.EqualFold(existing.PrincipalID, a.PrincipalID) &&
			existing.RoleDefinitionID == guid && sameScope(existing.Scope, scope)
		if !same {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeRoleAssignmentUpdateNotPermitted,
				"Role assignment '"+name+"' already exists with different properties; "+
					"role assignments cannot be updated.")
			return
		}
	case errors.Is(err, rbac.ErrAssignmentExists):
		azerr.WriteError(w, http.StatusConflict, azerr.CodeRoleAssignmentExists,
			"The role assignment already exists.")
		return
	default:
		internalError(w, err)
		return
	}
	stored, err := p.store.Get(name)
	if err != nil {
		internalError(w, err)
		return
	}
	gateway.WriteJSON(w, http.StatusCreated, toAssignment(stored))
}

// deleteAssignment answers 200 with the revoked assignment, or 204 when
// there was nothing to revoke: deletes are idempotent.
func (p *Provider) deleteAssignment(w http.ResponseWriter, scope, name string) {
	a, err := p.store.Get(name)
	if errors.Is(err, rbac.ErrAssignmentNotFound) || (err == nil && !sameScope(a.Scope, scope)) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	deleted, err := p.store.Delete(name)
	if err != nil {
		internalError(w, err)
		return
	}
	gateway.WriteJSON(w, http.StatusOK, toAssignment(deleted))
}

// assignmentLookupError maps a failed GET: not found (or found under
// another scope) is the client's 404, anything else is ours.
func (p *Provider) assignmentLookupError(w http.ResponseWriter, name string, err error) {
	if err == nil || errors.Is(err, rbac.ErrAssignmentNotFound) {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeRoleAssignmentNotFound,
			"The role assignment '"+name+"' was not found.")
		return
	}
	internalError(w, err)
}

// assignmentFilterRe accepts the terms az combines with "and":
// atScope(), principalId eq '…' and assignedTo('…') (which would also
// expand groups; Armite has none, so it is principalId eq).
var (
	andRe          = regexp.MustCompile(`(?i)\s+and\s+`)
	principalEqRe  = regexp.MustCompile(`(?i)^principalId\s+eq\s+'([^']*)'$`)
	assignedToRe   = regexp.MustCompile(`(?i)^assignedTo\('([^']*)'\)$`)
	atScopeLiteral = "atscope()"
)

// parseAssignmentFilter returns whether descendants are excluded and
// which principal to keep ("" for all). ok is false for a filter
// Armite does not understand.
func parseAssignmentFilter(filter string) (atScope bool, principal string, ok bool) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return false, "", true
	}
	for _, term := range andRe.Split(filter, -1) {
		switch {
		case strings.ToLower(term) == atScopeLiteral:
			atScope = true
		case principalEqRe.MatchString(term):
			principal = principalEqRe.FindStringSubmatch(term)[1]
		case assignedToRe.MatchString(term):
			principal = assignedToRe.FindStringSubmatch(term)[1]
		default:
			return false, "", false
		}
	}
	return atScope, principal, true
}

// listAssignments is ARM's ListForScope: everything at, above and below
// the scope, narrowed by $filter.
func (p *Provider) listAssignments(w http.ResponseWriter, r *http.Request, scope string) {
	filter := r.URL.Query().Get("$filter")
	atScope, principal, ok := parseAssignmentFilter(filter)
	if !ok {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidFilter,
			"The filter '"+filter+"' is not supported. Use atScope(), principalId eq '…' "+
				"or assignedTo('…').")
		return
	}
	all, err := p.store.List(scope, atScope)
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]assignment, 0, len(all))
	for _, a := range all {
		if principal != "" && !strings.EqualFold(a.PrincipalID, principal) {
			continue
		}
		out = append(out, toAssignment(a))
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []assignment `json:"value"`
	}{out})
}
