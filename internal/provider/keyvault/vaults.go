package keyvault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ioflux-org/provisio/internal/arm"
	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/store"
)

const (
	vaultType = "Microsoft.KeyVault/vaults"

	// maxBodyBytes bounds a PUT body; a vault definition is small.
	maxBodyBytes = 1 << 20
)

// vaultNameRe is the documented rule: 3 to 24 characters of letters,
// digits and hyphens, starting with a letter and ending with a letter
// or digit. "No consecutive hyphens" is checked separately.
var vaultNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$`)

func validVaultName(name string) bool {
	return vaultNameRe.MatchString(name) && !strings.Contains(name, "--")
}

// groupScopeRe matches the only scope a vault can live under.
var groupScopeRe = regexp.MustCompile(`(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+$`)

func groupName(scope string) string {
	return scope[strings.LastIndexByte(scope, '/')+1:]
}

// vault is the management-plane Vault resource. Tags are always
// present, empty or not: az keyvault update --set tags.x=y edits the
// object it read back, and a missing key gives it nothing to edit.
// Spec: keyvault mgmt 2025-05-01 openapi.json#/definitions/Vault
// (allOf common-types v5 ProxyResource: id, name, type; required: properties)
type vault struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties vaultProperties   `json:"properties"`
}

// vaultRequest is the PUT body.
// Spec: keyvault mgmt 2025-05-01 openapi.json#/definitions/VaultCreateOrUpdateParameters
// (required: location, properties)
type vaultRequest struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties *vaultProperties  `json:"properties"`
}

// sku is the vault SKU.
// Spec: keyvault mgmt 2025-05-01 openapi.json#/definitions/Sku (required: family, name)
type sku struct {
	Family string `json:"family"` // Spec: enum A
	Name   string `json:"name"`   // Spec: enum standard, premium
}

// vaultProperties is the vault's property bag. Optional booleans are
// pointers so that "absent" and "false" round-trip as the client sent
// them; unknown fields are dropped, as real ARM drops what it does not
// model. networkAcls is echoed verbatim: nothing enforces it.
// Spec: keyvault mgmt 2025-05-01 openapi.json#/definitions/VaultProperties
// (required: tenantId, sku)
type vaultProperties struct {
	TenantID                     string            `json:"tenantId"`
	Sku                          sku               `json:"sku"`
	AccessPolicies               []json.RawMessage `json:"accessPolicies"`
	VaultURI                     string            `json:"vaultUri,omitempty"`
	EnabledForDeployment         *bool             `json:"enabledForDeployment,omitempty"`
	EnabledForDiskEncryption     *bool             `json:"enabledForDiskEncryption,omitempty"`
	EnabledForTemplateDeployment *bool             `json:"enabledForTemplateDeployment,omitempty"`
	EnableSoftDelete             *bool             `json:"enableSoftDelete,omitempty"`
	SoftDeleteRetentionInDays    *int              `json:"softDeleteRetentionInDays,omitempty"`
	EnableRbacAuthorization      *bool             `json:"enableRbacAuthorization,omitempty"`
	EnablePurgeProtection        *bool             `json:"enablePurgeProtection,omitempty"`
	NetworkAcls                  json.RawMessage   `json:"networkAcls,omitempty"`
	// ProvisioningState - Spec: enum Succeeded, RegisteringDns.
	ProvisioningState   string `json:"provisioningState,omitempty"`
	PublicNetworkAccess string `json:"publicNetworkAccess,omitempty"`
}

// serveVaults lists the vaults below the request's scope: the group or
// the whole subscription, whichever the path named.
func (p *Provider) serveVaults(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on the vault collection.")
		return
	}
	all, err := p.store.List(id.Scope, vaultType)
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]vault, 0, len(all))
	for _, res := range all {
		v, err := toVault(res)
		if err != nil {
			internalError(w, err)
			return
		}
		out = append(out, v)
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []vault `json:"value"`
	}{out})
}

// serveVault handles one vault: PUT, GET, DELETE. PATCH is deferred; az
// keyvault update does GET + PUT and never sends it.
func (p *Provider) serveVault(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	switch r.Method {
	case http.MethodPut:
		p.putVault(w, r, id)
	case http.MethodGet:
		res, err := p.store.Get(id.String())
		if err != nil {
			vaultLookupError(w, id, err)
			return
		}
		v, err := toVault(res)
		if err != nil {
			internalError(w, err)
			return
		}
		gateway.WriteJSON(w, http.StatusOK, v)
	case http.MethodDelete:
		p.deleteVault(w, id)
	default:
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not supported on vaults yet.")
	}
}

// putVault creates or replaces a vault: 201 on create, 200 on replace.
// The group must exist, the name must be valid and free everywhere
// (vault hostnames are global), and an existing vault keeps its
// location. Access policies are accepted and echoed but never enforced:
// Provisio authorizes the data plane by RBAC alone.
func (p *Provider) putVault(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	name := id.Names[0]
	if !groupScopeRe.MatchString(id.Scope) {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"A vault must be created inside a resource group.")
		return
	}
	if !validVaultName(name) {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeVaultNameNotValid,
			fmt.Sprintf("The vault name '%s' is invalid. A vault's name must be between 3-24 "+
				"alphanumeric characters. The name must begin with a letter, end with a letter "+
				"or digit, and not contain consecutive hyphens.", name))

		return
	}
	if _, err := p.store.Get(id.Scope); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceGroupNotFound,
				"Resource group '"+groupName(id.Scope)+"' could not be found.")
			return
		}
		internalError(w, err)
		return
	}
	var body vaultRequest
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
	if body.Properties == nil {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid: properties is required.")
		return
	}
	props := body.Properties
	if !strings.EqualFold(props.TenantID, p.cfg.TenantID) {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid: properties.tenantId must be '"+p.cfg.TenantID+"'.")
		return
	}
	skuName := strings.ToLower(props.Sku.Name)
	if !strings.EqualFold(props.Sku.Family, "A") || (skuName != "standard" && skuName != "premium") {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid: properties.sku must have family 'A' and "+
				"name 'standard' or 'premium'.")
		return
	}
	resID := id.String()
	existing, err := p.store.Get(resID)
	switch {
	case err == nil:
		if !strings.EqualFold(existing.Location, body.Location) {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
				"The location of an existing vault cannot be changed.")
			return
		}
		resID, name, body.Location = existing.ID, existing.Name, existing.Location
	case errors.Is(err, store.ErrNotFound):
		if p.nameTaken(name) {
			azerr.WriteError(w, http.StatusConflict, azerr.CodeVaultAlreadyExists,
				"The vault name '"+name+"' is already in use. Vault names are globally unique "+
					"so it is possible that the name is already taken.")
			return
		}
	default:
		internalError(w, err)
		return
	}
	p.complete(props, name)
	raw, err := json.Marshal(props)
	if err != nil {
		internalError(w, err)
		return
	}
	res := store.Resource{
		ID: resID, Name: name, Type: vaultType,
		Location: body.Location, Tags: body.Tags, Properties: raw,
	}
	created, err := p.store.Put(res)
	if err != nil {
		internalError(w, err)
		return
	}
	v, err := toVault(res)
	if err != nil {
		internalError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	gateway.WriteJSON(w, status, v)
}

// nameTaken reports whether any vault in the subscription already has
// this name, whatever its group.
func (p *Provider) nameTaken(name string) bool {
	all, err := p.store.List("/", vaultType)
	if err != nil {
		return false
	}
	for _, res := range all {
		if strings.EqualFold(res.Name, name) {
			return true
		}
	}
	return false
}

// complete fills what the service decides: the URI, the state, and
// the defaults real ARM applies to omitted properties.
func (p *Provider) complete(props *vaultProperties, name string) {
	props.VaultURI = p.cfg.VaultURI(name)
	props.ProvisioningState = "Succeeded"
	props.Sku.Family = "A"
	props.Sku.Name = strings.ToLower(props.Sku.Name)
	if props.AccessPolicies == nil {
		props.AccessPolicies = []json.RawMessage{}
	}
	if props.EnableSoftDelete == nil {
		props.EnableSoftDelete = new(true)
	}
	if props.SoftDeleteRetentionInDays == nil {
		props.SoftDeleteRetentionInDays = new(90)
	}
	if props.PublicNetworkAccess == "" {
		props.PublicNetworkAccess = "Enabled"
	}
}

// deleteVault answers 200 when a vault was removed and 204 when there
// was none: deletes are idempotent, and vault soft delete is not
// emulated, so nothing lingers.
func (p *Provider) deleteVault(w http.ResponseWriter, id arm.ResourceID) {
	deleted, err := p.store.Delete(id.String())
	if err != nil {
		internalError(w, err)
		return
	}
	if !deleted {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// toVault rebuilds the wire shape from the stored envelope.
func toVault(res store.Resource) (vault, error) {
	var props vaultProperties
	if err := json.Unmarshal(res.Properties, &props); err != nil {
		return vault{}, fmt.Errorf("stored vault %s: %w", res.ID, err)
	}
	tags := res.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	return vault{
		ID: res.ID, Name: res.Name, Type: res.Type,
		Location: res.Location, Tags: tags, Properties: props,
	}, nil
}

// vaultLookupError maps a store error on a vault lookup to the ARM
// response, with ARM's own wording for a missing provider resource.
func vaultLookupError(w http.ResponseWriter, id arm.ResourceID, err error) {
	if errors.Is(err, store.ErrNotFound) {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			fmt.Sprintf("The Resource 'Microsoft.KeyVault/vaults/%s' under resource group '%s' "+
				"was not found. For more details please go to https://aka.ms/ARMResourceNotFoundFix",
				id.Names[0], groupName(id.Scope)))
		return
	}
	internalError(w, err)
}
