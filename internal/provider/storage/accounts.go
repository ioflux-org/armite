package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ioflux-org/provisio/internal/arm"
	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/store"
)

const (
	accountType = "Microsoft.Storage/storageAccounts"

	// maxBodyBytes bounds a PUT body; an account definition is small.
	maxBodyBytes = 1 << 20
)

// accountNameRe is Azure's rule: 3 to 24 lowercase letters and digits.
var accountNameRe = regexp.MustCompile(`^[a-z0-9]{3,24}$`)

// groupScopeRe matches the only scope an account can live under.
var groupScopeRe = regexp.MustCompile(`(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+$`)

// sku is the account SKU; the tier follows from the name.
type sku struct {
	Name string `json:"name"`
	Tier string `json:"tier,omitempty"`
}

// accountRequest is the PUT (and PATCH) body. Properties stay a map:
// the account has dozens of them, clients read back what they sent,
// and only a handful matter to the emulator.
type accountRequest struct {
	Location   string                     `json:"location"`
	Tags       map[string]string          `json:"tags"`
	Sku        *sku                       `json:"sku"`
	Kind       string                     `json:"kind"`
	Identity   json.RawMessage            `json:"identity,omitempty"`
	Properties map[string]json.RawMessage `json:"properties"`
}

// stored is what the resource store keeps in Properties: everything of
// the wire shape that is not in the common envelope.
type stored struct {
	Sku         sku                        `json:"sku"`
	Kind        string                     `json:"kind"`
	Identity    json.RawMessage            `json:"identity,omitempty"`
	Properties  map[string]json.RawMessage `json:"properties"`
	BlobService map[string]json.RawMessage `json:"blobService,omitempty"`
}

// account is the wire shape.
type account struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Type       string                     `json:"type"`
	Location   string                     `json:"location"`
	Tags       map[string]string          `json:"tags"`
	Sku        sku                        `json:"sku"`
	Kind       string                     `json:"kind"`
	Identity   json.RawMessage            `json:"identity,omitempty"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// readBody decodes a bounded JSON request body into v. An empty body is
// fine (the caller's validation names what is missing); malformed JSON
// is answered here with ARM's InvalidRequestContent, and false returned.
func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"The request content was invalid and could not be deserialized: "+err.Error())
		return false
	}
	return true
}

// defaults are the properties real ARM fills in for an omitted field, so
// a bare PUT reads back as a complete account. Only the blob endpoint is
// advertised: nothing serves queues, tables or files.
func (p *Provider) defaults(name, location string, created time.Time) map[string]json.RawMessage {
	t := created.UTC().Format(time.RFC3339)
	return map[string]json.RawMessage{
		"provisioningState":            raw("Succeeded"),
		"creationTime":                 raw(t),
		"primaryLocation":              raw(location),
		"statusOfPrimary":              raw("available"),
		"primaryEndpoints":             raw(map[string]string{"blob": p.cfg.BlobURI(name)}),
		"supportsHttpsTrafficOnly":     raw(true),
		"minimumTlsVersion":            raw("TLS1_2"),
		"allowBlobPublicAccess":        raw(false),
		"allowSharedKeyAccess":         raw(true),
		"allowCrossTenantReplication":  raw(false),
		"defaultToOAuthAuthentication": raw(false),
		"publicNetworkAccess":          raw("Enabled"),
		"accessTier":                   raw("Hot"),
		"isHnsEnabled":                 raw(false),
		"isNfsV3Enabled":               raw(false),
		"isSftpEnabled":                raw(false),
		"isLocalUserEnabled":           raw(false),
		"dnsEndpointType":              raw("Standard"),
		"keyCreationTime":              raw(map[string]string{"key1": t, "key2": t}),
		"networkAcls": raw(map[string]any{"bypass": "AzureServices", "defaultAction": "Allow",
			"virtualNetworkRules": []any{}, "ipRules": []any{}}),
		"encryption": raw(map[string]any{
			"keySource":                       "Microsoft.Storage",
			"requireInfrastructureEncryption": false,
			"services": map[string]any{
				"blob": map[string]any{"enabled": true, "keyType": "Account", "lastEnabledTime": t},
				"file": map[string]any{"enabled": true, "keyType": "Account", "lastEnabledTime": t},
			},
		}),
	}
}

// serveAccounts handles the collection: GET lists the subscription's or
// the group's accounts.
func (p *Provider) serveAccounts(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on the storage account collection.")
		return
	}
	all, err := p.store.List(id.Scope, accountType)
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]account, 0, len(all))
	for _, res := range all {
		a, err := toAccount(res)
		if err != nil {
			internalError(w, err)
			return
		}
		out = append(out, a)
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []account `json:"value"`
	}{out})
}

// serveAccount handles one account: PUT, PATCH, GET, DELETE.
func (p *Provider) serveAccount(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	switch r.Method {
	case http.MethodPut, http.MethodPatch:
		p.putAccount(w, r, id)
	case http.MethodGet:
		res, err := p.store.Get(id.String())
		if err != nil {
			accountLookupError(w, id, err)
			return
		}
		a, err := toAccount(res)
		if err != nil {
			internalError(w, err)
			return
		}
		gateway.WriteJSON(w, http.StatusOK, a)
	case http.MethodDelete:
		p.deleteAccount(w, r, id)
	default:
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not supported on storage accounts.")
	}
}

// putAccount creates or updates an account. A PUT of a new account
// generates its keys and, in managed mode, restarts Azurite knowing it;
// a PUT or PATCH of an existing one merges sku, kind, tags and
// properties, as ARM does, keeping the location.
func (p *Provider) putAccount(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	name := id.Names[0]
	if !groupScopeRe.MatchString(id.Scope) {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"A storage account must be created inside a resource group.")
		return
	}
	if !accountNameRe.MatchString(name) {
		azerr.WriteError(w, http.StatusBadRequest, "AccountNameInvalid", invalidName(name))
		return
	}
	if _, err := p.store.Get(id.Scope); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceGroupNotFound,
				"Resource group '"+groupOf(id.Scope)+"' could not be found.")
			return
		}
		internalError(w, err)
		return
	}
	var body accountRequest
	if !readBody(w, r, &body) {
		return
	}

	resID := id.String()
	existing, err := p.store.Get(resID)
	created := errors.Is(err, store.ErrNotFound)
	if err != nil && !created {
		internalError(w, err)
		return
	}
	var st stored
	var res store.Resource
	switch {
	case created:
		if r.Method == http.MethodPatch {
			accountLookupError(w, id, store.ErrNotFound)
			return
		}
		if body.Location == "" {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeLocationRequired,
				"The location property is required for this definition.")
			return
		}
		if body.Sku == nil || body.Sku.Name == "" {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
				"The request content was invalid: sku.name is required.")
			return
		}
		if p.nameTaken(name) {
			azerr.WriteError(w, http.StatusConflict, "StorageAccountAlreadyTaken",
				"The storage account named "+name+" is already taken.")
			return
		}
		if p.byo != nil {
			if _, ok := p.byo[name]; !ok {
				azerr.WriteError(w, http.StatusBadRequest, "StorageAccountNotConfigured",
					"The storage account '"+name+"' is not one of the accounts your Azurite "+
						"was started with; add it to azurite.accounts in provisio.yaml, or let "+
						"Provisio run Azurite (azurite.mode: managed).")
				return
			}
		}
		kind := body.Kind
		if kind == "" {
			kind = "StorageV2"
		}
		st = stored{Sku: *body.Sku, Kind: kind, Identity: body.Identity,
			Properties: p.defaults(name, body.Location, p.now())}
		res = store.Resource{ID: resID, Name: name, Type: accountType,
			Location: body.Location, Tags: body.Tags}
	default:
		if err := json.Unmarshal(existing.Properties, &st); err != nil {
			internalError(w, err)
			return
		}
		if body.Location != "" && !strings.EqualFold(existing.Location, body.Location) {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
				"The location of an existing storage account cannot be changed.")
			return
		}
		if body.Sku != nil && body.Sku.Name != "" {
			st.Sku = *body.Sku
		}
		if body.Kind != "" {
			st.Kind = body.Kind
		}
		if body.Identity != nil {
			st.Identity = body.Identity
		}
		res = existing
		if body.Tags != nil || r.Method == http.MethodPut {
			res.Tags = body.Tags
		}
	}
	for k, v := range body.Properties {
		st.Properties[k] = v
	}
	st.Sku.Tier = tierOf(st.Sku.Name)
	st.Properties["provisioningState"] = raw("Succeeded")
	res.Properties = raw(st)
	if res.Tags == nil {
		res.Tags = map[string]string{}
	}

	if created {
		if p.byo == nil {
			keys := accountKeys{Key1: newAccountKey(), Key2: newAccountKey(), Created: p.now()}
			if err := p.keys.Set(name, keys); err != nil {
				internalError(w, err)
				return
			}
		}
		if err := p.syncAzurite(); err != nil {
			_ = p.keys.Delete(name)
			internalError(w, err)
			return
		}
	}
	if _, err := p.store.Put(res); err != nil {
		internalError(w, err)
		return
	}
	a, err := toAccount(res)
	if err != nil {
		internalError(w, err)
		return
	}
	// 200 on create as well: the Storage API answers 202 with a poll URL
	// for the asynchronous case and 200 when the account is ready, which
	// here it always is; the SDKs' pollers accept no 201.
	gateway.WriteJSON(w, http.StatusOK, a)
}

// invalidName is Azure's wording for a name that breaks the rule.
func invalidName(name string) string {
	return name + " is not a valid storage account name. Storage account name must be " +
		"between 3 and 24 characters in length and use numbers and lower-case letters only."
}

// groupOf is the last segment of a group scope: the group's name.
func groupOf(scope string) string {
	return scope[strings.LastIndexByte(scope, '/')+1:]
}

// tierOf derives the SKU tier from its name: Premium_* is Premium,
// everything else Standard.
func tierOf(name string) string {
	if strings.HasPrefix(strings.ToLower(name), "premium") {
		return "Premium"
	}
	return "Standard"
}

// nameTaken reports whether any account in the subscription already has
// this name, whatever its group: account names are global.
func (p *Provider) nameTaken(name string) bool {
	all, err := p.store.List("/", accountType)
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

// deleteAccount removes the account, its keys and, best effort, its
// containers upstream, so a re-created account of the same name starts
// empty; then restarts Azurite without it. 200 when removed, 204 when
// there was nothing to remove.
func (p *Provider) deleteAccount(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	name := id.Names[0]
	res, err := p.store.Get(id.String())
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	p.wipeContainers(r, res.Name)
	if _, err := p.store.Delete(id.String()); err != nil {
		internalError(w, err)
		return
	}
	if err := p.keys.Delete(name); err != nil {
		internalError(w, err)
		return
	}
	if err := p.syncAzurite(); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// toAccount rebuilds the wire shape from the stored envelope.
func toAccount(res store.Resource) (account, error) {
	var st stored
	if err := json.Unmarshal(res.Properties, &st); err != nil {
		return account{}, fmt.Errorf("stored account %s: %w", res.ID, err)
	}
	tags := res.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	return account{ID: res.ID, Name: res.Name, Type: res.Type, Location: res.Location, Tags: tags,
		Sku: st.Sku, Kind: st.Kind, Identity: st.Identity, Properties: st.Properties}, nil
}

// accountLookupError maps a store error on an account lookup to the ARM
// response, with ARM's own wording for a missing resource.
func accountLookupError(w http.ResponseWriter, id arm.ResourceID, err error) {
	if errors.Is(err, store.ErrNotFound) {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			fmt.Sprintf("The Resource 'Microsoft.Storage/storageAccounts/%s' under resource "+
				"group '%s' was not found. For more details please go to "+
				"https://aka.ms/ARMResourceNotFoundFix", id.Names[0], groupOf(id.Scope)))
		return
	}
	internalError(w, err)
}

// accountKeysOf returns the keys to hand out for an account.
func (p *Provider) accountKeysOf(name string) (accountKeys, bool) {
	if p.byo != nil {
		k, ok := p.byo[lower(name)]
		if !ok {
			return accountKeys{}, false
		}
		k1, k2, has2 := strings.Cut(k, ":")
		if !has2 {
			k2 = k1
		}
		return accountKeys{Key1: k1, Key2: k2}, true
	}
	return p.keys.Get(name)
}

type keyEntry struct {
	KeyName      string `json:"keyName"`
	Value        string `json:"value"`
	Permissions  string `json:"permissions"`
	CreationTime string `json:"creationTime,omitempty"`
}

func (p *Provider) writeKeys(w http.ResponseWriter, k accountKeys) {
	created := ""
	if !k.Created.IsZero() {
		created = k.Created.UTC().Format(time.RFC3339)
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Keys []keyEntry `json:"keys"`
	}{[]keyEntry{
		{KeyName: "key1", Value: k.Key1, Permissions: "Full", CreationTime: created},
		{KeyName: "key2", Value: k.Key2, Permissions: "Full", CreationTime: created},
	}})
}

// listKeys answers POST .../storageAccounts/{name}/listKeys: the action
// RBAC guards as Microsoft.Storage/storageAccounts/listKeys/action.
func (p *Provider) listKeys(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodPost {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on listKeys.")
		return
	}
	accountID := arm.ResourceID{Scope: id.Scope, Namespace: id.Namespace,
		Types: id.Types[:1], Names: id.Names[:1]}
	if _, err := p.store.Get(accountID.String()); err != nil {
		accountLookupError(w, accountID, err)
		return
	}
	k, ok := p.accountKeysOf(id.Names[0])
	if !ok {
		internalError(w, fmt.Errorf("no keys for account %s", id.Names[0]))
		return
	}
	p.writeKeys(w, k)
}

// regenerateKey answers POST .../regenerateKey {"keyName": "key1"}: a
// new key, Azurite restarted to trust it, the full set returned.
func (p *Provider) regenerateKey(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodPost {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on regenerateKey.")
		return
	}
	accountID := arm.ResourceID{Scope: id.Scope, Namespace: id.Namespace,
		Types: id.Types[:1], Names: id.Names[:1]}
	if _, err := p.store.Get(accountID.String()); err != nil {
		accountLookupError(w, accountID, err)
		return
	}
	var body struct {
		KeyName string `json:"keyName"`
	}
	if !readBody(w, r, &body) {
		return
	}
	if p.byo != nil {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"Keys of a bring-your-own Azurite account are fixed by its configuration.")
		return
	}
	k, ok := p.keys.Get(id.Names[0])
	if !ok {
		internalError(w, fmt.Errorf("no keys for account %s", id.Names[0]))
		return
	}
	switch strings.ToLower(body.KeyName) {
	case "key1":
		k.Key1 = newAccountKey()
	case "key2":
		k.Key2 = newAccountKey()
	default:
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidRequestContent,
			"keyName must be key1 or key2.")
		return
	}
	if err := p.keys.Set(id.Names[0], k); err != nil {
		internalError(w, err)
		return
	}
	if err := p.syncAzurite(); err != nil {
		internalError(w, err)
		return
	}
	p.writeKeys(w, k)
}

// checkNameAvailability answers the pre-flight az and the SDKs make
// before creating an account.
func (p *Provider) checkNameAvailability(w http.ResponseWriter, r *http.Request,
	id arm.ResourceID) {
	if r.Method != http.MethodPost {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on checkNameAvailability.")
		return
	}
	var body struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if !readBody(w, r, &body) {
		return
	}
	type answer struct {
		NameAvailable bool   `json:"nameAvailable"`
		Reason        string `json:"reason,omitempty"`
		Message       string `json:"message,omitempty"`
	}
	switch {
	case !accountNameRe.MatchString(body.Name):
		gateway.WriteJSON(w, http.StatusOK,
			answer{false, "AccountNameInvalid", invalidName(body.Name)})
	case p.nameTaken(body.Name):
		gateway.WriteJSON(w, http.StatusOK, answer{false, "AlreadyExists",
			"The storage account named " + body.Name + " is already taken."})
	default:
		gateway.WriteJSON(w, http.StatusOK, answer{NameAvailable: true})
	}
}
