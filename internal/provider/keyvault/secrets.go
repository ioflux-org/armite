package keyvault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// vaultContext is what the data plane knows about the vault a request
// addresses: its name, its ARM ID (the RBAC scope), its URI (the prefix
// of every secret ID) and its location (quoted in 403s).
type vaultContext struct {
	Name     string
	ID       string
	URI      string
	Location string
}

const (
	// secretRetentionDays is soft delete's retention window; purge
	// protection is not modelled, so every secret is purgeable.
	secretRetentionDays = 90
	recoveryLevel       = "Recoverable+Purgeable"
	daySeconds          = 24 * 60 * 60

	actionPrefix = "Microsoft.KeyVault/vaults/secrets/"
)

// secretNameRe is the spec's pattern for secret names, bounded at the
// documented 127 characters.
var secretNameRe = regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)

// secretAttributes carries a version's attributes. Times are Unix
// seconds ("unixtime" in the spec), never ISO strings.
// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/SecretAttributes
type secretAttributes struct {
	Enabled         *bool  `json:"enabled,omitempty"`
	NotBefore       *int64 `json:"nbf,omitempty"`
	Expires         *int64 `json:"exp,omitempty"`
	Created         int64  `json:"created,omitempty"`         // Spec: readOnly
	Updated         int64  `json:"updated,omitempty"`         // Spec: readOnly
	RecoverableDays int    `json:"recoverableDays,omitempty"` // Spec: readOnly
	RecoveryLevel   string `json:"recoveryLevel,omitempty"`   // Spec: readOnly
}

// secretBundle is a secret version with its value.
// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/SecretBundle
type secretBundle struct {
	Value       string            `json:"value,omitempty"`
	ID          string            `json:"id"`
	ContentType string            `json:"contentType,omitempty"`
	Attributes  secretAttributes  `json:"attributes"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// deletedSecretBundle embeds secretBundle: struct embedding flattens the
// embedded fields into the same JSON object, which is how the spec
// defines it - a SecretBundle plus three recovery fields.
// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/DeletedSecretBundle
type deletedSecretBundle struct {
	secretBundle
	RecoveryID         string `json:"recoveryId"`
	ScheduledPurgeDate int64  `json:"scheduledPurgeDate"` // Spec: readOnly
	DeletedDate        int64  `json:"deletedDate"`        // Spec: readOnly
}

// secretItem is a listing entry: identity and attributes, no value, and
// an ID without a version.
// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/SecretItem
type secretItem struct {
	ID          string            `json:"id"`
	Attributes  secretAttributes  `json:"attributes"`
	Tags        map[string]string `json:"tags,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
}

// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/DeletedSecretItem
type deletedSecretItem struct {
	secretItem
	RecoveryID         string `json:"recoveryId"`
	ScheduledPurgeDate int64  `json:"scheduledPurgeDate"`
	DeletedDate        int64  `json:"deletedDate"`
}

// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/SecretSetParameters
// (required: value)
type secretSetParameters struct {
	Value       string            `json:"value"`
	Tags        map[string]string `json:"tags"`
	ContentType string            `json:"contentType"`
	Attributes  *secretAttributes `json:"attributes"`
}

// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/SecretUpdateParameters
type secretUpdateParameters struct {
	ContentType *string           `json:"contentType"`
	Attributes  *secretAttributes `json:"attributes"`
	Tags        map[string]string `json:"tags"`
}

// Listings page with nextLink; one page always suffices here, so it is
// always null (maxresults is ignored).
// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/SecretListResult
type secretListResult struct {
	Value    []secretItem `json:"value"`
	NextLink *string      `json:"nextLink"`
}

// Spec: keyvault data-plane 2025-07-01 secrets.json#/definitions/DeletedSecretListResult
type deletedSecretListResult struct {
	Value    []deletedSecretItem `json:"value"`
	NextLink *string             `json:"nextLink"`
}

// secretOp is a parsed data-plane request: the RBAC data action it
// needs, the scope suffix (below the vault ID) it is evaluated at, and
// the handler that serves it once authorized.
type secretOp struct {
	action string
	scope  string // "" for the vault itself, "/secrets/{name}" for one secret
	serve  secretHandler
}

// A secretHandler serves an authorized operation against one vault.
type secretHandler func(w http.ResponseWriter, v vaultContext)

// secretOperation maps method and path onto an operation. The grammar is
// the spec's: /secrets, /secrets/{name}[/{version}|/versions],
// /deletedsecrets, /deletedsecrets/{name}[/recover]. Backup and restore
// are not supported. Nothing here touches the store: parsing happens
// before authorization, serving after.
func (p *Provider) secretOperation(r *http.Request) (secretOp, *kvFailure) {
	if r.URL.Query().Get("api-version") == "" {
		return secretOp{}, &kvFailure{http.StatusBadRequest, kvBadParameter,
			"The api-version query parameter is required."}
	}
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	collection := strings.ToLower(segs[0])
	if len(segs) > 1 && !secretNameRe.MatchString(segs[1]) {
		return secretOp{}, &kvFailure{http.StatusBadRequest, kvBadParameter,
			"The request URI contains an invalid name: " + segs[1]}
	}
	notAllowed := func() (secretOp, *kvFailure) {
		return secretOp{}, &kvFailure{http.StatusMethodNotAllowed, kvMethodNotAllowed,
			"The method '" + r.Method + "' is not allowed on '" + r.URL.Path + "'."}
	}
	op := func(action, scope string, serve secretHandler) (secretOp, *kvFailure) {
		return secretOp{action: actionPrefix + action, scope: scope, serve: serve}, nil
	}

	switch {
	case collection == "secrets" && len(segs) == 1:
		if r.Method != http.MethodGet {
			return notAllowed()
		}
		return op("readMetadata/action", "", p.listSecrets)
	case collection == "secrets" && len(segs) == 2:
		name := segs[1]
		scope := "/secrets/" + name
		switch r.Method {
		case http.MethodPut:
			return op("setSecret/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.setSecret(w, r, v, name)
			})
		case http.MethodGet:
			return op("getSecret/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.getSecret(w, v, name, "")
			})
		case http.MethodDelete:
			return op("delete", scope, func(w http.ResponseWriter, v vaultContext) {
				p.deleteSecret(w, v, name)
			})
		case http.MethodPatch:
			// SDKs send PATCH /secrets/{name}/ (an empty version) for "the
			// current version"; the trim above folds it onto this case.
			return op("update/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.updateSecret(w, r, v, name, "")
			})
		}
		return notAllowed()
	case collection == "secrets" && len(segs) == 3:
		name, last := segs[1], segs[2]
		scope := "/secrets/" + name
		switch {
		case strings.EqualFold(last, "versions") && r.Method == http.MethodGet:
			return op("readMetadata/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.listVersions(w, v, name)
			})
		case strings.EqualFold(last, "backup"):
			return notAllowed()
		case r.Method == http.MethodGet:
			return op("getSecret/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.getSecret(w, v, name, last)
			})
		case r.Method == http.MethodPatch:
			return op("update/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.updateSecret(w, r, v, name, last)
			})
		}
		return notAllowed()
	case collection == "deletedsecrets" && len(segs) == 1:
		if r.Method != http.MethodGet {
			return notAllowed()
		}
		return op("readMetadata/action", "", p.listDeleted)
	case collection == "deletedsecrets" && len(segs) == 2:
		name := segs[1]
		scope := "/secrets/" + name
		switch r.Method {
		case http.MethodGet:
			return op("getSecret/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.getDeleted(w, v, name)
			})
		case http.MethodDelete:
			return op("purge/action", scope, func(w http.ResponseWriter, v vaultContext) {
				p.purgeSecret(w, v, name)
			})
		}
		return notAllowed()
	case collection == "deletedsecrets" && len(segs) == 3 && strings.EqualFold(segs[2], "recover"):
		if r.Method != http.MethodPost {
			return notAllowed()
		}
		name := segs[1]
		return op("recover/action", "/secrets/"+name, func(w http.ResponseWriter, v vaultContext) {
			p.recoverSecret(w, v, name)
		})
	}
	return secretOp{}, &kvFailure{http.StatusNotFound, kvNotFound,
		"The resource '" + r.URL.Path + "' does not exist in this vault."}
}

// newVersionID mints the 32-hex-digit version identifier Key Vault uses.
func newVersionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("keyvault: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func attributesOf(ver secretVersion) secretAttributes {
	return secretAttributes{
		Enabled:         new(ver.Enabled),
		NotBefore:       ver.NotBefore,
		Expires:         ver.Expires,
		Created:         ver.Created,
		Updated:         ver.Updated,
		RecoverableDays: secretRetentionDays,
		RecoveryLevel:   recoveryLevel,
	}
}

func bundle(v vaultContext, s secret, ver secretVersion) secretBundle {
	return secretBundle{
		Value:       ver.Value,
		ID:          v.URI + "secrets/" + s.Name + "/" + ver.Version,
		ContentType: ver.ContentType,
		Attributes:  attributesOf(ver),
		Tags:        ver.Tags,
	}
}

func deletedBundle(v vaultContext, s secret) deletedSecretBundle {
	deleted := *s.Deleted
	return deletedSecretBundle{
		secretBundle:       bundle(v, s, s.latest()),
		RecoveryID:         v.URI + "deletedsecrets/" + s.Name,
		ScheduledPurgeDate: deleted + secretRetentionDays*daySeconds,
		DeletedDate:        deleted,
	}
}

// item is a listing entry for a secret (unversioned ID, current
// attributes) or, given a version, for that version.
func item(v vaultContext, s secret, ver *secretVersion) secretItem {
	id := v.URI + "secrets/" + s.Name
	if ver == nil {
		ver = new(s.latest())
	} else {
		id += "/" + ver.Version
	}
	return secretItem{
		ID:          id,
		Attributes:  attributesOf(*ver),
		Tags:        ver.Tags,
		ContentType: ver.ContentType,
	}
}

// notFound is Key Vault's own wording, recovery hint included.
func notFound(w http.ResponseWriter, what string) {
	writeKVError(w, http.StatusNotFound, kvSecretNotFound,
		"A secret with (name/id) "+what+" was not found in this key vault. If you recently deleted "+
			"this secret you may be able to recover it using the correct recovery command. For help "+
			"resolving this issue, please see https://go.microsoft.com/fwlink/?linkid=2125182", "")
}

func (p *Provider) setSecret(w http.ResponseWriter, r *http.Request, v vaultContext, name string) {
	var body secretSetParameters
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&body); err != nil {
		writeKVError(w, http.StatusBadRequest, kvBadParameter,
			"The request body is not valid: "+err.Error(), "")
		return
	}
	if body.Value == "" {
		writeKVError(w, http.StatusBadRequest, kvBadParameter, "The value property is required.", "")
		return
	}
	now := p.now().Unix()
	ver := secretVersion{
		Version:     newVersionID(),
		Value:       body.Value,
		ContentType: body.ContentType,
		Tags:        body.Tags,
		Enabled:     true,
		Created:     now,
		Updated:     now,
	}
	if a := body.Attributes; a != nil {
		if a.Enabled != nil {
			ver.Enabled = *a.Enabled
		}
		ver.NotBefore, ver.Expires = a.NotBefore, a.Expires
	}
	s, stored, err := p.secrets.Set(v.Name, name, ver)
	switch {
	case errors.Is(err, errSecretDeleted):
		writeKVError(w, http.StatusConflict, kvConflict,
			"Secret "+name+" is currently in a deleted but recoverable state, and its name cannot be "+
				"reused; in this state, the secret can only be recovered or purged.", "")
		return
	case err != nil:
		kvInternalError(w, err)
		return
	}
	writeKVJSON(w, http.StatusOK, bundle(v, s, stored))
}

func (p *Provider) getSecret(w http.ResponseWriter, v vaultContext, name, version string) {
	s, ver, err := p.secrets.Get(v.Name, name, version)
	switch {
	case errors.Is(err, errSecretNotFound):
		notFound(w, name)
		return
	case errors.Is(err, errVersionNotFound):
		notFound(w, name+"/"+version)
		return
	case err != nil:
		kvInternalError(w, err)
		return
	}
	if !ver.Enabled {
		writeKVError(w, http.StatusForbidden, kvForbidden,
			"Operation get is not allowed on a disabled secret.", kvSecretDisabled)
		return
	}
	writeKVJSON(w, http.StatusOK, bundle(v, s, ver))
}

func (p *Provider) updateSecret(w http.ResponseWriter, r *http.Request, v vaultContext,
	name, version string) {
	var body secretUpdateParameters
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&body); err != nil {
		writeKVError(w, http.StatusBadRequest, kvBadParameter,
			"The request body is not valid: "+err.Error(), "")
		return
	}
	now := p.now().Unix()
	s, ver, err := p.secrets.Update(v.Name, name, version, func(cur *secretVersion) {
		if body.ContentType != nil {
			cur.ContentType = *body.ContentType
		}
		if body.Tags != nil {
			cur.Tags = body.Tags
		}
		if a := body.Attributes; a != nil {
			if a.Enabled != nil {
				cur.Enabled = *a.Enabled
			}
			if a.NotBefore != nil {
				cur.NotBefore = a.NotBefore
			}
			if a.Expires != nil {
				cur.Expires = a.Expires
			}
		}
		cur.Updated = now
	})
	switch {
	case errors.Is(err, errSecretNotFound):
		notFound(w, name)
		return
	case errors.Is(err, errVersionNotFound):
		notFound(w, name+"/"+version)
		return
	case err != nil:
		kvInternalError(w, err)
		return
	}
	b := bundle(v, s, ver)
	b.Value = "" // an update echoes the metadata, never the value
	writeKVJSON(w, http.StatusOK, b)
}

func (p *Provider) listSecrets(w http.ResponseWriter, v vaultContext) {
	all, err := p.secrets.List(v.Name, false)
	if err != nil {
		kvInternalError(w, err)
		return
	}
	out := make([]secretItem, 0, len(all))
	for _, s := range all {
		out = append(out, item(v, s, nil))
	}
	writeKVJSON(w, http.StatusOK, secretListResult{Value: out})
}

func (p *Provider) listVersions(w http.ResponseWriter, v vaultContext, name string) {
	s, _, err := p.secrets.Get(v.Name, name, "")
	if err != nil {
		if errors.Is(err, errSecretNotFound) {
			notFound(w, name)
			return
		}
		kvInternalError(w, err)
		return
	}
	out := make([]secretItem, 0, len(s.Versions))
	for i := range s.Versions {
		out = append(out, item(v, s, &s.Versions[i]))
	}
	writeKVJSON(w, http.StatusOK, secretListResult{Value: out})
}

func (p *Provider) deleteSecret(w http.ResponseWriter, v vaultContext, name string) {
	s, err := p.secrets.Delete(v.Name, name, p.now().Unix())
	if err != nil {
		if errors.Is(err, errSecretNotFound) {
			notFound(w, name)
			return
		}
		kvInternalError(w, err)
		return
	}
	writeKVJSON(w, http.StatusOK, deletedBundle(v, s))
}

func (p *Provider) getDeleted(w http.ResponseWriter, v vaultContext, name string) {
	s, err := p.secrets.GetDeleted(v.Name, name)
	if err != nil {
		if errors.Is(err, errSecretNotFound) {
			notFound(w, name)
			return
		}
		kvInternalError(w, err)
		return
	}
	writeKVJSON(w, http.StatusOK, deletedBundle(v, s))
}

func (p *Provider) listDeleted(w http.ResponseWriter, v vaultContext) {
	all, err := p.secrets.List(v.Name, true)
	if err != nil {
		kvInternalError(w, err)
		return
	}
	out := make([]deletedSecretItem, 0, len(all))
	for _, s := range all {
		deleted := *s.Deleted
		out = append(out, deletedSecretItem{
			secretItem:         item(v, s, nil),
			RecoveryID:         v.URI + "deletedsecrets/" + s.Name,
			ScheduledPurgeDate: deleted + secretRetentionDays*daySeconds,
			DeletedDate:        deleted,
		})
	}
	writeKVJSON(w, http.StatusOK, deletedSecretListResult{Value: out})
}

func (p *Provider) recoverSecret(w http.ResponseWriter, v vaultContext, name string) {
	s, err := p.secrets.Recover(v.Name, name)
	if err != nil {
		if errors.Is(err, errSecretNotFound) {
			notFound(w, name)
			return
		}
		kvInternalError(w, err)
		return
	}
	writeKVJSON(w, http.StatusOK, bundle(v, s, s.latest()))
}

func (p *Provider) purgeSecret(w http.ResponseWriter, v vaultContext, name string) {
	if err := p.secrets.Purge(v.Name, name); err != nil {
		if errors.Is(err, errSecretNotFound) {
			notFound(w, name)
			return
		}
		kvInternalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
