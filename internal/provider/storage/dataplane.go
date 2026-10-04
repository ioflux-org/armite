package storage

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/rbac"
	"github.com/ioflux-org/provisio/internal/store"
)

// Blob data-plane error codes, in the service's own XML envelope.
const (
	errNoAuthentication      = "NoAuthenticationInformation"
	errInvalidAuthentication = "InvalidAuthenticationInfo"
	errPermissionMismatch    = "AuthorizationPermissionMismatch"
	errKeyAuthNotPermitted   = "KeyBasedAuthenticationNotPermitted"
	errResourceNotFound      = "ResourceNotFound"
	errUnsupported           = "UnsupportedOperation"
)

// writeStorageError answers in the Blob service's XML envelope, code in
// the x-ms-error-code header as every storage client expects, and the
// request id in the message as the service writes it - the one httplog
// put on the response before the handler ran.
func writeStorageError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-ms-error-code", code)
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Error><Code>%s</Code><Message>%s
RequestId:%s
Time:%s</Message></Error>`, code, xmlEscaper.Replace(message), w.Header().Get("x-ms-request-id"),
		time.Now().UTC().Format("2006-01-02T15:04:05.0000000Z"))
}

// xmlEscaper escapes the three characters XML text cannot carry; quotes
// stay readable, unlike html.EscapeString's output.
var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// accountContext is what the data plane knows about the account a
// request addresses.
type accountContext struct {
	name      string
	id        string
	sharedKey bool // allowSharedKeyAccess
}

// accountFor resolves the request's Host to an account: the first label
// is the account name, and an account of that name must exist.
func (p *Provider) accountFor(hostport string) (accountContext, bool) {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	name, ok := strings.CutSuffix(host, "."+p.cfg.BlobHost)
	if !ok || name == "" || strings.Contains(name, ".") {
		return accountContext{}, false
	}
	all, err := p.store.List("/", accountType)
	if err != nil {
		return accountContext{}, false
	}
	for _, res := range all {
		if strings.EqualFold(res.Name, name) {
			acct := accountContext{name: res.Name, id: res.ID, sharedKey: sharedKeyAllowed(res)}
			return acct, true
		}
	}
	return accountContext{}, false
}

// sharedKeyAllowed reads properties.allowSharedKeyAccess; absent means
// allowed, as in Azure.
func sharedKeyAllowed(res store.Resource) bool {
	var st stored
	if err := json.Unmarshal(res.Properties, &st); err != nil {
		return true
	}
	var allowed bool
	if v, ok := st.Properties["allowSharedKeyAccess"]; ok && json.Unmarshal(v, &allowed) == nil {
		return allowed
	}
	return true
}

// DataPlane returns the handler for account hostnames
// ({account}.{BlobHost}): the Blob service API, authorized here and
// served by Azurite. A bearer token is verified and checked against the
// operation's action by the same Checker as the management plane, then
// the request is re-signed with the account key - Azurite trusts keys
// only. A request already carrying a key signature or a SAS goes
// through as it is, Azurite being the authority on keys, unless the
// account disallows key access.
func (p *Provider) DataPlane(pub *rsa.PublicKey, now func() time.Time,
	checker *rbac.Checker) http.Handler {
	p.now = now
	challenge := fmt.Sprintf("Bearer authorization_uri=%s/%s/oauth2/authorize resource_id=%s",
		p.cfg.LoginBaseURL(), p.cfg.TenantID, config.StorageAudience)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(p.upstream.base)
			r.Out.Host = hostFor(r.In.Context().Value(accountKey{}).(string))
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("storage: upstream %s: %v", p.upstream.base, err)
			writeStorageError(w, http.StatusBadGateway, "ServerBusy",
				"The blob store behind this account is not reachable: "+err.Error())
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.serveUnservedStub(w, r) {
			return
		}
		acct, ok := p.accountFor(r.Host)
		if !ok {
			writeStorageError(w, http.StatusNotFound, errResourceNotFound,
				"No storage account is served at '"+r.Host+"'.")
			return
		}
		authz := r.Header.Get("Authorization")
		switch {
		case strings.HasPrefix(authz, "Bearer "):
			// Two audiences are in use: Azure's storage resource, which az
			// and the SDKs ask for, and the account's own endpoint, which
			// Terraform's go-azure-sdk derives from the storage suffix.
			auth := gateway.NewAuthenticatorFor(p.cfg, pub, now, config.StorageAudience,
				strings.TrimSuffix(p.cfg.BlobURI(acct.name), "/"))
			principal, fail := auth.Verify(authz)
			if fail.Code != "" {
				w.Header().Set("WWW-Authenticate", challenge)
				writeStorageError(w, http.StatusUnauthorized, errInvalidAuthentication,
					fail.Message)
				return
			}
			op, ok := parseOperation(r.Method, r.URL)
			if !ok {
				writeStorageError(w, http.StatusBadRequest, errUnsupported,
					"Provisio does not recognize this blob operation and will not forward it.")
				return
			}
			if !p.authorize(w, checker, principal.ObjectID, op, acct) {
				return
			}
			if op.action == actDelegationKey {
				// Identity-based end to end: issued here, never forwarded.
				p.serveDelegationKey(w, r, principal.ObjectID)
				return
			}
			// Authorized: forward as the account itself. The signature
			// covers the path, query and x-ms-* headers the proxy keeps.
			r.Header.Del("Authorization")
			if !p.signAsAccount(w, r, acct.name) {
				return
			}
		case r.URL.Query().Get("sig") != "" && r.URL.Query().Get("skoid") != "":
			// A user delegation SAS: validated here, then authorized as
			// the principal that asked for the key, as Azure does.
			op, ok := parseOperation(r.Method, r.URL)
			if !ok {
				writeStorageError(w, http.StatusBadRequest, errUnsupported,
					"Provisio does not recognize this blob operation and will not forward it.")
				return
			}
			oid, err := p.validateDelegationSAS(r, acct.name, op)
			if err != nil {
				var refusal errSAS
				if errors.As(err, &refusal) {
					writeStorageError(w, http.StatusForbidden, refusal.code, refusal.message)
				} else {
					writeStorageError(w, http.StatusForbidden, "AuthenticationFailed", err.Error())
				}
				return
			}
			if !p.authorize(w, checker, oid, op, acct) {
				return
			}
			stripSAS(r)
			if !p.signAsAccount(w, r, acct.name) {
				return
			}
		case strings.HasPrefix(authz, "SharedKey ") || strings.HasPrefix(authz, "SharedKeyLite "):
			if !acct.sharedKey {
				writeStorageError(w, http.StatusForbidden, errKeyAuthNotPermitted,
					"Key based authentication is not permitted on this storage account.")
				return
			}
		case r.URL.Query().Get("sig") != "":
			// A service or account SAS, signed with the account key:
			// Azurite validates it, as it validates Shared Key.
			if !acct.sharedKey {
				writeStorageError(w, http.StatusForbidden, errKeyAuthNotPermitted,
					"Key based authentication is not permitted on this storage account.")
				return
			}
		case authz == "":
			w.Header().Set("WWW-Authenticate", challenge)
			writeStorageError(w, http.StatusUnauthorized, errNoAuthentication,
				"Server failed to authenticate the request. Please refer to the information "+
					"in the www-authenticate header.")
			return
		default:
			writeStorageError(w, http.StatusBadRequest, errInvalidAuthentication,
				"The authentication scheme is not supported.")
			return
		}
		proxy.ServeHTTP(w, r.WithContext(withAccount(r.Context(), acct.name)))
	})
}

// authorize runs the RBAC check for op on behalf of oid and writes the
// 403 when it fails: Azure's own first line, then what Azure never tells
// you. Reports whether the request may proceed.
func (p *Provider) authorize(w http.ResponseWriter, checker *rbac.Checker, oid string,
	op operation, acct accountContext) bool {
	scope := acct.id
	if op.container != "" {
		scope += "/blobServices/default/containers/" + op.container
	}
	allowed, err := checker.Check(oid, op.action, scope, op.data)
	if err == nil && !allowed && op.alt != "" {
		allowed, err = checker.Check(oid, op.alt, scope, true)
	}
	if err != nil {
		writeStorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return false
	}
	if !allowed {
		writeStorageError(w, http.StatusForbidden, errPermissionMismatch,
			fmt.Sprintf("This request is not authorized to perform this operation "+
				"using this permission.\nOperation: %s\nAction: '%s'\nScope: '%s'\n"+
				"Caller: oid=%s", op.name, op.action, scope, oid))
		return false
	}
	return true
}

// signAsAccount puts the account's Shared Key signature on r. Reports
// whether it could; a missing key is answered as an internal error.
func (p *Provider) signAsAccount(w http.ResponseWriter, r *http.Request, account string) bool {
	key, ok := p.keyFor(account)
	if !ok {
		writeStorageError(w, http.StatusInternalServerError, "InternalError",
			"No key is known for this account.")
		return false
	}
	signSharedKey(r, account, key)
	return true
}

// accountKey carries the account name to the proxy's Rewrite, which
// runs with the outgoing request and needs the Host to send.
type accountKey struct{}

func withAccount(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, accountKey{}, name)
}

// serveUnservedStub answers the one call Terraform makes to an
// account's queue and table services when it creates the account, a
// read of the service properties, with an empty configuration;
// everything else on those hosts is refused. Without it Terraform
// retries the connection for half a minute per service per account.
// Reports whether the request was for one of those hosts.
func (p *Provider) serveUnservedStub(w http.ResponseWriter, r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	queue := strings.HasSuffix(host, "."+p.cfg.QueueHost())
	table := strings.HasSuffix(host, "."+p.cfg.TableHost())
	if !queue && !table {
		return false
	}
	q := r.URL.Query()
	probe := q.Get("restype") == "service" && q.Get("comp") == "properties"
	if r.Method == http.MethodGet && probe {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("x-ms-version", apiVersion)
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><StorageServiceProperties>`+
			`<Logging><Version>1.0</Version><Delete>false</Delete><Read>false</Read>`+
			`<Write>false</Write><RetentionPolicy><Enabled>false</Enabled></RetentionPolicy>`+
			`</Logging>`+
			`<HourMetrics><Version>1.0</Version><Enabled>false</Enabled>`+
			`<RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></HourMetrics>`+
			`<MinuteMetrics><Version>1.0</Version><Enabled>false</Enabled>`+
			`<RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></MinuteMetrics>`+
			`<Cors/></StorageServiceProperties>`)
		return true
	}
	writeStorageError(w, http.StatusNotFound, "FeatureNotSupported",
		"Queues and tables are not served by this emulator; only the blob service is.")
	return true
}
