package keyvault

import (
	"crypto/rsa"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/rbac"
)

// DataPlane returns the handler for vault hostnames ({name}.{VaultHost}):
// Key Vault's secrets API, authenticated by challenge and authorized by
// data actions through the same Checker as the management plane. That
// shared Checker is the whole point: Owner passes vaults/write on ARM
// and fails secrets/getSecret/action here, from one set of assignments.
func (p *Provider) DataPlane(pub *rsa.PublicKey, now func() time.Time,
	checker *rbac.Checker) http.Handler {
	p.now = now
	auth := gateway.NewAuthenticatorFor(p.cfg, pub, now, p.cfg.VaultAudience())
	// The challenge tells clients where to log in and which resource to
	// ask a token for. SDKs verify that the vault they are calling is a
	// subdomain of that resource, so it is the vault host, not a URL of
	// Microsoft's.
	challenge := fmt.Sprintf("Bearer authorization=%q, resource=%q",
		p.cfg.LoginBaseURL()+"/"+p.cfg.TenantID, p.cfg.VaultAudience())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := p.vaultFor(r.Host)
		if !ok {
			writeKVError(w, http.StatusNotFound, kvVaultNotFound,
				"No vault is served at '"+r.Host+"'.", "")
			return
		}
		principal, fail := auth.Verify(r.Header.Get("Authorization"))
		if fail.Code != "" {
			w.Header().Set("WWW-Authenticate", challenge)
			writeKVError(w, http.StatusUnauthorized, kvUnauthorized, fail.Message, "")
			return
		}
		op, f := p.secretOperation(r)
		if f != nil {
			writeKVError(w, f.status, f.code, f.message, "")
			return
		}
		scope := v.ID + op.scope
		allowed, err := checker.Check(principal.ObjectID, op.action, scope, true)
		if err != nil {
			kvInternalError(w, err)
			return
		}
		if !allowed {
			writeKVError(w, http.StatusForbidden, kvForbidden,
				fmt.Sprintf(
					"Caller is not authorized to perform action on resource.\n"+
						"If role assignments, deny assignments or role definitions were changed recently, "+
						"please observe propagation time.\n"+
						"Caller: appid=%s;oid=%s;iss=%s\nAction: '%s'\nResource: '%s'\n"+
						"Assignment: (not found)\nDecisionReason: 'DeniedWithNoValidRBAC'\nVault: %s;location=%s",
					principal.AppID, principal.ObjectID, p.cfg.IssuerURL(), op.action, scope,
					v.Name, v.Location), kvForbiddenByRbac)
			return
		}
		op.serve(w, v)
	})
}

// vaultFor resolves the request's Host to a vault: the first label of
// the hostname is the vault name, and a vault of that name must exist
// as a resource. Real Azure answers a missing vault with NXDOMAIN;
// Provisio owns the whole suffix, so it answers 404.
func (p *Provider) vaultFor(hostport string) (vaultContext, bool) {
	host := hostport
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	name, ok := strings.CutSuffix(host, "."+p.cfg.VaultHost)
	if !ok || name == "" || strings.Contains(name, ".") {
		return vaultContext{}, false
	}
	all, err := p.store.List("/", vaultType)
	if err != nil {
		return vaultContext{}, false
	}
	for _, res := range all {
		if strings.EqualFold(res.Name, name) {
			return vaultContext{
				Name:     res.Name,
				ID:       res.ID,
				URI:      p.cfg.VaultURI(res.Name),
				Location: res.Location,
			}, true
		}
	}
	return vaultContext{}, false
}
