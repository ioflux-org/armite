package entra

import (
	"crypto/subtle"

	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/directory"
)

// ClientDirectory is what the token endpoint needs from a directory:
// the application and the service principal behind a client id, and
// whether a secret is one of the client's current passwords.
// *directory.Store is one. A Handler built without a directory answers
// from the configuration's clients, which is all there was before Graph.
type ClientDirectory interface {
	ByAppID(kind, appID string) (directory.Object, bool)
	Authenticate(appID, secret string) (directory.Object, bool)
}

// WithDirectory makes the token endpoint verify clients against dir, so
// a service principal created through Graph can log in. It returns h,
// for use where the handler is built; call it before serving.
func (h *Handler) WithDirectory(dir ClientDirectory) *Handler {
	h.dir = dir
	return h
}

// configClients answers from the configuration alone: every client is
// an application with a service principal, and its secret is compared
// in constant time. Tests of the other planes mint tokens through it
// without building a directory.
type configClients struct{ cfg config.Config }

func (c configClients) ByAppID(kind, appID string) (directory.Object, bool) {
	cl, ok := c.cfg.FindClient(appID)
	if !ok {
		return directory.Object{}, false
	}
	switch kind {
	case directory.KindApplication:
		return directory.Object{Kind: kind, AppID: cl.ID}, true
	case directory.KindServicePrincipal:
		return directory.Object{ID: cl.ObjectID, Kind: kind, AppID: cl.ID, AccountEnabled: true}, true
	}
	return directory.Object{}, false
}

func (c configClients) Authenticate(appID, secret string) (directory.Object, bool) {
	cl, ok := c.cfg.FindClient(appID)
	if !ok || subtle.ConstantTimeCompare([]byte(cl.Secret), []byte(secret)) != 1 {
		return directory.Object{}, false
	}
	return c.ByAppID(directory.KindServicePrincipal, appID)
}
