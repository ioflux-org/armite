package gateway

import (
	"net/http"
	"strings"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
)

// endpointsDocument is the cloud description ARM serves anonymously at
// /metadata/endpoints. az cloud register and Terraform's metadata_host
// read it to learn where to log in, which audience to request and where
// the resource manager is - which is why it cannot sit behind
// authentication: nobody holds a token yet.
type endpointsDocument struct {
	Name                     string            `json:"name"`
	Authentication           authentication    `json:"authentication"`
	ResourceManager          string            `json:"resourceManager"`
	MicrosoftGraphResourceID string            `json:"microsoftGraphResourceId"`
	Suffixes                 map[string]string `json:"suffixes"`
}

type authentication struct {
	LoginEndpoint    string   `json:"loginEndpoint"`
	Audiences        []string `json:"audiences"`
	Tenant           string   `json:"tenant"`
	IdentityProvider string   `json:"identityProvider"`
}

// endpointsFor builds the document from config. Trailing slashes follow
// real ARM's document; clients normalize them. Suffixes is empty until
// a data plane exists (M4 adds keyVaultDns) but always present: az
// indexes into it without checking.
func endpointsFor(cfg config.Config) endpointsDocument {
	return endpointsDocument{
		Name: "Provisio",
		Authentication: authentication{
			LoginEndpoint:    cfg.LoginBaseURL() + "/",
			Audiences:        []string{strings.TrimSuffix(cfg.ARMAudience, "/") + "/"},
			Tenant:           cfg.TenantID,
			IdentityProvider: "AAD",
		},
		ResourceManager: cfg.ARMBaseURL() + "/",
		// az builds a Graph client before listing role assignments and
		// refuses to run without this endpoint. Pointing it at the ARM
		// host makes the principal-name lookup fail with an HTTP error,
		// which az tolerates; a connection failure it would not.
		MicrosoftGraphResourceID: cfg.ARMBaseURL() + "/",
		Suffixes:                 map[string]string{},
	}
}

// serveEndpoints answers GET /metadata/endpoints. api-version 2022-09-01
// is this cloud's document (az cloud register, Terraform); 2019-05-01 is
// the same document in a list, the shape ARM_CLOUD_METADATA_URL expects.
// Any other well-formed version gets the single document: Provisio
// keeps no version matrix here either.
func serveEndpoints(cfg config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
				"The method '"+r.Method+"' is not allowed on '"+r.URL.Path+"'.")
			return
		}
		version := r.URL.Query().Get("api-version")
		if version == "" {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeMissingApiVersionParameter,
				"The api-version query parameter (?api-version=) is required for all requests.")
			return
		}
		doc := endpointsFor(cfg)
		if version == "2019-05-01" {
			WriteJSON(w, http.StatusOK, []endpointsDocument{doc})
			return
		}
		WriteJSON(w, http.StatusOK, doc)
	})
}
