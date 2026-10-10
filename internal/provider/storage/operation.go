package storage

import (
	"net/http"
	"net/url"
	"strings"
)

// operation is what a blob data-plane request asks for, in RBAC terms:
// the action (a management action for container-level work, a data
// action for blob-level work - that split is Azure's, and it is why
// Owner can create a container but not read a blob), the scope below
// the account, and a name for logs and errors.
type operation struct {
	name      string
	action    string
	data      bool
	container string // "" for account-level operations
	alt       string // an alternative data action that also permits it
}

// Every storage action lives under the blob service of an account.
const blobServices = "Microsoft.Storage/storageAccounts/blobServices/"

const (
	actContainersRead   = blobServices + "containers/read"
	actContainersWrite  = blobServices + "containers/write"
	actContainersDelete = blobServices + "containers/delete"
	actServiceRead      = blobServices + "read"
	actServiceWrite     = blobServices + "write"
	actDelegationKey    = blobServices + "generateUserDelegationKey/action"
	actBlobsRead        = blobServices + "containers/blobs/read"
	actBlobsWrite       = blobServices + "containers/blobs/write"
	actBlobsDelete      = blobServices + "containers/blobs/delete"
	actBlobsAdd         = blobServices + "containers/blobs/add/action"
	actBlobsFilter      = blobServices + "containers/blobs/filter/action"
	actBlobsTagsRead    = blobServices + "containers/blobs/tags/read"
	actBlobsTagsWrite   = blobServices + "containers/blobs/tags/write"
)

// parseOperation classifies a request by method, path and the restype
// and comp query parameters, following the Blob service's "permissions
// for calling data operations" table. Unknown shapes are refused rather
// than guessed: a request Armite cannot name, it does not forward.
func parseOperation(method string, u *url.URL) (operation, bool) {
	q := u.Query()
	restype, comp := strings.ToLower(q.Get("restype")), strings.ToLower(q.Get("comp"))
	path := strings.Trim(u.EscapedPath(), "/")
	container, _, hasBlob := strings.Cut(path, "/")
	if container != "" {
		if c, err := url.PathUnescape(container); err == nil {
			container = c
		}
	}
	read := method == http.MethodGet || method == http.MethodHead

	switch {
	case container == "": // account level
		switch {
		case comp == "list" && read:
			return operation{name: "List Containers", action: actContainersRead}, true
		case restype == "service" && comp == "properties" && read:
			return operation{name: "Get Blob Service Properties", action: actServiceRead}, true
		case restype == "service" && comp == "properties" && method == http.MethodPut:
			return operation{name: "Set Blob Service Properties", action: actServiceWrite}, true
		case restype == "service" && comp == "stats" && read:
			return operation{name: "Get Blob Service Stats", action: actServiceRead}, true
		case restype == "account" && comp == "properties" && read:
			return operation{name: "Get Account Information", action: actServiceRead}, true
		case restype == "service" && comp == "userdelegationkey" && method == http.MethodPost:
			return operation{name: "Get User Delegation Key", action: actDelegationKey}, true
		case comp == "blobs" && read:
			return operation{name: "Find Blobs by Tags", action: actBlobsFilter, data: true}, true
		}
	case !hasBlob && restype == "container": // container level
		op := operation{container: container}
		switch {
		case comp == "list" && read:
			op.name, op.action, op.data = "List Blobs", actBlobsRead, true
		case read:
			op.name, op.action = "Get Container Properties", actContainersRead
		case method == http.MethodPut && comp == "":
			op.name, op.action = "Create Container", actContainersWrite
		case method == http.MethodPut:
			op.name, op.action = "Set Container "+comp, actContainersWrite
		case method == http.MethodDelete:
			op.name, op.action = "Delete Container", actContainersDelete
		default:
			return operation{}, false
		}
		return op, true
	case hasBlob: // blob level
		op := operation{container: container, data: true}
		switch {
		case read && comp == "tags":
			op.name, op.action = "Get Blob Tags", actBlobsTagsRead
		case read:
			op.name, op.action = "Get Blob", actBlobsRead
		case method == http.MethodPost && comp == "query":
			op.name, op.action = "Query Blob Contents", actBlobsRead
		case method == http.MethodPut && comp == "tags":
			op.name, op.action = "Set Blob Tags", actBlobsTagsWrite
		case method == http.MethodPut && comp == "appendblock":
			op.name, op.action, op.alt = "Append Block", actBlobsWrite, actBlobsAdd
		case method == http.MethodPut:
			op.name, op.action = "Put Blob", actBlobsWrite
			if comp != "" {
				op.name = "Put Blob " + comp
			}
		case method == http.MethodDelete && comp == "":
			op.name, op.action = "Delete Blob", actBlobsDelete
		default:
			return operation{}, false
		}
		return op, true
	}
	return operation{}, false
}
