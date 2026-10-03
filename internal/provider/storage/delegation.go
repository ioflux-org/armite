package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A user delegation key is a SAS signing key tied to an identity instead
// of to the account key: a principal with the generateUserDelegationKey
// action asks for one, signs SAS tokens with it, and whoever presents
// such a SAS is authorized as that principal would be - the SAS's
// permissions intersected with the principal's RBAC, checked at use.
// That makes it the one blob feature that is identity-based end to end,
// so Provisio issues and validates these itself; Azurite never sees one.
//
// The key's value is derived from the fields the key carries (object id,
// tenant, window, service, version) with a secret seed, as Azurite does
// with its own seed: nothing is stored, and a SAS - which repeats those
// fields as skoid, sktid, skt, ske, sks, skv - lets the value be
// recomputed when it is presented.

const (
	maxDelegationKeyLife = 7 * 24 * time.Hour
	sasTimeLayout        = "2006-01-02T15:04:05Z"
)

// delegationKeyValue derives the key for the signed fields.
func (p *Provider) delegationKeyValue(oid, tid, start, expiry, service, version string) []byte {
	mac := hmac.New(sha256.New, p.delegationSeed)
	fields := []string{"udk", oid, tid, start, expiry, service, version}
	mac.Write([]byte(strings.Join(fields, "\n")))
	return mac.Sum(nil)
}

// parseSASTime accepts the ISO 8601 shapes clients send for key windows
// and SAS windows: seconds, minutes, fractions, or a date alone.
func parseSASTime(s string) (time.Time, error) {
	layouts := []string{sasTimeLayout, "2006-01-02T15:04Z", time.RFC3339Nano, "2006-01-02"}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not an ISO 8601 UTC time", s)
}

// serveDelegationKey answers POST /?restype=service&comp=userdelegationkey
// for an already authorized principal: Azure's XML in, Azure's XML out.
func (p *Provider) serveDelegationKey(w http.ResponseWriter, r *http.Request, oid string) {
	var info struct {
		Start  string `xml:"Start"`
		Expiry string `xml:"Expiry"`
	}
	dec := xml.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&info); err != nil {
		writeStorageError(w, http.StatusBadRequest, "InvalidXmlDocument",
			"The KeyInfo document could not be read: "+err.Error())
		return
	}
	now := p.now().UTC()
	start := now
	if info.Start != "" {
		t, err := parseSASTime(info.Start)
		if err != nil {
			writeStorageError(w, http.StatusBadRequest, "InvalidXmlDocument", "Start: "+err.Error())
			return
		}
		start = t
	}
	expiry, err := parseSASTime(info.Expiry)
	if err != nil {
		writeStorageError(w, http.StatusBadRequest, "InvalidXmlDocument", "Expiry: "+err.Error())
		return
	}
	if !expiry.After(start) || expiry.Sub(now) > maxDelegationKeyLife {
		writeStorageError(w, http.StatusBadRequest, "InvalidXmlDocument",
			"Expiry must be after Start and at most 7 days from now.")
		return
	}
	version := r.Header.Get("x-ms-version")
	if version == "" {
		version = apiVersion
	}
	st, ex := start.Format(sasTimeLayout), expiry.Format(sasTimeLayout)
	value := p.delegationKeyValue(oid, p.cfg.TenantID, st, ex, "b", version)
	type key struct {
		XMLName       xml.Name `xml:"UserDelegationKey"`
		SignedOid     string   `xml:"SignedOid"`
		SignedTid     string   `xml:"SignedTid"`
		SignedStart   string   `xml:"SignedStart"`
		SignedExpiry  string   `xml:"SignedExpiry"`
		SignedService string   `xml:"SignedService"`
		SignedVersion string   `xml:"SignedVersion"`
		Value         string   `xml:"Value"`
	}
	body, err := xml.Marshal(key{SignedOid: oid, SignedTid: p.cfg.TenantID, SignedStart: st,
		SignedExpiry: ex, SignedService: "b", SignedVersion: version,
		Value: base64.StdEncoding.EncodeToString(value)})
	if err != nil {
		writeStorageError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-ms-version", version)
	w.Header().Set("x-ms-request-id", newRequestID())
	w.Write([]byte(xml.Header))
	w.Write(body)
}

// sasParams are the query parameters that belong to a SAS; they are
// removed before the request goes upstream signed with the account key.
var sasParams = map[string]bool{
	"sv": true, "ss": true, "srt": true, "sp": true, "st": true, "se": true, "sip": true,
	"spr": true, "sr": true, "sig": true, "si": true, "ses": true, "skoid": true, "sktid": true,
	"skt": true, "ske": true, "sks": true, "skv": true, "skdutid": true, "saoid": true,
	"suoid": true, "scid": true, "sduoid": true, "sdd": true, "srh": true, "srq": true,
	"rscc": true, "rscd": true, "rsce": true, "rscl": true, "rsct": true,
}

// stripSAS removes the SAS parameters from the request's query.
func stripSAS(r *http.Request) {
	q := r.URL.Query()
	for name := range sasParams {
		q.Del(name)
	}
	r.URL.RawQuery = q.Encode()
}

// sasPermission is the permission letters, any of which lets a SAS
// authorize op, per the Blob service's table; "" means no SAS can.
func sasPermission(op operation) string {
	switch {
	case op.container == "":
		return "" // account-level operations need an account SAS or a token
	case op.name == "Create Container":
		return ""
	case op.name == "List Blobs":
		return "l"
	case op.name == "Delete Container", op.name == "Delete Blob":
		return "d"
	case op.name == "Get Container Properties", op.name == "Get Blob",
		op.name == "Query Blob Contents":
		return "r"
	case op.name == "Get Blob Tags", op.name == "Set Blob Tags":
		return "t"
	case op.name == "Put Blob", op.name == "Put Blob blocklist":
		return "cw" // create or write
	case op.name == "Append Block":
		return "aw"
	default:
		return "w"
	}
}

// delegationStringToSign rebuilds what the client signed, by the SAS
// version's layout: fields were added in 2020-02-10 (delegated agents),
// 2020-12-06 (encryption scope), 2025-07-05 (delegated user) and
// 2026-04-06 (bound request headers and parameters).
func delegationStringToSign(q url.Values, canonical, timestamp string) string {
	sv := q.Get("sv")
	fields := []string{q.Get("sp"), q.Get("st"), q.Get("se"), canonical, q.Get("skoid"),
		q.Get("sktid"), q.Get("skt"), q.Get("ske"), q.Get("sks"), q.Get("skv")}
	if sv >= "2020-02-10" {
		fields = append(fields, q.Get("saoid"), q.Get("suoid"), q.Get("scid"))
	}
	if sv >= "2025-07-05" {
		fields = append(fields, q.Get("skdutid"), q.Get("sduoid"))
	}
	fields = append(fields, q.Get("sip"), q.Get("spr"), sv, q.Get("sr"), timestamp)
	if sv >= "2020-12-06" {
		fields = append(fields, q.Get("ses"))
	}
	if sv >= "2026-04-06" {
		fields = append(fields, "", "") // bound headers and parameters: refused when present
	}
	fields = append(fields, q.Get("rscc"), q.Get("rscd"), q.Get("rsce"), q.Get("rscl"),
		q.Get("rsct"))
	return strings.Join(fields, "\n")
}

// errSAS is a refusal of a user-delegation SAS: the code and message of
// the 403 to send.
type errSAS struct{ code, message string }

func (e errSAS) Error() string { return e.message }

func authFailed(message string) errSAS {
	return errSAS{"AuthenticationFailed", message}
}

// validateDelegationSAS checks a user-delegation SAS on the request
// against op: fields, windows, the resource it covers, the permission
// letter, and the signature recomputed from the key the SAS names. It
// returns the delegating principal's object id, whose RBAC the caller
// checks next.
func (p *Provider) validateDelegationSAS(r *http.Request, account string,
	op operation) (string, error) {
	q := r.URL.Query()
	required := []string{"sv", "sp", "se", "sr", "sig",
		"skoid", "sktid", "skt", "ske", "sks", "skv"}
	for _, name := range required {
		if q.Get(name) == "" {
			return "", authFailed("The user delegation SAS lacks " + name + ".")
		}
	}
	if q.Get("srh") != "" || q.Get("srq") != "" || q.Get("si") != "" {
		return "", authFailed("SAS tokens bound to request headers, parameters or a stored " +
			"access policy are not supported.")
	}
	if !strings.EqualFold(q.Get("sktid"), p.cfg.TenantID) || q.Get("sks") != "b" {
		return "", authFailed("The user delegation key belongs to another tenant or service.")
	}
	if q.Get("sv") < "2018-11-09" {
		return "", authFailed("SAS version " + q.Get("sv") + " predates user delegation SAS.")
	}
	now := p.now().UTC()
	windows := []struct{ start, end, what string }{
		{q.Get("skt"), q.Get("ske"), "user delegation key"},
		{q.Get("st"), q.Get("se"), "SAS"},
	}
	for _, window := range windows {
		if window.start != "" {
			t, err := parseSASTime(window.start)
			if err != nil || now.Before(t) {
				return "", authFailed("The " + window.what + " is not yet valid.")
			}
		}
		t, err := parseSASTime(window.end)
		if err != nil || !now.Before(t) {
			return "", authFailed("The " + window.what + " has expired.")
		}
	}
	if q.Get("spr") == "http" {
		return "", authFailed("The SAS allows http only.")
	}

	// The resource the SAS covers, from the request it is used on.
	path := strings.Trim(r.URL.EscapedPath(), "/")
	containerPart, blobPart, hasBlob := strings.Cut(path, "/")
	container, _ := url.PathUnescape(containerPart)
	blob, _ := url.PathUnescape(blobPart)
	canonical := "/blob/" + account + "/" + container
	var timestamp string
	switch q.Get("sr") {
	case "c":
	case "b", "bs", "bv":
		if !hasBlob {
			return "", errSAS{"AuthorizationResourceTypeMismatch", "This request is not " +
				"authorized to perform this operation using this resource type."}
		}
		canonical += "/" + blob
		if q.Get("sr") == "bs" {
			timestamp = q.Get("snapshot")
		} else if q.Get("sr") == "bv" {
			timestamp = q.Get("versionid")
		}
	default:
		return "", authFailed("SAS resource " + q.Get("sr") + " is not supported.")
	}
	letters := sasPermission(op)
	if letters == "" || !strings.ContainsAny(q.Get("sp"), letters) {
		return "", errSAS{errPermissionMismatch,
			"This request is not authorized to perform this operation using this permission."}
	}

	key := p.delegationKeyValue(q.Get("skoid"), q.Get("sktid"), q.Get("skt"), q.Get("ske"),
		q.Get("sks"), q.Get("skv"))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(delegationStringToSign(q, canonical, timestamp)))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(q.Get("sig"))) {
		return "", authFailed("Server failed to authenticate the request. Make sure the value " +
			"of the signature is formed correctly.")
	}
	return strings.ToLower(q.Get("skoid")), nil
}
