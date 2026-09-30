package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	errLineRe = regexp.MustCompile(`line (\d+): (.*)`)
	goTypeRe  = regexp.MustCompile(` in type \S+`)
)

var guidPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Load builds the effective configuration: the defaults, then the YAML
// file at path laid over them (a key that is absent keeps its default;
// a list that is present replaces the default list), then the
// environment, then validation. An empty path means "defaults only".
// Unknown keys are errors, reported with their line and a snippet: a
// typo in provisio.yaml should stop the boot, not silently keep a
// default.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("config: %s:\n%w", path, explain(data, err))
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config: %s:\n%w", pathOrDefaults(path), err)
	}
	return cfg, nil
}

// Validate reports every problem at once, each naming the YAML key, so
// one boot shows the whole list instead of one item per attempt.
func (c Config) Validate() error {
	var errs []error
	fail := func(key, msg string) { errs = append(errs, fmt.Errorf("%s: %s", key, msg)) }
	guid := func(key, v string) {
		if !guidPattern.MatchString(strings.ToLower(v)) {
			fail(key, fmt.Sprintf("%q is not a GUID", v))
		}
	}
	host := func(key, v string) {
		if v == "" || strings.ContainsAny(v, ":/ ") {
			fail(key, fmt.Sprintf("%q must be a bare hostname (no scheme, port or path)", v))
		}
	}
	addr := func(key, v string) {
		if _, _, err := net.SplitHostPort(v); err != nil {
			fail(key, fmt.Sprintf("%q must be host:port", v))
		}
	}

	guid("tenant_id", c.TenantID)
	guid("subscription_id", c.SubscriptionID)
	for _, k := range []struct{ key, v string }{
		{"subscription_name", c.SubscriptionName}, {"tenant_name", c.TenantName},
		{"default_resource_group", c.DefaultResourceGroup},
	} {
		if k.v == "" {
			fail(k.key, "must not be empty")
		}
	}
	addr("listener_addr", c.ListenerAddr)
	addr("imds_addr", c.IMDSAddr)
	host("arm_host", c.ARMHost)
	host("login_host", c.LoginHost)
	host("vault_host", c.VaultHost)
	if c.ARMHost == c.LoginHost || c.ARMHost == c.VaultHost || c.LoginHost == c.VaultHost {
		fail("arm_host/login_host/vault_host",
			"must be three different hostnames (the router dispatches on them)")
	}
	if !strings.HasPrefix(c.ARMAudience, "https://") {
		fail("arm_audience", fmt.Sprintf("%q must be an https:// URL", c.ARMAudience))
	}

	principals := map[string]string{} // object id -> which key declared it
	if len(c.Clients) == 0 {
		fail("clients", "at least one client is required")
	}
	ids := map[string]bool{}
	for i, cl := range c.Clients {
		key := fmt.Sprintf("clients[%d]", i)
		guid(key+".id", cl.ID)
		guid(key+".object_id", cl.ObjectID)
		if cl.Secret == "" {
			fail(key+".secret", "must not be empty")
		}
		if ids[cl.ID] {
			fail(key+".id", fmt.Sprintf("%q is declared twice", cl.ID))
		}
		ids[cl.ID] = true
		if prev, dup := principals[cl.ObjectID]; dup {
			fail(key+".object_id", fmt.Sprintf("%q is already the object id of %s", cl.ObjectID, prev))
		}
		principals[cl.ObjectID] = key
	}
	guid("managed_identity.client_id", c.ManagedIdentity.ClientID)
	guid("managed_identity.object_id", c.ManagedIdentity.ObjectID)
	if prev, dup := principals[c.ManagedIdentity.ObjectID]; dup {
		fail("managed_identity.object_id", fmt.Sprintf("is already the object id of %s", prev))
	}
	principals[c.ManagedIdentity.ObjectID] = "managed_identity"

	for i, ra := range c.RoleAssignments {
		key := fmt.Sprintf("role_assignments[%d]", i)
		if _, ok := principals[ra.PrincipalID]; !ok {
			fail(key+".principal_id",
				fmt.Sprintf("%q is not a configured client or the managed identity", ra.PrincipalID))
		}
		role := ra.RoleDefinitionID
		if j := strings.LastIndex(role, "/"); j >= 0 {
			role = role[j+1:]
		}
		guid(key+".role_definition_id", role)
		if !strings.HasPrefix(ra.Scope, "/") {
			fail(key+".scope", fmt.Sprintf("%q must start with /", ra.Scope))
		}
	}
	return errors.Join(errs...)
}

// YAML renders the configuration as a document that Load accepts back.
func (c Config) YAML() ([]byte, error) {
	return encode(c)
}

// Redacted returns a copy with client secrets masked, for printing.
func (c Config) Redacted() Config {
	out := c
	out.Clients = make([]Client, len(c.Clients))
	for i, cl := range c.Clients {
		cl.Secret = "***"
		out.Clients[i] = cl
	}
	return out
}

// explain rewrites a YAML error for the person editing the file: one
// entry per problem, the Go type name removed, and the offending line
// of the file printed underneath. The library reports only "line N".
func explain(data []byte, err error) error {
	msgs := []string{err.Error()}
	var te *yaml.TypeError
	if errors.As(err, &te) {
		msgs = te.Errors
	}
	src := strings.Split(string(data), "\n")
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		found := errLineRe.FindStringSubmatch(m)
		if found == nil {
			out = append(out, m)
			continue
		}
		n, _ := strconv.Atoi(found[1])
		text := fmt.Sprintf("line %d: %s", n, goTypeRe.ReplaceAllString(found[2], ""))
		if n >= 1 && n <= len(src) {
			text += fmt.Sprintf("\n    %d | %s", n, src[n-1])
		}
		out = append(out, text)
	}
	return errors.New(strings.Join(out, "\n"))
}

// encode marshals with two-space indentation, the convention of every
// YAML file a user has next to this one (compose, workflows).
func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Template renders the defaults as a commented provisio.yaml: what
// "provisio config init" writes. The comments are the documentation a
// user has in front of them while editing, which is where it is read.
func Template() ([]byte, error) {
	var doc yaml.Node
	if err := doc.Encode(Default()); err != nil {
		return nil, err
	}
	notes := []struct{ path, head, line string }{
		{"tenant_id", "Provisio configuration. Every key is optional: delete the ones you do not\n" +
			"change and their defaults apply. A list you keep (clients, role_assignments)\n" +
			"replaces the default list. Unknown keys stop the boot.\n\n" +
			"The one tenant and subscription Provisio serves.", ""},
		{"listener_addr", "", "ARM, login and every vault; the port is part of every URL"},
		{"arm_host", "Bare hostnames; each must resolve to this machine (see docs/clients.md).", ""},
		{"vault_host", "", "vaults are {name}.vault_host"},
		{"arm_audience", "", "the ARM token audience clients ask for"},
		{"clients", "Service principals that can log in with client_credentials.", ""},
		{"imds_addr", "", "managed identity endpoint (AZURE_POD_IDENTITY_AUTHORITY_HOST)"},
		{"managed_identity", "The principal IMDS issues tokens for; it has no secret.", ""},
		{"role_assignments", "Granted at boot. principal_id must be a client's or the identity's\n" +
			"object_id; role_definition_id is a built-in role GUID (az role definition list) or a full\n" +
			"ARM path. Owner carries no data-plane actions: add e.g. Key Vault Secrets\n" +
			"Officer (b86a8fe4-44ce-4948-aee5-eccb2c155cd7) to use vaults without a grant.", ""},
		{"role_assignments.0.role_definition_id", "", "Owner"},
		{"role_assignments.1.role_definition_id", "", "Contributor"},
	}
	for _, n := range notes {
		if err := annotate(&doc, n.path, n.head, n.line); err != nil {
			return nil, err
		}
	}
	return encode(&doc)
}

// annotate attaches a head comment (above the key) and a line comment
// (after the value) to the node at path: mapping keys and sequence
// indexes separated by dots. A path that does not resolve is an error,
// so renaming a key cannot silently drop its comment.
func annotate(n *yaml.Node, path, head, line string) error {
	seg, rest, _ := strings.Cut(path, ".")
	switch n.Kind {
	case yaml.SequenceNode:
		i, err := strconv.Atoi(seg)
		if err != nil || i < 0 || i >= len(n.Content) {
			return fmt.Errorf("config template: no element %q", seg)
		}
		return annotate(n.Content[i], rest, head, line)
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if key.Value != seg {
				continue
			}
			if rest != "" {
				return annotate(value, rest, head, line)
			}
			key.HeadComment, value.LineComment = head, line
			return nil
		}
	}
	return fmt.Errorf("config template: no key %q", seg)
}

func pathOrDefaults(path string) string {
	if path == "" {
		return "defaults"
	}
	return path
}
