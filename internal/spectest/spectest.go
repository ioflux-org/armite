// Package spectest checks JSON bodies against the model definitions of
// a vendored Swagger 2.0 document: every required property present, no
// property the model does not declare, nested models checked the same
// way. It is a contract-test helper for provider packages and is never
// used at runtime. It understands the subset of JSON Schema Azure's
// specs use - properties, required, $ref, allOf, additionalProperties -
// and nothing more.
package spectest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strings"
	"testing"
)

// definitions is one file's "definitions" object, keyed by model name.
type definitions map[string]json.RawMessage

// Doc is a loaded spec plus the ARM common-types file its $refs reach
// into (Resource, ProxyResource, TrackedResource).
type Doc struct {
	defs   definitions
	common definitions
}

// Load reads the spec at specPath and, when commonPath is not empty,
// the common-types file it references.
func Load(t testing.TB, specPath, commonPath string) *Doc {
	t.Helper()
	d := &Doc{defs: load(t, specPath)}
	if commonPath != "" {
		d.common = load(t, commonPath)
	}
	return d
}

func load(t testing.TB, path string) definitions {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("spectest: %v", err)
	}
	var doc struct {
		Definitions definitions `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("spectest: %s: %v", path, err)
	}
	return doc.Definitions
}

// schema is the part of a JSON Schema object this package reads.
type schema struct {
	Ref        string            `json:"$ref"`
	AllOf      []schema          `json:"allOf"`
	Properties map[string]schema `json:"properties"`
	Required   []string          `json:"required"`
	Items      *schema           `json:"items"`
	Additional json.RawMessage   `json:"additionalProperties"`
}

// isModel reports whether a schema describes a structured object
// rather than a scalar or a free-form map such as tags.
func (s *schema) isModel() bool {
	return s.Ref != "" || len(s.AllOf) > 0 || len(s.Properties) > 0
}

// prop is a property's schema together with the file it was declared
// in, so that its own $refs resolve against the right file.
type prop struct {
	s    schema
	file definitions
}

// resolve follows a $ref: "#/definitions/X" within the current file, or
// into the common-types file when the path names it. Unknown targets
// resolve to nil and leave the model open.
func (d *Doc) resolve(ref string, from definitions) (*schema, definitions) {
	file := from
	if strings.Contains(ref, "common-types/resource-management/") {
		file = d.common
	}
	name := ref[strings.LastIndex(ref, "/")+1:]
	raw, ok := file[name]
	if !ok {
		return nil, nil
	}
	var s schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, nil
	}
	return &s, file
}

// flatten merges a schema and its allOf chain into one property map
// and one required list. A $ref that cannot be resolved contributes
// nothing and marks the result open, so unknown keys are not reported.
func (d *Doc) flatten(
	s *schema,
	file definitions,
) (props map[string]prop, required []string, open bool) {
	props = map[string]prop{}
	if s.Ref != "" {
		target, tfile := d.resolve(s.Ref, file)
		if target == nil {
			return props, nil, true
		}
		return d.flatten(target, tfile)
	}
	for i := range s.AllOf {
		p, r, o := d.flatten(&s.AllOf[i], file)
		maps.Copy(props, p)
		required = append(required, r...)
		open = open || o
	}
	for k, v := range s.Properties {
		props[k] = prop{s: v, file: file}
	}
	required = append(required, s.Required...)
	if len(s.Additional) > 0 && string(s.Additional) != "false" {
		open = true
	}
	return props, required, open
}

// Check fails t when body does not fit the named definition.
func (d *Doc) Check(t testing.TB, definition string, body []byte) {
	t.Helper()
	d.check(t, definition, &schema{Ref: "#/definitions/" + definition}, d.defs, body)
}

func (d *Doc) check(t testing.TB, where string, s *schema, file definitions, body []byte) {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Errorf("%s: not a JSON object: %v", where, err)
		return
	}
	props, required, open := d.flatten(s, file)
	for _, r := range required {
		if _, ok := obj[r]; !ok {
			t.Errorf("%s: required property %q is missing", where, r)
		}
	}
	for k, v := range obj {
		p, known := props[k]
		if !known {
			if !open {
				t.Errorf("%s: property %q is not in the spec", where, k)
			}
			continue
		}
		d.checkValue(t, where+"."+k, p, v)
	}
}

// checkValue recurses into objects and arrays whose schema names a
// model; scalars and free-form maps are accepted as they are.
func (d *Doc) checkValue(t testing.TB, where string, p prop, v json.RawMessage) {
	t.Helper()
	v = bytes.TrimSpace(v)
	if len(v) == 0 {
		return
	}
	switch v[0] {
	case '{':
		if p.s.isModel() {
			d.check(t, where, &p.s, p.file, v)
		}
	case '[':
		if p.s.Items == nil || !p.s.Items.isModel() {
			return
		}
		var items []json.RawMessage
		if err := json.Unmarshal(v, &items); err != nil {
			t.Errorf("%s: not an array: %v", where, err)
			return
		}
		for i, item := range items {
			d.checkValue(t, fmt.Sprintf("%s[%d]", where, i), prop{s: *p.s.Items, file: p.file}, item)
		}
	}
}
