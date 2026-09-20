package spectest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recorder captures Errorf calls so a test can assert on failures the
// helper reports, instead of failing itself.
type recorder struct {
	testing.TB
	msgs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

const miniSpec = `{"definitions": {
	"Thing": {"required": ["name"], "allOf": [{"$ref": "#/definitions/Base"}],
			  "properties": {"name": {"type": "string"},
							 "inner": {"$ref": "#/definitions/Inner"},
							 "tags": {"type": "object", "additionalProperties": {"type": "string"}},
							 "list": {"type": "array", "items": {"$ref": "#/definitions/Inner"}}}},
	"Base": {"properties": {"id": {"type": "string"}}},
	"Inner": {"required": ["x"], "properties": {"x": {"type": "integer"}}}
  }}`

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheck(t *testing.T) {
	doc := Load(t, write(t, miniSpec), "")
	tests := []struct {
		name string
		body string
		want []string // substrings of the reported problems, in order
	}{
		{"fits", `{"id":"1","name":"a","inner":{"x":1},"tags":{"k":"v"},"list":[{"x":2}]}`, nil},
		{"missing required", `{"id":"1"}`, []string{`required property "name"`}},
		{"unknown top-level key", `{"name":"a","color":"red"}`, []string{`property "color"`}},
		{"unknown nested key via $ref", `{"name":"a","inner":{"x":1,"y":2}}`,
			[]string{`Thing.inner: property "y"`}},
		{"missing required in an array item", `{"name":"a","list":[{"x":1},{}]}`,
			[]string{`Thing.list[1]: required property "x"`}},
		{"free-form map is not inspected", `{"name":"a","tags":{"anything":"goes"}}`, nil},
	}
	for _, tt := range tests {
		rec := &recorder{TB: t}
		doc.Check(rec, "Thing", []byte(tt.body))
		if len(rec.msgs) != len(tt.want) {
			t.Errorf("%s: reported %v, want %d problems", tt.name, rec.msgs, len(tt.want))
			continue
		}
		for i, w := range tt.want {
			if !strings.Contains(rec.msgs[i], w) {
				t.Errorf("%s: problem %d = %q, want it to mention %q", tt.name, i, rec.msgs[i], w)
			}
		}
	}
}

func TestCommonTypesInheritance(t *testing.T) {
	const proxy = "../../common-types/resource-management/v5/types.json#/definitions/ProxyResource"
	spec := `{"definitions": {"Vault": {"required": ["properties"],
	  "allOf": [{"$ref": "` + proxy + `"}],
	  "properties": {"properties": {"type": "object", "properties": {"a": {"type": "string"}}}}}}}`
	doc := Load(t, write(t, spec), "testdata/common-types/v5/types.json")
	rec := &recorder{TB: t}
	body := `{"id":"i","name":"n","type":"t","properties":{"a":"1"},"bogus":1}`
	doc.Check(rec, "Vault", []byte(body))
	if len(rec.msgs) != 1 || !strings.Contains(rec.msgs[0], `"bogus"`) {
		t.Errorf("want one problem about bogus (id/name/type come from common-types), got %v", rec.msgs)
	}
}
