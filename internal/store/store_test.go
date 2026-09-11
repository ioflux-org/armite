package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	sub    = "/subscriptions/22222222-2222-2222-2222-222222222222"
	rgType = "Microsoft.Resources/resourceGroups"
	kvType = "Microsoft.KeyVault/vaults"
	props  = `{"provisioningState":"Succeeded"}`
)

// rg builds a resource group envelope the way the provider will.
func rg(name string) Resource {
	return Resource{
		ID:         sub + "/resourceGroups/" + name,
		Name:       name,
		Type:       rgType,
		Location:   "eastus",
		Tags:       map[string]string{"env": "dev"},
		Properties: json.RawMessage(props),
	}
}

// vault builds a vault envelope inside resource group rgName.
func vault(rgName, name string) Resource {
	return Resource{
		ID:       sub + "/resourceGroups/" + rgName + "/providers/" + kvType + "/" + name,
		Name:     name,
		Type:     kvType,
		Location: "eastus",
	}
}

func mustPut(t *testing.T, s *Store, r Resource) bool {
	t.Helper()
	created, err := s.Put(r)
	if err != nil {
		t.Fatalf("Put(%s): %v", r.ID, err)
	}
	return created
}

func TestPutGetRoundTrip(t *testing.T) {
	s := New()
	if !mustPut(t, s, rg("Dev")) {
		t.Fatal("first Put: created = false, want true")
	}

	got, err := s.Get(sub + "/RESOURCEGROUPS/dev")
	if err != nil {
		t.Fatalf("Get with other casing: %v", err)
	}
	if got.ID != sub+"/resourceGroups/Dev" || got.Name != "Dev" {
		t.Errorf("Get echoed id %q name %q, want the casing given to Put", got.ID, got.Name)
	}
	if got.Tags["env"] != "dev" || string(got.Properties) != props {
		t.Errorf("Get lost tags or properties: %+v", got)
	}
}

func TestPutReplaces(t *testing.T) {
	s := New()
	mustPut(t, s, rg("dev"))

	updated := rg("dev")
	updated.Location = "westus"
	updated.Tags = nil
	if mustPut(t, s, updated) {
		t.Fatal("second Put: created = true, want false")
	}

	got, err := s.Get(updated.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Location != "westus" || got.Tags != nil {
		t.Errorf("Put did not replace the whole resource: %+v", got)
	}
}

func TestPutRejectsEmptyID(t *testing.T) {
	s := New()
	if _, err := s.Put(Resource{Name: "dev", Type: rgType}); err == nil {
		t.Fatal("Put with empty ID: err = nil, want error")
	}
}

func TestGetMissing(t *testing.T) {
	s := New()
	if _, err := s.Get(sub + "/resourceGroups/random"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteReportsExistence(t *testing.T) {
	s := New()
	mustPut(t, s, rg("dev"))

	deleted, err := s.Delete(sub + "/RESOURCEGROUPS/dev")
	if err != nil || !deleted {
		t.Fatalf("first Delete = (%v, %v), want (true, nil)", deleted, err)
	}
	deleted, err = s.Delete(sub + "/resourceGroups/dev")
	if err != nil || deleted {
		t.Fatalf("second Delete = (%v, %v), want (false, nil)", deleted, err)
	}
	if _, err := s.Get(sub + "/resourceGroups/dev"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrNotFound", err)
	}
}

func TestList(t *testing.T) {
	s := New()
	mustPut(t, s, rg("beta"))
	mustPut(t, s, rg("alpha"))
	mustPut(t, s, rg("alpha2"))
	mustPut(t, s, vault("alpha", "v1"))
	mustPut(t, s, vault("alpha2", "v2"))

	alpha := sub + "/resourceGroups/alpha"
	allRGs := []string{alpha, alpha + "2", sub + "/resourceGroups/beta"}
	v1 := vault("alpha", "v1").ID
	v2 := vault("alpha2", "v2").ID
	up := strings.ToUpper(sub) + "/"

	tests := []struct {
		name  string
		scope string
		typ   string
		want  []string // IDs, in order
	}{
		{"rgs under the sub, sorted", sub, rgType, allRGs},
		{"type is case-insensitive", sub, "MICROSOFT.resources/resourcegroups", allRGs},
		{"scope case-insensitive, trailing slash ok", up, rgType, allRGs},
		{"vaults at any depth under the sub", sub, kvType, []string{v1, v2}},
		{"vaults under one rg", alpha, kvType, []string{v1}},
		{"segment boundary: alpha is not alpha2", alpha + "2", kvType, []string{v2}},
		{"strict: the scope itself is excluded", alpha, rgType, nil},
		{"root scope lists everything of the type", "/", kvType, []string{v1, v2}},
		{"empty scope is root", "", rgType, allRGs},
		{"other subscription: nothing", "/subscriptions/other", rgType, nil},
		{"unknown type: nothing", sub, "Microsoft.Storage/storageAccounts", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.List(tt.scope, tt.typ)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if got == nil {
				t.Fatal("List returned nil, want a non-nil slice")
			}
			var ids []string
			for _, r := range got {
				ids = append(ids, r.ID)
			}
			if !slices.Equal(ids, tt.want) {
				t.Errorf("List(%q, %q) = %v, want %v", tt.scope, tt.typ, ids, tt.want)
			}
		})
	}
}

func TestCopiesInAndOut(t *testing.T) {
	s := New()
	in := rg("dev")
	mustPut(t, s, in)

	// Mutating the caller's value after Put must not reach the store.
	in.Tags["env"] = "prod"
	in.Properties[1] = 'X'
	got, err := s.Get(in.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Tags["env"] != "dev" || string(got.Properties) != props {
		t.Errorf("Put shared memory with the caller: %+v", got)
	}

	// Mutating what Get returned must not reach the store either.
	got.Tags["env"] = "prod"
	got.Properties[1] = 'X'
	again, err := s.Get(in.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if again.Tags["env"] != "dev" || string(again.Properties) != props {
		t.Errorf("Get shared memory with the caller: %+v", again)
	}

	// And the same for List.
	list, err := s.List(sub, rgType)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d resources, %v; want 1, nil", len(list), err)
	}
	list[0].Tags["env"] = "prod"
	list[0].Properties[1] = 'X'
	again, err = s.Get(in.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if again.Tags["env"] != "dev" || string(again.Properties) != props {
		t.Errorf("List shared memory with the caller: %+v", again)
	}
}

// TestConcurrentAccess has no assertions of its own: run with -race, the
// detector fails the test if two goroutines touch the map unsynchronized.
func TestConcurrentAccess(t *testing.T) {
	s := New()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			r := rg(fmt.Sprintf("rg%d", i))
			for range 50 {
				if _, err := s.Put(r); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.Get(r.ID); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.List(sub, rgType); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.Delete(r.ID); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}
