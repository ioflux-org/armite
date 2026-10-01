package rbac

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/state"
)

const testPrincipal = "44444444-4444-4444-4444-444444444444"

// reopen builds a store over the journal in dir and replays it, as a
// restart does.
func reopen(t *testing.T, dir string) (*state.Log, *AssignmentStore) {
	t.Helper()
	log, err := state.Open(dir, bytes.Repeat([]byte{1}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	s := NewAssignmentStore(log)
	if err := log.Replay(); err != nil {
		t.Fatal(err)
	}
	return log, s
}

func TestStoreAddAndQuery(t *testing.T) {
	s := NewAssignmentStore(nil)
	err := s.Add(RoleAssignment{
		PrincipalID:      testPrincipal,
		RoleDefinitionID: "/providers/Microsoft.Authorization/roleDefinitions/" + ownerID,
		Scope:            "/subscriptions/ABC/",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	got := s.forPrincipalAtScope(testPrincipal, "/subscriptions/abc/resourcegroups/dev")
	if len(got) != 1 {
		t.Fatalf("got %d assignments, want 1", len(got))
	}
	if got[0].RoleDefinitionID != ownerID {
		t.Errorf("RoleDefinitionID = %q, want bare GUID %q", got[0].RoleDefinitionID, ownerID)
	}
	if got[0].Scope != "/subscriptions/ABC" {
		t.Errorf("Scope = %q, want casing kept and slash dropped: %q", got[0].Scope, "/subscriptions/ABC")
	}
}

func TestStoreFiltering(t *testing.T) {
	s := NewAssignmentStore(nil)
	if err := s.Add(RoleAssignment{
		PrincipalID:      testPrincipal,
		RoleDefinitionID: readerID,
		Scope:            "/subscriptions/abc/resourcegroups/dev",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if got := s.forPrincipalAtScope(testPrincipal, "/subscriptions/abc"); len(got) != 0 {
		t.Errorf("rg-scoped assignment leaked to subscription-scope query: %v", got)
	}
	if got := s.forPrincipalAtScope("99999999-9999-9999-9999-999999999999", "/subscriptions/abc/resourcegroups/dev"); len(got) != 0 {
		t.Errorf("wrong principal got assignments: %v", got)
	}
	if got := s.forPrincipalAtScope(strings.ToUpper(testPrincipal), "/subscriptions/ABC/resourceGroups/Dev/"); len(got) != 1 {
		t.Errorf("uppercase principal + messy scope: got %d assignments, want 1", len(got))
	}
}

func TestAddCanonicalizes(t *testing.T) {
	s := NewAssignmentStore(nil)
	err := s.Add(RoleAssignment{
		PrincipalID:      strings.ToUpper(testPrincipal),
		RoleDefinitionID: "/providers/Microsoft.Authorization/roleDefinitions/" + strings.ToUpper(ownerID),
		Scope:            "/subscriptions/ABC/resourceGroups/Dev/",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	list, err := s.List("/", false)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d assignments, %v; want 1", len(list), err)
	}
	got := list[0]
	if got.PrincipalID != testPrincipal || got.RoleDefinitionID != ownerID {
		t.Errorf("principal/role = %q/%q, want lowercase bare values", got.PrincipalID, got.RoleDefinitionID)
	}
	if got.Scope != "/subscriptions/ABC/resourceGroups/Dev" {
		t.Errorf("Scope = %q, want casing kept and the trailing slash gone", got.Scope)
	}
	wantID := got.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + got.Name
	if got.ID != wantID {
		t.Errorf("ID = %q, want %q", got.ID, wantID)
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuid.MatchString(got.Name) {
		t.Errorf("derived Name = %q, want a version-5 UUID shape", got.Name)
	}
}

func TestDeriveNameIsStable(t *testing.T) {
	a := deriveName(testPrincipal, ownerID, "/subscriptions/abc")
	b := deriveName(testPrincipal, ownerID, "/subscriptions/abc")
	c := deriveName(testPrincipal, ownerID, "/subscriptions/abc/resourcegroups/dev")
	if a != b {
		t.Errorf("same triple gave different names: %s vs %s", a, b)
	}
	if a == c {
		t.Errorf("different scopes gave the same name: %s", a)
	}
}

// named builds an assignment for testPrincipal with an explicit name.
func named(name, role, scope string) RoleAssignment {
	return RoleAssignment{Name: name, PrincipalID: testPrincipal, RoleDefinitionID: role, Scope: scope}
}

// errAny marks a table row that wants some error without naming it.
var errAny = errors.New("any error")

func TestAddRefusesDuplicates(t *testing.T) {
	s := NewAssignmentStore(nil)
	const sub = "/subscriptions/abc"
	first := named("Name-1", ownerID, sub)
	if err := s.Add(first); err != nil {
		t.Fatalf("Add: %v", err)
	}
	tests := []struct {
		name string
		a    RoleAssignment
		want error // nil means accepted
	}{
		{"same name again", first, ErrAssignmentNameTaken},
		{"same name, other casing", named("name-1", readerID, sub), ErrAssignmentNameTaken},
		{"same triple, new name", named("name-2", ownerID, sub), ErrAssignmentExists},
		{"same triple, scope casing differs", named("name-3", ownerID, "/Subscriptions/ABC/"), ErrAssignmentExists},
		{"same principal and role, child scope", named("name-4", ownerID, sub+"/resourceGroups/dev"), nil},
		{"same principal and scope, other role", named("name-5", readerID, sub), nil},
		{"no principal", RoleAssignment{Name: "name-6", RoleDefinitionID: readerID, Scope: sub}, errAny},
	}
	for _, tt := range tests {
		err := s.Add(tt.a)
		switch {
		case tt.want == nil && err != nil:
			t.Errorf("%s: Add = %v, want accepted", tt.name, err)
		case tt.want == errAny && err == nil:
			t.Errorf("%s: Add accepted, want an error", tt.name)
		case tt.want != nil && tt.want != errAny && !errors.Is(err, tt.want):
			t.Errorf("%s: Add = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestGetDeleteRevokes(t *testing.T) {
	s := NewAssignmentStore(nil)
	const (
		name  = "revoke-me"
		sub   = "/subscriptions/abc"
		rg    = sub + "/resourceGroups/dev"
		write = "Microsoft.Resources/subscriptions/resourceGroups/write"
	)
	if err := s.Add(named(name, ownerID, sub)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	everything := []Permission{{Actions: []string{"*"}}}
	defs := map[string]RoleDefinition{ownerID: {Name: ownerID, Permissions: everything}}
	checker := NewChecker(defs, s)

	if got, err := s.Get(strings.ToUpper(name)); err != nil || got.Name != name {
		t.Errorf("Get with other casing = %+v, %v; want the assignment", got, err)
	}
	if ok, _ := checker.Check(testPrincipal, write, rg, false); !ok {
		t.Fatal("Check before Delete = false, want true")
	}

	deleted, err := s.Delete(name)
	if err != nil || deleted.Name != name {
		t.Fatalf("Delete = %+v, %v; want the deleted assignment", deleted, err)
	}
	if _, err := s.Get(name); !errors.Is(err, ErrAssignmentNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrAssignmentNotFound", err)
	}
	if _, err := s.Delete(name); !errors.Is(err, ErrAssignmentNotFound) {
		t.Errorf("second Delete: err = %v, want ErrAssignmentNotFound", err)
	}
	if ok, _ := checker.Check(testPrincipal, write, rg, false); ok {
		t.Error("Check after Delete = true, want false: revocation must take effect at once")
	}
}

func TestListForScope(t *testing.T) {
	s := NewAssignmentStore(nil)
	const (
		sub   = "/subscriptions/abc"
		rg    = sub + "/resourceGroups/dev"
		vault = rg + "/providers/Microsoft.KeyVault/vaults/v1"
		other = "/subscriptions/other"
	)
	for i, scope := range []string{sub, rg, vault, other} {
		if err := s.Add(named("n"+string(rune('1'+i)), ownerID, scope)); err != nil {
			t.Fatalf("Add(%s): %v", scope, err)
		}
	}

	tests := []struct {
		name        string
		scope       string
		atScopeOnly bool
		want        string // last characters of the names, in order
	}{
		{"rg, at or above", rg, true, "1,2"},
		{"rg, at above and below", rg, false, "1,2,3"},
		{"sub, at or above, messy casing", strings.ToUpper(sub) + "/", true, "1"},
		{"sub, everything beneath", sub, false, "1,2,3"},
		{"vault sees its ancestors", vault, true, "1,2,3"},
		{"root sees all", "/", false, "1,2,3,4"},
		{"unrelated scope sees nothing", "/subscriptions/zzz", false, ""},
	}
	for _, tt := range tests {
		got, err := s.List(tt.scope, tt.atScopeOnly)
		if err != nil {
			t.Fatalf("%s: List: %v", tt.name, err)
		}
		if got == nil {
			t.Fatalf("%s: List returned nil, want a non-nil slice", tt.name)
		}
		var last []string
		for _, a := range got {
			last = append(last, a.Name[len(a.Name)-1:])
		}
		if joined := strings.Join(last, ","); joined != tt.want {
			t.Errorf("%s: List = [%s], want [%s]", tt.name, joined, tt.want)
		}
	}
}

func TestAssignmentsSurviveReplay(t *testing.T) {
	dir := t.TempDir()
	log, s := reopen(t, dir)
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	keep := RoleAssignment{Name: "AAAA", PrincipalID: testPrincipal, RoleDefinitionID: ownerID,
		Scope: "/subscriptions/ABC", PrincipalType: "ServicePrincipal", CreatedOn: created}
	drop := RoleAssignment{Name: "BBBB", PrincipalID: testPrincipal, RoleDefinitionID: readerID,
		Scope: "/subscriptions/ABC/resourceGroups/dev"}
	for _, a := range []RoleAssignment{keep, drop} {
		if err := s.Add(a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Delete("bbbb"); err != nil {
		t.Fatal(err)
	}
	log.Close()

	log, s = reopen(t, dir)
	defer log.Close()
	got, err := s.Get("aaaa")
	if err != nil || got.Scope != "/subscriptions/ABC" || got.RoleDefinitionID != ownerID ||
		!got.CreatedOn.Equal(created) || got.ID == "" {
		t.Errorf("after replay: %+v, %v", got, err)
	}
	if _, err := s.Get("bbbb"); !errors.Is(err, ErrAssignmentNotFound) {
		t.Errorf("a revoked assignment must stay revoked after replay: %v", err)
	}
	if err := s.Add(keep); !errors.Is(err, ErrAssignmentNameTaken) {
		t.Errorf("replayed assignments must count as taken: %v", err)
	}
}
