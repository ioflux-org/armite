package rbac

import (
	"strings"
	"testing"
)

func TestSeed(t *testing.T) {
	defs, err := LoadBuiltinRoles()
	if err != nil {
		t.Fatal(err)
	}
	const (
		owner = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
		sub   = "/subscriptions/sub-1"
	)

	store := NewAssignmentStore(nil)
	good := []RoleAssignment{
		{PrincipalID: "p1", RoleDefinitionID: owner, Scope: sub},
		{PrincipalID: "p2", RoleDefinitionID: "/providers/Microsoft.Authorization/roleDefinitions/" + owner, Scope: sub},
	}
	if err := Seed(store, defs, good); err != nil {
		t.Fatalf("Seed(good) failed: %v", err)
	}
	checker := NewChecker(defs, store)
	for _, p := range []string{"p1", "p2"} {
		ok, err := checker.Check(p, "Microsoft.Resources/subscriptions/resourceGroups/write", sub+"/resourceGroups/dev", false)
		if err != nil || !ok {
			t.Errorf("after Seed, Check(%s) = %v , %v, want true", p, ok, err)
		}
	}

	seeded, err := store.List(sub, true)
	if err != nil || len(seeded) != 2 {
		t.Fatalf("List after Seed = %d assignments, %v; want 2", len(seeded), err)
	}
	for _, a := range seeded {
		if a.Name == "" || a.ID == "" || a.PrincipalType != "ServicePrincipal" || a.CreatedOn.IsZero() {
			t.Errorf("seeded assignment lacks ARM fields: %+v", a)
		}
	}

	bad := []RoleAssignment{
		{PrincipalID: "p3", RoleDefinitionID: "not-a-role", Scope: sub},
	}
	err = Seed(NewAssignmentStore(nil), defs, bad)
	if err == nil || !strings.Contains(err.Error(), "not-a-role") {
		t.Errorf("Seed(bad) error = %v, want an error naming the unknown role", err)
	}
}

// On a restart the seeds already exist, replayed from the journal; Seed
// must leave them alone rather than refuse to boot.
func TestSeedIsIdempotent(t *testing.T) {
	defs, err := LoadBuiltinRoles()
	if err != nil {
		t.Fatal(err)
	}
	const sub = "/subscriptions/sub-1"
	seeds := []RoleAssignment{
		{PrincipalID: "p1", RoleDefinitionID: ownerID, Scope: sub},
	}
	store := NewAssignmentStore(nil)
	for i := range 2 {
		if err := Seed(store, defs, seeds); err != nil {
			t.Fatalf("Seed #%d: %v", i+1, err)
		}
	}
	// The same grant under a client-chosen name counts as seeded too.
	err = store.Add(RoleAssignment{Name: "client-chosen", PrincipalID: "p2",
		RoleDefinitionID: ownerID, Scope: sub})
	if err != nil {
		t.Fatal(err)
	}
	again := []RoleAssignment{{PrincipalID: "p2", RoleDefinitionID: ownerID, Scope: sub}}
	if err = Seed(store, defs, again); err != nil {
		t.Errorf("a seed already granted under another name: %v", err)
	}
	all, _ := store.List(sub, true)
	if len(all) != 2 {
		t.Errorf("%d assignments after repeated seeding, want 2", len(all))
	}
}

