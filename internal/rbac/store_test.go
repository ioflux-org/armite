package rbac

import (
	"strings"
	"testing"
)

const testPrincipal = "44444444-4444-4444-4444-444444444444"

func TestStoreAddAndQuery(t *testing.T) {
	s := NewAssignmentStore()
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
	if got[0].Scope != "/subscriptions/abc" {
		t.Errorf("Scope = %q, want normalized %q", got[0].Scope, "/subscriptions/abc")
	}
}

func TestStoreFiltering(t *testing.T) {
	s := NewAssignmentStore()
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
