package rbac

import (
	"fmt"
	"strings"
	"time"
)

// Seed adds boot-time assignments, refusing any whose role definition is
// unknown. Evaluation tolerates a dangling reference (it grants nothing);
// boot does not - a typo in config must stop the process, not silently
// deny everything. Assignments before the bad one are already stored;
// callers are expected to exit on error. Seeds get the ARM fields a
// client would have supplied: every configured principal is a service
// principal, and boot time is their creation time.
func Seed(store *AssignmentStore, defs map[string]RoleDefinition, assignments []RoleAssignment) error {
	now := time.Now()
	for _, a := range assignments {
		id := strings.ToLower(bareGUID(a.RoleDefinitionID))
		if _, ok := defs[id]; !ok {
			return fmt.Errorf("seed assignment for principal %s: unknown role definition %q", a.PrincipalID, a.RoleDefinitionID)
		}
		if a.PrincipalType == "" {
			a.PrincipalType = "ServicePrincipal"
		}
		if a.CreatedOn.IsZero() {
			a.CreatedOn = now
		}
		if err := store.Add(a); err != nil {
			return fmt.Errorf("seed assignment for principal %s: %w", a.PrincipalID, err)
		}
	}
	return nil
}
