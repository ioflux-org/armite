package rbac

import (
	"fmt"
	"strings"
)

// Seed adds boot-time assignments, refusing any whose role definition is
// unknown. Evaluation tolerates a dangling reference (it grants nothing);
// boot does not - a typo in config must stop the process, not silently
// deny everything. Assignments before the bad one are already stored;
// callers are expected to exit on error.
func Seed(store *AssignmentStore, defs map[string]RoleDefinition, assignments []RoleAssignment) error {
	for _, a := range assignments {
		id := strings.ToLower(bareGUID(a.RoleDefinitionID))
		if _, ok := defs[id]; !ok {
			return fmt.Errorf("seed assignment for principal %s: unknown role definition %q", a.PrincipalID, a.RoleDefinitionID)
		}
		if err := store.Add(a); err != nil {
			return fmt.Errorf("seed assignment for principal %s: %w", a.PrincipalID, err)
		}
	}
	return nil
}
