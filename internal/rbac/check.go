package rbac

// Checker evaluates RBAC decisions against a set of role definitions and
// an assignment store. It is the single evaluator for both planes:
// management actions (Actions/NotActions) and data actions
// (DataActions/NotDataActions), selected by isDataAction.
type Checker struct {
	defs  map[string]RoleDefinition
	store *AssignmentStore
}

// NewChecker returns a Checker that evaluates against defs and store.
func NewChecker(defs map[string]RoleDefinition, store *AssignmentStore) *Checker {
	return &Checker{defs: defs, store: store}
}

// Check reports whether principalID may perform action at scope. The
// decision is default-deny: true requires at least one assignment whose
// role definition allows the action. The error is always nil today; it
// is part of the signature so a database-backed evaluation can fail
// without breaking callers.
func (c *Checker) Check(principalID, action, scope string, isDataAction bool) (bool, error) {
	for _, a := range c.store.forPrincipalAtScope(principalID, scope) {
		def, ok := c.defs[a.RoleDefinitionID]
		if !ok {
			continue // dangling reference grants nothing: deny by default
		}
		for _, perm := range def.Permissions {
			allows, denies := perm.Actions, perm.NotActions
			if isDataAction {
				allows, denies = perm.DataActions, perm.NotDataActions
			}
			if matchesAny(allows, action) && !matchesAny(denies, action) {
				return true, nil
			}
		}
	}
	return false, nil
}

// matchesAny reports whether action matches at least one pattern.
func matchesAny(patterns []string, action string) bool {
	for _, p := range patterns {
		if matchPattern(p, action) {
			return true
		}
	}
	return false
}
