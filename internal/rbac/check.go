package rbac

// Checker evaluates RBAC decisions against a set of role definitions and
// an assignment store. It is the single evaluator for both planes:
// management actions (Actions/NotActions) and data actions
// (DataActions/NotDataActions), selected by isDataAction.
type Checker struct {
	defs   map[string]RoleDefinition
	store  *AssignmentStore
	groups func(principalID string) []string
}

// NewChecker returns a Checker that evaluates against defs and store.
func NewChecker(defs map[string]RoleDefinition, store *AssignmentStore) *Checker {
	return &Checker{defs: defs, store: store}
}

// WithGroups makes the checker count a principal's groups: groups
// returns the ids of every group the principal belongs to, directly or
// through other groups, and an assignment to any of them is then an
// assignment to the principal. It is asked on every check, so a
// membership change shows on the next request. It returns c; call it
// before serving.
func (c *Checker) WithGroups(groups func(principalID string) []string) *Checker {
	c.groups = groups
	return c
}

// Check reports whether principalID may perform action at scope. The
// decision is default-deny: true requires at least one assignment - to
// the principal or to a group it is in - whose role definition allows
// the action. The error is always nil today; it is part of the
// signature so a database-backed evaluation can fail without breaking
// callers.
func (c *Checker) Check(principalID, action, scope string, isDataAction bool) (bool, error) {
	principals := []string{principalID}
	if c.groups != nil {
		principals = append(principals, c.groups(principalID)...)
	}
	for _, principal := range principals {
		for _, a := range c.store.forPrincipalAtScope(principal, scope) {
			if c.grants(a, action, isDataAction) {
				return true, nil
			}
		}
	}
	return false, nil
}

// grants reports whether the assignment's role allows action.
func (c *Checker) grants(a RoleAssignment, action string, isDataAction bool) bool {
	def, ok := c.defs[a.RoleDefinitionID]
	if !ok {
		return false // dangling reference grants nothing: deny by default
	}
	for _, perm := range def.Permissions {
		allows, denies := perm.Actions, perm.NotActions
		if isDataAction {
			allows, denies = perm.DataActions, perm.NotDataActions
		}
		if matchesAny(allows, action) && !matchesAny(denies, action) {
			return true
		}
	}
	return false
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
