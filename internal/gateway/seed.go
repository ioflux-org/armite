package gateway

import (
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/rbac"
)

// SeedAssignments converts the configured boot-time grants into rbac
// assignments. The conversion lives here, not in rbac, so rbac stays
// independent of config - it is meant to be publishable on its own.
func SeedAssignments(cfg config.Config) []rbac.RoleAssignment {
	out := make([]rbac.RoleAssignment, 0, len(cfg.RoleAssignments))
	for _, s := range cfg.RoleAssignments {
		out = append(out, rbac.RoleAssignment{
			PrincipalID:      s.PrincipalID,
			RoleDefinitionID: s.RoleDefinitionID,
			Scope:            s.Scope,
		})
	}
	return out
}
