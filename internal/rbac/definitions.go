package rbac

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// Permission is one entry of a role definition's permissions array.
// Azure models this as an array; built-in roles always have exactly one
// entry, but we keep the array so a raw `az role definition list` dump
// parses unmodified.
type Permission struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

// RoleDefinition mirrors the `az role definition list` JSON shape.
// Name holds the role's GUID; for built-in roles it is globally fixed
// across all of Azure.
type RoleDefinition struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	RoleName         string       `json:"roleName"`
	RoleType         string       `json:"roleType"`
	Description      string       `json:"description"`
	Permissions      []Permission `json:"permissions"`
	AssignableScopes []string     `json:"assignableScopes"`
	Type             string       `json:"type"`
}

//go:embed seed/builtin_roles.json
var builtinRolesJSON []byte

// LoadBuiltinRoles parses the embedded seed dump and indexes the role
// definitions by GUID (the Name field).
func LoadBuiltinRoles() (map[string]RoleDefinition, error) {
	var defs []RoleDefinition
	if err := json.Unmarshal(builtinRolesJSON, &defs); err != nil {
		return nil, fmt.Errorf("parse builtin roles seed: %w", err)
	}
	byID := make(map[string]RoleDefinition, len(defs))
	for _, d := range defs {
		if d.Name == "" {
			return nil, fmt.Errorf("role definition %q has empty name (GUID)", d.RoleName)
		}
		if _, dup := byID[d.Name]; dup {
			return nil, fmt.Errorf("duplicate role definition GUID %s", d.Name)
		}
		byID[d.Name] = d
	}
	return byID, nil
}
