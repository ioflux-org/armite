//go:build !linux

package azurite

import "os/exec"

// dieWithParent is Linux-only; elsewhere a killed Armite can leave
// Azurite running, and the next boot reports the port in use.
func dieWithParent(cmd *exec.Cmd) {}
