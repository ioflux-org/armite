package azurite

import (
	"os/exec"
	"syscall"
)

// dieWithParent asks the kernel to end the child when Armite ends,
// however it ends: a killed Armite must not leave an Azurite holding
// the port for the next boot.
func dieWithParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
