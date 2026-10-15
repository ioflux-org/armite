//go:build windows

package azurite

import (
	"os/exec"
	"strconv"
)

// interrupt ends the process and everything under it. Windows cannot
// deliver a signal to a child, and the child here is the cmd.exe that
// npm's azurite-blob.cmd shim is: killing it alone leaves the node
// underneath listening on the port with the old account list. taskkill
// /T walks the tree; /F is the only way to end a console program that
// has no window to close.
func interrupt(cmd *exec.Cmd) {
	_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
}
