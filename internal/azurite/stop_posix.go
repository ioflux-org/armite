//go:build !windows

package azurite

import (
	"os"
	"os/exec"
)

// interrupt asks Azurite to stop politely, so it flushes its metadata
// database; stopLocked falls back to Kill after five seconds.
func interrupt(cmd *exec.Cmd) {
	_ = cmd.Process.Signal(os.Interrupt)
}
