package azurite

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

// Find resolves the azurite-blob to run: the configured command on
// PATH first (an install of your own wins), else the copy that
// "armite azurite install" put under installDir. The error names both
// places and the fix, so the boot log and doctor can print it as is.
func Find(command, installDir string) (string, error) {
	if path, err := exec.LookPath(command); err == nil {
		return path, nil
	}
	installed := filepath.Join(installDir, "node_modules", ".bin", "azurite-blob")
	if path, err := exec.LookPath(installed); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("%s is not on PATH and not installed under %s: "+
		"run `armite azurite install` (needs npm), or npm install -g azurite", command, installDir)
}
