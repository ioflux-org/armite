package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ioflux-org/armite/internal/azurite"
)

// runAzurite serves "armite azurite install [version]": a pinned
// Azurite under the cache directory, installed with the npm on this
// machine, found afterwards without any PATH work. Re-running it
// reinstalls; deleting the directory uninstalls.
func runAzurite(args []string) {
	if len(args) == 0 || args[0] != "install" {
		fmt.Fprintln(os.Stderr, "usage: armite azurite install [version]")
		os.Exit(2)
	}
	version := azurite.Version
	if len(args) > 1 {
		version = args[1]
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		log.Fatal("npm is not on PATH: install Node.js LTS from https://nodejs.org (it brings npm) " +
			"and run this again, or npm install -g azurite yourself")
	}
	dir := azurite.InstallDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("installing azurite@%s under %s\n", version, dir)
	cmd := exec.Command(npm, "install", "--prefix", dir, "--no-audit", "--no-fund",
		"--loglevel=error", "azurite@"+version)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("npm install failed: %v", err)
	}
	path, err := exec.LookPath(filepath.Join(dir, "node_modules", ".bin", "azurite-blob"))
	if err != nil {
		log.Fatalf("npm finished but %s is not there: %v", dir, err)
	}
	fmt.Printf("installed %s\nthe server and `armite doctor` find it there; delete %s to remove it\n", path, dir)
}
