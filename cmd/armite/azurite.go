package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ioflux-org/armite/internal/config"
)

// azuriteVersion is the Azurite the server is tested against; keep it
// in step with the Dockerfile and ci.yml.
const azuriteVersion = "3.37.0"

// azuriteInstallDir is where "armite azurite install" puts Azurite and
// where the server and doctor look for it.
func azuriteInstallDir() string {
	return filepath.Join(config.CacheDir(), "azurite")
}

// runAzurite serves "armite azurite install [version]": a pinned
// Azurite under the cache directory, installed with the npm on this
// machine, found afterwards without any PATH work. Re-running it
// reinstalls; deleting the directory uninstalls.
func runAzurite(args []string) {
	if len(args) == 0 || args[0] != "install" {
		fmt.Fprintln(os.Stderr, "usage: armite azurite install [version]")
		os.Exit(2)
	}
	version := azuriteVersion
	if len(args) > 1 {
		version = args[1]
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		log.Fatal("npm is not on PATH: install Node.js LTS from https://nodejs.org (it brings npm) " +
			"and run this again, or npm install -g azurite yourself")
	}
	dir := azuriteInstallDir()
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
