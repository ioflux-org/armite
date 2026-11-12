package azurite

import (
	"path/filepath"

	"github.com/ioflux-org/armite/internal/config"
)

// Version is the Azurite the server is tested against; keep it in step
// with the Dockerfile and ci.yml.
const Version = "3.37.0"

// InstallDir is where "armite azurite install" puts Azurite and where
// Find looks for it when the command is not on PATH.
func InstallDir() string {
	return filepath.Join(config.CacheDir(), "azurite")
}
