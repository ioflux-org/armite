package azurite

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindPrefersPathThenTheInstall(t *testing.T) {
	onPath, install := t.TempDir(), t.TempDir()
	t.Setenv("PATH", onPath)
	name := "azurite-blob"
	if runtime.GOOS == "windows" {
		name += ".cmd"
	}
	if _, err := Find("azurite-blob", install); err == nil {
		t.Fatal("nothing anywhere, expected an error")
	}
	bin := filepath.Join(install, "node_modules", ".bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := Find("azurite-blob", install); err != nil || !strings.HasPrefix(got, bin) {
		t.Fatalf("installed copy: %q, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(onPath, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := Find("azurite-blob", install); err != nil || !strings.HasPrefix(got, onPath) {
		t.Fatalf("PATH must win: %q, %v", got, err)
	}
}
