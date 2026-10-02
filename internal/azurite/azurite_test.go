package azurite

import (
	"strings"
	"testing"
)

func TestAccountsEnv(t *testing.T) {
	got := accountsEnv(map[string]string{"zeta": "k2", "alpha": "k1"})
	if got != "alpha:k1;zeta:k2" {
		t.Errorf("accountsEnv = %q, want names sorted, name:key joined by ;", got)
	}
	empty := accountsEnv(nil)
	if !strings.HasPrefix(empty, "placeholder:") || len(empty) < len("placeholder:")+80 {
		t.Errorf("no accounts must yield a placeholder with a random key, got %q", empty)
	}
	if accountsEnv(nil) == empty {
		t.Error("the placeholder key must differ between calls")
	}
}
