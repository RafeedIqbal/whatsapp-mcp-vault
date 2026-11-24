package main

import (
	"fmt"
	"strings"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

// vaultKeyEnv names the variable holding the instance data key. It belongs in
// the host's secret settings, never on the data disk it protects.
const vaultKeyEnv = "WHATSAPP_MCP_VAULT_KEY"

// vaultKeyFromEnv returns the configured data key. There is no fallback: with
// no key the store cannot be opened, because it is never written unencrypted.
func vaultKeyFromEnv(getenv func(string) string) (vault.Key, error) {
	raw := getenv(vaultKeyEnv)
	if strings.TrimSpace(raw) == "" {
		return vault.Key{}, fmt.Errorf("%s is not set: the store is encrypted and needs a 64-hex-character key "+
			"(generate one with `openssl rand -hex 32` and keep it in your host's secret settings, not on the data disk)", vaultKeyEnv)
	}
	key, err := vault.ParseKey(raw)
	if err != nil {
		return vault.Key{}, fmt.Errorf("%s is invalid: %w", vaultKeyEnv, err)
	}
	return key, nil
}
