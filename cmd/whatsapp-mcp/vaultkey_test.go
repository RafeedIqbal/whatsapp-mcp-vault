package main

import (
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestVaultKeyFromEnvReadsTheConfiguredKey(t *testing.T) {
	want := strings.Repeat("c4", 32)
	k, err := vaultKeyFromEnv(envOf(map[string]string{vaultKeyEnv: want}))
	if err != nil {
		t.Fatalf("vaultKeyFromEnv: %v", err)
	}
	if k[0] != 0xc4 || k[31] != 0xc4 {
		t.Fatalf("decoded wrong key bytes")
	}
}

func TestVaultKeyFromEnvFailsClosedWhenUnset(t *testing.T) {
	_, err := vaultKeyFromEnv(envOf(nil))
	if err == nil {
		t.Fatal("no key configured but no error: the store would have nothing to encrypt with")
	}
	// The operator must be told which variable to set.
	if !strings.Contains(err.Error(), vaultKeyEnv) {
		t.Fatalf("error does not name %s: %v", vaultKeyEnv, err)
	}
}

func TestVaultKeyFromEnvNeverEchoesABadValue(t *testing.T) {
	bad := "hunter2-not-a-real-key"
	_, err := vaultKeyFromEnv(envOf(map[string]string{vaultKeyEnv: bad}))
	if err == nil {
		t.Fatal("want error for a malformed key")
	}
	if strings.Contains(err.Error(), bad) {
		t.Fatalf("error echoes the configured value: %v", err)
	}
}
