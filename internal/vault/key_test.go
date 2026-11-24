package vault

import (
	"strings"
	"testing"
)

func TestNewKeyIsRandomAndNonZero(t *testing.T) {
	a, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	b, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	if a.IsZero() || b.IsZero() {
		t.Fatal("NewKey returned an all-zero key")
	}
	if a == b {
		t.Fatal("two NewKey calls returned the same key")
	}
}

func TestParseKeyAcceptsExactly64HexChars(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	k, err := ParseKey(hex64)
	if err != nil {
		t.Fatalf("ParseKey(valid): %v", err)
	}
	if k[0] != 0xab || k[31] != 0xab {
		t.Fatalf("ParseKey decoded wrong bytes: % x", k[:4])
	}
	// Surrounding whitespace from an env file is tolerated.
	if _, err := ParseKey("  " + hex64 + "\n"); err != nil {
		t.Fatalf("ParseKey(padded): %v", err)
	}
}

func TestParseKeyRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"too short": strings.Repeat("ab", 31),
		"too long":  strings.Repeat("ab", 33),
		"not hex":   strings.Repeat("zz", 32),
		"all zero":  strings.Repeat("00", 32),
	}
	for name, in := range cases {
		if _, err := ParseKey(in); err == nil {
			t.Errorf("ParseKey(%s) = nil error, want rejection", name)
		}
	}
}

func TestParseKeyErrorNeverEchoesTheInput(t *testing.T) {
	secret := strings.Repeat("zy", 32)
	_, err := ParseKey(secret)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "zy") {
		t.Fatalf("error leaks key material: %v", err)
	}
}

func TestDBKeyIsDeterministicAndSeparatedByName(t *testing.T) {
	k, _ := ParseKey(strings.Repeat("11", 32))
	m1, m2 := k.DBKey("messages"), k.DBKey("messages")
	w := k.DBKey("whatsapp")
	if m1 != m2 {
		t.Fatal("DBKey is not deterministic")
	}
	if m1 == w {
		t.Fatal("different database names produced the same subkey")
	}
	if m1 == [32]byte(k) {
		t.Fatal("subkey equals the master key")
	}
	other, _ := ParseKey(strings.Repeat("22", 32))
	if other.DBKey("messages") == m1 {
		t.Fatal("different master keys produced the same subkey")
	}
}
