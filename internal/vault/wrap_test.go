package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// fastKDF keeps Argon2id cheap in tests; production uses DefaultKDFParams.
var fastKDF = KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}

func mustNewKey(t *testing.T) Key {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// --- passphrase wrap -------------------------------------------------------

func TestPassphraseWrapRoundTrips(t *testing.T) {
	k := mustNewKey(t)
	w, err := WrapWithPassphrase(k, "correct horse battery staple", fastKDF)
	if err != nil {
		t.Fatalf("WrapWithPassphrase: %v", err)
	}
	got, err := w.Unwrap("correct horse battery staple")
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got != k {
		t.Fatal("unwrapped key differs from the original")
	}
}

func TestPassphraseWrapRejectsTheWrongPassphrase(t *testing.T) {
	w, err := WrapWithPassphrase(mustNewKey(t), "correct horse battery staple", fastKDF)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []string{"correct horse battery stapler", "", "Correct horse battery staple"} {
		if _, err := w.Unwrap(wrong); !errors.Is(err, ErrWrongSecret) {
			t.Errorf("Unwrap(%q) err = %v, want ErrWrongSecret", wrong, err)
		}
	}
}

func TestPassphraseWrapDetectsTampering(t *testing.T) {
	w, err := WrapWithPassphrase(mustNewKey(t), "correct horse battery staple", fastKDF)
	if err != nil {
		t.Fatal(err)
	}
	for i := range w.Sealed {
		tampered := w
		tampered.Sealed = bytes.Clone(w.Sealed)
		tampered.Sealed[i] ^= 0x01
		if _, err := tampered.Unwrap("correct horse battery staple"); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("flipping byte %d of the sealed key was not detected (err=%v)", i, err)
		}
	}
	saltFlipped := w
	saltFlipped.Salt = bytes.Clone(w.Salt)
	saltFlipped.Salt[0] ^= 0x01
	if _, err := saltFlipped.Unwrap("correct horse battery staple"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("a changed salt was not detected (err=%v)", err)
	}
}

func TestPassphraseWrapIsDifferentEveryTime(t *testing.T) {
	k := mustNewKey(t)
	a, _ := WrapWithPassphrase(k, "correct horse battery staple", fastKDF)
	b, _ := WrapWithPassphrase(k, "correct horse battery staple", fastKDF)
	if bytes.Equal(a.Salt, b.Salt) || bytes.Equal(a.Sealed, b.Sealed) {
		t.Fatal("two wraps of the same key under the same passphrase are identical")
	}
}

func TestPassphraseWrapNeverContainsTheKey(t *testing.T) {
	k := mustNewKey(t)
	w, _ := WrapWithPassphrase(k, "correct horse battery staple", fastKDF)
	if bytes.Contains(w.Sealed, k[:]) || bytes.Contains(w.Sealed, k[:8]) {
		t.Fatal("sealed blob contains key bytes")
	}
}

func TestPassphraseWrapUsesItsOwnStoredCostSettings(t *testing.T) {
	// A wrap made with one cost setting must keep opening after the default
	// changes, because the settings travel with the wrap.
	k := mustNewKey(t)
	w, _ := WrapWithPassphrase(k, "correct horse battery staple", fastKDF)
	if w.Params != fastKDF {
		t.Fatalf("stored params = %+v, want %+v", w.Params, fastKDF)
	}
	changed := w
	changed.Params.Time++
	if _, err := changed.Unwrap("correct horse battery staple"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("different cost settings still opened the wrap (err=%v)", err)
	}
}

func TestPassphraseWrapRefusesUnsafeCostSettings(t *testing.T) {
	// Settings come back from disk; absurd values must not become a way to
	// exhaust memory or to make guessing free.
	for name, p := range map[string]KDFParams{
		"zero time":    {Time: 0, MemoryKiB: 8 * 1024, Threads: 1},
		"zero threads": {Time: 1, MemoryKiB: 8 * 1024, Threads: 0},
		"tiny memory":  {Time: 1, MemoryKiB: 16, Threads: 1},
		"huge memory":  {Time: 1, MemoryKiB: 64 * 1024 * 1024, Threads: 1},
	} {
		if _, err := WrapWithPassphrase(mustNewKey(t), "correct horse battery staple", p); err == nil {
			t.Errorf("%s: WrapWithPassphrase accepted %+v", name, p)
		}
		w := PassphraseWrap{Params: p, Salt: make([]byte, 16), Sealed: make([]byte, 72)}
		if _, err := w.Unwrap("x"); err == nil || errors.Is(err, ErrWrongSecret) {
			t.Errorf("%s: Unwrap ran the KDF with %+v (err=%v)", name, p, err)
		}
	}
}

func TestDefaultKDFParamsAreStrongEnough(t *testing.T) {
	p := DefaultKDFParams()
	// At least the OWASP-recommended Argon2id floor (19 MiB, 2 passes).
	if p.MemoryKiB < 19*1024 || p.Time < 2 || p.Threads < 1 {
		t.Fatalf("default Argon2id settings too weak: %+v", p)
	}
}

// --- secret wrap (tokens, codes, recovery codes) ---------------------------

func secret(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSecretWrapRoundTrips(t *testing.T) {
	k := mustNewKey(t)
	sealed, err := WrapWithSecret(k, secret(0x01), "access-token")
	if err != nil {
		t.Fatalf("WrapWithSecret: %v", err)
	}
	got, err := UnwrapWithSecret(sealed, secret(0x01), "access-token")
	if err != nil || got != k {
		t.Fatalf("UnwrapWithSecret: key match=%v err=%v", got == k, err)
	}
}

func TestSecretWrapRejectsTheWrongSecretAndTampering(t *testing.T) {
	sealed, _ := WrapWithSecret(mustNewKey(t), secret(0x01), "access-token")
	if _, err := UnwrapWithSecret(sealed, secret(0x02), "access-token"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong secret err = %v, want ErrWrongSecret", err)
	}
	bad := bytes.Clone(sealed)
	bad[len(bad)-1] ^= 0x01
	if _, err := UnwrapWithSecret(bad, secret(0x01), "access-token"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("tampered blob err = %v, want ErrWrongSecret", err)
	}
	if _, err := UnwrapWithSecret(sealed[:10], secret(0x01), "access-token"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("truncated blob err = %v, want ErrWrongSecret", err)
	}
}

func TestSecretWrapIsBoundToItsPurpose(t *testing.T) {
	// A blob stored for a refresh token must not open when presented as an
	// access token, even with the same secret bytes.
	sealed, _ := WrapWithSecret(mustNewKey(t), secret(0x01), "refresh-token")
	if _, err := UnwrapWithSecret(sealed, secret(0x01), "access-token"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("cross-purpose unwrap err = %v, want ErrWrongSecret", err)
	}
}

func TestSecretWrapRefusesShortSecrets(t *testing.T) {
	// These wraps skip the slow passphrase KDF, so they are only safe for
	// long random secrets.
	if _, err := WrapWithSecret(mustNewKey(t), []byte("short"), "access-token"); err == nil {
		t.Fatal("WrapWithSecret accepted a 5-byte secret")
	}
}

func TestSecretIDIsStableSeparatedAndNotTheSecret(t *testing.T) {
	s := secret(0x01)
	id := SecretID(s, "access-token")
	if id != SecretID(s, "access-token") {
		t.Fatal("SecretID is not deterministic")
	}
	if id == SecretID(s, "refresh-token") {
		t.Fatal("SecretID is the same across purposes")
	}
	if id == SecretID(secret(0x02), "access-token") {
		t.Fatal("different secrets share an ID")
	}
	if strings.Contains(id, hexString(s)) || id == hexString(s) {
		t.Fatal("SecretID exposes the secret")
	}
	// The stored ID must not be usable to open the wrap: the wrap key is
	// derived separately from the secret, never from the ID.
	sealed, _ := WrapWithSecret(mustNewKey(t), s, "access-token")
	if _, err := UnwrapWithSecret(sealed, []byte(id), "access-token"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("the lookup ID opened the wrap (err=%v)", err)
	}
}

// --- recovery codes --------------------------------------------------------

func TestRecoveryCodesAreLongRandomAndReadable(t *testing.T) {
	a, err := NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewRecoveryCode()
	if a == b {
		t.Fatal("two recovery codes are identical")
	}
	// Grouped for reading aloud / writing down: XXXX-XXXX-...
	groups := strings.Split(a, "-")
	if len(groups) != 8 {
		t.Fatalf("recovery code %q has %d groups, want 8", a, len(groups))
	}
	for _, g := range groups {
		if len(g) != 4 {
			t.Fatalf("group %q is not 4 characters", g)
		}
	}
}

func TestRecoveryCodeBytesToleratesHowPeopleTypeThem(t *testing.T) {
	code, _ := NewRecoveryCode()
	want, err := RecoveryCodeBytes(code)
	if err != nil {
		t.Fatalf("RecoveryCodeBytes(canonical): %v", err)
	}
	if len(want) < 20 {
		t.Fatalf("recovery code carries only %d bytes of entropy", len(want))
	}
	variants := []string{
		strings.ToLower(code),
		strings.ReplaceAll(code, "-", " "),
		strings.ReplaceAll(code, "-", ""),
		"  " + code + "\n",
	}
	for _, v := range variants {
		got, err := RecoveryCodeBytes(v)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("RecoveryCodeBytes(%q): equal=%v err=%v", v, bytes.Equal(got, want), err)
		}
	}
}

func TestRecoveryCodeBytesRejectsMalformedCodes(t *testing.T) {
	code, _ := NewRecoveryCode()
	for name, in := range map[string]string{
		"empty":      "",
		"too short":  code[:len(code)-5],
		"bad symbol": "!" + code[1:],
	} {
		if _, err := RecoveryCodeBytes(in); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
}

func TestRecoveryCodeUnwrapsWhatItWrapped(t *testing.T) {
	k := mustNewKey(t)
	code, _ := NewRecoveryCode()
	raw, _ := RecoveryCodeBytes(code)
	sealed, err := WrapWithSecret(k, raw, "recovery-code")
	if err != nil {
		t.Fatal(err)
	}
	typed, _ := RecoveryCodeBytes(strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	got, err := UnwrapWithSecret(sealed, typed, "recovery-code")
	if err != nil || got != k {
		t.Fatalf("recovery code as typed did not open the wrap: err=%v", err)
	}
}

// --- sealing small blobs under a secret ------------------------------------

func TestSealWithSecretRoundTripsAndIsBoundToSecretAndPurpose(t *testing.T) {
	plain := []byte(`{"next":"tokens"}`)
	sealed, err := SealWithSecret(plain, secret(0x01), "refresh-successor")
	if err != nil {
		t.Fatalf("SealWithSecret: %v", err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("sealed blob contains the plaintext")
	}
	got, err := OpenWithSecret(sealed, secret(0x01), "refresh-successor")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("OpenWithSecret = %q err=%v", got, err)
	}
	if _, err := OpenWithSecret(sealed, secret(0x02), "refresh-successor"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong secret err = %v, want ErrWrongSecret", err)
	}
	if _, err := OpenWithSecret(sealed, secret(0x01), "something-else"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong purpose err = %v, want ErrWrongSecret", err)
	}
	bad := bytes.Clone(sealed)
	bad[len(bad)/2] ^= 0x01
	if _, err := OpenWithSecret(bad, secret(0x01), "refresh-successor"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("tampered blob err = %v, want ErrWrongSecret", err)
	}
	if _, err := SealWithSecret(plain, []byte("short"), "refresh-successor"); err == nil {
		t.Error("SealWithSecret accepted a short secret")
	}
}
