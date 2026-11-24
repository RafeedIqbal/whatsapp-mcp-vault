package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodPassphrase = "correct horse battery staple"

// fakeClock is a settable clock for lockout tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func openTestMeta(t *testing.T, dir string, clock *fakeClock) *Meta {
	t.Helper()
	m, err := OpenMeta(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("OpenMeta: %v", err)
	}
	m.kdf = fastKDF
	if clock != nil {
		m.now = clock.now
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestMetaStartsUninitialised(t *testing.T) {
	m := openTestMeta(t, t.TempDir(), nil)
	ok, err := m.Initialized(context.Background())
	if err != nil || ok {
		t.Fatalf("Initialized = %v err=%v, want false", ok, err)
	}
	if _, err := m.UnlockWithPassphrase(context.Background(), goodPassphrase); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("unlock before setup err = %v, want ErrNotInitialized", err)
	}
}

func TestMetaInitializeThenUnlockReturnsTheSameKey(t *testing.T) {
	ctx := context.Background()
	m := openTestMeta(t, t.TempDir(), nil)
	key, recovery, err := m.Initialize(ctx, goodPassphrase)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if key.IsZero() || recovery == "" {
		t.Fatal("Initialize returned an empty key or recovery code")
	}
	if ok, _ := m.Initialized(ctx); !ok {
		t.Fatal("Initialized is false after Initialize")
	}
	got, err := m.UnlockWithPassphrase(ctx, goodPassphrase)
	if err != nil || got != key {
		t.Fatalf("UnlockWithPassphrase: same key=%v err=%v", got == key, err)
	}
	got, err = m.UnlockWithRecoveryCode(ctx, strings.ToLower(strings.ReplaceAll(recovery, "-", " ")))
	if err != nil || got != key {
		t.Fatalf("UnlockWithRecoveryCode: same key=%v err=%v", got == key, err)
	}
}

func TestMetaInitializeOnlyOnce(t *testing.T) {
	// A second setup would silently replace the key and orphan the archive.
	ctx := context.Background()
	m := openTestMeta(t, t.TempDir(), nil)
	first, _, err := m.Initialize(ctx, goodPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Initialize(ctx, "another long passphrase here"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Initialize err = %v, want ErrAlreadyInitialized", err)
	}
	if got, err := m.UnlockWithPassphrase(ctx, goodPassphrase); err != nil || got != first {
		t.Fatalf("original passphrase no longer opens the original key (err=%v)", err)
	}
}

func TestMetaRejectsWeakPassphrases(t *testing.T) {
	m := openTestMeta(t, t.TempDir(), nil)
	for _, weak := range []string{"", "short", "elevenchars", strings.Repeat(" ", 20)} {
		if _, _, err := m.Initialize(context.Background(), weak); !errors.Is(err, ErrWeakPassphrase) {
			t.Errorf("Initialize(%q) err = %v, want ErrWeakPassphrase", weak, err)
		}
	}
	if ok, _ := m.Initialized(context.Background()); ok {
		t.Fatal("a rejected passphrase still initialised the vault")
	}
}

func TestMetaWrongPassphraseIsRejected(t *testing.T) {
	ctx := context.Background()
	m := openTestMeta(t, t.TempDir(), nil)
	m.Initialize(ctx, goodPassphrase)
	if _, err := m.UnlockWithPassphrase(ctx, "correct horse battery stapler"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("err = %v, want ErrWrongSecret", err)
	}
	if _, err := m.UnlockWithRecoveryCode(ctx, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("wrong recovery code err = %v, want ErrWrongSecret", err)
	}
}

func TestMetaLocksOutAfterRepeatedWrongGuesses(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	m := openTestMeta(t, t.TempDir(), clock)
	key, _, _ := m.Initialize(ctx, goodPassphrase)

	for i := 0; i < maxFreeAttempts; i++ {
		if _, err := m.UnlockWithPassphrase(ctx, "wrong guess number one"); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("attempt %d err = %v, want ErrWrongSecret", i+1, err)
		}
	}

	// Locked: even the right passphrase is refused, and the error says until when.
	_, err := m.UnlockWithPassphrase(ctx, goodPassphrase)
	var locked *LockedOutError
	if !errors.As(err, &locked) {
		t.Fatalf("after %d wrong guesses err = %v, want *LockedOutError", maxFreeAttempts, err)
	}
	if !locked.Until.After(clock.now()) {
		t.Fatalf("lockout ends at %v, not in the future of %v", locked.Until, clock.now())
	}

	// After the lockout passes the right passphrase works again.
	clock.t = locked.Until.Add(time.Second)
	got, err := m.UnlockWithPassphrase(ctx, goodPassphrase)
	if err != nil || got != key {
		t.Fatalf("after lockout expired: same key=%v err=%v", got == key, err)
	}

	// And success clears the count: a single new wrong guess does not lock.
	if _, err := m.UnlockWithPassphrase(ctx, "wrong guess number two"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("first wrong guess after a success err = %v, want ErrWrongSecret", err)
	}
	if _, err := m.UnlockWithPassphrase(ctx, goodPassphrase); err != nil {
		t.Fatalf("locked out again after one wrong guess: %v", err)
	}
}

func TestMetaLockoutGrowsWithEachFurtherWrongGuess(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	m := openTestMeta(t, t.TempDir(), clock)
	m.Initialize(ctx, goodPassphrase)

	lockoutAfterAnotherWrongGuess := func() time.Duration {
		t.Helper()
		_, err := m.UnlockWithPassphrase(ctx, "a wrong guess, again")
		if !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("err = %v, want ErrWrongSecret", err)
		}
		_, err = m.UnlockWithPassphrase(ctx, goodPassphrase)
		var locked *LockedOutError
		if !errors.As(err, &locked) {
			t.Fatalf("expected a lockout, got %v", err)
		}
		d := locked.Until.Sub(clock.now())
		clock.t = locked.Until.Add(time.Second)
		return d
	}

	for i := 0; i < maxFreeAttempts-1; i++ {
		m.UnlockWithPassphrase(ctx, "a wrong guess, again")
	}
	first := lockoutAfterAnotherWrongGuess()
	second := lockoutAfterAnotherWrongGuess()
	third := lockoutAfterAnotherWrongGuess()
	if !(second > first && third > second) {
		t.Fatalf("lockouts did not grow: %v, %v, %v", first, second, third)
	}
	// It must stay bounded, or a prankster could lock the owner out for days.
	for i := 0; i < 20; i++ {
		if d := lockoutAfterAnotherWrongGuess(); d > maxLockout {
			t.Fatalf("lockout %v exceeds the cap %v", d, maxLockout)
		}
	}
}

func TestMetaLockoutDoesNotRunTheSlowDerivation(t *testing.T) {
	// While locked out, a guess must be refused before the memory-hard
	// derivation runs; otherwise the lockout would not limit resource use.
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	m := openTestMeta(t, t.TempDir(), clock)
	m.Initialize(ctx, goodPassphrase)
	for i := 0; i < maxFreeAttempts; i++ {
		m.UnlockWithPassphrase(ctx, "a wrong guess, again")
	}
	before := m.derivations
	for i := 0; i < 10; i++ {
		m.UnlockWithPassphrase(ctx, goodPassphrase)
	}
	if m.derivations != before {
		t.Fatalf("ran the derivation %d times while locked out", m.derivations-before)
	}
}

func TestMetaStateSurvivesAReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	clock := &fakeClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	m := openTestMeta(t, dir, clock)
	key, _, _ := m.Initialize(ctx, goodPassphrase)
	for i := 0; i < maxFreeAttempts; i++ {
		m.UnlockWithPassphrase(ctx, "a wrong guess, again")
	}
	m.Close()

	// A restart must not hand an attacker a fresh set of guesses.
	m2 := openTestMeta(t, dir, clock)
	if ok, _ := m2.Initialized(ctx); !ok {
		t.Fatal("not initialised after reopen")
	}
	var locked *LockedOutError
	if _, err := m2.UnlockWithPassphrase(ctx, goodPassphrase); !errors.As(err, &locked) {
		t.Fatalf("lockout was forgotten across a reopen (err=%v)", err)
	}
	clock.t = locked.Until.Add(time.Second)
	if got, err := m2.UnlockWithPassphrase(ctx, goodPassphrase); err != nil || got != key {
		t.Fatalf("unlock after reopen: same key=%v err=%v", got == key, err)
	}
}

func TestMetaChangePassphrase(t *testing.T) {
	ctx := context.Background()
	m := openTestMeta(t, t.TempDir(), nil)
	key, recovery, _ := m.Initialize(ctx, goodPassphrase)

	const next = "a brand new passphrase to use"
	if err := m.ChangePassphrase(ctx, key, next); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	if _, err := m.UnlockWithPassphrase(ctx, goodPassphrase); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("old passphrase still works (err=%v)", err)
	}
	if got, err := m.UnlockWithPassphrase(ctx, next); err != nil || got != key {
		t.Fatalf("new passphrase: same key=%v err=%v", got == key, err)
	}
	if got, err := m.UnlockWithRecoveryCode(ctx, recovery); err != nil || got != key {
		t.Fatalf("recovery code stopped working after a passphrase change (err=%v)", err)
	}
	if err := m.ChangePassphrase(ctx, key, "weak"); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("weak replacement err = %v, want ErrWeakPassphrase", err)
	}
	// Only the holder of the real key may change the passphrase.
	other := mustNewKey(t)
	if err := m.ChangePassphrase(ctx, other, "yet another passphrase here"); err == nil {
		t.Fatal("ChangePassphrase accepted a key that is not this vault's key")
	}
}

func TestMetaFileHoldsNoUsableSecret(t *testing.T) {
	// meta.db is deliberately not encrypted (it must be readable while the
	// instance is locked), so nothing in it may be a secret on its own.
	ctx := context.Background()
	dir := t.TempDir()
	m := openTestMeta(t, dir, nil)
	key, recovery, _ := m.Initialize(ctx, goodPassphrase)
	m.Close()

	raw, _ := RecoveryCodeBytes(recovery)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for name, secret := range map[string][]byte{
			"the instance key":         key[:],
			"the passphrase":           []byte(goodPassphrase),
			"the recovery code":        []byte(recovery),
			"the recovery code (bare)": []byte(strings.ReplaceAll(recovery, "-", "")),
			"the recovery code bytes":  raw,
			"a database subkey":        func() []byte { s := key.DBKey("messages"); return s[:] }(),
		} {
			if bytes.Contains(b, secret) {
				t.Errorf("%s contains %s", e.Name(), name)
			}
		}
	}
}

// Anyone who can reach the sign-in page can pause passphrase sign-in by
// guessing wrong. The recovery code is the owner's way through that: it is far
// too long to guess, so it is never paused and never adds to the count.
func TestRecoveryCodeWorksDuringALockoutAndDoesNotExtendIt(t *testing.T) {
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	m := openTestMeta(t, t.TempDir(), clock)
	key, recovery, _ := m.Initialize(ctx, goodPassphrase)
	for i := 0; i < maxFreeAttempts; i++ {
		m.UnlockWithPassphrase(ctx, "a wrong guess, again")
	}
	var locked *LockedOutError
	if _, err := m.UnlockWithPassphrase(ctx, goodPassphrase); !errors.As(err, &locked) {
		t.Fatalf("precondition: passphrase sign-in should be paused (err=%v)", err)
	}

	got, err := m.UnlockWithRecoveryCode(ctx, recovery)
	if err != nil || got != key {
		t.Fatalf("recovery code during a lockout: same key=%v err=%v", got == key, err)
	}
	// Wrong recovery codes are refused but do not lengthen the passphrase pause.
	until := locked.Until
	for i := 0; i < 10; i++ {
		if _, err := m.UnlockWithRecoveryCode(ctx, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("wrong recovery code err = %v, want ErrWrongSecret", err)
		}
	}
	if _, err := m.UnlockWithPassphrase(ctx, goodPassphrase); !errors.As(err, &locked) || !locked.Until.Equal(until) {
		t.Fatalf("wrong recovery codes changed the passphrase pause: %v (was until %v)", err, until)
	}
}

func TestUnlockAcceptsEitherThePassphraseOrTheRecoveryCode(t *testing.T) {
	ctx := context.Background()
	m := openTestMeta(t, t.TempDir(), nil)
	key, recovery, _ := m.Initialize(ctx, goodPassphrase)
	for name, secret := range map[string]string{
		"passphrase":                goodPassphrase,
		"recovery code":             recovery,
		"recovery code, lower case": strings.ToLower(recovery),
		"recovery code, spaced":     strings.ReplaceAll(recovery, "-", " "),
	} {
		if got, err := m.Unlock(ctx, secret); err != nil || got != key {
			t.Errorf("%s: same key=%v err=%v", name, got == key, err)
		}
	}
	if _, err := m.Unlock(ctx, "neither of the two secrets"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("wrong secret err = %v", err)
	}
	// A passphrase that merely looks like a recovery code is still a passphrase.
	m2 := openTestMeta(t, t.TempDir(), nil)
	lookalike := "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345-6789"
	k2, _, err := m2.Initialize(ctx, lookalike)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m2.Unlock(ctx, lookalike); err != nil || got != k2 {
		t.Fatalf("a passphrase shaped like a recovery code does not unlock: %v", err)
	}
}
