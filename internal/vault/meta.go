package vault

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Meta is the one database that is deliberately NOT encrypted. It holds what
// the instance has to know while it is locked: whether it has been set up,
// the sealed copies of the key, and how many wrong guesses have been made.
// Nothing in it is a secret on its own; every sealed copy needs a passphrase,
// recovery code or token that is never stored.
type Meta struct {
	db  *sql.DB
	kdf KDFParams
	now func() time.Time

	// mu serialises unlock attempts. The passphrase derivation is memory-hard
	// by design, so running several at once could exhaust a small instance.
	mu sync.Mutex
	// derivations counts slow passphrase derivations run (observed by tests).
	derivations int
}

var (
	// ErrNotInitialized means first-time setup has not been done.
	ErrNotInitialized = errors.New("vault: not set up yet")
	// ErrAlreadyInitialized means setup was attempted a second time. Setting up
	// again would replace the key and orphan everything encrypted under it.
	ErrAlreadyInitialized = errors.New("vault: already set up")
	// ErrWeakPassphrase is returned for passphrases shorter than the minimum.
	ErrWeakPassphrase = fmt.Errorf("vault: passphrase must be at least %d characters", minPassphraseLen)
)

// LockedOutError is returned while unlocking is suspended after repeated
// wrong guesses.
type LockedOutError struct{ Until time.Time }

func (e *LockedOutError) Error() string {
	return "vault: too many wrong attempts; try again after " + e.Until.UTC().Format(time.RFC3339)
}

const (
	minPassphraseLen = 12
	// maxFreeAttempts wrong guesses in a row are allowed before unlocking is
	// suspended. Each further wrong guess doubles the suspension, up to
	// maxLockout, so guessing is slow but the owner is never shut out for long.
	maxFreeAttempts = 5
	baseLockout     = 30 * time.Second
	maxLockout      = 15 * time.Minute

	recoveryPurpose = "recovery-code"
)

const metaSchema = `
CREATE TABLE IF NOT EXISTS vault (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	kdf_time        INTEGER NOT NULL,
	kdf_memory_kib  INTEGER NOT NULL,
	kdf_threads     INTEGER NOT NULL,
	salt            BLOB NOT NULL,
	wrap_passphrase BLOB NOT NULL,
	wrap_recovery   BLOB NOT NULL,
	key_check       BLOB NOT NULL,
	created_at      INTEGER NOT NULL,
	failed_attempts INTEGER NOT NULL DEFAULT 0,
	locked_until    INTEGER NOT NULL DEFAULT 0
);
`

// OpenMeta opens (creating if needed) the unencrypted state database at path.
func OpenMeta(path string) (*Meta, error) {
	db, err := sql.Open("sqlite3", "file:"+escapeURIPath(path)+"?_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	if _, err := db.Exec(metaSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("prepare state database: %w", err)
	}
	// Not secret, but there is no reason for other local users to read it.
	_ = os.Chmod(path, 0o600)
	return &Meta{db: db, kdf: DefaultKDFParams(), now: time.Now}, nil
}

// SetKDFParams changes the cost settings used for passphrases set from now
// on. Existing wraps keep the settings they were made with.
func (m *Meta) SetKDFParams(p KDFParams) error {
	if err := p.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kdf = p
	return nil
}

// DB exposes the state database so sign-in records can live beside the vault
// state in the same file.
func (m *Meta) DB() *sql.DB { return m.db }

// Close closes the state database.
func (m *Meta) Close() error { return m.db.Close() }

// Initialized reports whether first-time setup has been done.
func (m *Meta) Initialized(ctx context.Context) (bool, error) {
	var n int
	if err := m.db.QueryRowContext(ctx, `SELECT count(*) FROM vault`).Scan(&n); err != nil {
		return false, fmt.Errorf("read vault state: %w", err)
	}
	return n > 0, nil
}

// Initialize performs first-time setup: it creates the instance key and stores
// it sealed under passphrase and under a new recovery code. The key and the
// recovery code are returned once and are not recoverable from storage.
func (m *Meta) Initialize(ctx context.Context, passphrase string) (Key, string, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return Key{}, "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok, err := m.Initialized(ctx); err != nil {
		return Key{}, "", err
	} else if ok {
		return Key{}, "", ErrAlreadyInitialized
	}

	key, err := NewKey()
	if err != nil {
		return Key{}, "", err
	}
	recovery, err := NewRecoveryCode()
	if err != nil {
		return Key{}, "", err
	}
	recoveryRaw, err := RecoveryCodeBytes(recovery)
	if err != nil {
		return Key{}, "", err
	}
	m.derivations++
	pw, err := WrapWithPassphrase(key, passphrase, m.kdf)
	if err != nil {
		return Key{}, "", err
	}
	rw, err := WrapWithSecret(key, recoveryRaw, recoveryPurpose)
	if err != nil {
		return Key{}, "", err
	}
	_, err = m.db.ExecContext(ctx, `INSERT INTO vault
		(id, kdf_time, kdf_memory_kib, kdf_threads, salt, wrap_passphrase, wrap_recovery, key_check, created_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pw.Params.Time, pw.Params.MemoryKiB, pw.Params.Threads, pw.Salt, pw.Sealed, rw, keyCheck(key), m.now().Unix())
	if err != nil {
		if isUniqueViolation(err) {
			return Key{}, "", ErrAlreadyInitialized
		}
		return Key{}, "", fmt.Errorf("store vault state: %w", err)
	}
	return key, recovery, nil
}

// UnlockWithPassphrase returns the instance key if passphrase is right. Wrong
// guesses are counted, and after maxFreeAttempts in a row further attempts are
// refused (with *LockedOutError) for a growing period.
func (m *Meta) UnlockWithPassphrase(ctx context.Context, passphrase string) (Key, error) {
	return m.attempt(ctx, func(st vaultState) (Key, error) {
		m.derivations++
		return st.passphrase.Unwrap(passphrase)
	})
}

// UnlockWithRecoveryCode returns the instance key if code is the recovery code
// issued at setup. It shares the wrong-guess limit with the passphrase.
func (m *Meta) UnlockWithRecoveryCode(ctx context.Context, code string) (Key, error) {
	return m.attempt(ctx, func(st vaultState) (Key, error) {
		raw, err := RecoveryCodeBytes(code)
		if err != nil {
			return Key{}, ErrWrongSecret
		}
		return UnwrapWithSecret(st.recovery, raw, recoveryPurpose)
	})
}

// ChangePassphrase replaces the passphrase. The caller proves ownership by
// presenting the instance key itself (obtained from an unlock). The recovery
// code keeps working.
func (m *Meta) ChangePassphrase(ctx context.Context, key Key, newPassphrase string) error {
	if err := checkPassphrase(newPassphrase); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.load(ctx)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(st.keyCheck, keyCheck(key)) != 1 {
		return ErrWrongSecret
	}
	m.derivations++
	pw, err := WrapWithPassphrase(key, newPassphrase, m.kdf)
	if err != nil {
		return err
	}
	_, err = m.db.ExecContext(ctx, `UPDATE vault SET kdf_time = ?, kdf_memory_kib = ?, kdf_threads = ?, salt = ?, wrap_passphrase = ?,
		failed_attempts = 0, locked_until = 0 WHERE id = 1`,
		pw.Params.Time, pw.Params.MemoryKiB, pw.Params.Threads, pw.Salt, pw.Sealed)
	if err != nil {
		return fmt.Errorf("store new passphrase: %w", err)
	}
	return nil
}

type vaultState struct {
	passphrase     PassphraseWrap
	recovery       []byte
	keyCheck       []byte
	failedAttempts int
	lockedUntil    time.Time
}

func (m *Meta) load(ctx context.Context) (vaultState, error) {
	var st vaultState
	var lockedUntil int64
	err := m.db.QueryRowContext(ctx, `SELECT kdf_time, kdf_memory_kib, kdf_threads, salt, wrap_passphrase, wrap_recovery, key_check,
		failed_attempts, locked_until FROM vault WHERE id = 1`).Scan(
		&st.passphrase.Params.Time, &st.passphrase.Params.MemoryKiB, &st.passphrase.Params.Threads,
		&st.passphrase.Salt, &st.passphrase.Sealed, &st.recovery, &st.keyCheck, &st.failedAttempts, &lockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return vaultState{}, ErrNotInitialized
	}
	if err != nil {
		return vaultState{}, fmt.Errorf("read vault state: %w", err)
	}
	if lockedUntil > 0 {
		st.lockedUntil = time.Unix(lockedUntil, 0)
	}
	return st, nil
}

// attempt runs one unlock try under the wrong-guess limit. While locked out it
// returns before try runs, so a lockout also stops the expensive derivation.
func (m *Meta) attempt(ctx context.Context, try func(vaultState) (Key, error)) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.load(ctx)
	if err != nil {
		return Key{}, err
	}
	now := m.now()
	if now.Before(st.lockedUntil) {
		return Key{}, &LockedOutError{Until: st.lockedUntil}
	}

	key, err := try(st)
	switch {
	case err == nil:
		if st.failedAttempts != 0 || !st.lockedUntil.IsZero() {
			if _, uerr := m.db.ExecContext(ctx, `UPDATE vault SET failed_attempts = 0, locked_until = 0 WHERE id = 1`); uerr != nil {
				return Key{}, fmt.Errorf("record successful unlock: %w", uerr)
			}
		}
		return key, nil
	case errors.Is(err, ErrWrongSecret):
		failed := st.failedAttempts + 1
		var until int64
		if failed >= maxFreeAttempts {
			until = now.Add(lockoutFor(failed)).Unix()
		}
		if _, uerr := m.db.ExecContext(ctx, `UPDATE vault SET failed_attempts = ?, locked_until = ? WHERE id = 1`, failed, until); uerr != nil {
			return Key{}, fmt.Errorf("record failed unlock: %w", uerr)
		}
		return Key{}, ErrWrongSecret
	default:
		return Key{}, err
	}
}

// lockoutFor is the suspension after the given number of consecutive wrong
// guesses: baseLockout at the limit, doubling with each further one, capped.
func lockoutFor(failed int) time.Duration {
	extra := failed - maxFreeAttempts
	if extra < 0 {
		return 0
	}
	if extra > 10 { // far past the cap; avoid shifting into overflow
		return maxLockout
	}
	d := baseLockout << uint(extra)
	if d > maxLockout {
		return maxLockout
	}
	return d
}

func checkPassphrase(p string) error {
	if utf8.RuneCountInString(strings.TrimSpace(p)) < minPassphraseLen {
		return ErrWeakPassphrase
	}
	return nil
}

// keyCheck is a one-way fingerprint of the key, stored so a presented key can
// be recognised as this vault's. It cannot be turned back into the key or into
// any database key.
func keyCheck(k Key) []byte {
	return derive(k[:], "wa-vault/v1/key-check", 32)
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
