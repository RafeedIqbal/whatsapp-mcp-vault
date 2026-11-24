package vault

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// The instance key is never stored on its own. It is kept only as sealed
// copies ("wraps"), each of which opens with one secret:
//
//   - the owner's passphrase (slow Argon2id derivation, because people choose
//     guessable secrets);
//   - the recovery code, and each sign-in code and token (fast HKDF
//     derivation, safe only because those are long random values).
//
// A wrap is XChaCha20-Poly1305 over the key, so opening it with the wrong
// secret, or after any change to the stored bytes, fails loudly.

// ErrWrongSecret is returned when a wrap does not open: the passphrase, code
// or token is wrong, or the stored wrap has been altered.
var ErrWrongSecret = errors.New("vault: wrong passphrase, code or token")

const (
	saltLen = 16
	// sealedLen is nonce + key + authentication tag.
	sealedLen = chacha20poly1305.NonceSizeX + len(Key{}) + chacha20poly1305.Overhead
	// minSecretLen is the shortest secret WrapWithSecret accepts. Those wraps
	// skip the slow passphrase derivation, so the secret must be unguessable.
	minSecretLen = 16
)

// KDFParams are the Argon2id cost settings a passphrase wrap was made with.
// They are stored beside the wrap so it keeps opening if the defaults change.
type KDFParams struct {
	Time      uint32 // passes
	MemoryKiB uint32
	Threads   uint8
}

// DefaultKDFParams is the cost used for new passphrase wraps: 64 MiB and three
// passes, above the OWASP floor for Argon2id and small enough for a 512 MB
// instance.
func DefaultKDFParams() KDFParams {
	return KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 2}
}

// validate bounds the settings. They are read back from disk, so values that
// would make guessing free or exhaust memory are refused rather than run.
func (p KDFParams) validate() error {
	const minMemoryKiB, maxMemoryKiB = 8 * 1024, 1024 * 1024 // 8 MiB .. 1 GiB
	switch {
	case p.Time < 1 || p.Time > 64:
		return errors.New("vault: passphrase cost settings out of range (passes)")
	case p.Threads < 1 || p.Threads > 16:
		return errors.New("vault: passphrase cost settings out of range (threads)")
	case p.MemoryKiB < minMemoryKiB || p.MemoryKiB > maxMemoryKiB:
		return errors.New("vault: passphrase cost settings out of range (memory)")
	}
	return nil
}

// PassphraseWrap is the instance key sealed under a passphrase.
type PassphraseWrap struct {
	Params KDFParams
	Salt   []byte
	Sealed []byte
}

// WrapWithPassphrase seals k under passphrase using the given cost settings.
func WrapWithPassphrase(k Key, passphrase string, p KDFParams) (PassphraseWrap, error) {
	if err := p.validate(); err != nil {
		return PassphraseWrap{}, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return PassphraseWrap{}, errors.New("vault: could not read random bytes")
	}
	sealed, err := seal(k, passphraseKEK(passphrase, salt, p), passphraseAAD(salt, p))
	if err != nil {
		return PassphraseWrap{}, err
	}
	return PassphraseWrap{Params: p, Salt: salt, Sealed: sealed}, nil
}

// Unwrap opens the wrap with passphrase. It returns ErrWrongSecret when the
// passphrase is wrong or the stored wrap (salt, settings or sealed bytes) has
// been altered.
func (w PassphraseWrap) Unwrap(passphrase string) (Key, error) {
	if err := w.Params.validate(); err != nil {
		return Key{}, err
	}
	if len(w.Salt) != saltLen {
		return Key{}, errors.New("vault: stored passphrase wrap is malformed")
	}
	return open(w.Sealed, passphraseKEK(passphrase, w.Salt, w.Params), passphraseAAD(w.Salt, w.Params))
}

func passphraseKEK(passphrase string, salt []byte, p KDFParams) []byte {
	return argon2.IDKey([]byte(passphrase), salt, p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
}

// passphraseAAD binds the salt and cost settings into the seal, so swapping
// either on disk is detected even if the derived key happened to match.
func passphraseAAD(salt []byte, p KDFParams) []byte {
	return []byte(fmt.Sprintf("wa-vault/v1/wrap/passphrase|%x|%d|%d|%d", salt, p.Time, p.MemoryKiB, p.Threads))
}

// WrapWithSecret seals k under a long random secret (a token, sign-in code or
// recovery code). purpose names what the secret is; a wrap only opens when the
// same purpose is given back.
func WrapWithSecret(k Key, secret []byte, purpose string) ([]byte, error) {
	if len(secret) < minSecretLen {
		return nil, errors.New("vault: secret too short to protect a key")
	}
	return seal(k, secretKEK(secret, purpose), []byte("wa-vault/v1/wrap/"+purpose))
}

// UnwrapWithSecret opens a wrap made by WrapWithSecret.
func UnwrapWithSecret(sealed, secret []byte, purpose string) (Key, error) {
	if len(secret) < minSecretLen {
		return Key{}, ErrWrongSecret
	}
	return open(sealed, secretKEK(secret, purpose), []byte("wa-vault/v1/wrap/"+purpose))
}

// SealWithSecret encrypts a small blob under a long random secret, bound to
// purpose like WrapWithSecret. It is for short records that must only be
// readable by whoever holds that secret (for example the replacement tokens
// kept briefly for a client that retries a refresh).
func SealWithSecret(plain, secret []byte, purpose string) ([]byte, error) {
	if len(secret) < minSecretLen {
		return nil, errors.New("vault: secret too short to protect data")
	}
	return sealBytes(plain, derive(secret, "wa-vault/v1/seal/"+purpose, chacha20poly1305.KeySize), []byte("wa-vault/v1/seal/"+purpose))
}

// OpenWithSecret decrypts a blob made by SealWithSecret.
func OpenWithSecret(sealed, secret []byte, purpose string) ([]byte, error) {
	if len(secret) < minSecretLen {
		return nil, ErrWrongSecret
	}
	return openBytes(sealed, derive(secret, "wa-vault/v1/seal/"+purpose, chacha20poly1305.KeySize), []byte("wa-vault/v1/seal/"+purpose))
}

// SecretID returns the value a secret is looked up by in storage. It is
// derived one-way and separately from the wrapping key, so what is stored can
// neither reveal the secret nor open the wrap filed under it.
func SecretID(secret []byte, purpose string) string {
	return hexString(derive(secret, "wa-vault/v1/id/"+purpose, sha256.Size))
}

func secretKEK(secret []byte, purpose string) []byte {
	return derive(secret, "wa-vault/v1/kek/"+purpose, chacha20poly1305.KeySize)
}

func derive(secret []byte, info string, n int) []byte {
	// hkdf.Key only fails when n exceeds 255 hash blocks.
	b, err := hkdf.Key(sha256.New, secret, nil, info, n)
	if err != nil {
		panic("vault: hkdf: " + err.Error())
	}
	return b
}

func seal(k Key, kek, aad []byte) ([]byte, error) {
	return sealBytes(k[:], kek, aad)
}

func open(sealed, kek, aad []byte) (Key, error) {
	if len(sealed) != sealedLen {
		return Key{}, ErrWrongSecret
	}
	plain, err := openBytes(sealed, kek, aad)
	if err != nil {
		return Key{}, err
	}
	var k Key
	copy(k[:], plain)
	return k, nil
}

// sealBytes returns nonce || ciphertext || tag.
func sealBytes(plain, kek, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, errors.New("vault: could not initialise cipher")
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX, chacha20poly1305.NonceSizeX+len(plain)+chacha20poly1305.Overhead)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("vault: could not read random bytes")
	}
	return aead.Seal(nonce, nonce, plain, aad), nil
}

func openBytes(sealed, kek, aad []byte) ([]byte, error) {
	if len(sealed) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, ErrWrongSecret
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, errors.New("vault: could not initialise cipher")
	}
	plain, err := aead.Open(nil, sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:], aad)
	if err != nil {
		return nil, ErrWrongSecret
	}
	return plain, nil
}

// Recovery codes are 160 random bits written as eight groups of four
// characters. The alphabet leaves out 0, O, 1 and I, so no two characters in a
// code can be mistaken for each other when it is written down.
const (
	recoveryBytes  = 20
	recoveryGroups = 8
	recoveryGroup  = 4
)

var recoveryEncoding = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").WithPadding(base32.NoPadding)

// NewRecoveryCode returns a fresh recovery code, formatted for writing down.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, recoveryBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("vault: could not read random bytes")
	}
	enc := recoveryEncoding.EncodeToString(raw) // 32 characters for 20 bytes
	groups := make([]string, 0, recoveryGroups)
	for i := 0; i < len(enc); i += recoveryGroup {
		groups = append(groups, enc[i:i+recoveryGroup])
	}
	return strings.Join(groups, "-"), nil
}

// RecoveryCodeBytes turns a recovery code as a person typed it (any case, with
// dashes, spaces or neither) back into its secret bytes.
func RecoveryCodeBytes(code string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(code))
	if len(cleaned) != recoveryGroups*recoveryGroup {
		return nil, errors.New("vault: recovery code has the wrong length")
	}
	raw, err := recoveryEncoding.DecodeString(cleaned)
	if err != nil || len(raw) != recoveryBytes {
		return nil, errors.New("vault: recovery code contains characters that are never used in one")
	}
	return raw, nil
}
