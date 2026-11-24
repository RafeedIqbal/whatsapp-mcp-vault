// Package vault holds the instance data key and opens the SQLCipher-encrypted
// databases that everything on disk lives in. Nothing in this package writes
// key material to disk, to logs, or into error messages.
package vault

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// Key is the 32-byte data key for one instance. Every database is encrypted
// under a subkey derived from it (see DBKey); the key itself is never used
// directly as a cipher key.
type Key [32]byte

// NewKey returns a fresh random key.
func NewKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, errors.New("vault: could not read random bytes for a new key")
	}
	return k, nil
}

// ParseKey decodes a key written as exactly 64 hexadecimal characters.
// Surrounding whitespace is ignored. Errors never include the input.
func ParseKey(s string) (Key, error) {
	s = strings.TrimSpace(s)
	if len(s) != hex.EncodedLen(len(Key{})) {
		return Key{}, errors.New("vault: key must be exactly 64 hexadecimal characters")
	}
	var k Key
	if _, err := hex.Decode(k[:], []byte(s)); err != nil {
		return Key{}, errors.New("vault: key contains non-hexadecimal characters")
	}
	if k.IsZero() {
		return Key{}, errors.New("vault: an all-zero key is not allowed")
	}
	return k, nil
}

// IsZero reports whether the key is unset.
func (k Key) IsZero() bool { return k == Key{} }

// DBKey derives the cipher key for the named database. Different names give
// unrelated keys, so one database file cannot be opened as another.
func (k Key) DBKey(name string) [32]byte {
	var out [32]byte
	// hkdf.Key only fails when the requested length exceeds 255 hash blocks.
	b, err := hkdf.Key(sha256.New, k[:], nil, "wa-vault/v1/db/"+name, len(out))
	if err != nil {
		panic("vault: hkdf: " + err.Error())
	}
	copy(out[:], b)
	return out
}

func hexString(b []byte) string { return hex.EncodeToString(b) }
