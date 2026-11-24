// Package vaulttest supplies fixed keys for tests. It must never be imported
// by non-test code: a key in source is not a secret.
package vaulttest

import (
	"database/sql"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

// Key returns the fixed key tests open their stores with.
func Key() vault.Key { return fixed(0x5a) }

// OtherKey returns a second fixed key, different from Key.
func OtherKey() vault.Key { return fixed(0xc3) }

// OpenDB opens the database at path the way production does, under Key and
// the given database name, so a fixture can seed a file the store will then
// be able to read.
func OpenDB(path, name string) (*sql.DB, error) {
	return vault.OpenDB(path, Key(), name, vault.Options{})
}

func fixed(b byte) vault.Key {
	var k vault.Key
	for i := range k {
		k[i] = b
	}
	return k
}
