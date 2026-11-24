package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const plaintextMarker = "PLAINTEXT_MARKER_7c1e_lunch_at_noon"

func testKey(t *testing.T, b byte) Key {
	t.Helper()
	k, err := ParseKey(strings.Repeat(string("0123456789abcdef"[b>>4])+string("0123456789abcdef"[b&0xf]), 32))
	if err != nil {
		t.Fatalf("test key: %v", err)
	}
	return k
}

// assertNothingReadable fails if any file in dir contains the marker, a
// plaintext SQLite header, or a table name.
func assertNothingReadable(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no files on disk to inspect")
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{plaintextMarker, "SQLite format 3", "secret_notes"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s contains %q in the clear", e.Name(), needle)
			}
		}
	}
}

func TestOpenDBWritesNothingReadableToDisk(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "messages.db"), testKey(t, 0xa1), "messages", Options{})
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE secret_notes (body TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO secret_notes VALUES (?)`, plaintextMarker); err != nil {
		t.Fatal(err)
	}
	// While open: the write-ahead log is live and must be opaque too.
	assertNothingReadable(t, dir)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	assertNothingReadable(t, dir)
}

func TestOpenDBReadsBackWithTheSameKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages.db")
	key := testKey(t, 0xa1)
	db, err := OpenDB(path, key, "messages", Options{})
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE secret_notes (body TEXT)`)
	db.Exec(`INSERT INTO secret_notes VALUES (?)`, plaintextMarker)
	db.Close()

	db2, err := OpenDB(path, key, "messages", Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var got string
	if err := db2.QueryRow(`SELECT body FROM secret_notes`).Scan(&got); err != nil || got != plaintextMarker {
		t.Fatalf("read back %q err=%v", got, err)
	}
}

func TestOpenDBRejectsTheWrongKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages.db")
	db, err := OpenDB(path, testKey(t, 0xa1), "messages", Options{})
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE secret_notes (body TEXT)`)
	db.Close()

	_, err = OpenDB(path, testKey(t, 0xb2), "messages", Options{})
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("OpenDB(wrong key) err = %v, want ErrWrongKey", err)
	}
}

func TestOpenDBSeparatesDatabasesByName(t *testing.T) {
	// The same master key must not open a file created under another name:
	// each database gets its own derived key.
	path := filepath.Join(t.TempDir(), "x.db")
	key := testKey(t, 0xa1)
	db, err := OpenDB(path, key, "messages", Options{})
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE secret_notes (body TEXT)`)
	db.Close()

	if _, err := OpenDB(path, key, "whatsapp", Options{}); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("opening under another name err = %v, want ErrWrongKey", err)
	}
}

func TestOpenDBRefusesAZeroKey(t *testing.T) {
	_, err := OpenDB(filepath.Join(t.TempDir(), "messages.db"), Key{}, "messages", Options{})
	if err == nil {
		t.Fatal("OpenDB accepted an all-zero key")
	}
}

func TestOpenDBErrorsNeverContainTheKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages.db")
	good, bad := testKey(t, 0xa1), testKey(t, 0xb2)
	db, _ := OpenDB(path, good, "messages", Options{})
	db.Exec(`CREATE TABLE secret_notes (body TEXT)`)
	db.Close()

	_, err := OpenDB(path, bad, "messages", Options{})
	if err == nil {
		t.Fatal("want error")
	}
	sub := bad.DBKey("messages")
	for _, leak := range []string{strings.Repeat("b2", 32), hexString(sub[:]), "_pragma_key"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks key material (%q): %v", leak[:8], err)
		}
	}
}

func TestOpenDBUsesWriteAheadLogAndForeignKeys(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "messages.db"), testKey(t, 0xa1), "messages", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode string
	var fk int
	db.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	if mode != "wal" || fk != 1 {
		t.Fatalf("journal_mode=%q foreign_keys=%d, want wal and 1", mode, fk)
	}
}

func TestOpenDBSupportsFullTextSearch(t *testing.T) {
	// Message search relies on FTS4, which the bundled SQLCipher build
	// enables without extra build tags. If this fails the search feature
	// cannot work in this build.
	db, err := OpenDB(filepath.Join(t.TempDir(), "messages.db"), testKey(t, 0xa1), "messages", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE VIRTUAL TABLE ft USING fts4(body, tokenize=unicode61)`); err != nil {
		t.Fatalf("fts4 unavailable: %v", err)
	}
	db.Exec(`INSERT INTO ft(body) VALUES ('Café lunch tomorrow'), ('nothing here')`)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ft WHERE ft MATCH 'cafe'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("fts4 match n=%d err=%v", n, err)
	}
}

func TestOpenDBReadOnlyCannotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whatsapp.db")
	key := testKey(t, 0xa1)
	rw, err := OpenDB(path, key, "whatsapp", Options{})
	if err != nil {
		t.Fatal(err)
	}
	rw.Exec(`CREATE TABLE secret_notes (body TEXT)`)
	rw.Exec(`INSERT INTO secret_notes VALUES ('x')`)
	defer rw.Close()

	ro, err := OpenDB(path, key, "whatsapp", Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer ro.Close()
	var n int
	if err := ro.QueryRow(`SELECT count(*) FROM secret_notes`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("read-only read n=%d err=%v", n, err)
	}
	if _, err := ro.Exec(`INSERT INTO secret_notes VALUES ('y')`); err == nil {
		t.Fatal("read-only handle accepted a write")
	}
}

func TestOpenDBLazyToleratesAMissingFileUntilItAppears(t *testing.T) {
	// The message store opens the session database read-only before the
	// WhatsApp client has created it; that handle must start working once
	// the file exists.
	path := filepath.Join(t.TempDir(), "whatsapp.db")
	key := testKey(t, 0xa1)
	ro, err := OpenDB(path, key, "whatsapp", Options{ReadOnly: true, Lazy: true})
	if err != nil {
		t.Fatalf("lazy open of a missing file: %v", err)
	}
	defer ro.Close()
	var n int
	if err := ro.QueryRow(`SELECT 1`).Scan(&n); err == nil {
		t.Fatal("query succeeded although the file does not exist")
	}

	rw, err := OpenDB(path, key, "whatsapp", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	rw.Exec(`CREATE TABLE secret_notes (body TEXT)`)

	if err := ro.QueryRow(`SELECT count(*) FROM secret_notes`).Scan(&n); err != nil {
		t.Fatalf("lazy handle still failing after the file appeared: %v", err)
	}
}
