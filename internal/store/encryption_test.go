package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
	"github.com/sealjay/mcp-whatsapp/internal/vault/vaulttest"
)

const archiveMarker = "ARCHIVE_MARKER_4d2b_see_you_at_noon"

func assertStoreDirOpaque(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{archiveMarker, "SQLite format 3", "CREATE TABLE", "15550001111"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s contains %q in the clear", e.Name(), needle)
			}
		}
	}
}

func TestOpenKeepsMessagesUnreadableOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, vaulttest.Key())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	const chat = "15550001111@s.whatsapp.net"
	now := time.Now().UTC()
	if err := s.StoreChat(chat, archiveMarker+" chat name", now); err != nil {
		t.Fatal(err)
	}
	msg := Message{ID: "M1", ChatJID: chat, Sender: "15550001111", Content: archiveMarker, Timestamp: now}
	if err := s.StoreMessage(context.Background(), msg, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	assertStoreDirOpaque(t, dir) // write-ahead log still live
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	assertStoreDirOpaque(t, dir)

	// And the same key reads it back.
	s2, err := Open(dir, vaulttest.Key())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	got, err := s2.ListMessages(context.Background(), ListMessagesParams{ChatJID: chat, Limit: 5})
	if err != nil || len(got) != 1 || got[0].Content != archiveMarker {
		t.Fatalf("read back %+v err=%v", got, err)
	}
}

func TestOpenRejectsTheWrongKey(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, vaulttest.Key())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(dir, vaulttest.OtherKey()); !errors.Is(err, vault.ErrWrongKey) {
		t.Fatalf("Open(wrong key) err = %v, want vault.ErrWrongKey", err)
	}
}

func TestOpenRefusesToRunWithoutAKey(t *testing.T) {
	if _, err := Open(t.TempDir(), vault.Key{}); err == nil {
		t.Fatal("Open accepted an unset key")
	}
}

func TestOpenReadsTheEncryptedSessionDatabase(t *testing.T) {
	// The store resolves hidden-ID senders through the WhatsApp session
	// database, which is encrypted under the same instance key.
	dir := t.TempDir()
	wa, err := vault.OpenDB(filepath.Join(dir, "whatsapp.db"), vaulttest.Key(), SessionDBName, vault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer wa.Close()
	if _, err := wa.Exec(`CREATE TABLE whatsmeow_lid_map (lid TEXT PRIMARY KEY, pn TEXT UNIQUE NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := wa.Exec(`INSERT INTO whatsmeow_lid_map VALUES ('99887766', '15550001111')`); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, vaulttest.Key())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.ResolveLIDToJID("99887766@lid"); got != "15550001111@s.whatsapp.net" {
		t.Fatalf("ResolveLIDToJID = %q, want the mapped phone JID", got)
	}
}
