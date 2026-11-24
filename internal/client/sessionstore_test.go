package client

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
	"github.com/sealjay/mcp-whatsapp/internal/vault/vaulttest"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestOpenSessionStoreKeepsLoginKeysUnreadableOnDisk(t *testing.T) {
	dir := t.TempDir()
	container, err := openSessionStore(context.Background(), dir, vaulttest.Key(), waLog.Noop)
	if err != nil {
		t.Fatalf("openSessionStore: %v", err)
	}
	// A new, unpaired device still has freshly generated identity keys in memory;
	// what matters here is what the schema and any writes leave on disk.
	if container.NewDevice() == nil {
		t.Fatal("no device")
	}
	check := func(when string) {
		t.Helper()
		entries, _ := os.ReadDir(dir)
		if len(entries) == 0 {
			t.Fatalf("%s: nothing on disk", when)
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, needle := range []string{"SQLite format 3", "whatsmeow_device", "whatsmeow_sessions", "CREATE TABLE"} {
				if bytes.Contains(b, []byte(needle)) {
					t.Errorf("%s: %s contains %q in the clear", when, e.Name(), needle)
				}
			}
		}
	}
	check("while open")
	if err := container.Close(); err != nil {
		t.Fatal(err)
	}
	check("after close")
}

func TestOpenSessionStoreRejectsTheWrongKey(t *testing.T) {
	dir := t.TempDir()
	container, err := openSessionStore(context.Background(), dir, vaulttest.Key(), waLog.Noop)
	if err != nil {
		t.Fatal(err)
	}
	container.Close()

	_, err = openSessionStore(context.Background(), dir, vaulttest.OtherKey(), waLog.Noop)
	if !errors.Is(err, vault.ErrWrongKey) {
		t.Fatalf("openSessionStore(wrong key) err = %v, want vault.ErrWrongKey", err)
	}
}
