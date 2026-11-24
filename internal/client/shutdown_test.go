package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sealjay/mcp-whatsapp/internal/store"
	"github.com/sealjay/mcp-whatsapp/internal/vault"
	"github.com/sealjay/mcp-whatsapp/internal/vault/vaulttest"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// A real shutdown found the session database's write-ahead log left behind
// with megabytes of un-checkpointed data, because nothing closed it. The
// message store keeps its own read-only handle on the same file, so closing
// must work with that handle still open.
func TestCloseSessionStoreLeavesNoPendingWriteAheadLog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	container, err := openSessionStore(ctx, dir, vaulttest.Key(), waLog.Noop)
	if err != nil {
		t.Fatal(err)
	}
	// Write something so the write-ahead log has content beyond the schema.
	dev := container.NewDevice()
	dev.ID = &types.JID{User: "447700000010", Device: 3, Server: types.DefaultUserServer}
	dev.Account = &waAdv.ADVSignedDeviceIdentity{Details: []byte{}, AccountSignature: make([]byte, 64), AccountSignatureKey: make([]byte, 32), DeviceSignature: make([]byte, 64)}
	if err := dev.Save(ctx); err != nil {
		t.Fatal(err)
	}

	// The message store's read-only handle, open across the close.
	reader, err := vault.OpenDB(filepath.Join(dir, "whatsapp.db"), vaulttest.Key(), store.SessionDBName, vault.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	walPath := filepath.Join(dir, "whatsapp.db-wal")
	if info, err := os.Stat(walPath); err != nil || info.Size() == 0 {
		t.Fatalf("precondition: expected a non-empty write-ahead log before closing (err=%v)", err)
	}

	if err := container.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if info, err := os.Stat(walPath); err == nil && info.Size() != 0 {
		t.Fatalf("write-ahead log still holds %d bytes after close", info.Size())
	}

	// And everything written is in the main file: a fresh open sees the device.
	again, err := openSessionStore(ctx, dir, vaulttest.Key(), waLog.Noop)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	got, err := again.GetFirstDevice(ctx)
	if err != nil || got == nil || got.ID == nil || got.ID.User != "447700000010" {
		t.Fatalf("device after reopen = %+v err=%v", got, err)
	}
}
