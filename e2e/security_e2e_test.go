//go:build e2e

package e2e

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSendFileRejectsOutOfRootPath(t *testing.T) {
	h := newHarness(t)
	h.initializeMCP()

	res := h.callTool("send_file", map[string]any{
		"recipient":  "00000000@s.whatsapp.net",
		"media_path": "/etc/passwd",
	})
	if !res.IsError {
		t.Fatalf("expected error result, got success: %+v", res)
	}
	if !strings.Contains(res.Text, "allowed root") {
		t.Fatalf("error should mention allowed root, got %q", res.Text)
	}
}

// download_media returns media in the tool result and never writes files, so
// a caller-supplied path (an argument older versions honoured) must be inert.
func TestDownloadMediaIgnoresOutputPath(t *testing.T) {
	h := newHarness(t)
	h.initializeMCP()

	target := filepath.Join(t.TempDir(), "exfil.bin")
	h.callTool("download_media", map[string]any{
		"message_id":  "any",
		"chat_jid":    "00000000@s.whatsapp.net",
		"output_path": target,
	})
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("download_media touched the caller-supplied path %s (stat err: %v)", target, err)
	}
}

// Everything the daemon keeps on disk is encrypted: no file in the store
// directory may be a readable SQLite database.
func TestStoreDirectoryHoldsNoReadableDatabase(t *testing.T) {
	h := newHarness(t)
	h.initializeMCP()

	found := 0
	err := filepath.WalkDir(h.storeDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		found++
		for _, needle := range []string{"SQLite format 3", "CREATE TABLE", "whatsmeow_device"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s contains %q in the clear", filepath.Base(p), needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("store directory is empty: nothing was checked")
	}
}
