package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/store"
	"github.com/sealjay/mcp-whatsapp/internal/vault/vaulttest"
	"go.mau.fi/whatsmeow"
)

const (
	mediaChat  = "447700000099@s.whatsapp.net"
	mediaMsgID = "M-MEDIA-1"
)

// mediaFixture is a store holding one media message plus a client whose
// network fetch is replaced by a stub that returns served and counts calls.
type mediaFixture struct {
	c        *Client
	storeDir string
	fetches  int
}

func newMediaFixture(t *testing.T, payload, served []byte, mediaType, filename string, declaredLength uint64) *mediaFixture {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir, vaulttest.Key())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.StoreChat(mediaChat, "test", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if err := s.StoreMessage(context.Background(), store.Message{
		ID: mediaMsgID, ChatJID: mediaChat, Sender: mediaChat, Content: "x", Timestamp: time.Now().UTC(),
		MediaType: mediaType, Filename: filename, URL: "https://example.invalid/media", DirectPath: "/media",
	}, []byte{1}, digest[:], []byte{2}, declaredLength); err != nil {
		t.Fatal(err)
	}
	f := &mediaFixture{c: newClientWithStore(t, s), storeDir: dir}
	f.c.downloadMedia = func(context.Context, whatsmeow.DownloadableMessage) ([]byte, error) {
		f.fetches++
		return served, nil
	}
	return f
}

// filesUnder lists every path below dir, so a test can prove a call created none.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, strings.TrimPrefix(p, dir))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestDownloadReturnsTheDecryptedBytes(t *testing.T) {
	payload := []byte("DECRYPTED-IMAGE-BYTES")
	f := newMediaFixture(t, payload, payload, "image", "photo.jpg", uint64(len(payload)))

	got := f.c.Download(context.Background(), mediaMsgID, mediaChat)
	if !got.Success {
		t.Fatalf("Download failed: %s", got.Message)
	}
	if !bytes.Equal(got.Data, payload) {
		t.Fatalf("Data = %q, want the payload", got.Data)
	}
	if got.MediaType != "image" || got.Filename != "photo.jpg" || got.Size != len(payload) {
		t.Fatalf("metadata = %q %q %d", got.MediaType, got.Filename, got.Size)
	}
}

func TestDownloadWritesNothingToDisk(t *testing.T) {
	payload := []byte("DECRYPTED-MARKER-51ab-never-on-disk")
	f := newMediaFixture(t, payload, payload, "document", "report.pdf", uint64(len(payload)))
	before := filesUnder(t, f.storeDir)

	if got := f.c.DownloadWithMediaRetry(context.Background(), mediaMsgID, mediaChat); !got.Success {
		t.Fatalf("download failed: %s", got.Message)
	}

	after := filesUnder(t, f.storeDir)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("download created files:\nbefore: %v\nafter:  %v", before, after)
	}
	for _, rel := range after {
		b, err := os.ReadFile(filepath.Join(f.storeDir, rel))
		if err != nil {
			continue // directories
		}
		if bytes.Contains(b, payload) {
			t.Fatalf("%s contains the decrypted media", rel)
		}
	}
}

func TestDownloadKeepsNoCopyBetweenCalls(t *testing.T) {
	payload := []byte("PAYLOAD")
	f := newMediaFixture(t, payload, payload, "image", "photo.jpg", uint64(len(payload)))
	f.c.Download(context.Background(), mediaMsgID, mediaChat)
	f.c.Download(context.Background(), mediaMsgID, mediaChat)
	if f.fetches != 2 {
		t.Fatalf("fetched %d times for 2 calls: a copy was kept somewhere", f.fetches)
	}
}

func TestDownloadRejectsBytesThatDoNotMatchTheMessage(t *testing.T) {
	payload := []byte("EXPECTED")
	f := newMediaFixture(t, payload, []byte("TAMPERED"), "image", "photo.jpg", uint64(len(payload)))
	got := f.c.Download(context.Background(), mediaMsgID, mediaChat)
	if got.Success || got.Data != nil {
		t.Fatalf("mismatched payload accepted: %+v", got)
	}
}

func TestDownloadRefusesMediaTooLargeToHoldInMemory(t *testing.T) {
	payload := []byte("x")
	f := newMediaFixture(t, payload, payload, "video", "clip.mp4", maxMediaBytes+1)
	got := f.c.Download(context.Background(), mediaMsgID, mediaChat)
	if got.Success {
		t.Fatal("oversized media accepted")
	}
	if !strings.Contains(got.Message, "limit") {
		t.Fatalf("message does not explain the limit: %q", got.Message)
	}
	if f.fetches != 0 {
		t.Fatalf("oversized media was fetched %d times before being refused", f.fetches)
	}
}

func TestDownloadRejectsMessagesWithoutMedia(t *testing.T) {
	f := newMediaFixture(t, []byte("x"), []byte("x"), "", "", 1)
	got := f.c.Download(context.Background(), mediaMsgID, mediaChat)
	if got.Success || !strings.Contains(got.Message, "not a media message") {
		t.Fatalf("got %+v", got)
	}
	if got := f.c.Download(context.Background(), "NO-SUCH-ID", mediaChat); got.Success {
		t.Fatalf("unknown message succeeded: %+v", got)
	}
}

func TestValidateMediaPayloadRejectsOversizedMetadata(t *testing.T) {
	if err := validateMediaPayload([]byte("small"), maxMediaBytes+1, nil); err == nil {
		t.Fatal("oversized media metadata accepted")
	}
}

func TestValidateMediaPayloadRejectsWrongHashAndLength(t *testing.T) {
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	if err := validateMediaPayload(payload, uint64(len(payload)), digest[:]); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	if err := validateMediaPayload(payload, uint64(len(payload)+1), digest[:]); err == nil {
		t.Fatal("wrong length accepted")
	}
	wrong := sha256.Sum256([]byte("other"))
	if err := validateMediaPayload(payload, uint64(len(payload)), wrong[:]); err == nil {
		t.Fatal("wrong hash accepted")
	}
}
