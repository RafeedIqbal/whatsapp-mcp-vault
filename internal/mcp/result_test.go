package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sealjay/mcp-whatsapp/internal/client"
)

// jpegMagic is the minimum prefix (SOI + APP0 marker) that
// http.DetectContentType recognises as image/jpeg.
var jpegMagic = []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}

// oggMagic is the "OggS" capture pattern for an Ogg container. The
// http.DetectContentType sniff table matches this even without a Vorbis /
// Opus payload following it.
var oggMagic = []byte("OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00")

const testMediaURI = "whatsapp://media/447700000001%40s.whatsapp.net/MSG1"

func downloaded(mediaType, filename string, data []byte) client.DownloadResult {
	return client.DownloadResult{
		Success:   true,
		Message:   "Successfully downloaded " + mediaType + " media",
		MediaType: mediaType,
		Filename:  filename,
		Size:      len(data),
		Data:      data,
	}
}

// firstText returns the Text field of the first content block, which the
// downloadMediaResult contract guarantees is a JSON summary.
func firstText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("empty content")
	}
	txt, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] should be TextContent, got %T", res.Content[0])
	}
	return txt.Text
}

// summary parses the first content block as the JSON summary.
func summary(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(firstText(t, res)), &got); err != nil {
		t.Fatalf("summary is not JSON: %v (raw: %q)", err, firstText(t, res))
	}
	return got
}

func mustResult(t *testing.T, r client.DownloadResult) *mcp.CallToolResult {
	t.Helper()
	res, err := downloadMediaResult(r, testMediaURI)
	if err != nil {
		t.Fatalf("downloadMediaResult: %v", err)
	}
	return res
}

func TestDownloadMediaResult_ImageInlined(t *testing.T) {
	res := mustResult(t, downloaded("image", "img.jpg", jpegMagic))
	if len(res.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(res.Content))
	}
	img, ok := res.Content[1].(mcp.ImageContent)
	if !ok {
		t.Fatalf("content[1] should be ImageContent, got %T", res.Content[1])
	}
	if img.MIMEType != "image/jpeg" {
		t.Errorf("MIMEType = %q, want image/jpeg", img.MIMEType)
	}
	decoded, err := base64.StdEncoding.DecodeString(img.Data)
	if err != nil || string(decoded) != string(jpegMagic) {
		t.Errorf("decoded bytes = %x err=%v, want %x", decoded, err, jpegMagic)
	}
}

func TestDownloadMediaResult_AudioInlined(t *testing.T) {
	res := mustResult(t, downloaded("audio", "voice.ogg", oggMagic))
	if len(res.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(res.Content))
	}
	aud, ok := res.Content[1].(mcp.AudioContent)
	if !ok {
		t.Fatalf("content[1] should be AudioContent, got %T", res.Content[1])
	}
	if !strings.HasPrefix(aud.MIMEType, "audio/") {
		t.Errorf("MIMEType = %q, want audio/*", aud.MIMEType)
	}
}

// Documents and videos have no image/audio content type, so a remote client
// receives them as an embedded resource carrying the bytes.
func TestDownloadMediaResult_DocumentEmbeddedAsResource(t *testing.T) {
	pdf := []byte("%PDF-1.4 minimal")
	res := mustResult(t, downloaded("document", "spec.pdf", pdf))
	if len(res.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(res.Content))
	}
	emb, ok := res.Content[1].(mcp.EmbeddedResource)
	if !ok {
		t.Fatalf("content[1] should be EmbeddedResource, got %T", res.Content[1])
	}
	blob, ok := emb.Resource.(mcp.BlobResourceContents)
	if !ok {
		t.Fatalf("embedded resource should be a blob, got %T", emb.Resource)
	}
	if blob.URI != testMediaURI {
		t.Errorf("URI = %q, want %q", blob.URI, testMediaURI)
	}
	if blob.MIMEType != "application/pdf" {
		t.Errorf("MIMEType = %q, want application/pdf", blob.MIMEType)
	}
	decoded, err := base64.StdEncoding.DecodeString(blob.Blob)
	if err != nil || string(decoded) != string(pdf) {
		t.Errorf("blob = %q err=%v, want the document bytes", decoded, err)
	}
}

func TestDownloadMediaResult_VideoEmbeddedAsResource(t *testing.T) {
	mp4 := []byte{0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm'}
	res := mustResult(t, downloaded("video", "clip.mp4", mp4))
	if len(res.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(res.Content))
	}
	if _, ok := res.Content[1].(mcp.EmbeddedResource); !ok {
		t.Fatalf("content[1] should be EmbeddedResource, got %T", res.Content[1])
	}
}

func TestDownloadMediaResult_FailureIsSummaryOnly(t *testing.T) {
	res := mustResult(t, client.DownloadResult{
		Success: false,
		Message: "failed to download media: download failed with status code 403",
	})
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content block on failure, got %d", len(res.Content))
	}
	if s := summary(t, res); s["success"] != false || !strings.Contains(s["message"].(string), "403") {
		t.Errorf("summary = %v", s)
	}
}

func TestDownloadMediaResult_OversizedIsNotEmbedded(t *testing.T) {
	oversized := make([]byte, inlineMediaMaxBytes+1)
	copy(oversized, jpegMagic)
	res := mustResult(t, downloaded("image", "huge.jpg", oversized))
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content block for oversized media, got %d", len(res.Content))
	}
	// The caller must be told why nothing came back, not just see a success.
	if note, _ := summary(t, res)["note"].(string); !strings.Contains(note, "too large") {
		t.Errorf("summary does not explain the missing media: %v", summary(t, res))
	}
}

// The summary describes the media; it never carries a server file path (media
// is not written to disk) and never the bytes themselves.
func TestDownloadMediaResult_SummaryHasNoPathAndNoBytes(t *testing.T) {
	res := mustResult(t, downloaded("image", "img.jpg", jpegMagic))
	s := summary(t, res)
	for _, forbidden := range []string{"path", "Path", "data", "Data"} {
		if _, ok := s[forbidden]; ok {
			t.Errorf("summary has a %q field: %v", forbidden, s)
		}
	}
	if s["media_type"] != "image" || s["filename"] != "img.jpg" || s["size_bytes"] != float64(len(jpegMagic)) {
		t.Errorf("summary = %v", s)
	}
}
