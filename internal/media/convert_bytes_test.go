package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// silentWAV is a short mono 16-bit PCM clip.
func silentWAV(ms int) []byte {
	const rate = 8000
	samples := rate * ms / 1000
	data := make([]byte, samples*2)
	var b bytes.Buffer
	b.WriteString("RIFF")
	binary.Write(&b, binary.LittleEndian, uint32(36+len(data)))
	b.WriteString("WAVEfmt ")
	binary.Write(&b, binary.LittleEndian, uint32(16))
	binary.Write(&b, binary.LittleEndian, uint16(1)) // PCM
	binary.Write(&b, binary.LittleEndian, uint16(1)) // mono
	binary.Write(&b, binary.LittleEndian, uint32(rate))
	binary.Write(&b, binary.LittleEndian, uint32(rate*2))
	binary.Write(&b, binary.LittleEndian, uint16(2))
	binary.Write(&b, binary.LittleEndian, uint16(16))
	b.WriteString("data")
	binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	b.Write(data)
	return b.Bytes()
}

func TestConvertToOpusOggBytesProducesOggWithoutTouchingTheTempDir(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
	// Point the temp dir somewhere empty so any stray temp file is visible.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	out, err := ConvertToOpusOggBytes(context.Background(), silentWAV(300))
	if err != nil {
		t.Fatalf("ConvertToOpusOggBytes: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("OggS")) {
		t.Fatalf("output is not an Ogg stream: % x", out[:min(8, len(out))])
	}
	if _, _, err := AnalyzeOggOpus(out); err != nil {
		t.Fatalf("converted clip is not valid Ogg Opus for a voice note: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(tmp, "*"))
	if len(left) != 0 {
		t.Fatalf("conversion left files in the temp dir: %v", left)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Fatalf("temp dir not empty: %v", entries)
	}
}

func TestConvertToOpusOggBytesRejectsGarbageAndEmptyInput(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
	if _, err := ConvertToOpusOggBytes(context.Background(), []byte("this is not audio at all")); err == nil {
		t.Fatal("garbage input converted without error")
	}
	if _, err := ConvertToOpusOggBytes(context.Background(), nil); err == nil {
		t.Fatal("empty input converted without error")
	}
}

// ffmpeg runs with a minimal environment: nothing from the server's own
// environment (which holds deployment secrets) is passed to it.
func TestConvertToOpusOggBytesDoesNotNeedTheServerEnvironment(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}
	t.Setenv("MCP_WHATSAPP_TEST_SENTINEL_12345", "should-not-reach-ffmpeg")
	for _, kv := range minimalEnv() {
		if strings.HasPrefix(kv, "MCP_WHATSAPP_TEST_SENTINEL_12345=") {
			t.Fatal("the conversion environment includes an unrelated server variable")
		}
	}
	if out, err := ConvertToOpusOggBytes(context.Background(), silentWAV(200)); err != nil || len(out) == 0 {
		t.Fatalf("conversion with the minimal environment failed: %v", err)
	}
}
