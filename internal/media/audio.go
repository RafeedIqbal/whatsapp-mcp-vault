package media

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"regexp"
	"time"
)

// AnalyzeOggOpus returns the unclamped duration rounded up to seconds and a
// 64-byte waveform. Truncated or invalid Ogg/Opus streams return an error,
// including streams whose last page lacks the end-of-stream flag.
func AnalyzeOggOpus(data []byte) (duration uint32, waveform []byte, err error) {
	return analyzeOggOpus(data, true)
}

// OggOpusDuration returns the duration of an Ogg/Opus stream rounded up to
// seconds. Unlike AnalyzeOggOpus it does not require the end-of-stream flag on
// the last page: WhatsApp voice notes are complete, well-formed streams whose
// final page is not flagged. Truncated pages and bad headers still fail.
func OggOpusDuration(data []byte) (uint32, error) {
	d, _, err := analyzeOggOpus(data, false)
	return d, err
}

func analyzeOggOpus(data []byte, requireEOS bool) (duration uint32, waveform []byte, err error) {
	if len(data) < 4 || string(data[0:4]) != "OggS" {
		return 0, nil, fmt.Errorf("not a valid Ogg file (missing OggS signature)")
	}

	var lastGranule uint64
	var preSkip uint16
	var firstSerial uint32
	var serialSet bool
	var lastSequence uint32
	var sequenceSet bool
	var ended bool
	var unfinishedPacket bool
	pageIndex := 0

	for i := 0; i < len(data); {
		if ended {
			return 0, nil, errors.New("unexpected data after Ogg end of stream")
		}
		if len(data)-i < 27 {
			return 0, nil, errors.New("truncated Ogg page header")
		}

		if string(data[i:i+4]) != "OggS" {
			return 0, nil, errors.New("invalid Ogg page signature")
		}
		if data[i+4] != 0 {
			return 0, nil, errors.New("unsupported Ogg page version")
		}
		serial := binary.LittleEndian.Uint32(data[i+14 : i+18])
		sequence := binary.LittleEndian.Uint32(data[i+18 : i+22])
		if !serialSet {
			firstSerial = serial
			serialSet = true
		} else if serial != firstSerial {
			return 0, nil, errors.New("inconsistent Ogg stream serial")
		}
		if sequenceSet {
			if sequence != lastSequence+1 {
				return 0, nil, errors.New("non-sequential Ogg page sequence")
			}
		}
		lastSequence = sequence
		sequenceSet = true

		granulePos := binary.LittleEndian.Uint64(data[i+6 : i+14])
		numSegments := int(data[i+26])

		remaining := len(data) - i
		if remaining < 27 || numSegments > remaining-27 {
			return 0, nil, errors.New("truncated Ogg segment table")
		}
		segmentTable := data[i+27 : i+27+numSegments]

		pageSize := 27 + numSegments
		for _, segLen := range segmentTable {
			if int(segLen) > remaining-pageSize {
				return 0, nil, errors.New("truncated Ogg page body")
			}
			pageSize += int(segLen)
		}
		if pageSize > remaining {
			return 0, nil, errors.New("truncated Ogg page body")
		}

		if pageIndex == 0 {
			if data[i+5]&2 == 0 {
				return 0, nil, errors.New("Ogg Opus header page is missing BOS")
			}
			if numSegments == 0 || segmentTable[0] < 19 || segmentTable[0] == 255 {
				return 0, nil, errors.New("truncated OpusHead identification packet")
			}
			pageData := data[i+27+numSegments : i+pageSize]
			if !bytes.HasPrefix(pageData, []byte("OpusHead")) {
				return 0, nil, errors.New("missing OpusHead identification header")
			}
			headPacket := data[i+27+numSegments : i+27+numSegments+int(segmentTable[0])]
			if len(headPacket) < 19 {
				return 0, nil, errors.New("truncated OpusHead identification header")
			}
			preSkip = binary.LittleEndian.Uint16(headPacket[10:12])
		}

		ended = data[i+5]&4 != 0
		for _, segLen := range segmentTable {
			if segLen < 255 {
				unfinishedPacket = false
			} else {
				unfinishedPacket = true
			}
		}
		if granulePos == math.MaxUint64 {
			return 0, nil, errors.New("undefined final Ogg granule position")
		}
		if unfinishedPacket && (ended || i+pageSize == len(data)) {
			return 0, nil, errors.New("unfinished packet at Ogg end of stream")
		}
		if granulePos > math.MaxInt64 || granulePos < lastGranule {
			return 0, nil, errors.New("invalid Ogg granule position")
		}
		lastGranule = granulePos
		pageIndex++
		i += pageSize
	}

	if requireEOS && !ended {
		return 0, nil, errors.New("missing Ogg end of stream")
	}
	if lastGranule <= uint64(preSkip) {
		return 0, nil, errors.New("Ogg granule position does not exceed Opus pre-skip")
	}

	// Opus granules always count 48 kHz samples, regardless of the input-rate hint.
	playback := lastGranule - uint64(preSkip)
	const maxSeconds = uint64(math.MaxUint32)
	if playback > maxSeconds*48000 {
		return 0, nil, errors.New("Ogg duration exceeds the supported range")
	}
	seconds := (playback + 47999) / 48000
	if seconds > maxSeconds {
		return 0, nil, errors.New("Ogg duration exceeds the supported range")
	}
	duration = uint32(seconds)

	waveform = PlaceholderWaveform(duration)
	return duration, waveform, nil
}

// PlaceholderWaveform generates a deterministic 64-byte synthetic waveform
// based on duration. Used when we can't derive a real waveform.
func PlaceholderWaveform(duration uint32) []byte {
	const waveformLength = 64
	waveform := make([]byte, waveformLength)

	r := rand.New(rand.NewPCG(uint64(duration), 0))

	baseAmplitude := 35.0
	d := int(duration)
	if d > 120 {
		d = 120
	}
	frequencyFactor := float64(d) / 30.0

	for i := range waveform {
		pos := float64(i) / float64(waveformLength)

		val := baseAmplitude * math.Sin(pos*math.Pi*frequencyFactor*8)
		val += (baseAmplitude / 2) * math.Sin(pos*math.Pi*frequencyFactor*16)

		val += (r.Float64() - 0.5) * 15

		fadeInOut := math.Sin(pos * math.Pi)
		val = val * (0.7 + 0.3*fadeInOut)

		val = val + 50

		if val < 0 {
			val = 0
		} else if val > 100 {
			val = 100
		}

		waveform[i] = byte(val)
	}

	return waveform
}

var safeEnvKeys = []string{"PATH", "TMPDIR", "TEMP", "TMP", "HOME"}

// minimalEnv returns a restricted environment for child processes, carrying
// only the variables ffmpeg needs (path resolution, temp dirs, home for codec
// config) while excluding credentials, tokens, and other sensitive values.
func minimalEnv() []string {
	env := make([]string, 0, len(safeEnvKeys))
	for _, k := range safeEnvKeys {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// absPathRe matches absolute file paths (Unix-style).
var absPathRe = regexp.MustCompile(`/[\w/.\-]+`)

// sanitizeStderr strips absolute file paths from ffmpeg stderr output and
// truncates to a maximum of 200 characters. This prevents leaking local
// filesystem layout to MCP callers.
func sanitizeStderr(s string) string {
	s = absPathRe.ReplaceAllString(s, "<path>")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// maxConvertedAudioBytes bounds what a conversion may produce.
const maxConvertedAudioBytes = 32 << 20

// ConvertToOpusOggBytes converts audio held in memory to Ogg Opus, the format
// WhatsApp voice notes use. ffmpeg reads the clip from its standard input and
// writes the result to its standard output, so nothing is written to disk.
//
// Formats that can only be read with seeking (some .m4a/.mp4 files, whose
// index sits at the end) cannot be converted this way and return an error.
func ConvertToOpusOggBytes(ctx context.Context, input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("no audio to convert")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return nil, errors.New("ffmpeg not found on PATH; install ffmpeg to use voice messages")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-hide_banner", "-loglevel", "error", "-nostdin",
		"-protocol_whitelist", "pipe",
		"-i", "pipe:0",
		"-vn",
		"-c:a", "libopus",
		"-b:a", "32k",
		"-vbr", "on",
		"-compression_level", "10",
		"-f", "ogg",
		"pipe:1",
	)
	cmd.Env = minimalEnv()
	cmd.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	var stderr diagnosticPrefix
	cmd.Stdout = &limitedWriter{w: &stdout, left: maxConvertedAudioBytes}
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("audio conversion stopped: %w", ctx.Err())
		}
		return nil, fmt.Errorf("ffmpeg conversion failed: %w: %s", err, sanitizeStderr(string(stderr)))
	}
	if stdout.Len() == 0 {
		return nil, errors.New("ffmpeg produced no audio")
	}
	return stdout.Bytes(), nil
}

// diagnosticPrefix keeps draining stderr after collecting enough context for an error.
type diagnosticPrefix []byte

const maxDiagnosticBytes = 4096

func (d *diagnosticPrefix) Write(p []byte) (int, error) {
	n := min(len(p), maxDiagnosticBytes-len(*d))
	*d = append(*d, p[:n]...)
	return len(p), nil
}

// limitedWriter fails once more than its budget has been written.
type limitedWriter struct {
	w    *bytes.Buffer
	left int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.left {
		return 0, errors.New("converted audio is too large")
	}
	l.left -= len(p)
	return l.w.Write(p)
}
