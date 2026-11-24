// Package security holds policy-layer helpers used across the MCP bridge:
// path allowlisting for outbound media, filename sanitisation for inbound
// documents, and a log redactor for JIDs and message bodies.
package security

import (
	"path/filepath"
	"strings"
	"time"
)

// SafeFilename returns filepath.Base(raw) unless the base is one of the
// degenerate values that could escape a join or hit special-case behaviour
// ("", ".", "..", "/", or contains a null byte), in which case it returns
// a timestamped fallback of the form "document_YYYYMMDD_HHMMSS". Matches
// the old whatsapp-bridge behaviour.
func SafeFilename(raw string) string {
	if strings.ContainsRune(raw, '\x00') {
		return fallbackFilename()
	}
	base := filepath.Base(raw)
	switch base {
	case "", ".", "..", "/":
		return fallbackFilename()
	}
	sanitised := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, base)
	if strings.TrimSpace(sanitised) == "" {
		return fallbackFilename()
	}
	return sanitised
}

func fallbackFilename() string {
	return "document_" + time.Now().UTC().Format("20060102_150405")
}
