package security

import (
	"strings"
	"testing"
)

func TestSafeFilename(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // "" means must match the fallback pattern
	}{
		{"plain", "photo.jpg", "photo.jpg"},
		{"path strips to base", "a/b/c.txt", "c.txt"},
		{"traversal strips to leaf", "../etc/passwd", "passwd"},
		{"cross-platform separators", `folder\evil\name.pdf`, "folder_evil_name.pdf"},
		{"control characters", "evil\nname.pdf", "evil_name.pdf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeFilename(tc.in)
			if got != tc.want {
				t.Fatalf("SafeFilename(%q): want %q, got %q", tc.in, tc.want, got)
			}
		})
	}

	fallbacks := []string{"", ".", "..", "/"}
	for _, in := range fallbacks {
		t.Run("fallback/"+in, func(t *testing.T) {
			got := SafeFilename(in)
			if !strings.HasPrefix(got, "document_") {
				t.Fatalf("SafeFilename(%q) should fall back to document_*, got %q", in, got)
			}
		})
	}

	t.Run("null byte falls back", func(t *testing.T) {
		got := SafeFilename("evil\x00name.txt")
		if !strings.HasPrefix(got, "document_") {
			t.Fatalf("null-byte name should fall back, got %q", got)
		}
	})
}
