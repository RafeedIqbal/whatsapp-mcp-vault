package main

import (
	"strings"
	"testing"
	"time"
)

func TestResolvePublicURL(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		addr string
		want string
	}{
		"explicit":              {map[string]string{"PUBLIC_URL": "https://wa.example.com/"}, "0.0.0.0:8765", "https://wa.example.com"},
		"render fallback":       {map[string]string{"RENDER_EXTERNAL_URL": "https://alice-wa.onrender.com"}, "0.0.0.0:10000", "https://alice-wa.onrender.com"},
		"explicit beats render": {map[string]string{"PUBLIC_URL": "https://a.example", "RENDER_EXTERNAL_URL": "https://b.example"}, "0.0.0.0:1", "https://a.example"},
		"local default":         {nil, "127.0.0.1:8765", "http://127.0.0.1:8765"},
		"loopback http is fine": {map[string]string{"PUBLIC_URL": "http://localhost:9000"}, "127.0.0.1:9000", "http://localhost:9000"},
	} {
		got, err := resolvePublicURL(envOf(tc.env), tc.addr)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q err=%v, want %q", name, got, err, tc.want)
		}
	}
}

func TestResolvePublicURLRefusesInsecureOrUnknownAddresses(t *testing.T) {
	// Sign-in sends the passphrase and tokens to this address, so anything
	// other than https is only acceptable on the machine itself.
	for name, tc := range map[string]struct {
		env  map[string]string
		addr string
	}{
		"plain http on a public host": {map[string]string{"PUBLIC_URL": "http://wa.example.com"}, "0.0.0.0:8765"},
		"not a URL":                   {map[string]string{"PUBLIC_URL": "wa.example.com"}, "0.0.0.0:8765"},
		"with a path":                 {map[string]string{"PUBLIC_URL": "https://example.com/wa"}, "0.0.0.0:8765"},
		"remote bind with no URL":     {nil, "0.0.0.0:8765"},
	} {
		if got, err := resolvePublicURL(envOf(tc.env), tc.addr); err == nil {
			t.Errorf("%s: accepted, resolved to %q", name, got)
		}
	}
}

func TestIdleLockFromEnv(t *testing.T) {
	for name, tc := range map[string]struct {
		val  string
		want time.Duration
		ok   bool
	}{
		"default":      {"", 15 * time.Minute, true},
		"minutes":      {"5m", 5 * time.Minute, true},
		"seconds":      {"90s", 90 * time.Second, true},
		"too short":    {"100ms", 0, false},
		"too long":     {"48h", 0, false},
		"not duration": {"fifteen", 0, false},
	} {
		got, err := idleLockFromEnv(envOf(map[string]string{"IDLE_LOCK": tc.val}))
		if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
			t.Errorf("%s: got %v err=%v, want %v ok=%v", name, got, err, tc.want, tc.ok)
		}
	}
}

func TestKeyInEnvironmentModeIsLocalOnly(t *testing.T) {
	// The mode that keeps the key in an environment variable must never be
	// reachable from the network: hosted instances use passphrase sign-in.
	err := checkServeMode(true /*envKey*/, true /*allowRemote*/)
	if err == nil || !strings.Contains(err.Error(), vaultKeyEnv) {
		t.Fatalf("err = %v, want a refusal naming %s", err, vaultKeyEnv)
	}
	for _, ok := range [][2]bool{{true, false}, {false, true}, {false, false}} {
		if err := checkServeMode(ok[0], ok[1]); err != nil {
			t.Errorf("checkServeMode(%v, %v) = %v, want allowed", ok[0], ok[1], err)
		}
	}
}
