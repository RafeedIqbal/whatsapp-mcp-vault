//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	e2eSetupToken = "e2e-setup-token-0123456789abcdef"
	e2ePassphrase = "an end to end test passphrase"
	e2eVerifier   = "e2e-pkce-verifier-that-is-long-enough-to-be-valid-0123456789"
	e2eCallback   = "http://127.0.0.1:9/callback"
)

// syncBuffer collects the daemon's stderr for assertions.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// signInDaemon is the binary running in passphrase mode: no key configured.
type signInDaemon struct {
	t        *testing.T
	base     string
	storeDir string
	logs     *syncBuffer
	browser  *http.Client
}

func startSignInDaemon(t *testing.T, idleLock string) *signInDaemon {
	t.Helper()
	repo := repoRoot(t)
	bin := filepath.Join(repo, "bin", "whatsapp-mcp")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("binary not built (run make build): %v", err)
	}
	storeDir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	logs := &syncBuffer{}
	cmd := exec.Command(bin, "-store", storeDir, "serve", "-addr", addr)
	cmd.Env = append(envWithout(os.Environ(), "WHATSAPP_MCP_VAULT_KEY"), "SETUP_TOKEN="+e2eSetupToken, "IDLE_LOCK="+idleLock)
	cmd.Stdout, cmd.Stderr = logs, io.MultiWriter(logs, os.Stderr)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	jar, _ := cookiejar.New(nil)
	d := &signInDaemon{t: t, base: "http://" + addr, storeDir: storeDir, logs: logs,
		browser: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(d.base + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return d
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("daemon did not become healthy; logs:\n%s", logs.String())
	return nil
}

func envWithout(env []string, name string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return out
}

func (d *signInDaemon) do(req *http.Request) (*http.Response, string) {
	d.t.Helper()
	resp, err := d.browser.Do(req)
	if err != nil {
		d.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (d *signInDaemon) postForm(path string, v url.Values) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodPost, d.base+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return d.do(req)
}

// rpc calls the tool endpoint and returns the HTTP status and decoded reply.
func (d *signInDaemon) rpc(token, method string) (int, map[string]any, http.Header) {
	d.t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q}`, method)
	req, _ := http.NewRequest(http.MethodPost, d.base+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, raw := d.do(req)
	var out map[string]any
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "data: ")
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &out) == nil {
			break
		}
	}
	return resp.StatusCode, out, resp.Header
}

func (d *signInDaemon) toolNames(token string) map[string]bool {
	d.t.Helper()
	status, out, _ := d.rpc(token, "tools/list")
	if status != http.StatusOK {
		d.t.Fatalf("tools/list: status %d reply %v", status, out)
	}
	names := map[string]bool{}
	result, _ := out["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, tool := range tools {
		if m, ok := tool.(map[string]any); ok {
			names[fmt.Sprint(m["name"])] = true
		}
	}
	if len(names) == 0 {
		d.t.Fatalf("tools/list returned no tools: %v", out)
	}
	return names
}

var (
	e2eRequestID = regexp.MustCompile(`name="request_id" value="([^"]+)"`)
	e2eRecovery  = regexp.MustCompile(`\b([A-Z2-9]{4}(?:-[A-Z2-9]{4}){7})\b`)
)

// signIn runs registration, consent and the code exchange, ticking scopes.
func (d *signInDaemon) signIn(scopes ...string) string {
	d.t.Helper()
	regBody, _ := json.Marshal(map[string]any{"client_name": "e2e client", "redirect_uris": []string{e2eCallback}})
	req, _ := http.NewRequest(http.MethodPost, d.base+"/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	resp, raw := d.do(req)
	var reg map[string]any
	if resp.StatusCode != http.StatusCreated || json.Unmarshal([]byte(raw), &reg) != nil {
		d.t.Fatalf("register: %d %s", resp.StatusCode, raw)
	}
	clientID := fmt.Sprint(reg["client_id"])

	sum := sha256.Sum256([]byte(e2eVerifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {e2eCallback},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"e2e"}, "scope": {"whatsapp.read whatsapp.send whatsapp.manage"}, "resource": {d.base + "/mcp"},
	}
	getReq, _ := http.NewRequest(http.MethodGet, d.base+"/authorize?"+q.Encode(), nil)
	resp, page := d.do(getReq)
	m := e2eRequestID.FindStringSubmatch(page)
	if resp.StatusCode != http.StatusOK || m == nil {
		d.t.Fatalf("authorize page: %d %s", resp.StatusCode, page)
	}
	resp, body := d.postForm("/authorize", url.Values{"request_id": {m[1]}, "passphrase": {e2ePassphrase}, "action": {"approve"}, "scope": scopes})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
		d.t.Fatalf("approve: %d %s", resp.StatusCode, body)
	}
	resp, raw = d.postForm("/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"client_id": {clientID}, "redirect_uri": {e2eCallback}, "code_verifier": {e2eVerifier}})
	var tok map[string]any
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(raw), &tok) != nil {
		d.t.Fatalf("token: %d %s", resp.StatusCode, raw)
	}
	return fmt.Sprint(tok["access_token"])
}

func (d *signInDaemon) waitForLog(substr string, count int, within time.Duration) {
	d.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if strings.Count(d.logs.String(), substr) >= count {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	d.t.Fatalf("did not see %q %d time(s) within %s; logs:\n%s", substr, count, within, d.logs.String())
}

// The whole hosted flow against the real binary: claim the instance, sign a
// client in, call tools, watch it lock when idle, and unlock again from the
// token alone. No WhatsApp account is linked; the tool list does not need one.
func TestPassphraseSignInEndToEnd(t *testing.T) {
	d := startSignInDaemon(t, "2s")

	// Before anything: tools are closed and say where to sign in.
	status, _, hdr := d.rpc("", "tools/list")
	if status != http.StatusUnauthorized || !strings.Contains(hdr.Get("WWW-Authenticate"), d.base+"/.well-known/oauth-protected-resource") {
		t.Fatalf("unauthenticated tools/list: status %d WWW-Authenticate %q", status, hdr.Get("WWW-Authenticate"))
	}

	// The container health check passes while the instance is locked.
	hc := exec.Command(filepath.Join(repoRoot(t), "bin", "whatsapp-mcp"), "healthcheck", "-addr", strings.TrimPrefix(d.base, "http://"))
	if out, err := hc.CombinedOutput(); err != nil {
		t.Fatalf("healthcheck against a locked instance failed: %v\n%s", err, out)
	}

	// Claim the instance.
	resp, page := d.postForm("/setup", url.Values{"action": {"init"}, "setup_token": {e2eSetupToken}, "passphrase": {e2ePassphrase}, "confirm": {e2ePassphrase}})
	recovery := e2eRecovery.FindString(page)
	if resp.StatusCode != http.StatusOK || recovery == "" {
		t.Fatalf("setup: %d %s", resp.StatusCode, page)
	}

	// A read-only sign-in sees no tool that sends or changes anything.
	readToken := d.signIn("whatsapp.read")
	read := d.toolNames(readToken)
	if !read["list_messages"] || read["send_message"] || read["create_group"] {
		t.Fatalf("read-only tools: list_messages=%v send_message=%v create_group=%v", read["list_messages"], read["send_message"], read["create_group"])
	}
	// A sign-in with sending gets send tools but still no group management.
	sendToken := d.signIn("whatsapp.read", "whatsapp.send")
	send := d.toolNames(sendToken)
	if !send["send_message"] || send["create_group"] {
		t.Fatalf("send tools: send_message=%v create_group=%v", send["send_message"], send["create_group"])
	}
	d.waitForLog("instance unlocked", 1, 30*time.Second)

	// On disk: only the state database is readable, and it holds no secret.
	err := filepath.WalkDir(d.storeDir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		name := filepath.Base(p)
		if strings.HasPrefix(name, "meta.db") {
			for label, secret := range map[string]string{"the passphrase": e2ePassphrase, "the recovery code": recovery,
				"an access token": strings.TrimPrefix(readToken, "wamcp_at_"), "the setup code": e2eSetupToken} {
				if bytes.Contains(b, []byte(secret)) {
					t.Errorf("%s contains %s", name, label)
				}
			}
			return nil
		}
		for _, needle := range []string{"SQLite format 3", "CREATE TABLE", "whatsmeow_device"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s contains %q in the clear", name, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Idle: the instance locks itself.
	d.waitForLog("instance locked", 1, 30*time.Second)

	// The same token, and nothing else, brings it back.
	if again := d.toolNames(readToken); !again["list_messages"] || again["send_message"] {
		t.Fatalf("after re-unlock the read-only token sees: send_message=%v", again["send_message"])
	}
	d.waitForLog("instance unlocked", 2, 30*time.Second)
}

// The development mode that reads the key from the environment must refuse to
// be exposed to the network.
func TestKeyInEnvironmentModeRefusesRemoteBinding(t *testing.T) {
	bin := filepath.Join(repoRoot(t), "bin", "whatsapp-mcp")
	cmd := exec.Command(bin, "-store", t.TempDir(), "serve", "-addr", "0.0.0.0:0", "-allow-remote")
	cmd.Env = append(os.Environ(), "WHATSAPP_MCP_VAULT_KEY="+strings.Repeat("ab", 32))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the daemon started; output:\n%s", out)
	}
	if !strings.Contains(string(out), "WHATSAPP_MCP_VAULT_KEY") || !strings.Contains(string(out), "local use only") {
		t.Fatalf("refusal does not explain itself:\n%s", out)
	}
}
