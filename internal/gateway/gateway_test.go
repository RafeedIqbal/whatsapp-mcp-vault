package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/oauth"
	"github.com/sealjay/mcp-whatsapp/internal/session"
	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

const (
	testIssuer     = "https://wa.example.test"
	testSetupToken = "setup-token-from-the-host-0123456789"
	testPassphrase = "correct horse battery staple"
)

// fakeRuntime stands in for the stores, WhatsApp client and tool server.
type fakeRuntime struct {
	key    vault.Key
	closed atomic.Int32
}

func (r *fakeRuntime) Close() error { r.closed.Add(1); return nil }
func (r *fakeRuntime) MCP(scope string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "mcp:"+scope) })
}
func (r *fakeRuntime) Owner() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { io.WriteString(w, "owner:"+req.URL.Path) })
}

type fixture struct {
	t        *testing.T
	srv      *httptest.Server
	meta     *vault.Meta
	store    *oauth.Store
	sessions *session.Manager[*fakeRuntime]
	builds   atomic.Int32
	lastRT   atomic.Pointer[fakeRuntime]
	buildErr error
	now      time.Time
	gw       *Gateway[*fakeRuntime]
}

type fixtureOpt func(*Config[*fakeRuntime])

func newFixture(t *testing.T, opts ...fixtureOpt) *fixture {
	t.Helper()
	f := &fixture{t: t, now: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	meta, err := vault.OpenMeta(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	if err := meta.SetKDFParams(vault.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	f.meta = meta
	f.store, err = oauth.NewStore(meta.DB())
	if err != nil {
		t.Fatal(err)
	}
	f.sessions = session.New(func(_ context.Context, key vault.Key) (*fakeRuntime, error) {
		f.builds.Add(1)
		if f.buildErr != nil {
			return nil, f.buildErr
		}
		rt := &fakeRuntime{key: key}
		f.lastRT.Store(rt)
		return rt, nil
	}, 15*time.Minute)
	cfg := Config[*fakeRuntime]{
		Meta:       meta,
		OAuth:      oauth.NewServer(oauth.Config{Issuer: testIssuer, Store: f.store, Unlock: meta.Unlock}),
		RevokeAll:  f.store.RevokeAll,
		Sessions:   f.sessions,
		SetupToken: testSetupToken,
		Now:        func() time.Time { return f.now },
	}
	for _, o := range opts {
		o(&cfg)
	}
	f.gw = New(cfg)
	f.srv = httptest.NewServer(f.gw.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

// browser is an HTTP client with a cookie jar that does not follow redirects.
func (f *fixture) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (f *fixture) get(c *http.Client, path string) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
	return do(f.t, c, req)
}

func (f *fixture) post(c *http.Client, path string, form url.Values) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(f.t, c, req)
}

func (f *fixture) mcp(token string) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/mcp", strings.NewReader(`{}`))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(f.t, http.DefaultClient, req)
}

// setUp initialises the vault through the setup page and returns the browser
// (now holding the owner cookie) and the page it was shown.
func (f *fixture) setUp() (*http.Client, string) {
	f.t.Helper()
	b := f.browser()
	resp, body := f.post(b, "/setup", url.Values{"action": {"init"}, "setup_token": {testSetupToken},
		"passphrase": {testPassphrase}, "confirm": {testPassphrase}})
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("setup: status %d body %s", resp.StatusCode, body)
	}
	return b, body
}

// token issues an access token directly from the store, as a completed
// sign-in would.
func (f *fixture) token(scope string) string {
	f.t.Helper()
	key, err := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase)
	if err != nil {
		f.t.Fatal(err)
	}
	pair, err := f.store.IssueTokens(context.Background(), oauth.Grant{ClientID: "c", Scope: scope, Resource: testIssuer + "/mcp"}, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return pair.AccessToken
}

// --- always available ------------------------------------------------------

func TestHealthIsAvailableWhileLockedAndBeforeSetup(t *testing.T) {
	f := newFixture(t)
	if resp, _ := f.get(http.DefaultClient, "/healthz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d", resp.StatusCode)
	}
	if f.builds.Load() != 0 {
		t.Fatal("a health check unlocked the instance")
	}
}

// A locked instance is the normal resting state, not a fault: the readiness
// probe (used by the container health check) must pass while locked, or the
// host would keep restarting an instance that is simply idle.
func TestReadinessPassesWhileLocked(t *testing.T) {
	f := newFixture(t)
	if resp, _ := f.get(http.DefaultClient, "/readyz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz = %d while locked, want 200", resp.StatusCode)
	}
	if f.builds.Load() != 0 {
		t.Fatal("a readiness probe unlocked the instance")
	}
}

func TestSignInDiscoveryIsServed(t *testing.T) {
	f := newFixture(t)
	resp, body := f.get(http.DefaultClient, "/.well-known/oauth-authorization-server")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, testIssuer+"/token") {
		t.Fatalf("AS metadata: %d %s", resp.StatusCode, body)
	}
}

// --- the tool endpoint -----------------------------------------------------

func TestToolEndpointRequiresAToken(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	for name, tok := range map[string]string{"no token": "", "garbage": "nonsense", "made-up": "wamcp_at_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		resp, body := f.mcp(tok)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d body %s, want 401", name, resp.StatusCode, body)
		}
		if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
			t.Errorf("%s: no pointer to sign-in in WWW-Authenticate", name)
		}
		if strings.HasPrefix(body, "mcp:") {
			t.Errorf("%s: the request reached the tools", name)
		}
	}
	if f.builds.Load() != 0 || f.sessions.Unlocked() {
		t.Fatal("an unauthenticated request unlocked the instance")
	}
}

func TestAValidTokenUnlocksAndReachesTheTools(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	f.sessions.Lock() // setup leaves the owner signed in; start from locked
	builds := f.builds.Load()

	tok := f.token("whatsapp.read whatsapp.send")
	resp, body := f.mcp(tok)
	if resp.StatusCode != http.StatusOK || body != "mcp:whatsapp.read whatsapp.send" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if !f.sessions.Unlocked() || f.builds.Load() != builds+1 {
		t.Fatalf("unlocked=%v builds=%d", f.sessions.Unlocked(), f.builds.Load())
	}
	// The runtime was built with the vault's own key, carried by the token.
	want, _ := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase)
	if f.lastRT.Load().key != want {
		t.Fatal("the runtime was not built with the instance key")
	}
	// A second call shares the unlocked runtime.
	f.mcp(tok)
	if f.builds.Load() != builds+1 {
		t.Fatal("a second request unlocked again")
	}
}

func TestEachTokenGetsOnlyItsOwnPermissionTier(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	for _, scope := range []string{"whatsapp.read", "whatsapp.read whatsapp.send", "whatsapp.read whatsapp.manage"} {
		if _, body := f.mcp(f.token(scope)); body != "mcp:"+scope {
			t.Errorf("token with scope %q reached %q", scope, body)
		}
	}
}

func TestAfterAnIdleLockTheTokenAloneUnlocksAgain(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	tok := f.token("whatsapp.read")
	f.mcp(tok)
	first := f.lastRT.Load()
	f.sessions.Lock()
	if first.closed.Load() != 1 || f.sessions.Unlocked() {
		t.Fatal("precondition: instance should be locked")
	}
	builds := f.builds.Load()
	if resp, body := f.mcp(tok); resp.StatusCode != http.StatusOK || body != "mcp:whatsapp.read" {
		t.Fatalf("after lock: status %d body %q", resp.StatusCode, body)
	}
	if f.builds.Load() != builds+1 || f.lastRT.Load() == first {
		t.Fatal("the instance did not unlock afresh from the token")
	}
}

func TestARevokedTokenNoLongerUnlocks(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	tok := f.token("whatsapp.read")
	if err := f.store.RevokeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.sessions.Lock()
	builds := f.builds.Load()
	if resp, _ := f.mcp(tok); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token: status %d", resp.StatusCode)
	}
	if f.builds.Load() != builds {
		t.Fatal("a revoked token unlocked the instance")
	}
}

func TestUnlockFailureIsReportedWithoutDetails(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	f.sessions.Lock()
	f.buildErr = errors.New("open messages db: disk says /secret/path is corrupt")
	resp, body := f.mcp(f.token("whatsapp.read"))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
	if strings.Contains(body, "/secret/path") || strings.Contains(body, "corrupt") {
		t.Fatalf("internal error text reached the client: %s", body)
	}
}

// --- setup -----------------------------------------------------------------

var recoveryPattern = regexp.MustCompile(`\b([A-Z2-9]{4}(?:-[A-Z2-9]{4}){7})\b`)

func TestSetupCreatesTheVaultAndShowsTheRecoveryCodeOnce(t *testing.T) {
	f := newFixture(t)
	if _, body := f.get(http.DefaultClient, "/setup"); !strings.Contains(strings.ToLower(body), "setup code") {
		t.Fatalf("setup page does not ask for the setup code: %s", body)
	}
	b, body := f.setUp()
	m := recoveryPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no recovery code on the page: %s", body)
	}
	if ok, _ := f.meta.Initialized(context.Background()); !ok {
		t.Fatal("vault not initialised after setup")
	}
	fromPass, err := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase)
	if err != nil {
		t.Fatalf("the chosen passphrase does not unlock: %v", err)
	}
	fromCode, err := f.meta.UnlockWithRecoveryCode(context.Background(), m[1])
	if err != nil || fromCode != fromPass {
		t.Fatalf("the shown recovery code does not unlock the same key: %v", err)
	}
	// The code is not shown again.
	if _, again := f.get(b, "/setup"); recoveryPattern.MatchString(again) {
		t.Fatal("the recovery code is shown a second time")
	}
}

func TestSetupRequiresTheSetupCode(t *testing.T) {
	f := newFixture(t)
	for name, code := range map[string]string{"wrong": "not-the-setup-token", "empty": "", "prefix": testSetupToken[:10]} {
		resp, _ := f.post(f.browser(), "/setup", url.Values{"action": {"init"}, "setup_token": {code},
			"passphrase": {testPassphrase}, "confirm": {testPassphrase}})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s setup code: status %d, want 403", name, resp.StatusCode)
		}
	}
	if ok, _ := f.meta.Initialized(context.Background()); ok {
		t.Fatal("the vault was initialised without the setup code")
	}
}

func TestSetupIsDisabledWhenNoSetupCodeIsConfigured(t *testing.T) {
	// Without a configured code, anyone who found the URL first could claim
	// the instance.
	f := newFixture(t, func(c *Config[*fakeRuntime]) { c.SetupToken = "" })
	resp, _ := f.post(f.browser(), "/setup", url.Values{"action": {"init"}, "setup_token": {""},
		"passphrase": {testPassphrase}, "confirm": {testPassphrase}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	if ok, _ := f.meta.Initialized(context.Background()); ok {
		t.Fatal("setup ran with no setup code configured")
	}
}

func TestSetupRejectsMismatchedOrWeakPassphrases(t *testing.T) {
	f := newFixture(t)
	for name, form := range map[string]url.Values{
		"mismatch": {"action": {"init"}, "setup_token": {testSetupToken}, "passphrase": {testPassphrase}, "confirm": {"something different here"}},
		"too weak": {"action": {"init"}, "setup_token": {testSetupToken}, "passphrase": {"short"}, "confirm": {"short"}},
	} {
		resp, _ := f.post(f.browser(), "/setup", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, resp.StatusCode)
		}
	}
	if ok, _ := f.meta.Initialized(context.Background()); ok {
		t.Fatal("a rejected passphrase initialised the vault")
	}
}

func TestSetupCannotBeRunTwice(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	before, _ := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase)
	resp, _ := f.post(f.browser(), "/setup", url.Values{"action": {"init"}, "setup_token": {testSetupToken},
		"passphrase": {"an attacker's passphrase 123"}, "confirm": {"an attacker's passphrase 123"}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second setup: status %d, want 409", resp.StatusCode)
	}
	after, err := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase)
	if err != nil || after != before {
		t.Fatal("a second setup changed the vault")
	}
}

func TestSetupPagesCannotBeFramedOrCached(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.get(http.DefaultClient, "/setup")
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("XFO=%q Cache-Control=%q", resp.Header.Get("X-Frame-Options"), resp.Header.Get("Cache-Control"))
	}
}

// --- owner pages (pairing) -------------------------------------------------

func ownerCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == ownerCookieName {
			return c
		}
	}
	return nil
}

func TestOwnerPagesNeedAnOwnerSignIn(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	f.sessions.Lock()
	builds := f.builds.Load()
	for _, path := range []string{"/pair", "/pair/qr.png", "/pair/reset"} {
		resp, body := f.get(f.browser(), path)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" || strings.HasPrefix(body, "owner:") {
			t.Errorf("%s without sign-in: status %d location %q body %q", path, resp.StatusCode, resp.Header.Get("Location"), body)
		}
	}
	if f.builds.Load() != builds {
		t.Fatal("an anonymous request to the owner pages unlocked the instance")
	}
}

func TestSetupSignsTheOwnerInForPairing(t *testing.T) {
	f := newFixture(t)
	b, _ := f.setUp()
	resp, body := f.get(b, "/pair")
	if resp.StatusCode != http.StatusOK || body != "owner:/pair" {
		t.Fatalf("/pair after setup: status %d body %q", resp.StatusCode, body)
	}
	if !f.sessions.Unlocked() {
		t.Fatal("the owner pages did not unlock the instance")
	}
}

func TestOwnerCanSignInAgainWithThePassphrase(t *testing.T) {
	f := newFixture(t)
	f.setUp()

	b := f.browser()
	resp, body := f.post(b, "/setup", url.Values{"action": {"login"}, "passphrase": {"definitely not the passphrase"}})
	if resp.StatusCode != http.StatusOK || ownerCookie(resp) != nil || !strings.Contains(strings.ToLower(body), "wrong passphrase") {
		t.Fatalf("wrong passphrase: status %d cookie=%v", resp.StatusCode, ownerCookie(resp))
	}
	resp, _ = f.post(b, "/setup", url.Values{"action": {"login"}, "passphrase": {testPassphrase}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/pair" || ownerCookie(resp) == nil {
		t.Fatalf("right passphrase: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, body := f.get(b, "/pair"); body != "owner:/pair" {
		t.Fatalf("/pair after login = %q", body)
	}
}

func TestOwnerCookieIsLockedDown(t *testing.T) {
	f := newFixture(t, func(c *Config[*fakeRuntime]) { c.SecureCookies = true })
	resp, _ := f.post(f.browser(), "/setup", url.Values{"action": {"init"}, "setup_token": {testSetupToken},
		"passphrase": {testPassphrase}, "confirm": {testPassphrase}})
	c := ownerCookie(resp)
	if c == nil {
		t.Fatal("no owner cookie set")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie attributes: HttpOnly=%v Secure=%v SameSite=%v Path=%q", c.HttpOnly, c.Secure, c.SameSite, c.Path)
	}
	if len(c.Value) < 32 {
		t.Fatalf("owner session id is only %d characters", len(c.Value))
	}
}

func TestOwnerSignInExpiresWhenIdle(t *testing.T) {
	f := newFixture(t)
	b, _ := f.setUp()
	if _, body := f.get(b, "/pair"); body != "owner:/pair" {
		t.Fatal("precondition: signed in")
	}
	f.now = f.now.Add(ownerIdle + time.Minute)
	if resp, _ := f.get(b, "/pair"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("idle owner session still works: status %d", resp.StatusCode)
	}
}

func TestAForgedOwnerCookieIsIgnored(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/pair", nil)
	req.AddCookie(&http.Cookie{Name: ownerCookieName, Value: strings.Repeat("A", 43)})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if resp, body := do(t, c, req); resp.StatusCode != http.StatusSeeOther || strings.HasPrefix(body, "owner:") {
		t.Fatalf("forged cookie: status %d body %q", resp.StatusCode, body)
	}
}

func TestOwnerPagesRefuseRequestsCausedByAnotherSite(t *testing.T) {
	f := newFixture(t)
	b, _ := f.setUp()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/pair/reset", strings.NewReader(""))
	req.Header.Set("Origin", "https://evil.example")
	if resp, body := do(t, b, req); resp.StatusCode != http.StatusForbidden || strings.HasPrefix(body, "owner:") {
		t.Fatalf("cross-site POST: status %d body %q", resp.StatusCode, body)
	}
	// The same request from this site goes through.
	same, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/pair/reset", strings.NewReader(""))
	same.Header.Set("Origin", f.srv.URL)
	if resp, body := do(t, b, same); resp.StatusCode != http.StatusOK || body != "owner:/pair/reset" {
		t.Fatalf("same-site POST: status %d body %q", resp.StatusCode, body)
	}
}

// Upload pages and download links are served by the front door itself, with
// no sign-in (their one-time address is the permission) and without waking a
// locked instance.
func TestExtraRoutesAreServedWithoutUnlocking(t *testing.T) {
	f := newFixture(t, func(c *Config[*fakeRuntime]) {
		c.Extra = func(mux *http.ServeMux) {
			mux.HandleFunc("GET /upload/{id}", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upload:"+r.PathValue("id")) })
		}
	})
	resp, body := f.get(http.DefaultClient, "/upload/abc")
	if resp.StatusCode != http.StatusOK || body != "upload:abc" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if f.builds.Load() != 0 {
		t.Fatal("an upload page request unlocked the instance")
	}
}

// --- owner key lifetime ----------------------------------------------------

// An owner sign-in keeps the key in memory so the pairing pages work. It must
// be dropped when idle even if the owner simply closes the tab and never
// sends another request.
func TestOwnerKeyIsForgottenWhenIdleWithNoFurtherRequest(t *testing.T) {
	f := newFixture(t)
	f.setUp()
	if n := f.gw.ownerCount(); n != 1 {
		t.Fatalf("owner sessions after setup = %d, want 1", n)
	}
	f.now = f.now.Add(ownerIdle - time.Minute)
	f.gw.ExpireOwners()
	if f.gw.ownerCount() != 1 {
		t.Fatal("an owner session was dropped before it was idle")
	}
	f.now = f.now.Add(2 * time.Minute)
	f.gw.ExpireOwners()
	if n := f.gw.ownerCount(); n != 0 {
		t.Fatalf("%d owner session(s) still hold the key after the idle period", n)
	}
}

func (f *fixture) ownerAction(b *http.Client, form url.Values) (*http.Response, string) {
	return f.post(b, "/setup", form)
}

func TestLockNowForgetsOwnerKeysAndLocksTheInstance(t *testing.T) {
	f := newFixture(t)
	b, _ := f.setUp()
	f.get(b, "/pair") // unlocks
	if !f.sessions.Unlocked() {
		t.Fatal("precondition: unlocked")
	}
	resp, _ := f.ownerAction(b, url.Values{"action": {"lock"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("lock: status %d", resp.StatusCode)
	}
	if f.sessions.Unlocked() || f.gw.ownerCount() != 0 {
		t.Fatalf("after lock now: unlocked=%v owner sessions=%d", f.sessions.Unlocked(), f.gw.ownerCount())
	}
	if resp, _ := f.get(b, "/pair"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("the owner pages still open after lock now: status %d", resp.StatusCode)
	}
}

func TestOwnerCanSignOut(t *testing.T) {
	f := newFixture(t)
	b, _ := f.setUp()
	if resp, _ := f.ownerAction(b, url.Values{"action": {"logout"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	if f.gw.ownerCount() != 0 {
		t.Fatal("sign-out left the key in memory")
	}
	if resp, _ := f.get(b, "/pair"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("owner pages open after sign-out: status %d", resp.StatusCode)
	}
}

// --- recovery, passphrase change, revoking sign-ins ------------------------

func recoveryCodeFrom(t *testing.T, page string) string {
	t.Helper()
	m := recoveryPattern.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no recovery code on the setup page")
	}
	return m[1]
}

func TestRecoveryCodeSetsANewPassphrase(t *testing.T) {
	f := newFixture(t)
	_, page := f.setUp()
	code := recoveryCodeFrom(t, page)
	before, _ := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase)
	const next = "a brand new passphrase after recovery"

	b := f.browser()
	if resp, _ := f.post(b, "/setup", url.Values{"action": {"recover"}, "recovery_code": {"AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"}, "passphrase": {next}, "confirm": {next}}); resp.StatusCode != http.StatusOK || ownerCookie(resp) != nil {
		t.Fatalf("wrong recovery code: status %d cookie=%v", resp.StatusCode, ownerCookie(resp))
	}
	if resp, _ := f.post(b, "/setup", url.Values{"action": {"recover"}, "recovery_code": {code}, "passphrase": {next}, "confirm": {"something else entirely"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched new passphrase: status %d", resp.StatusCode)
	}
	resp, _ := f.post(b, "/setup", url.Values{"action": {"recover"}, "recovery_code": {strings.ToLower(code)}, "passphrase": {next}, "confirm": {next}})
	if resp.StatusCode != http.StatusSeeOther || ownerCookie(resp) == nil {
		t.Fatalf("recovery: status %d", resp.StatusCode)
	}
	if _, err := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase); !errors.Is(err, vault.ErrWrongSecret) {
		t.Fatalf("the forgotten passphrase still works (err=%v)", err)
	}
	after, err := f.meta.UnlockWithPassphrase(context.Background(), next)
	if err != nil || after != before {
		t.Fatalf("new passphrase: same key=%v err=%v", after == before, err)
	}
}

func TestRecoveryWorksWhilePassphraseSignInIsPaused(t *testing.T) {
	f := newFixture(t)
	_, page := f.setUp()
	code := recoveryCodeFrom(t, page)
	for i := 0; i < 6; i++ {
		f.post(f.browser(), "/setup", url.Values{"action": {"login"}, "passphrase": {"a wrong guess from someone"}})
	}
	if resp, body := f.post(f.browser(), "/setup", url.Values{"action": {"login"}, "passphrase": {testPassphrase}}); resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("precondition: passphrase sign-in should be paused, got %d %s", resp.StatusCode, body)
	}
	// The recovery code signs the owner in directly...
	if resp, _ := f.post(f.browser(), "/setup", url.Values{"action": {"login"}, "passphrase": {code}}); resp.StatusCode != http.StatusSeeOther || ownerCookie(resp) == nil {
		t.Fatalf("recovery code at sign-in during a pause: status %d", resp.StatusCode)
	}
	// ...and can set a new passphrase.
	const next = "a new passphrase set during the pause"
	if resp, _ := f.post(f.browser(), "/setup", url.Values{"action": {"recover"}, "recovery_code": {code}, "passphrase": {next}, "confirm": {next}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("recovery during a pause: status %d", resp.StatusCode)
	}
}

func TestOwnerCanChangeThePassphrase(t *testing.T) {
	f := newFixture(t)
	b, _ := f.setUp()
	const next = "the owner chose another passphrase"

	// Not signed in: nothing changes.
	if resp, _ := f.post(f.browser(), "/setup", url.Values{"action": {"change"}, "passphrase": {next}, "confirm": {next}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("change without sign-in: status %d", resp.StatusCode)
	}
	if _, err := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase); err != nil {
		t.Fatalf("an anonymous request changed the passphrase: %v", err)
	}

	if resp, _ := f.ownerAction(b, url.Values{"action": {"change"}, "passphrase": {next}, "confirm": {"mismatch here"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatch: status %d", resp.StatusCode)
	}
	if resp, body := f.ownerAction(b, url.Values{"action": {"change"}, "passphrase": {next}, "confirm": {next}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("change: status %d %s", resp.StatusCode, body)
	}
	if _, err := f.meta.UnlockWithPassphrase(context.Background(), next); err != nil {
		t.Fatalf("new passphrase does not work: %v", err)
	}
	if _, err := f.meta.UnlockWithPassphrase(context.Background(), testPassphrase); !errors.Is(err, vault.ErrWrongSecret) {
		t.Fatalf("old passphrase still works (err=%v)", err)
	}
}

func TestOwnerCanSignEveryAppOut(t *testing.T) {
	f := newFixture(t, func(c *Config[*fakeRuntime]) {})
	b, _ := f.setUp()
	tok := f.token("whatsapp.read")
	if resp, _ := f.mcp(tok); resp.StatusCode != http.StatusOK {
		t.Fatal("precondition: token works")
	}
	// Not signed in: tokens are untouched.
	f.post(f.browser(), "/setup", url.Values{"action": {"revoke"}})
	if resp, _ := f.mcp(tok); resp.StatusCode != http.StatusOK {
		t.Fatal("an anonymous request revoked the tokens")
	}
	if resp, body := f.ownerAction(b, url.Values{"action": {"revoke"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: status %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.mcp(tok); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a token still works after the owner signed every app out: status %d", resp.StatusCode)
	}
}
