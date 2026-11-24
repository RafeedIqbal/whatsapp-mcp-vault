package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

const (
	testIssuer     = "https://wa.example.test"
	testPassphrase = "correct horse battery staple"
	claudeCallback = "https://claude.ai/api/mcp/auth_callback"
	testVerifier   = "a-pkce-verifier-that-is-long-enough-to-be-valid-0123456789"
)

type serverFixture struct {
	t     *testing.T
	srv   *httptest.Server
	store *Store
	key   vault.Key
	clock *fakeClock
	oauth *Server
}

// newServerFixture runs the sign-in server over a real vault state database
// that has been set up with testPassphrase.
func newServerFixture(t *testing.T) *serverFixture {
	t.Helper()
	meta, err := vault.OpenMeta(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	if err := meta.SetKDFParams(vault.KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}); err != nil {
		t.Fatal(err)
	}
	key, _, err := meta.Initialize(context.Background(), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(meta.DB())
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: time.Now()}
	o := NewServer(Config{
		Issuer: testIssuer,
		Store:  store,
		Unlock: meta.UnlockWithPassphrase,
		Now:    clock.now,
	})
	mux := http.NewServeMux()
	o.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &serverFixture{t: t, srv: srv, store: store, key: key, clock: clock, oauth: o}
}

// client never follows redirects: the tests inspect them.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (f *serverFixture) get(path string) (*http.Response, string) {
	f.t.Helper()
	resp, err := noRedirect.Get(f.srv.URL + path)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (f *serverFixture) postForm(path string, v url.Values) (*http.Response, string) {
	f.t.Helper()
	resp, err := noRedirect.PostForm(f.srv.URL+path, v)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (f *serverFixture) postJSON(path string, body any) (*http.Response, map[string]any) {
	f.t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := noRedirect.Post(f.srv.URL+path, "application/json", strings.NewReader(string(buf)))
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (f *serverFixture) register(redirect string) string {
	f.t.Helper()
	resp, out := f.postJSON("/register", map[string]any{"client_name": "Claude", "redirect_uris": []string{redirect}})
	if resp.StatusCode != http.StatusCreated {
		f.t.Fatalf("register %s: status %d body %v", redirect, resp.StatusCode, out)
	}
	return out["client_id"].(string)
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeQuery(clientID, redirect string, extra url.Values) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"code_challenge":        {challengeFor(testVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"st4te"},
		"scope":                 {"whatsapp.read whatsapp.send"},
		"resource":              {testIssuer + "/mcp"},
	}
	for k, v := range extra {
		if v == nil {
			q.Del(k)
		} else {
			q[k] = v
		}
	}
	return "/authorize?" + q.Encode()
}

var requestIDPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)

// consent loads the consent page and returns its request id.
func (f *serverFixture) consent(clientID, redirect string, extra url.Values) string {
	f.t.Helper()
	resp, body := f.get(authorizeQuery(clientID, redirect, extra))
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("GET /authorize: status %d body %s", resp.StatusCode, body)
	}
	m := requestIDPattern.FindStringSubmatch(body)
	if m == nil {
		f.t.Fatalf("consent page has no request_id: %s", body)
	}
	return m[1]
}

// approve submits the consent form and returns the redirect it produced.
func (f *serverFixture) approve(requestID, passphrase string, scopes ...string) (*http.Response, *url.URL, string) {
	f.t.Helper()
	form := url.Values{"request_id": {requestID}, "passphrase": {passphrase}, "action": {"approve"}, "scope": scopes}
	resp, body := f.postForm("/authorize", form)
	var loc *url.URL
	if l := resp.Header.Get("Location"); l != "" {
		loc, _ = url.Parse(l)
	}
	return resp, loc, body
}

// signIn runs the whole flow and returns the token response.
func (f *serverFixture) signIn(scopes ...string) map[string]any {
	f.t.Helper()
	clientID := f.register(claudeCallback)
	reqID := f.consent(clientID, claudeCallback, nil)
	resp, loc, body := f.approve(reqID, testPassphrase, scopes...)
	if resp.StatusCode != http.StatusFound || loc == nil || loc.Query().Get("code") == "" {
		f.t.Fatalf("approve: status %d location %v body %s", resp.StatusCode, loc, body)
	}
	tr, raw := f.postForm("/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {claudeCallback}, "code_verifier": {testVerifier}, "resource": {testIssuer + "/mcp"},
	})
	if tr.StatusCode != http.StatusOK {
		f.t.Fatalf("token: status %d body %s", tr.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		f.t.Fatal(err)
	}
	out["client_id"] = clientID
	return out
}

func bearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// --- discovery -------------------------------------------------------------

func TestDiscoveryDocumentsDescribeThisServer(t *testing.T) {
	f := newServerFixture(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, body := f.get(path)
		var doc map[string]any
		if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &doc) != nil {
			t.Fatalf("%s: status %d body %s", path, resp.StatusCode, body)
		}
		if doc["resource"] != testIssuer+"/mcp" {
			t.Errorf("%s resource = %v", path, doc["resource"])
		}
		if as, _ := doc["authorization_servers"].([]any); len(as) != 1 || as[0] != testIssuer {
			t.Errorf("%s authorization_servers = %v", path, doc["authorization_servers"])
		}
	}

	resp, body := f.get("/.well-known/oauth-authorization-server")
	var as map[string]any
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &as) != nil {
		t.Fatalf("AS metadata: status %d body %s", resp.StatusCode, body)
	}
	want := map[string]any{
		"issuer": testIssuer, "authorization_endpoint": testIssuer + "/authorize",
		"token_endpoint": testIssuer + "/token", "registration_endpoint": testIssuer + "/register",
	}
	for k, v := range want {
		if as[k] != v {
			t.Errorf("%s = %v, want %v", k, as[k], v)
		}
	}
	has := func(key, val string) bool {
		list, _ := as[key].([]any)
		for _, x := range list {
			if x == val {
				return true
			}
		}
		return false
	}
	if !has("code_challenge_methods_supported", "S256") || has("code_challenge_methods_supported", "plain") {
		t.Errorf("PKCE methods = %v, want S256 only", as["code_challenge_methods_supported"])
	}
	if !has("token_endpoint_auth_methods_supported", "none") || !has("grant_types_supported", "refresh_token") || !has("response_types_supported", "code") {
		t.Errorf("AS metadata missing required capabilities: %v", as)
	}
	if as["authorization_response_iss_parameter_supported"] != true {
		t.Errorf("iss parameter support not advertised")
	}
}

func TestUnauthenticatedRequestsAreToldWhereToSignIn(t *testing.T) {
	f := newServerFixture(t)
	rec := httptest.NewRecorder()
	f.oauth.WriteUnauthorized(rec)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	h := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(h, "Bearer ") || !strings.Contains(h, `resource_metadata="`+testIssuer+`/.well-known/oauth-protected-resource"`) {
		t.Fatalf("WWW-Authenticate = %q", h)
	}
}

// --- registration ----------------------------------------------------------

func TestRegistrationAcceptsKnownCallbacksAndLoopback(t *testing.T) {
	f := newServerFixture(t)
	for _, redirect := range []string{claudeCallback, "http://127.0.0.1:49152/callback", "http://localhost:3334/oauth/callback"} {
		if id := f.register(redirect); id == "" {
			t.Errorf("no client_id for %s", redirect)
		}
	}
}

func TestRegistrationRejectsCallbacksItDoesNotKnow(t *testing.T) {
	// A sign-in code is delivered to the callback. An arbitrary callback
	// would let any website pose as a client and collect one.
	f := newServerFixture(t)
	for _, redirect := range []string{
		"https://evil.example/callback",
		"https://claude.ai.evil.example/api/mcp/auth_callback",
		"http://claude.ai/api/mcp/auth_callback", // not https
		"http://192.168.1.10/callback",           // not loopback
		"javascript:alert(1)",
		"claude://callback",
		"",
	} {
		resp, out := f.postJSON("/register", map[string]any{"client_name": "x", "redirect_uris": []string{redirect}})
		if resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_redirect_uri" {
			t.Errorf("redirect %q: status %d body %v, want 400 invalid_redirect_uri", redirect, resp.StatusCode, out)
		}
	}
	resp, out := f.postJSON("/register", map[string]any{"client_name": "x", "redirect_uris": []string{}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no redirect URIs: status %d body %v", resp.StatusCode, out)
	}
}

func TestRegistrationIsRateLimited(t *testing.T) {
	f := newServerFixture(t)
	for i := 0; i < registrationsPerHour; i++ {
		f.register(claudeCallback)
	}
	resp, _ := f.postJSON("/register", map[string]any{"client_name": "x", "redirect_uris": []string{claudeCallback}})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after %d registrations", resp.StatusCode, registrationsPerHour)
	}
	f.clock.advance(time.Hour + time.Minute)
	f.register(claudeCallback) // allowed again
}

// --- the sign-in flow ------------------------------------------------------

func TestSignInIssuesTokensThatOpenTheVault(t *testing.T) {
	f := newServerFixture(t)
	tok := f.signIn("whatsapp.read", "whatsapp.send")

	if tok["token_type"] != "Bearer" || tok["refresh_token"] == nil || tok["expires_in"] != float64(accessTTL/time.Second) {
		t.Fatalf("token response = %v", tok)
	}
	if tok["scope"] != "whatsapp.read whatsapp.send" {
		t.Fatalf("scope = %v", tok["scope"])
	}
	g, key, err := f.oauth.Authenticate(bearer(tok["access_token"].(string)))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if key != f.key {
		t.Fatal("the access token does not open the instance key")
	}
	if g.Scope != "whatsapp.read whatsapp.send" || g.Resource != testIssuer+"/mcp" {
		t.Fatalf("grant = %+v", g)
	}
}

func TestApprovalRedirectCarriesStateAndIssuer(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	resp, loc, _ := f.approve(f.consent(clientID, claudeCallback, nil), testPassphrase, "whatsapp.read")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != claudeCallback {
		t.Fatalf("redirected to %s", got)
	}
	q := loc.Query()
	if q.Get("state") != "st4te" || q.Get("iss") != testIssuer || !strings.HasPrefix(q.Get("code"), codePrefix) {
		t.Fatalf("redirect query = %v", q)
	}
}

func TestOnlyTheScopesTheOwnerTickedAreGranted(t *testing.T) {
	f := newServerFixture(t)
	// The client asked for read and send; the owner ticked read only.
	if tok := f.signIn("whatsapp.read"); tok["scope"] != "whatsapp.read" {
		t.Fatalf("scope = %v, want whatsapp.read only", tok["scope"])
	}
	// Ticking something the client never asked for, or an unknown scope, adds nothing.
	if tok := f.signIn("whatsapp.read", "whatsapp.manage", "admin"); tok["scope"] != "whatsapp.read" {
		t.Fatalf("scope = %v, want whatsapp.read only", tok["scope"])
	}
	// Reading is the floor: approving with nothing ticked still grants read.
	if tok := f.signIn(); tok["scope"] != "whatsapp.read" {
		t.Fatalf("scope = %v, want whatsapp.read", tok["scope"])
	}
}

func TestWrongPassphraseIssuesNoCode(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	reqID := f.consent(clientID, claudeCallback, nil)
	resp, loc, body := f.approve(reqID, "not the passphrase at all", "whatsapp.read")
	if resp.StatusCode != http.StatusOK || loc != nil {
		t.Fatalf("status %d location %v: a wrong passphrase must stay on the page", resp.StatusCode, loc)
	}
	if !strings.Contains(strings.ToLower(body), "wrong passphrase") {
		t.Fatalf("page does not say the passphrase was wrong: %s", body)
	}
	// The page can be retried with the right passphrase.
	next := requestIDPattern.FindStringSubmatch(body)
	if next == nil {
		t.Fatal("no request_id on the retry page")
	}
	if resp, loc, _ := f.approve(next[1], testPassphrase, "whatsapp.read"); resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("retry with the right passphrase failed: status %d", resp.StatusCode)
	}
}

func TestRepeatedWrongPassphrasesLockSignIn(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	var body string
	for i := 0; i < 6; i++ {
		_, _, body = f.approve(f.consent(clientID, claudeCallback, nil), "wrong passphrase guess", "whatsapp.read")
	}
	if !strings.Contains(strings.ToLower(body), "too many") {
		t.Fatalf("no lockout message after repeated wrong guesses: %s", body)
	}
	// Even the right passphrase is refused while locked.
	if resp, loc, _ := f.approve(f.consent(clientID, claudeCallback, nil), testPassphrase, "whatsapp.read"); resp.StatusCode == http.StatusFound {
		t.Fatalf("signed in during a lockout: %v", loc)
	}
}

func TestDenyRedirectsWithAccessDenied(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	resp, _ := f.postForm("/authorize", url.Values{"request_id": {f.consent(clientID, claudeCallback, nil)}, "action": {"deny"}})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "st4te" || loc.Query().Get("code") != "" {
		t.Fatalf("deny: status %d location %v", resp.StatusCode, loc)
	}
}

func TestConsentRequestCannotBeReplayedOrForged(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	reqID := f.consent(clientID, claudeCallback, nil)
	if resp, _, _ := f.approve(reqID, testPassphrase, "whatsapp.read"); resp.StatusCode != http.StatusFound {
		t.Fatal("first approval failed")
	}
	if resp, loc, _ := f.approve(reqID, testPassphrase, "whatsapp.read"); resp.StatusCode != http.StatusBadRequest || loc != nil {
		t.Fatalf("replayed consent request: status %d", resp.StatusCode)
	}
	if resp, loc, _ := f.approve("made-up-request-id", testPassphrase, "whatsapp.read"); resp.StatusCode != http.StatusBadRequest || loc != nil {
		t.Fatalf("forged consent request: status %d", resp.StatusCode)
	}
	stale := f.consent(clientID, claudeCallback, nil)
	f.clock.advance(consentTTL + time.Second)
	if resp, _, _ := f.approve(stale, testPassphrase, "whatsapp.read"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired consent request: status %d", resp.StatusCode)
	}
}

// --- /authorize validation -------------------------------------------------

func TestAuthorizeNeverRedirectsToAnUnregisteredCallback(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	for name, path := range map[string]string{
		"unknown client":      authorizeQuery("c_nope", claudeCallback, nil),
		"different callback":  authorizeQuery(clientID, "https://evil.example/cb", nil),
		"callback with extra": authorizeQuery(clientID, claudeCallback+"/extra", nil),
	} {
		resp, _ := f.get(path)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d location %q, want a 400 page and no redirect", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestAuthorizeReportsRequestErrorsToTheClient(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	for name, tc := range map[string]struct {
		extra url.Values
		want  string
	}{
		"no PKCE challenge":   {url.Values{"code_challenge": nil}, "invalid_request"},
		"plain PKCE":          {url.Values{"code_challenge_method": {"plain"}}, "invalid_request"},
		"wrong response type": {url.Values{"response_type": {"token"}}, "unsupported_response_type"},
		"another resource":    {url.Values{"resource": {"https://other.example/mcp"}}, "invalid_target"},
	} {
		resp, _ := f.get(authorizeQuery(clientID, claudeCallback, tc.extra))
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != tc.want || loc.Query().Get("state") != "st4te" {
			t.Errorf("%s: status %d location %v, want redirect with error=%s", name, resp.StatusCode, loc, tc.want)
		}
	}
}

func TestConsentPageCannotBeFramedOrCached(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	resp, body := f.get(authorizeQuery(clientID, claudeCallback, nil))
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("consent page can be framed: XFO=%q CSP=%q", resp.Header.Get("X-Frame-Options"), resp.Header.Get("Content-Security-Policy"))
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	// The page names who is asking and where the code will go.
	if !strings.Contains(body, "Claude") || !strings.Contains(body, "claude.ai") {
		t.Errorf("consent page does not identify the client and its callback host")
	}
}

func TestClientNameIsEscapedOnTheConsentPage(t *testing.T) {
	f := newServerFixture(t)
	_, out := f.postJSON("/register", map[string]any{"client_name": `<script>alert(1)</script>`, "redirect_uris": []string{claudeCallback}})
	_, body := f.get(authorizeQuery(out["client_id"].(string), claudeCallback, nil))
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("client name is rendered as HTML")
	}
}

// --- /token ----------------------------------------------------------------

func (f *serverFixture) freshCode(clientID string) string {
	f.t.Helper()
	_, loc, _ := f.approve(f.consent(clientID, claudeCallback, nil), testPassphrase, "whatsapp.read")
	return loc.Query().Get("code")
}

func TestTokenExchangeChecksVerifierClientAndCallback(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	other := f.register(claudeCallback)
	good := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
			"redirect_uri": {claudeCallback}, "code_verifier": {testVerifier}}
	}
	for name, mutate := range map[string]func(url.Values){
		"wrong PKCE verifier":  func(v url.Values) { v.Set("code_verifier", "some-other-verifier-that-is-also-long-enough-000000") },
		"missing verifier":     func(v url.Values) { v.Del("code_verifier") },
		"another client":       func(v url.Values) { v.Set("client_id", other) },
		"another callback":     func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:1/cb") },
		"another resource":     func(v url.Values) { v.Set("resource", "https://other.example/mcp") },
		"made-up code":         func(v url.Values) { v.Set("code", codePrefix+"AAAA") },
		"unsupported grant":    func(v url.Values) { v.Set("grant_type", "password") },
		"client_id left blank": func(v url.Values) { v.Del("client_id") },
	} {
		form := good(f.freshCode(clientID))
		mutate(form)
		resp, body := f.postForm("/token", form)
		if resp.StatusCode != http.StatusBadRequest || strings.Contains(body, "access_token") {
			t.Errorf("%s: status %d body %s, want a 400 with no token", name, resp.StatusCode, body)
		}
		if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
			t.Errorf("%s: token response is cacheable", name)
		}
	}
}

func TestSignInCodeWorksOnlyOnce(t *testing.T) {
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {f.freshCode(clientID)}, "client_id": {clientID},
		"redirect_uri": {claudeCallback}, "code_verifier": {testVerifier}}
	if resp, body := f.postForm("/token", form); resp.StatusCode != http.StatusOK {
		t.Fatalf("first exchange: %d %s", resp.StatusCode, body)
	}
	resp, body := f.postForm("/token", form)
	var out map[string]any
	json.Unmarshal([]byte(body), &out)
	if resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("replayed code: status %d body %s", resp.StatusCode, body)
	}
}

func TestRefreshGrantRotatesTokens(t *testing.T) {
	f := newServerFixture(t)
	tok := f.signIn("whatsapp.read")
	clientID := tok["client_id"].(string)
	resp, body := f.postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {clientID}})
	var next map[string]any
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &next) != nil {
		t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	if next["access_token"] == tok["access_token"] || next["refresh_token"] == tok["refresh_token"] || next["scope"] != "whatsapp.read" {
		t.Fatalf("refresh response = %v", next)
	}
	if _, key, err := f.oauth.Authenticate(bearer(next["access_token"].(string))); err != nil || key != f.key {
		t.Fatalf("refreshed access token: key match=%v err=%v", key == f.key, err)
	}
	// Another client cannot use it.
	resp, _ = f.postForm("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {next["refresh_token"].(string)}, "client_id": {"c_someone_else"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh by another client: status %d", resp.StatusCode)
	}
}

// --- bearer authentication -------------------------------------------------

func TestAuthenticateRejectsMissingMalformedAndWrongAudienceTokens(t *testing.T) {
	f := newServerFixture(t)
	tok := f.signIn("whatsapp.read")

	none := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if _, _, err := f.oauth.Authenticate(none); err == nil {
		t.Error("request without a token authenticated")
	}
	basic := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	basic.Header.Set("Authorization", "Basic "+tok["access_token"].(string))
	if _, _, err := f.oauth.Authenticate(basic); err == nil {
		t.Error("non-Bearer Authorization authenticated")
	}
	inQuery := httptest.NewRequest(http.MethodPost, "/mcp?access_token="+tok["access_token"].(string), nil)
	if _, _, err := f.oauth.Authenticate(inQuery); err == nil {
		t.Error("token in the query string authenticated")
	}
	if _, _, err := f.oauth.Authenticate(bearer(tok["refresh_token"].(string))); err == nil {
		t.Error("refresh token accepted as an access token")
	}

	// A token minted for another resource must not work here.
	pair, _ := f.store.IssueTokens(context.Background(), Grant{ClientID: "c", Scope: "whatsapp.read", Resource: "https://other.example/mcp"}, f.key)
	if _, _, err := f.oauth.Authenticate(bearer(pair.AccessToken)); err == nil {
		t.Error("token for another resource authenticated")
	}
}

// --- flooding --------------------------------------------------------------

func TestAFloodOfConsentPagesDoesNotBlockARealSignIn(t *testing.T) {
	// Opening the consent page needs no credentials. Filling the server with
	// abandoned ones must push out the oldest, not refuse the newest.
	f := newServerFixture(t)
	clientID := f.register(claudeCallback)
	stale := f.consent(clientID, claudeCallback, nil)
	for i := 0; i < maxPendingConsents; i++ {
		f.consent(clientID, claudeCallback, nil)
	}
	fresh := f.consent(clientID, claudeCallback, nil)
	if resp, loc, body := f.approve(fresh, testPassphrase, "whatsapp.read"); resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("sign-in after a flood of consent pages failed: %d %s", resp.StatusCode, body)
	}
	if resp, _, _ := f.approve(stale, testPassphrase, "whatsapp.read"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the oldest consent page was not the one dropped: status %d", resp.StatusCode)
	}
}
