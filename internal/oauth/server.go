package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

// The permissions a client can be granted. Reading is the floor: every
// sign-in includes it. Sending and managing are opt-in on the consent page.
const (
	ScopeRead   = "whatsapp.read"
	ScopeSend   = "whatsapp.send"
	ScopeManage = "whatsapp.manage"
)

var supportedScopes = []string{ScopeRead, ScopeSend, ScopeManage}

const (
	resourcePath = "/mcp"
	// consentTTL is how long an open consent page stays valid.
	consentTTL = 10 * time.Minute
	// maxPendingConsents bounds the consent pages held in memory.
	maxPendingConsents = 200
	// registrationsPerHour limits dynamic client registration, which is
	// unauthenticated by design.
	registrationsPerHour = 20
)

// defaultRedirectURIs are the HTTPS callbacks accepted without configuration.
// A sign-in code is delivered to the callback, so only known ones are allowed;
// loopback callbacks (a client running on the owner's own machine) are always
// accepted.
var defaultRedirectURIs = []string{
	"https://claude.ai/api/mcp/auth_callback",
	"https://claude.com/api/mcp/auth_callback",
}

// Config configures the sign-in server.
type Config struct {
	// Issuer is the public base URL of this instance, e.g.
	// https://alice-wa.example.com (no trailing slash).
	Issuer string
	Store  *Store
	// Unlock checks the owner's passphrase and returns the instance key. It is
	// vault.Meta.UnlockWithPassphrase in production.
	Unlock func(ctx context.Context, passphrase string) (vault.Key, error)
	// ExtraRedirectURIs are additional exact HTTPS callbacks to accept.
	ExtraRedirectURIs []string
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Server implements the OAuth endpoints and bearer-token checking.
type Server struct {
	cfg      Config
	issuer   string
	resource string

	mu             sync.Mutex
	pending        map[string]pendingConsent
	pendingSeq     uint64
	regWindowStart time.Time
	regCount       int
}

// pendingConsent is a consent page that has been shown and not yet answered.
type pendingConsent struct {
	client      Client
	redirectURI string
	state       string
	challenge   string
	requested   []string
	expires     time.Time
	seq         uint64 // order of arrival, for dropping the oldest
}

// NewServer returns a sign-in server for cfg.
func NewServer(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	issuer := strings.TrimRight(cfg.Issuer, "/")
	return &Server{cfg: cfg, issuer: issuer, resource: issuer + resourcePath, pending: map[string]pendingConsent{}}
}

// Resource is the identifier of the protected MCP endpoint (issuer + /mcp).
func (s *Server) Resource() string { return s.resource }

// Mount registers the sign-in endpoints on mux.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource"+resourcePath, s.handleProtectedResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleServerMetadata)
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("GET /authorize", s.handleAuthorizePage)
	mux.HandleFunc("POST /authorize", s.handleAuthorizeSubmit)
	mux.HandleFunc("POST /token", s.handleToken)
}

// --- discovery -------------------------------------------------------------

func (s *Server) handleProtectedResource(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"scopes_supported":         supportedScopes,
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *Server) handleServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.issuer + "/authorize",
		"token_endpoint":                                 s.issuer + "/token",
		"registration_endpoint":                          s.issuer + "/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"scopes_supported":                               supportedScopes,
		"authorization_response_iss_parameter_supported": true,
	})
}

// WriteUnauthorized answers a request that has no valid token, pointing the
// client at the document that says where to sign in.
func (s *Server) WriteUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+s.issuer+`/.well-known/oauth-protected-resource"`)
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token", "error_description": "sign in required"})
}

// Authenticate checks the request's bearer token. It returns what the token
// is good for and the instance key it opens. Tokens are accepted only from the
// Authorization header and only if they were issued for this resource.
func (s *Server) Authenticate(r *http.Request) (Grant, vault.Key, error) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return Grant{}, vault.Key{}, ErrInvalidToken
	}
	g, key, err := s.cfg.Store.Authenticate(r.Context(), strings.TrimSpace(token))
	if err != nil {
		return Grant{}, vault.Key{}, err
	}
	if g.Resource != s.resource {
		return Grant{}, vault.Key{}, ErrInvalidToken
	}
	return g, key, nil
}

// --- registration ----------------------------------------------------------

type registrationRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.allowRegistration() {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations; try again later")
		return
	}
	var req registrationRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be JSON")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between 1 and 10 redirect_uris are required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !s.redirectAllowed(u) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri",
				"redirect URI is not accepted by this server: only known client callbacks and loopback addresses are allowed")
			return
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "Unnamed client"
	}
	if len(name) > 100 {
		name = name[:100]
	}
	c, err := s.cfg.Store.RegisterClient(r.Context(), name, req.RedirectURIs)
	if errors.Is(err, ErrTooManyClients) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "client limit reached")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not register client")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  c.ID,
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_id_issued_at":        c.CreatedAt.Unix(),
	})
}

func (s *Server) allowRegistration() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if now.Sub(s.regWindowStart) >= time.Hour {
		s.regWindowStart, s.regCount = now, 0
	}
	if s.regCount >= registrationsPerHour {
		return false
	}
	s.regCount++
	return true
}

// redirectAllowed reports whether a callback may be registered: an exact
// known HTTPS callback, or plain HTTP to a loopback address.
func (s *Server) redirectAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		for _, ok := range append(append([]string{}, defaultRedirectURIs...), s.cfg.ExtraRedirectURIs...) {
			if raw == ok {
				return true
			}
		}
		return false
	case "http":
		return isLoopbackHost(u.Hostname())
	default:
		return false
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameRedirect compares a presented callback with a registered one. They must
// be identical, except that a loopback callback may use any port (a local
// client picks a free one each time).
func sameRedirect(presented, registered string) bool {
	if presented == registered {
		return true
	}
	p, err1 := url.Parse(presented)
	r, err2 := url.Parse(registered)
	if err1 != nil || err2 != nil {
		return false
	}
	return p.Scheme == "http" && r.Scheme == "http" && isLoopbackHost(p.Hostname()) && p.Hostname() == r.Hostname() &&
		p.Path == r.Path && p.RawQuery == r.RawQuery && p.Fragment == "" && p.User == nil
}

// --- consent ---------------------------------------------------------------

func (s *Server) handleAuthorizePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Until the client and its callback are verified, errors are shown here
	// and never sent anywhere: redirecting would hand control to whoever
	// crafted the link.
	client, err := s.cfg.Store.Client(r.Context(), q.Get("client_id"))
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "This sign-in link is not valid: the application is not registered with this server.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	matched := false
	for _, reg := range client.RedirectURIs {
		if sameRedirect(redirectURI, reg) {
			matched = true
			break
		}
	}
	if !matched {
		s.renderError(w, http.StatusBadRequest, "This sign-in link is not valid: its return address does not match the application.")
		return
	}

	state := q.Get("state")
	fail := func(code, description string) {
		s.redirectError(w, r, redirectURI, state, code, description)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if res := q.Get("resource"); res != "" && res != s.resource {
		fail("invalid_target", "this server only issues tokens for "+s.resource)
		return
	}

	p := pendingConsent{
		client:      client,
		redirectURI: redirectURI,
		state:       state,
		challenge:   q.Get("code_challenge"),
		requested:   requestedScopes(q.Get("scope")),
	}
	s.renderConsent(w, http.StatusOK, p, "")
}

func (s *Server) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, http.StatusBadRequest, "The form could not be read.")
		return
	}
	p, ok := s.takePending(r.PostForm.Get("request_id"))
	if !ok {
		s.renderError(w, http.StatusBadRequest, "This sign-in page has expired or was already used. Start again from the application.")
		return
	}
	if r.PostForm.Get("action") != "approve" {
		s.redirectError(w, r, p.redirectURI, p.state, "access_denied", "the owner declined")
		return
	}

	key, err := s.cfg.Unlock(r.Context(), r.PostForm.Get("passphrase"))
	var locked *vault.LockedOutError
	switch {
	case err == nil:
	case errors.Is(err, vault.ErrWrongSecret):
		s.renderConsent(w, http.StatusOK, p, "Wrong passphrase. Please try again.")
		return
	case errors.As(err, &locked):
		s.renderConsent(w, http.StatusOK, p, "Too many wrong attempts. Sign-in is paused until "+locked.Until.UTC().Format("15:04 UTC")+".")
		return
	case errors.Is(err, vault.ErrNotInitialized):
		s.renderError(w, http.StatusServiceUnavailable, "This server has not been set up yet. Open its /setup page first.")
		return
	default:
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed because of a server error. Nothing was granted.")
		return
	}

	code, err := s.cfg.Store.IssueCode(r.Context(), CodeGrant{
		ClientID:      p.client.ID,
		RedirectURI:   p.redirectURI,
		Scope:         strings.Join(grantedScopes(p.requested, r.PostForm["scope"]), " "),
		Resource:      s.resource,
		CodeChallenge: p.challenge,
	}, key)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed because of a server error. Nothing was granted.")
		return
	}
	u, _ := url.Parse(p.redirectURI)
	q := u.Query()
	q.Set("code", code)
	if p.state != "" {
		q.Set("state", p.state)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	noStore(w)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// requestedScopes is what the client asked for, limited to what exists. A
// client that asks for nothing is offered everything; reading is always in.
func requestedScopes(param string) []string {
	asked := map[string]bool{}
	for _, sc := range strings.Fields(param) {
		asked[sc] = true
	}
	var out []string
	for _, sc := range supportedScopes {
		if sc == ScopeRead || len(asked) == 0 || asked[sc] {
			out = append(out, sc)
		}
	}
	return out
}

// grantedScopes is what the owner ticked, limited to what the client asked
// for. Reading is always granted.
func grantedScopes(requested, ticked []string) []string {
	want := map[string]bool{ScopeRead: true}
	for _, sc := range ticked {
		want[sc] = true
	}
	var out []string
	for _, sc := range requested {
		if want[sc] {
			out = append(out, sc)
		}
	}
	return out
}

func (s *Server) putPending(p pendingConsent) (string, error) {
	id, err := randomString(24)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	for k, v := range s.pending {
		if !now.Before(v.expires) {
			delete(s.pending, k)
		}
	}
	// Opening a consent page needs no credentials, so the store is capped by
	// dropping the oldest page, never by refusing the newest: a flood of
	// abandoned pages must not be able to block a real sign-in.
	for len(s.pending) >= maxPendingConsents {
		var oldest string
		for k, v := range s.pending {
			if oldest == "" || v.seq < s.pending[oldest].seq {
				oldest = k
			}
		}
		delete(s.pending, oldest)
	}
	s.pendingSeq++
	p.seq = s.pendingSeq
	p.expires = now.Add(consentTTL)
	s.pending[id] = p
	return id, nil
}

// takePending returns a consent page's request and forgets it: each page can
// be answered once.
func (s *Server) takePending(id string) (pendingConsent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return pendingConsent{}, false
	}
	delete(s.pending, id)
	if !s.cfg.Now().Before(p.expires) {
		return pendingConsent{}, false
	}
	return p, true
}

// --- token endpoint --------------------------------------------------------

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form could not be read")
		return
	}
	f := r.PostForm
	clientID := f.Get("client_id")
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	var pair TokenPair
	var err error
	switch f.Get("grant_type") {
	case "authorization_code":
		pair, err = s.exchangeCode(r.Context(), f, clientID)
	case "refresh_token":
		pair, err = s.cfg.Store.Refresh(r.Context(), f.Get("refresh_token"), clientID)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	if errors.Is(err, ErrInvalidGrant) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the code or refresh token is invalid, expired or already used")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  pair.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    int(pair.ExpiresIn / time.Second),
		"refresh_token": pair.RefreshToken,
		"scope":         pair.Scope,
	})
}

func (s *Server) exchangeCode(ctx context.Context, f url.Values, clientID string) (TokenPair, error) {
	g, key, err := s.cfg.Store.RedeemCode(ctx, f.Get("code"))
	if err != nil {
		return TokenPair{}, err
	}
	// The code is already spent. Every check below fails closed.
	if g.ClientID != clientID || g.RedirectURI != f.Get("redirect_uri") {
		return TokenPair{}, ErrInvalidGrant
	}
	if res := f.Get("resource"); res != "" && res != g.Resource {
		return TokenPair{}, ErrInvalidGrant
	}
	if !pkceMatches(f.Get("code_verifier"), g.CodeChallenge) {
		return TokenPair{}, ErrInvalidGrant
	}
	return s.cfg.Store.IssueTokens(ctx, Grant{ClientID: g.ClientID, Scope: g.Scope, Resource: g.Resource}, key)
}

// pkceMatches checks an S256 verifier against the challenge sent at /authorize.
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// --- responses -------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	noStore(w)
	writeJSON(w, status, map[string]any{"error": code, "error_description": description})
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// redirectError reports a problem to the client through its (already
// verified) callback.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderError(w, http.StatusBadRequest, "This sign-in link is not valid.")
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	noStore(w)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// PageHeaders locks a sign-in page down: never cached, never framed (so it
// cannot be overlaid to trick a click), no scripts, no outside resources.
// formTarget is the one outside origin the form's redirect may land on.
func PageHeaders(w http.ResponseWriter, formTarget string) {
	noStore(w)
	formAction := "form-action 'self'"
	if formTarget != "" {
		formAction += " " + formTarget
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
}

type consentView struct {
	RequestID    string
	ClientName   string
	CallbackHost string
	Scopes       []scopeView
	Error        string
}

type scopeView struct {
	Name, Label, Detail string
	Required            bool
}

var scopeText = map[string][2]string{
	ScopeRead:   {"Read chats", "List and search your chats and messages, and view media."},
	ScopeSend:   {"Send messages", "Send and reply to messages, react, edit and delete, on your behalf."},
	ScopeManage: {"Manage groups and settings", "Create and change groups, block contacts, change privacy settings."},
}

func (s *Server) renderConsent(w http.ResponseWriter, status int, p pendingConsent, errMsg string) {
	id, err := s.putPending(p)
	if err != nil {
		s.renderError(w, http.StatusServiceUnavailable, "Too many sign-in pages are open. Close some and try again.")
		return
	}
	u, _ := url.Parse(p.redirectURI)
	view := consentView{RequestID: id, ClientName: p.client.Name, CallbackHost: u.Host, Error: errMsg}
	for _, sc := range p.requested {
		view.Scopes = append(view.Scopes, scopeView{Name: sc, Label: scopeText[sc][0], Detail: scopeText[sc][1], Required: sc == ScopeRead})
	}
	PageHeaders(w, u.Scheme+"://"+u.Host)
	w.WriteHeader(status)
	_ = consentTemplate.Execute(w, view)
}

func (s *Server) renderError(w http.ResponseWriter, status int, message string) {
	PageHeaders(w, "")
	w.WriteHeader(status)
	_ = errorTemplate.Execute(w, message)
}

// PageStyle is the shared look of the sign-in and setup pages.
const PageStyle = `<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a;background:#fafafa}
h1{font-size:1.3rem;margin:0 0 .5rem}
.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:1.25rem}
.who{color:#444;margin:0 0 1rem}
label.scope{display:block;margin:.6rem 0}
.detail{display:block;color:#555;font-size:.9rem;margin-left:1.6rem}
input[type=password]{width:100%;box-sizing:border-box;padding:.6rem;font-size:1rem;border:1px solid #aaa;border-radius:6px;margin:.3rem 0 1rem}
button{font-size:1rem;padding:.6rem 1.1rem;border-radius:6px;border:1px solid #888;background:#fff;cursor:pointer}
button.primary{background:#0b6e4f;border-color:#0b6e4f;color:#fff}
.error{background:#fdecea;border:1px solid #f5c2c0;border-radius:6px;padding:.6rem;margin:0 0 1rem}
.note{color:#555;font-size:.9rem;margin-top:1rem}
@media (prefers-color-scheme:dark){body{background:#151515;color:#eee}.card{background:#1f1f1f;border-color:#3a3a3a}.who,.detail,.note{color:#bbb}input[type=password],button{background:#2a2a2a;color:#eee;border-color:#555}.error{background:#4a1f1d;border-color:#7a302d}}
</style>`

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Allow access to your WhatsApp</title>` + PageStyle + `</head><body>
<div class="card">
<h1>Allow access to your WhatsApp?</h1>
<p class="who"><strong>{{.ClientName}}</strong> is asking to connect. After you approve, you are sent back to <strong>{{.CallbackHost}}</strong>.</p>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/authorize" autocomplete="off">
<input type="hidden" name="request_id" value="{{.RequestID}}">
{{range .Scopes}}<label class="scope"><input type="checkbox" name="scope" value="{{.Name}}"{{if .Required}} checked disabled{{end}}> {{.Label}}{{if .Required}} (always included){{end}}
<span class="detail">{{.Detail}}</span></label>
{{end}}
<label for="passphrase">Your passphrase</label>
<input type="password" id="passphrase" name="passphrase" required autofocus autocomplete="current-password">
<button class="primary" type="submit" name="action" value="approve">Allow</button>
<button type="submit" name="action" value="deny" formnovalidate>Cancel</button>
</form>
<p class="note">Only tick what you want this application to be able to do. You can connect again later with different choices.</p>
</div></body></html>`))

var errorTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in problem</title>` + PageStyle + `</head><body>
<div class="card"><h1>Sign-in problem</h1><p>{{.}}</p></div></body></html>`))
