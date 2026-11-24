// Package gateway is the instance's always-on front door.
//
// It is the only part that runs while the instance is locked. It serves
// first-time setup, the sign-in endpoints and a health check, none of which
// need the key. Everything else is behind it: a tool request is let through
// only with a valid access token, and it is that token which brings the key
// that unlocks the instance; the owner pages (linking WhatsApp) are let
// through only after the owner has entered the passphrase.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/oauth"
	"github.com/sealjay/mcp-whatsapp/internal/session"
	"github.com/sealjay/mcp-whatsapp/internal/store"
	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

// Runtime is what exists while the instance is unlocked, as the gateway
// sees it.
type Runtime interface {
	session.Runtime
	// MCP returns the tool endpoint for a client granted the given OAuth
	// scope. Tools outside the grant are not there to be called.
	MCP(scope string) http.Handler
	// Owner returns the owner-only pages (linking WhatsApp).
	Owner() http.Handler
}

const (
	ownerCookieName = "wa_owner"
	// ownerIdle is how long an owner sign-in lasts without use.
	ownerIdle = 15 * time.Minute
	// maxOwnerSessions bounds owner sign-ins held in memory.
	maxOwnerSessions = 8
	// maxSetupFailures wrong setup codes are tolerated per hour.
	maxSetupFailures = 10
	// maxToolRequestBytes bounds one tool request body.
	maxToolRequestBytes = 8 << 20
)

// Config configures the gateway.
type Config[R Runtime] struct {
	Meta     *vault.Meta
	OAuth    *oauth.Server
	Sessions *session.Manager[R]
	// SetupToken is the one-time code the host gives the owner to claim a new
	// instance. Empty disables setup entirely.
	SetupToken string
	// SecureCookies marks the owner cookie Secure (set when served over https).
	SecureCookies bool
	OwnerIdle     time.Duration
	Grants        *oauth.Store
	// Discard clears pending work for a revoked family, or all families for an empty ID.
	Discard func(string)
	// Extra mounts further always-available routes (the one-time upload page
	// and download links). They are served without a sign-in and without
	// unlocking the instance. Optional.
	Extra func(mux *http.ServeMux)
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Logf records operational failures. It is never given keys, tokens,
	// passphrases or message content. Optional.
	Logf func(format string, args ...any)
}

// Gateway serves the instance's public routes.
type Gateway[R Runtime] struct {
	cfg Config[R]

	grantMu       sync.RWMutex
	mu            sync.Mutex
	owners        map[string]*ownerSession
	setupFailures int
	setupWindow   time.Time
}

type ownerSession struct {
	wrappedKey []byte
	lastUsed   time.Time
}

// New returns a gateway for cfg.
func New[R Runtime](cfg Config[R]) *Gateway[R] {
	if cfg.OwnerIdle <= 0 {
		cfg.OwnerIdle = ownerIdle
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Gateway[R]{cfg: cfg, owners: map[string]*ownerSession{}}
}

// Handler returns the gateway's routes.
func (g *Gateway[R]) Handler() http.Handler {
	mux := http.NewServeMux()
	probe := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"ok":true}` + "\n"))
	}
	// Both probes mean "the process is up". Locked is the resting state, so
	// readiness must not depend on being unlocked or connected, and neither
	// probe says whether the instance is in use.
	mux.HandleFunc("GET /healthz", probe)
	mux.HandleFunc("GET /readyz", probe)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	})
	g.cfg.OAuth.Mount(mux)
	if g.cfg.Extra != nil {
		g.cfg.Extra(mux)
	}
	mux.HandleFunc("/mcp", g.handleTools)
	mux.HandleFunc("GET /setup", g.handleSetupPage)
	mux.HandleFunc("POST /setup", g.handleSetupSubmit)
	mux.HandleFunc("/pair", g.handleOwner)
	mux.HandleFunc("/pair/", g.handleOwner)
	mux.HandleFunc("GET "+store.SourcePath+"{id}", g.handleOwner)
	return mux
}

// --- tools -----------------------------------------------------------------

func (g *Gateway[R]) handleTools(w http.ResponseWriter, r *http.Request) {
	g.grantMu.RLock()
	defer g.grantMu.RUnlock()
	grant, key, err := g.cfg.OAuth.Authenticate(r)
	if err != nil {
		g.cfg.OAuth.WriteUnauthorized(w)
		return
	}
	rt, release, err := g.cfg.Sessions.Acquire(r.Context(), key)
	if err != nil {
		g.unavailable(w, "unlock for a tool request", err)
		return
	}
	defer release()
	r.Body = http.MaxBytesReader(w, r.Body, maxToolRequestBytes)
	rt.MCP(grant.Scope).ServeHTTP(w, r.WithContext(oauth.WithGrant(r.Context(), grant)))
}

// unavailable reports that the instance could not be unlocked. The cause is
// logged, never sent: it can name paths and internal state.
func (g *Gateway[R]) unavailable(w http.ResponseWriter, what string, err error) {
	g.cfg.Logf("gateway: %s failed: %v", what, err)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"temporarily_unavailable","error_description":"the instance could not be unlocked; try again shortly"}` + "\n"))
}

// --- owner pages -----------------------------------------------------------

func (g *Gateway[R]) handleOwner(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	signIn := "/setup"
	if id := r.PathValue("id"); id != "" {
		oauth.PageHeaders(w, "")
		if !store.ValidSourceID(id) {
			http.NotFound(w, r)
			return
		}
		signIn += "?source=" + id
	}
	key, ok := g.ownerKey(r)
	if !ok {
		http.Redirect(w, r, signIn, http.StatusSeeOther)
		return
	}
	rt, release, err := g.cfg.Sessions.Acquire(r.Context(), key)
	if err != nil {
		g.unavailable(w, "unlock for the owner pages", err)
		return
	}
	defer release()
	rt.Owner().ServeHTTP(w, r)
}

// sameOrigin refuses state-changing requests that a different site caused.
// The owner cookie is SameSite=Strict already; this is a second barrier.
func sameOrigin(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func (g *Gateway[R]) ownerKey(r *http.Request) (vault.Key, bool) {
	c, err := r.Cookie(ownerCookieName)
	if err != nil || c.Value == "" {
		return vault.Key{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.cfg.Now()
	g.expireOwnersLocked(now)
	secret := []byte(c.Value)
	s, ok := g.owners[vault.SecretID(secret, ownerCookieName)]
	if !ok {
		return vault.Key{}, false
	}
	key, err := vault.UnwrapWithSecret(s.wrappedKey, secret, ownerCookieName)
	if err != nil {
		return vault.Key{}, false
	}
	s.lastUsed = now
	return key, true
}

func (g *Gateway[R]) expireOwnersLocked(now time.Time) {
	for id, s := range g.owners {
		if now.Sub(s.lastUsed) >= g.cfg.OwnerIdle {
			delete(g.owners, id)
		}
	}
}

// ExpireOwners drops owner sign-ins that have gone idle, and with them the
// copies of the key they hold. It must be called periodically: an owner who
// closes the tab sends no further request that would trigger the check.
func (g *Gateway[R]) ExpireOwners() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expireOwnersLocked(g.cfg.Now())
}

// Run calls ExpireOwners every interval until ctx ends, then forgets every
// owner sign-in.
func (g *Gateway[R]) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			g.forgetOwners()
			return
		case <-t.C:
			g.ExpireOwners()
		}
	}
}

func (g *Gateway[R]) ownerCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.owners)
}

// forgetOwners ends every owner sign-in and wipes the keys they held.
func (g *Gateway[R]) forgetOwners() {
	g.mu.Lock()
	defer g.mu.Unlock()
	clear(g.owners)
}

// forgetOwner ends the owner sign-in the request carries, if any.
func (g *Gateway[R]) forgetOwner(r *http.Request) {
	c, err := r.Cookie(ownerCookieName)
	if err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.owners, vault.SecretID([]byte(c.Value), ownerCookieName))
}

func (g *Gateway[R]) clearOwnerCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: ownerCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: g.cfg.SecureCookies, SameSite: http.SameSiteStrictMode})
}

// signOwnerIn keeps only a sealed key and the one-way ID of its browser cookie.
func (g *Gateway[R]) signOwnerIn(w http.ResponseWriter, key vault.Key) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return errors.New("gateway: could not read random bytes")
	}
	cookie := base64.RawURLEncoding.EncodeToString(raw)
	secret := []byte(cookie)
	wrapped, err := vault.WrapWithSecret(key, secret, ownerCookieName)
	if err != nil {
		return err
	}
	id := vault.SecretID(secret, ownerCookieName)
	g.mu.Lock()
	now := g.cfg.Now()
	g.expireOwnersLocked(now)
	for len(g.owners) >= maxOwnerSessions {
		var oldest string
		for k, s := range g.owners {
			if oldest == "" || s.lastUsed.Before(g.owners[oldest].lastUsed) {
				oldest = k
			}
		}
		delete(g.owners, oldest)
	}
	g.owners[id] = &ownerSession{wrappedKey: wrapped, lastUsed: now}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: ownerCookieName, Value: cookie, Path: "/",
		HttpOnly: true, Secure: g.cfg.SecureCookies, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// --- setup -----------------------------------------------------------------

type setupView struct {
	Source      string
	Endpoint    string
	Connections []oauth.Connection
	Mode        string // "init", "login", "recover", "owner", "recovery", "disabled"
	Error       string
	Notice      string
	Recovery    string
}

func (g *Gateway[R]) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	initialised, err := g.cfg.Meta.Initialized(r.Context())
	if err != nil {
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "disabled", Error: "The server's state could not be read."})
		return
	}
	switch {
	case !initialised && g.cfg.SetupToken == "":
		g.renderSetup(r, w, http.StatusOK, setupView{Mode: "disabled"})
	case !initialised:
		g.renderSetup(r, w, http.StatusOK, setupView{Mode: "init"})
	default:
		if _, ok := g.ownerKey(r); ok {
			if id := r.URL.Query().Get("source"); store.ValidSourceID(id) {
				oauth.PageHeaders(w, "")
				http.Redirect(w, r, store.SourcePath+id, http.StatusSeeOther)
				return
			}
			g.renderSetup(r, w, http.StatusOK, setupView{Mode: "owner"})
			return
		}
		if r.URL.Query().Has("recover") {
			g.renderSetup(r, w, http.StatusOK, setupView{Mode: "recover"})
			return
		}
		g.renderSetup(r, w, http.StatusOK, setupView{Mode: "login"})
	}
}

func (g *Gateway[R]) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		g.renderSetup(r, w, http.StatusBadRequest, setupView{Mode: "login", Error: "The form could not be read."})
		return
	}
	switch r.PostForm.Get("action") {
	case "init":
		g.handleInit(w, r)
	case "login":
		g.handleLogin(w, r)
	case "recover":
		g.handleRecover(w, r)
	case "change":
		g.handleChangePassphrase(w, r)
	case "revoke", "disconnect":
		g.handleRevoke(w, r)
	case "lock":
		g.handleLockNow(w, r)
	case "logout":
		g.forgetOwner(r)
		g.clearOwnerCookie(w)
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func (g *Gateway[R]) handleInit(w http.ResponseWriter, r *http.Request) {
	// No configured code means nobody may claim the instance, however they ask.
	if g.cfg.SetupToken == "" {
		g.renderSetup(r, w, http.StatusForbidden, setupView{Mode: "disabled"})
		return
	}
	if !g.setupAttemptAllowed() {
		g.renderSetup(r, w, http.StatusTooManyRequests, setupView{Mode: "init", Error: "Too many wrong setup codes. Try again in an hour."})
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("setup_token")), []byte(g.cfg.SetupToken)) != 1 {
		g.recordSetupFailure()
		g.renderSetup(r, w, http.StatusForbidden, setupView{Mode: "init", Error: "That setup code is not right."})
		return
	}
	if ok, err := g.cfg.Meta.Initialized(r.Context()); err != nil {
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "disabled", Error: "The server's state could not be read."})
		return
	} else if ok {
		g.renderSetup(r, w, http.StatusConflict, setupView{Mode: "login", Error: "This server is already set up. Sign in with the passphrase."})
		return
	}
	pass := r.PostForm.Get("passphrase")
	if pass != r.PostForm.Get("confirm") {
		g.renderSetup(r, w, http.StatusBadRequest, setupView{Mode: "init", Error: "The two passphrases do not match."})
		return
	}
	key, recovery, err := g.cfg.Meta.Initialize(r.Context(), pass)
	switch {
	case errors.Is(err, vault.ErrWeakPassphrase):
		g.renderSetup(r, w, http.StatusBadRequest, setupView{Mode: "init", Error: "Choose a passphrase of at least 12 characters."})
		return
	case errors.Is(err, vault.ErrAlreadyInitialized):
		g.renderSetup(r, w, http.StatusConflict, setupView{Mode: "login", Error: "This server is already set up. Sign in with the passphrase."})
		return
	case err != nil:
		g.cfg.Logf("gateway: setup failed: %v", err)
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "init", Error: "Setup failed because of a server error. Nothing was created."})
		return
	}
	if err := g.signOwnerIn(w, key); err != nil {
		g.cfg.Logf("gateway: owner sign-in after setup failed: %v", err)
	}
	g.renderSetup(r, w, http.StatusOK, setupView{Mode: "recovery", Recovery: recovery})
}

func (g *Gateway[R]) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Either secret the owner holds signs them in. The recovery code is not
	// subject to the wrong-guess pause, so it works even while someone else's
	// guesses have paused passphrase sign-in.
	key, err := g.cfg.Meta.Unlock(r.Context(), r.PostForm.Get("passphrase"))
	var locked *vault.LockedOutError
	switch {
	case err == nil:
	case errors.Is(err, vault.ErrWrongSecret):
		g.renderSetup(r, w, http.StatusOK, setupView{Mode: "login", Error: "Wrong passphrase. Please try again."})
		return
	case errors.As(err, &locked):
		g.renderSetup(r, w, http.StatusOK, setupView{Mode: "login", Error: "Too many wrong attempts. Passphrase sign-in is paused until " + locked.Until.UTC().Format("15:04 UTC") + ". Your recovery code still works."})
		return
	case errors.Is(err, vault.ErrNotInitialized):
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	default:
		g.cfg.Logf("gateway: owner sign-in failed: %v", err)
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "login", Error: "Sign-in failed because of a server error."})
		return
	}
	if err := g.signOwnerIn(w, key); err != nil {
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "login", Error: "Sign-in failed because of a server error."})
		return
	}
	destination := "/pair"
	if id := r.PostForm.Get("source"); store.ValidSourceID(id) {
		destination = store.SourcePath + id
	}
	oauth.PageHeaders(w, "")
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

// handleRecover lets the owner back in with the recovery code and sets a new
// passphrase in the same step.
func (g *Gateway[R]) handleRecover(w http.ResponseWriter, r *http.Request) {
	pass := r.PostForm.Get("passphrase")
	if pass != r.PostForm.Get("confirm") {
		g.renderSetup(r, w, http.StatusBadRequest, setupView{Mode: "recover", Error: "The two passphrases do not match."})
		return
	}
	key, err := g.cfg.Meta.UnlockWithRecoveryCode(r.Context(), r.PostForm.Get("recovery_code"))
	switch {
	case err == nil:
	case errors.Is(err, vault.ErrWrongSecret):
		g.renderSetup(r, w, http.StatusOK, setupView{Mode: "recover", Error: "That recovery code is not right."})
		return
	case errors.Is(err, vault.ErrNotInitialized):
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	default:
		g.cfg.Logf("gateway: recovery failed: %v", err)
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "recover", Error: "Recovery failed because of a server error."})
		return
	}
	switch err := g.cfg.Meta.ChangePassphrase(r.Context(), key, pass); {
	case errors.Is(err, vault.ErrWeakPassphrase):
		g.renderSetup(r, w, http.StatusBadRequest, setupView{Mode: "recover", Error: "Choose a passphrase of at least 12 characters."})
		return
	case err != nil:
		g.cfg.Logf("gateway: setting a new passphrase failed: %v", err)
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "recover", Error: "The new passphrase could not be saved."})
		return
	}
	if err := g.signOwnerIn(w, key); err != nil {
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "login", Notice: "Your passphrase was changed. Sign in with it."})
		return
	}
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

// requireOwner returns the signed-in owner's key, or sends the browser to
// the sign-in page.
func (g *Gateway[R]) requireOwner(w http.ResponseWriter, r *http.Request) (vault.Key, bool) {
	key, ok := g.ownerKey(r)
	if !ok {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	}
	return key, ok
}

func (g *Gateway[R]) handleChangePassphrase(w http.ResponseWriter, r *http.Request) {
	key, ok := g.requireOwner(w, r)
	if !ok {
		return
	}
	pass := r.PostForm.Get("passphrase")
	if pass != r.PostForm.Get("confirm") {
		g.renderSetup(r, w, http.StatusBadRequest, setupView{Mode: "owner", Error: "The two passphrases do not match."})
		return
	}
	switch err := g.cfg.Meta.ChangePassphrase(r.Context(), key, pass); {
	case errors.Is(err, vault.ErrWeakPassphrase):
		g.renderSetup(r, w, http.StatusBadRequest, setupView{Mode: "owner", Error: "Choose a passphrase of at least 12 characters."})
	case err != nil:
		g.cfg.Logf("gateway: changing the passphrase failed: %v", err)
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "owner", Error: "The new passphrase could not be saved."})
	default:
		g.renderSetup(r, w, http.StatusOK, setupView{Mode: "owner", Notice: "Passphrase changed. Apps that are already connected stay connected."})
	}
}

// handleRevokeAll signs every connected app out. Each has to be approved
// again with the passphrase.
func (g *Gateway[R]) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.requireOwner(w, r); !ok {
		return
	}
	g.grantMu.Lock()
	defer g.grantMu.Unlock()
	family := ""
	notice := "Every app has been signed out. Connect them again to approve them with your passphrase."
	var err error
	if r.PostForm.Get("action") == "disconnect" {
		family = r.PostForm.Get("family")
		if family == "" {
			http.Error(w, "Select a connection.", http.StatusBadRequest)
			return
		}
		err = g.cfg.Grants.RevokeConnection(r.Context(), family)
		notice = "This connection has been signed out."
	} else {
		err = g.cfg.Grants.RevokeAll(r.Context())
	}
	if err != nil && !errors.Is(err, oauth.ErrInvalidGrant) {
		g.cfg.Logf("gateway: revoking sign-ins failed: %v", err)
		g.renderSetup(r, w, http.StatusInternalServerError, setupView{Mode: "owner", Error: "The sign-in could not be revoked."})
		return
	}
	if g.cfg.Discard != nil {
		g.cfg.Discard(family)
	}
	g.renderSetup(r, w, http.StatusOK, setupView{Mode: "owner", Notice: notice})
}

// handleLockNow locks the instance immediately and ends every owner sign-in.
func (g *Gateway[R]) handleLockNow(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.requireOwner(w, r); !ok {
		return
	}
	g.forgetOwners()
	g.cfg.Sessions.Lock()
	g.clearOwnerCookie(w)
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

func (g *Gateway[R]) setupAttemptAllowed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg.Now().Sub(g.setupWindow) >= time.Hour {
		g.setupWindow, g.setupFailures = g.cfg.Now(), 0
	}
	return g.setupFailures < maxSetupFailures
}

func (g *Gateway[R]) recordSetupFailure() {
	g.mu.Lock()
	g.setupFailures++
	g.mu.Unlock()
}

func (g *Gateway[R]) renderSetup(r *http.Request, w http.ResponseWriter, status int, v setupView) {
	if id := r.FormValue("source"); v.Mode == "login" && store.ValidSourceID(id) {
		v.Source = id
	}
	if v.Mode == "owner" {
		v.Endpoint = g.cfg.OAuth.Resource()
		var err error
		v.Connections, err = g.cfg.Grants.Connections(r.Context())
		if err != nil {
			v.Error = "The connected apps could not be loaded."
			status = http.StatusInternalServerError
		}
	}
	oauth.PageHeaders(w, "")
	w.WriteHeader(status)
	_ = setupTemplate.Execute(w, v)
}

var setupTemplate = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WhatsApp connector setup</title>` + strings.Replace(oauth.PageStyle, "</style>", `label{display:block;margin-top:.6rem}
input[type=text]{width:100%;box-sizing:border-box;padding:.6rem;font-size:1rem;border:1px solid #aaa;border-radius:6px;margin:.3rem 0 1rem}
.code{font:1.15rem/1.6 ui-monospace,monospace;letter-spacing:.05em;background:#f1f1f1;border-radius:6px;padding:.6rem;word-break:break-all}
.notice{background:#e8f5ee;border:1px solid #b7dcc6;border-radius:6px;padding:.6rem;margin:0 0 1rem}
hr{border:0;border-top:1px solid #ddd;margin:1.25rem 0}
form+form{margin-top:1rem}
a.button{display:inline-block;text-decoration:none;font-size:1rem;padding:.6rem 1.1rem;border-radius:6px;background:#0b6e4f;color:#fff}
@media (prefers-color-scheme:dark){input[type=text]{background:#2a2a2a;color:#eee;border-color:#555}.code{background:#2a2a2a}.notice{background:#1d3a2b;border-color:#2f5d45}hr{border-top-color:#3a3a3a}}
</style>`, 1) + `</head><body><div class="card">
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
{{if .Notice}}<p class="notice" role="status">{{.Notice}}</p>{{end}}
{{if eq .Mode "init"}}
<h1>Set up your WhatsApp connector</h1>
<p class="who">Choose the passphrase that protects your chats. It is never stored: without it (or the recovery code you get next) nobody, including whoever hosts this server, can read your archive.</p>
<form method="post" action="/setup" autocomplete="off">
<input type="hidden" name="action" value="init">
<label for="setup_token">Setup code (from whoever gave you this address)</label>
<input type="password" id="setup_token" name="setup_token" required autofocus>
<label for="passphrase">New passphrase (at least 12 characters)</label>
<input type="password" id="passphrase" name="passphrase" required minlength="12" autocomplete="new-password">
<label for="confirm">Passphrase again</label>
<input type="password" id="confirm" name="confirm" required minlength="12" autocomplete="new-password">
<button class="primary" type="submit">Create</button>
</form>
{{else if eq .Mode "recovery"}}
<h1>Save your recovery code</h1>
<p class="who">This is the only way back in if you forget your passphrase. It is shown once and cannot be shown again. Write it down or put it in a password manager now.</p>
<p class="code">{{.Recovery}}</p>
<p><a class="button" href="/pair">I have saved it: link WhatsApp</a></p>
{{else if eq .Mode "login"}}
{{if .Source}}<h1>Sign in to view this message</h1>{{else}}<h1>Sign in to manage this connector</h1>
<p class="who">Enter your passphrase to link or re-link WhatsApp.</p>{{end}}
<form method="post" action="/setup" autocomplete="off">
<input type="hidden" name="action" value="login">
{{if .Source}}<input type="hidden" name="source" value="{{.Source}}">{{end}}
<label for="passphrase">Your passphrase</label>
<input type="password" id="passphrase" name="passphrase" required autofocus autocomplete="current-password">
<button class="primary" type="submit">Sign in</button>
</form>
<p class="note">You can also enter your recovery code here. <a href="/setup?recover">Forgot your passphrase?</a></p>
{{else if eq .Mode "recover"}}
<h1>Set a new passphrase</h1>
<p class="who">Enter the recovery code you saved at setup and choose a new passphrase. Your archive and connected apps are kept.</p>
<form method="post" action="/setup" autocomplete="off">
<input type="hidden" name="action" value="recover">
<label for="recovery_code">Recovery code</label>
<input type="text" id="recovery_code" name="recovery_code" required autofocus autocapitalize="characters" spellcheck="false">
<label for="passphrase">New passphrase (at least 12 characters)</label>
<input type="password" id="passphrase" name="passphrase" required minlength="12" autocomplete="new-password">
<label for="confirm">New passphrase again</label>
<input type="password" id="confirm" name="confirm" required minlength="12" autocomplete="new-password">
<button class="primary" type="submit">Save</button>
</form>
{{else if eq .Mode "owner"}}
<h1>You are signed in</h1>
<h2>Connected apps</h2>
<p>Add this URL in ChatGPT or Claude and choose OAuth sign-in.</p>
<p><code>{{.Endpoint}}</code></p>
{{range .Connections}}<form method="post" action="/setup">
<input type="hidden" name="action" value="disconnect"><input type="hidden" name="family" value="{{.FamilyID}}">
<strong>{{.Name}}</strong> <small>{{.Scope}}</small> <button type="submit">Disconnect</button></form>
{{else}}<p>No apps connected.</p>{{end}}
<p><a class="button" href="/pair">Link or re-link WhatsApp</a></p>
<hr>
<form method="post" action="/setup" autocomplete="off">
<input type="hidden" name="action" value="change">
<label for="passphrase">Change passphrase (at least 12 characters)</label>
<input type="password" id="passphrase" name="passphrase" required minlength="12" autocomplete="new-password">
<label for="confirm">New passphrase again</label>
<input type="password" id="confirm" name="confirm" required minlength="12" autocomplete="new-password">
<button type="submit">Change passphrase</button>
</form>
<hr>
<form method="post" action="/setup"><input type="hidden" name="action" value="revoke">
<p class="note">Sign every connected app out, for example if a device was lost. Each app has to be approved again.</p>
<button type="submit">Sign all apps out</button></form>
<form method="post" action="/setup"><input type="hidden" name="action" value="lock">
<p class="note">Lock now: disconnect from WhatsApp and discard the key from memory until the next sign-in.</p>
<button type="submit">Lock now</button></form>
<form method="post" action="/setup"><input type="hidden" name="action" value="logout">
<button type="submit">Sign out of this page</button></form>
{{else}}
<h1>Setup is not available</h1>
<p class="who">This server has not been set up, and no setup code is configured. Whoever hosts it needs to set SETUP_TOKEN and restart it.</p>
{{end}}
</div></body></html>`))
