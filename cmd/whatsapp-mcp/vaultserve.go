package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/daemon"
	"github.com/sealjay/mcp-whatsapp/internal/gateway"
	mcpsrv "github.com/sealjay/mcp-whatsapp/internal/mcp"
	"github.com/sealjay/mcp-whatsapp/internal/oauth"
	"github.com/sealjay/mcp-whatsapp/internal/security"
	"github.com/sealjay/mcp-whatsapp/internal/session"
	"github.com/sealjay/mcp-whatsapp/internal/store"
	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

// This file is the hosted mode of `serve`: passphrase sign-in.
//
// The instance key is not configured anywhere. It is created at first-time
// setup, kept only as sealed copies, and exists in memory only between a
// request that presents a valid token (or the owner's passphrase) and the
// idle lock. While locked the process holds no key, no open database and no
// connection to WhatsApp.

// checkServeMode refuses the one unsafe combination: the development mode
// that reads the key from the environment, exposed beyond this machine.
func checkServeMode(envKey, allowRemote bool) error {
	if envKey && allowRemote {
		return fmt.Errorf("%s is set, which keeps the data key in the environment: that mode is for local use only. "+
			"Unset it to use passphrase sign-in before allowing remote connections", vaultKeyEnv)
	}
	return nil
}

// resolvePublicURL is the address clients reach this instance at. Sign-in
// sends the passphrase and tokens there, so it must be https unless it is
// this machine itself.
func resolvePublicURL(getenv func(string) string, addr string) (string, error) {
	raw := strings.TrimSpace(getenv("PUBLIC_URL"))
	if raw == "" {
		raw = strings.TrimSpace(getenv("RENDER_EXTERNAL_URL"))
	}
	if raw == "" {
		if !isLoopbackAddr(addr) {
			return "", errors.New("PUBLIC_URL is not set: it must be the https address clients use to reach this server")
		}
		raw = "http://" + addr
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("PUBLIC_URL must be a full address such as https://wa.example.com")
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("PUBLIC_URL must be only the scheme and host, with no path")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("PUBLIC_URL must be https: sign-in sends the passphrase to it")
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// idleLockFromEnv is how long the instance stays unlocked without use
// (IDLE_LOCK, a duration such as 15m; default 15 minutes).
func idleLockFromEnv(getenv func(string) string) (time.Duration, error) {
	raw := strings.TrimSpace(getenv("IDLE_LOCK"))
	if raw == "" {
		return 15 * time.Minute, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, errors.New("IDLE_LOCK must be a duration such as 15m or 90s")
	}
	if d < time.Second || d > 24*time.Hour {
		return 0, errors.New("IDLE_LOCK must be between 1s and 24h")
	}
	return d, nil
}

type vaultServeOptions struct {
	storeDir         string
	addr             string
	redactor         *security.Redactor
	allowedMediaRoot string
	readOnly         bool
	labelsEnabled    bool
	fullHistory      bool
}

// instance is everything that exists only while unlocked: the stores, the
// WhatsApp client and the tool servers.
type instance struct {
	st     *store.Store
	c      *client.Client
	d      *daemon.Server
	cancel context.CancelFunc
	owner  http.Handler
	tools  map[mcpsrv.Access]http.Handler
	forced *mcpsrv.Access // set in read-only mode: every sign-in gets this
}

func (r *instance) MCP(scope string) http.Handler {
	access := mcpsrv.AccessFromScope(scope)
	if r.forced != nil {
		access = *r.forced
	}
	return r.tools[access]
}

func (r *instance) Owner() http.Handler { return r.owner }

// Close disconnects from WhatsApp and closes both databases.
func (r *instance) Close() error {
	r.cancel()
	r.d.Shutdown()
	err := errors.Join(r.c.Close(), r.st.Close())
	fmt.Fprintln(os.Stderr, "instance locked: disconnected from WhatsApp, databases closed, key discarded")
	return err
}

// syncWait bounds how long an unlock waits for WhatsApp to deliver what
// arrived while the instance was locked.
const syncWait = 20 * time.Second

// buildRuntime returns the function that brings the instance up from its key.
func buildRuntime(o vaultServeOptions) func(context.Context, vault.Key) (*instance, error) {
	return func(ctx context.Context, key vault.Key) (*instance, error) {
		st, err := store.Open(o.storeDir, key)
		if err != nil {
			return nil, fmt.Errorf("open store: %w", err)
		}
		// The runtime outlives the request that unlocked it.
		runCtx, cancel := context.WithCancel(context.Background())
		fail := func(err error) (*instance, error) {
			cancel()
			_ = st.Close()
			return nil, err
		}
		c, err := client.New(runCtx, client.Config{
			StoreDir:         o.storeDir,
			Key:              key,
			Store:            st,
			Logger:           client.NewStderrLogger("Client", "INFO", false),
			AllowedMediaRoot: o.allowedMediaRoot,
			Redactor:         o.redactor,
			LabelsEnabled:    o.labelsEnabled,
			FullHistory:      o.fullHistory,
		})
		if err != nil {
			return fail(fmt.Errorf("init client: %w", err))
		}
		d, err := daemon.New(daemon.Config{Addr: "gateway", Driver: newProductionDriver(c)})
		if err != nil {
			_ = c.Close()
			return fail(fmt.Errorf("init pairing: %w", err))
		}

		rt := &instance{st: st, c: c, d: d, cancel: cancel, owner: d.Handler(), tools: map[mcpsrv.Access]http.Handler{}}
		for _, access := range []mcpsrv.Access{{}, {Send: true}, {Manage: true}, {Send: true, Manage: true}} {
			mux := http.NewServeMux()
			mcpsrv.NewServerWithAccess(c, d.Cache(), o.labelsEnabled, access).AttachHTTP(mux)
			rt.tools[access] = mux
		}
		if o.readOnly {
			rt.forced = &mcpsrv.Access{}
		}

		if err := d.Boot(runCtx); err != nil {
			_ = rt.Close()
			return nil, fmt.Errorf("connect: %w", err)
		}
		if c.IsLoggedIn() {
			if !c.WaitForOfflineSync(ctx, syncWait) {
				fmt.Fprintln(os.Stderr, "unlock: WhatsApp has not finished delivering the backlog yet; answering with what has arrived")
			}
		}
		fmt.Fprintln(os.Stderr, "instance unlocked")
		return rt, nil
	}
}

func runVaultServe(ctx context.Context, o vaultServeOptions) int {
	publicURL, err := resolvePublicURL(os.Getenv, o.addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		return 2
	}
	idle, err := idleLockFromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		return 2
	}
	if err := os.MkdirAll(o.storeDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "create store dir: %v\n", err)
		return 1
	}
	meta, err := vault.OpenMeta(filepath.Join(o.storeDir, "meta.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	defer meta.Close()
	tokens, err := oauth.NewStore(meta.DB())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	var extraRedirects []string
	for _, u := range strings.Split(os.Getenv("OAUTH_REDIRECT_ALLOWLIST"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			extraRedirects = append(extraRedirects, u)
		}
	}
	signIn := oauth.NewServer(oauth.Config{Issuer: publicURL, Store: tokens, Unlock: meta.UnlockWithPassphrase, ExtraRedirectURIs: extraRedirects})
	sessions := session.New(buildRuntime(o), idle)
	gw := gateway.New(gateway.Config[*instance]{
		Meta:          meta,
		OAuth:         signIn,
		Sessions:      sessions,
		SetupToken:    strings.TrimSpace(os.Getenv("SETUP_TOKEN")),
		SecureCookies: strings.HasPrefix(publicURL, "https://"),
		Logf:          func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) },
	})

	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		return 1
	}
	httpSrv := &http.Server{
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		// Tool calls can wait on WhatsApp (media, history from the phone).
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	lockerDone := make(chan struct{})
	go func() {
		sessions.Run(ctx, 5*time.Second) // locks when idle, and on shutdown
		close(lockerDone)
	}()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = tokens.PurgeExpired(context.Background())
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "whatsapp-mcp listening on %s, reachable at %s (locked; unlocks on sign-in, locks after %s idle)\n", ln.Addr(), publicURL, idle)
	if ok, _ := meta.Initialized(ctx); !ok {
		if os.Getenv("SETUP_TOKEN") == "" {
			fmt.Fprintln(os.Stderr, "not set up, and SETUP_TOKEN is not set: nobody can claim this instance until it is")
		} else {
			fmt.Fprintf(os.Stderr, "not set up yet: open %s/setup and enter the setup code\n", publicURL)
		}
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.Serve(ln) }()
	code := 0
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "http: %v\n", err)
			code = 1
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	select {
	case <-lockerDone:
	case <-time.After(15 * time.Second):
		fmt.Fprintln(os.Stderr, "shutdown: gave up waiting for the instance to lock")
	}
	return code
}
