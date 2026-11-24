package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type storeFixture struct {
	s     *Store
	clock *fakeClock
	dir   string
	key   vault.Key
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	dir := t.TempDir()
	meta, err := vault.OpenMeta(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	s, err := NewStore(meta.DB())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	clock := &fakeClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	s.now = clock.now
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return &storeFixture{s: s, clock: clock, dir: dir, key: key}
}

var testGrant = Grant{ClientID: "client-1", Scope: "whatsapp.read whatsapp.send", Resource: "https://wa.example.test/mcp"}

// --- clients ---------------------------------------------------------------

func TestRegisteredClientCanBeLookedUp(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	c, err := f.s.RegisterClient(ctx, "Claude", []string{"https://claude.ai/api/mcp/auth_callback"})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	other, _ := f.s.RegisterClient(ctx, "Other", []string{"http://127.0.0.1/callback"})
	if c.ID == "" || c.ID == other.ID {
		t.Fatalf("client IDs not unique: %q %q", c.ID, other.ID)
	}
	got, err := f.s.Client(ctx, c.ID)
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if got.Name != "Claude" || len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://claude.ai/api/mcp/auth_callback" {
		t.Fatalf("looked-up client = %+v", got)
	}
	if _, err := f.s.Client(ctx, "no-such-client"); !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("unknown client err = %v, want ErrUnknownClient", err)
	}
}

func TestClientRegistrationIsCapped(t *testing.T) {
	// Registration is open to anyone who can reach the server, so it must not
	// be a way to fill the disk.
	f := newStoreFixture(t)
	ctx := context.Background()
	for i := 0; i < maxClients; i++ {
		if _, err := f.s.RegisterClient(ctx, "c", []string{"https://example.test/cb"}); err != nil {
			t.Fatalf("registration %d: %v", i+1, err)
		}
	}
	if _, err := f.s.RegisterClient(ctx, "one too many", []string{"https://example.test/cb"}); !errors.Is(err, ErrTooManyClients) {
		t.Fatalf("err = %v, want ErrTooManyClients", err)
	}
}

// --- authorization codes ---------------------------------------------------

var testCode = CodeGrant{
	ClientID: "client-1", RedirectURI: "https://claude.ai/api/mcp/auth_callback",
	Scope: "whatsapp.read", Resource: "https://wa.example.test/mcp", CodeChallenge: "challenge-value",
}

func TestCodeRedeemsOnceForTheSameGrantAndKey(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	code, err := f.s.IssueCode(ctx, testCode, f.key)
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	got, key, err := f.s.RedeemCode(ctx, code)
	if err != nil {
		t.Fatalf("RedeemCode: %v", err)
	}
	if got != testCode {
		t.Fatalf("redeemed grant = %+v, want %+v", got, testCode)
	}
	if key != f.key {
		t.Fatal("redeemed code did not return the instance key it was issued with")
	}
	// Single use: a replayed code is worthless.
	if _, _, err := f.s.RedeemCode(ctx, code); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("second redeem err = %v, want ErrInvalidGrant", err)
	}
}

func TestCodeExpiresQuickly(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	code, _ := f.s.IssueCode(ctx, testCode, f.key)
	f.clock.advance(codeTTL + time.Second)
	if _, _, err := f.s.RedeemCode(ctx, code); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired code err = %v, want ErrInvalidGrant", err)
	}
}

func TestUnknownOrMalformedCodesAreRejected(t *testing.T) {
	f := newStoreFixture(t)
	for _, bad := range []string{"", "garbage", codePrefix + "not-base64!!", codePrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32))} {
		if _, _, err := f.s.RedeemCode(context.Background(), bad); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("RedeemCode(%q) err = %v, want ErrInvalidGrant", bad, err)
		}
	}
}

// --- tokens ----------------------------------------------------------------

func TestAccessTokenAuthenticatesAndCarriesTheKey(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	pair, err := f.s.IssueTokens(ctx, testGrant, f.key)
	if err != nil {
		t.Fatalf("IssueTokens: %v", err)
	}
	if !strings.HasPrefix(pair.AccessToken, accessPrefix) || !strings.HasPrefix(pair.RefreshToken, refreshPrefix) {
		t.Fatalf("token prefixes: %q %q", pair.AccessToken[:12], pair.RefreshToken[:12])
	}
	if pair.ExpiresIn != accessTTL || pair.Scope != testGrant.Scope {
		t.Fatalf("pair metadata = %v %q", pair.ExpiresIn, pair.Scope)
	}
	g, key, err := f.s.Authenticate(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if g.ClientID != testGrant.ClientID || g.Scope != testGrant.Scope || g.Resource != testGrant.Resource {
		t.Fatalf("authenticated grant = %+v", g)
	}
	if key != f.key {
		t.Fatal("access token did not return the instance key")
	}
}

func TestTokensAreUniqueAndLong(t *testing.T) {
	f := newStoreFixture(t)
	a, _ := f.s.IssueTokens(context.Background(), testGrant, f.key)
	b, _ := f.s.IssueTokens(context.Background(), testGrant, f.key)
	seen := map[string]bool{}
	for _, tok := range []string{a.AccessToken, a.RefreshToken, b.AccessToken, b.RefreshToken} {
		if seen[tok] {
			t.Fatal("duplicate token issued")
		}
		seen[tok] = true
		raw, err := base64.RawURLEncoding.DecodeString(tokenBody(tok))
		if err != nil || len(raw) < 32 {
			t.Fatalf("token carries %d random bytes (err=%v), want at least 32", len(raw), err)
		}
	}
}

func TestInvalidAccessTokensAreRejected(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	pair, _ := f.s.IssueTokens(ctx, testGrant, f.key)

	for name, tok := range map[string]string{
		"empty":                    "",
		"garbage":                  "not-a-token",
		"well-formed but unknown":  accessPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"a refresh token":          pair.RefreshToken,
		"right token, one bit off": pair.AccessToken[:len(pair.AccessToken)-1] + flipLast(pair.AccessToken),
	} {
		if _, _, err := f.s.Authenticate(ctx, tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v, want ErrInvalidToken", name, err)
		}
	}

	f.clock.advance(accessTTL + time.Second)
	if _, _, err := f.s.Authenticate(ctx, pair.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired access token err = %v, want ErrInvalidToken", err)
	}
}

// tokenBody strips the kind prefix from a credential, leaving its base64url
// body (which may itself contain underscores).
func tokenBody(tok string) string {
	for _, p := range []string{codePrefix, accessPrefix, refreshPrefix} {
		if rest, ok := strings.CutPrefix(tok, p); ok {
			return rest
		}
	}
	return tok
}

func flipLast(s string) string {
	if strings.HasSuffix(s, "A") {
		return "B"
	}
	return "A"
}

// --- refresh ---------------------------------------------------------------

func TestRefreshIssuesANewPairThatStillOpensTheKey(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	first, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	f.clock.advance(30 * time.Minute)

	next, err := f.s.Refresh(ctx, first.RefreshToken, testGrant.ClientID)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if next.AccessToken == first.AccessToken || next.RefreshToken == first.RefreshToken {
		t.Fatal("refresh returned the old tokens")
	}
	if next.Scope != testGrant.Scope {
		t.Fatalf("scope after refresh = %q", next.Scope)
	}
	g, key, err := f.s.Authenticate(ctx, next.AccessToken)
	if err != nil || key != f.key || g.Resource != testGrant.Resource {
		t.Fatalf("new access token: key match=%v grant=%+v err=%v", key == f.key, g, err)
	}
}

func TestRefreshRetriedWithinTheGraceWindowGetsTheSamePair(t *testing.T) {
	// Clients retry and parallelise refreshes. A retry of a refresh that
	// already succeeded must get the same answer, not be treated as theft.
	f := newStoreFixture(t)
	ctx := context.Background()
	first, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	next, err := f.s.Refresh(ctx, first.RefreshToken, testGrant.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(refreshGrace - time.Second)
	again, err := f.s.Refresh(ctx, first.RefreshToken, testGrant.ClientID)
	if err != nil {
		t.Fatalf("retry within grace: %v", err)
	}
	if again.AccessToken != next.AccessToken || again.RefreshToken != next.RefreshToken {
		t.Fatal("retry within the grace window returned different tokens")
	}
	if _, _, err := f.s.Authenticate(ctx, next.AccessToken); err != nil {
		t.Fatalf("tokens were revoked by a legitimate retry: %v", err)
	}
}

func TestReusingARotatedRefreshTokenAfterGraceRevokesEverything(t *testing.T) {
	// A refresh token used again long after it was replaced means it leaked:
	// someone other than the client holds a copy. Kill the whole chain.
	f := newStoreFixture(t)
	ctx := context.Background()
	first, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	next, _ := f.s.Refresh(ctx, first.RefreshToken, testGrant.ClientID)

	f.clock.advance(refreshGrace + time.Second)
	if _, err := f.s.Refresh(ctx, first.RefreshToken, testGrant.ClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("reuse after grace err = %v, want ErrInvalidGrant", err)
	}
	if _, _, err := f.s.Authenticate(ctx, next.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("the chain's current access token still works after reuse (err=%v)", err)
	}
	if _, err := f.s.Refresh(ctx, next.RefreshToken, testGrant.ClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("the chain's current refresh token still works after reuse (err=%v)", err)
	}
	// A different sign-in (another chain) is untouched.
	other, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	if _, _, err := f.s.Authenticate(ctx, other.AccessToken); err != nil {
		t.Fatalf("an unrelated sign-in was revoked too: %v", err)
	}
}

func TestRefreshRejectsWrongClientExpiredAndWrongKind(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	pair, _ := f.s.IssueTokens(ctx, testGrant, f.key)

	if _, err := f.s.Refresh(ctx, pair.RefreshToken, "some-other-client"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("wrong client err = %v, want ErrInvalidGrant", err)
	}
	// The failed attempt must not have used the token up.
	if _, err := f.s.Refresh(ctx, pair.RefreshToken, testGrant.ClientID); err != nil {
		t.Fatalf("refresh token was consumed by another client's failed attempt: %v", err)
	}
	if _, err := f.s.Refresh(ctx, pair.AccessToken, testGrant.ClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("access token used as refresh err = %v, want ErrInvalidGrant", err)
	}

	stale, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	f.clock.advance(refreshTTL + time.Second)
	if _, err := f.s.Refresh(ctx, stale.RefreshToken, testGrant.ClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired refresh err = %v, want ErrInvalidGrant", err)
	}
}

func TestRevokeAllEndsEverySignIn(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	a, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	b, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	if err := f.s.RevokeAll(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []TokenPair{a, b} {
		if _, _, err := f.s.Authenticate(ctx, p.AccessToken); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("access token survives RevokeAll (err=%v)", err)
		}
		if _, err := f.s.Refresh(ctx, p.RefreshToken, testGrant.ClientID); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("refresh token survives RevokeAll (err=%v)", err)
		}
	}
}

// --- at rest ---------------------------------------------------------------

func TestStoredSignInRecordsHoldNoUsableSecret(t *testing.T) {
	// The state database is not encrypted. Reading it must give neither a
	// working token or code nor the key they open.
	f := newStoreFixture(t)
	ctx := context.Background()
	code, _ := f.s.IssueCode(ctx, testCode, f.key)
	first, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	next, _ := f.s.Refresh(ctx, first.RefreshToken, testGrant.ClientID)

	secrets := map[string][]byte{"the instance key": f.key[:]}
	for name, tok := range map[string]string{
		"the code": code, "access token": first.AccessToken, "refresh token": first.RefreshToken,
		"new access token": next.AccessToken, "new refresh token": next.RefreshToken,
	} {
		body := tokenBody(tok)
		raw, err := base64.RawURLEncoding.DecodeString(body)
		if err != nil {
			t.Fatal(err)
		}
		secrets[name] = []byte(body)
		secrets[name+" (raw bytes)"] = raw
	}

	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(f.dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for name, secret := range secrets {
			if bytes.Contains(b, secret) {
				t.Errorf("%s contains %s", e.Name(), name)
			}
		}
	}
}

func TestPurgeExpiredRemovesDeadRecordsOnly(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	old, _ := f.s.IssueTokens(ctx, testGrant, f.key)
	f.s.IssueCode(ctx, testCode, f.key)
	f.clock.advance(refreshTTL + time.Hour)
	live, _ := f.s.IssueTokens(ctx, testGrant, f.key)

	if err := f.s.PurgeExpired(ctx); err != nil {
		t.Fatal(err)
	}
	var tokens, codes int
	f.s.db.QueryRow(`SELECT count(*) FROM oauth_tokens`).Scan(&tokens)
	f.s.db.QueryRow(`SELECT count(*) FROM oauth_codes`).Scan(&codes)
	if tokens != 2 || codes != 0 {
		t.Fatalf("after purge: %d token rows and %d code rows, want 2 and 0", tokens, codes)
	}
	if _, _, err := f.s.Authenticate(ctx, live.AccessToken); err != nil {
		t.Fatalf("purge removed a live token: %v", err)
	}
	if _, _, err := f.s.Authenticate(ctx, old.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token err = %v", err)
	}
}
