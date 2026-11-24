// Package oauth is the instance's own OAuth 2.1 authorization server: the
// sign-in an MCP client (Claude, ChatGPT, …) goes through before it may call
// tools.
//
// It differs from an ordinary token store in one way that the whole security
// model rests on: every sign-in code and token carries a sealed copy of the
// instance key that only that code or token can open. The server stores the
// sealed copies and one-way lookup IDs, never the codes or tokens themselves.
// So what is on disk can neither be replayed as a credential nor used to
// decrypt anything; the key exists in usable form only while a client is
// presenting a valid token.
package oauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

var (
	// ErrUnknownClient: no client is registered under that ID.
	ErrUnknownClient = errors.New("oauth: unknown client")
	// ErrTooManyClients: the registration cap has been reached.
	ErrTooManyClients = errors.New("oauth: too many registered clients")
	// ErrInvalidGrant: a sign-in code or refresh token is unknown, expired,
	// already used, revoked, or presented by the wrong client.
	ErrInvalidGrant = errors.New("oauth: invalid grant")
	// ErrInvalidToken: an access token is unknown, expired or revoked.
	ErrInvalidToken = errors.New("oauth: invalid token")
)

const (
	codeTTL    = 2 * time.Minute
	accessTTL  = time.Hour
	refreshTTL = 90 * 24 * time.Hour
	// refreshGrace is how long a refresh token that has just been replaced
	// still answers with its replacement. Clients retry and parallelise
	// refreshes; without this a retry would look like a stolen token.
	refreshGrace = 60 * time.Second
	// maxClients caps dynamic registration, which is open to anyone who can
	// reach the server.
	maxClients = 100

	tokenBytes    = 32
	codePrefix    = "wamcp_ac_"
	accessPrefix  = "wamcp_at_"
	refreshPrefix = "wamcp_rt_"

	purposeCode      = "auth-code"
	purposeAccess    = "access-token"
	purposeRefresh   = "refresh-token"
	purposeSuccessor = "refresh-successor"
)

const schema = `
CREATE TABLE IF NOT EXISTS oauth_clients (
	client_id     TEXT PRIMARY KEY,
	name          TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
	id             TEXT PRIMARY KEY,
	client_id      TEXT NOT NULL,
	redirect_uri   TEXT NOT NULL,
	scope          TEXT NOT NULL,
	resource       TEXT NOT NULL,
	code_challenge TEXT NOT NULL,
	wrapped_key    BLOB NOT NULL,
	expires_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
	id          TEXT PRIMARY KEY,
	kind        TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
	family_id   TEXT NOT NULL,
	client_id   TEXT NOT NULL,
	scope       TEXT NOT NULL,
	resource    TEXT NOT NULL,
	wrapped_key BLOB NOT NULL,
	expires_at  INTEGER NOT NULL,
	revoked_at  INTEGER NOT NULL DEFAULT 0,
	rotated_at  INTEGER NOT NULL DEFAULT 0,
	successor   BLOB
);
CREATE INDEX IF NOT EXISTS oauth_tokens_family ON oauth_tokens (family_id);
`

// Store persists clients, sign-in codes and tokens in the state database.
type Store struct {
	db  *sql.DB
	now func() time.Time
	// mu makes read-then-write sequences (redeem, refresh) atomic. There is
	// one process per instance, so a mutex is enough.
	mu sync.Mutex
}

// NewStore prepares the sign-in tables in db (the vault's state database).
func NewStore(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("prepare sign-in tables: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

// Client is a registered MCP client application.
type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
}

// RegisterClient records a new client and assigns it an ID.
func (s *Store) RegisterClient(ctx context.Context, name string, redirectURIs []string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM oauth_clients`).Scan(&n); err != nil {
		return Client{}, fmt.Errorf("count clients: %w", err)
	}
	if n >= maxClients {
		// Make room by dropping the oldest client nobody is signed in with.
		// A flood of throwaway registrations then costs the flooder its own
		// registrations, not a real client's ability to register.
		now := s.now().Unix()
		res, err := s.db.ExecContext(ctx, `DELETE FROM oauth_clients WHERE client_id = (
			SELECT c.client_id FROM oauth_clients c
			WHERE NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.client_id AND t.revoked_at = 0 AND t.expires_at > ?)
			  AND NOT EXISTS (SELECT 1 FROM oauth_codes k WHERE k.client_id = c.client_id AND k.expires_at > ?)
			ORDER BY c.created_at ASC, c.rowid ASC LIMIT 1)`, now, now)
		if err != nil {
			return Client{}, fmt.Errorf("make room for client: %w", err)
		}
		if evicted, _ := res.RowsAffected(); evicted == 0 {
			return Client{}, ErrTooManyClients
		}
	}
	id, err := randomString(16)
	if err != nil {
		return Client{}, err
	}
	c := Client{ID: "c_" + id, Name: name, RedirectURIs: redirectURIs, CreatedAt: s.now()}
	uris, err := json.Marshal(redirectURIs)
	if err != nil {
		return Client{}, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO oauth_clients (client_id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)`,
		c.ID, c.Name, string(uris), c.CreatedAt.Unix()); err != nil {
		return Client{}, fmt.Errorf("store client: %w", err)
	}
	return c, nil
}

// Client returns the registered client with the given ID.
func (s *Store) Client(ctx context.Context, id string) (Client, error) {
	var c Client
	var uris string
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT client_id, name, redirect_uris, created_at FROM oauth_clients WHERE client_id = ?`, id).
		Scan(&c.ID, &c.Name, &uris, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrUnknownClient
	}
	if err != nil {
		return Client{}, fmt.Errorf("read client: %w", err)
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return Client{}, fmt.Errorf("read client: %w", err)
	}
	c.CreatedAt = time.Unix(created, 0)
	return c, nil
}

// CodeGrant is what the owner approved on the consent page, bound to the
// sign-in code issued for it.
type CodeGrant struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	Resource      string
	CodeChallenge string // PKCE S256 challenge
}

// IssueCode creates a one-time sign-in code for g carrying a sealed copy of key.
func (s *Store) IssueCode(ctx context.Context, g CodeGrant, key vault.Key) (string, error) {
	code, raw, err := newSecret(codePrefix)
	if err != nil {
		return "", err
	}
	wrapped, err := vault.WrapWithSecret(key, raw, purposeCode)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO oauth_codes (id, client_id, redirect_uri, scope, resource, code_challenge, wrapped_key, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		vault.SecretID(raw, purposeCode), g.ClientID, g.RedirectURI, g.Scope, g.Resource, g.CodeChallenge, wrapped, s.now().Add(codeTTL).Unix())
	if err != nil {
		return "", fmt.Errorf("store sign-in code: %w", err)
	}
	return code, nil
}

// RedeemCode exchanges a sign-in code for the grant it was issued for and the
// instance key. A code works once; any second use, and any use after it has
// expired, fails with ErrInvalidGrant.
func (s *Store) RedeemCode(ctx context.Context, code string) (CodeGrant, vault.Key, error) {
	raw, ok := parseSecret(code, codePrefix)
	if !ok {
		return CodeGrant{}, vault.Key{}, ErrInvalidGrant
	}
	id := vault.SecretID(raw, purposeCode)

	s.mu.Lock()
	defer s.mu.Unlock()
	var g CodeGrant
	var wrapped []byte
	var expires int64
	err := s.db.QueryRowContext(ctx, `SELECT client_id, redirect_uri, scope, resource, code_challenge, wrapped_key, expires_at
		FROM oauth_codes WHERE id = ?`, id).Scan(&g.ClientID, &g.RedirectURI, &g.Scope, &g.Resource, &g.CodeChallenge, &wrapped, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return CodeGrant{}, vault.Key{}, ErrInvalidGrant
	}
	if err != nil {
		return CodeGrant{}, vault.Key{}, fmt.Errorf("read sign-in code: %w", err)
	}
	// Spent the moment it is looked at, whatever happens next.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_codes WHERE id = ?`, id); err != nil {
		return CodeGrant{}, vault.Key{}, fmt.Errorf("consume sign-in code: %w", err)
	}
	if !s.now().Before(time.Unix(expires, 0)) {
		return CodeGrant{}, vault.Key{}, ErrInvalidGrant
	}
	key, err := vault.UnwrapWithSecret(wrapped, raw, purposeCode)
	if err != nil {
		return CodeGrant{}, vault.Key{}, ErrInvalidGrant
	}
	return g, key, nil
}

// Grant is what a set of tokens is good for.
type Grant struct {
	ClientID string
	Scope    string
	Resource string
	// FamilyID links every token descended from one sign-in. Leave it empty
	// to start a new sign-in.
	FamilyID string
}

// TokenPair is what the token endpoint returns to a client.
type TokenPair struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    time.Duration `json:"expires_in"`
	Scope        string        `json:"scope"`
}

// IssueTokens creates an access and a refresh token for g, each carrying its
// own sealed copy of key.
func (s *Store) IssueTokens(ctx context.Context, g Grant, key vault.Key) (TokenPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueLocked(ctx, s.db, g, key)
}

// execer is satisfied by *sql.DB and *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (s *Store) issueLocked(ctx context.Context, db execer, g Grant, key vault.Key) (TokenPair, error) {
	if g.FamilyID == "" {
		fam, err := randomString(16)
		if err != nil {
			return TokenPair{}, err
		}
		g.FamilyID = fam
	}
	now := s.now()
	insert := func(prefix, kind, purpose string, ttl time.Duration) (string, error) {
		tok, raw, err := newSecret(prefix)
		if err != nil {
			return "", err
		}
		wrapped, err := vault.WrapWithSecret(key, raw, purpose)
		if err != nil {
			return "", err
		}
		_, err = db.ExecContext(ctx, `INSERT INTO oauth_tokens (id, kind, family_id, client_id, scope, resource, wrapped_key, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			vault.SecretID(raw, purpose), kind, g.FamilyID, g.ClientID, g.Scope, g.Resource, wrapped, now.Add(ttl).Unix())
		if err != nil {
			return "", fmt.Errorf("store %s token: %w", kind, err)
		}
		return tok, nil
	}
	access, err := insert(accessPrefix, "access", purposeAccess, accessTTL)
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := insert(refreshPrefix, "refresh", purposeRefresh, refreshTTL)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: accessTTL, Scope: g.Scope}, nil
}

// Authenticate checks an access token and returns what it is good for and the
// instance key it opens.
func (s *Store) Authenticate(ctx context.Context, accessToken string) (Grant, vault.Key, error) {
	raw, ok := parseSecret(accessToken, accessPrefix)
	if !ok {
		return Grant{}, vault.Key{}, ErrInvalidToken
	}
	var g Grant
	var wrapped []byte
	var expires, revoked int64
	err := s.db.QueryRowContext(ctx, `SELECT family_id, client_id, scope, resource, wrapped_key, expires_at, revoked_at
		FROM oauth_tokens WHERE id = ? AND kind = 'access'`, vault.SecretID(raw, purposeAccess)).
		Scan(&g.FamilyID, &g.ClientID, &g.Scope, &g.Resource, &wrapped, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, vault.Key{}, ErrInvalidToken
	}
	if err != nil {
		return Grant{}, vault.Key{}, fmt.Errorf("read token: %w", err)
	}
	if revoked != 0 || !s.now().Before(time.Unix(expires, 0)) {
		return Grant{}, vault.Key{}, ErrInvalidToken
	}
	key, err := vault.UnwrapWithSecret(wrapped, raw, purposeAccess)
	if err != nil {
		return Grant{}, vault.Key{}, ErrInvalidToken
	}
	return g, key, nil
}

// Refresh replaces a refresh token with a new access/refresh pair.
//
// The old refresh token keeps answering with that same new pair for
// refreshGrace, so a client that retries gets a consistent result. Using it
// after that means a copy has leaked: every token descended from the same
// sign-in is revoked and the call fails.
func (s *Store) Refresh(ctx context.Context, refreshToken, clientID string) (TokenPair, error) {
	raw, ok := parseSecret(refreshToken, refreshPrefix)
	if !ok {
		return TokenPair{}, ErrInvalidGrant
	}
	id := vault.SecretID(raw, purposeRefresh)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.dropStaleSuccessorsLocked(ctx); err != nil {
		return TokenPair{}, err
	}
	var g Grant
	var wrapped, successor []byte
	var expires, revoked, rotated int64
	err := s.db.QueryRowContext(ctx, `SELECT family_id, client_id, scope, resource, wrapped_key, expires_at, revoked_at, rotated_at, successor
		FROM oauth_tokens WHERE id = ? AND kind = 'refresh'`, id).
		Scan(&g.FamilyID, &g.ClientID, &g.Scope, &g.Resource, &wrapped, &expires, &revoked, &rotated, &successor)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenPair{}, ErrInvalidGrant
	}
	if err != nil {
		return TokenPair{}, fmt.Errorf("read refresh token: %w", err)
	}
	now := s.now()
	if revoked != 0 || g.ClientID != clientID || !now.Before(time.Unix(expires, 0)) {
		return TokenPair{}, ErrInvalidGrant
	}

	if rotated != 0 {
		if now.Sub(time.Unix(rotated, 0)) <= refreshGrace && len(successor) > 0 {
			plain, err := vault.OpenWithSecret(successor, raw, purposeSuccessor)
			if err == nil {
				var pair TokenPair
				if json.Unmarshal(plain, &pair) == nil {
					return pair, nil
				}
			}
		}
		// Deleted, not flagged: a revoked row must not keep a sealed copy of
		// the key (or the replacement tokens) lying in the state database.
		if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_tokens WHERE family_id = ?`, g.FamilyID); err != nil {
			return TokenPair{}, fmt.Errorf("revoke sign-in after token reuse: %w", err)
		}
		return TokenPair{}, ErrInvalidGrant
	}

	key, err := vault.UnwrapWithSecret(wrapped, raw, purposeRefresh)
	if err != nil {
		return TokenPair{}, ErrInvalidGrant
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenPair{}, fmt.Errorf("refresh: %w", err)
	}
	defer tx.Rollback()
	pair, err := s.issueLocked(ctx, tx, g, key)
	if err != nil {
		return TokenPair{}, err
	}
	plain, err := json.Marshal(pair)
	if err != nil {
		return TokenPair{}, err
	}
	sealed, err := vault.SealWithSecret(plain, raw, purposeSuccessor)
	if err != nil {
		return TokenPair{}, err
	}
	// The retired token keeps its row (so later reuse is detected) and, for
	// the grace window only, the sealed replacement pair. Its sealed copy of
	// the key is dropped now: a retired token must not still open the vault.
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_tokens SET rotated_at = ?, successor = ?, wrapped_key = x'' WHERE id = ?`, now.Unix(), sealed, id); err != nil {
		return TokenPair{}, fmt.Errorf("retire refresh token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return TokenPair{}, fmt.Errorf("refresh: %w", err)
	}
	return pair, nil
}

// RevokeAll ends every sign-in: all tokens are deleted (with their sealed
// keys) and pending codes are discarded. Clients have to sign in again with the passphrase.
func (s *Store) RevokeAll(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_tokens`); err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_codes`); err != nil {
		return fmt.Errorf("discard sign-in codes: %w", err)
	}
	return nil
}

// PurgeExpired deletes codes and tokens that can no longer be used.
func (s *Store) PurgeExpired(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_tokens WHERE expires_at <= ?`, now); err != nil {
		return fmt.Errorf("purge tokens: %w", err)
	}
	if err := s.dropStaleSuccessorsLocked(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oauth_codes WHERE expires_at <= ?`, now); err != nil {
		return fmt.Errorf("purge sign-in codes: %w", err)
	}
	return nil
}

// dropStaleSuccessorsLocked removes replacement token pairs that are past the
// grace window in which a retry could still ask for them. mu must be held.
func (s *Store) dropStaleSuccessorsLocked(ctx context.Context) error {
	cutoff := s.now().Add(-refreshGrace).Unix()
	if _, err := s.db.ExecContext(ctx, `UPDATE oauth_tokens SET successor = NULL WHERE successor IS NOT NULL AND rotated_at != 0 AND rotated_at < ?`, cutoff); err != nil {
		return fmt.Errorf("drop stale replacement tokens: %w", err)
	}
	return nil
}

// newSecret returns a fresh random credential as the string handed to the
// client and the raw bytes everything is derived from.
func newSecret(prefix string) (string, []byte, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, errors.New("oauth: could not read random bytes")
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), raw, nil
}

// parseSecret recovers the raw bytes of a credential of the expected kind.
func parseSecret(s, prefix string) ([]byte, bool) {
	body, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return nil, false
	}
	// Strict: only the one canonical spelling of a credential is accepted.
	// Lenient decoding ignores the last character's unused bits, so several
	// different strings would otherwise all be the same token.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(raw) != tokenBytes {
		return nil, false
	}
	return raw, true
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("oauth: could not read random bytes")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
