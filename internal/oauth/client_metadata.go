package oauth

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/ingest"
)

const chatGPTCallback = "https://chatgpt.com/connector_platform_oauth_redirect"

var publishedClients = map[string]struct{ name, callback string }{
	"https://chatgpt.com/oauth/client.json":             {"ChatGPT", chatGPTCallback},
	"https://claude.ai/oauth/mcp-oauth-client-metadata": {"Claude", "https://claude.ai/api/mcp/auth_callback"},
}

type cachedClient struct {
	client  Client
	expires time.Time
}

func fetchClientDocument(ctx context.Context, id string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	blob, err := ingest.NewFetcher(16<<10).FetchExact(ctx, id)
	return blob.Data, err
}

// Fetch only the two published identities. A document never adds callbacks
// to the instance allowlist. Existing DCR registrations still use the store.
func (s *Server) resolveClient(ctx context.Context, id string) (Client, error) {
	provider, known := publishedClients[id]
	if !known {
		return s.cfg.Store.Client(ctx, id)
	}
	s.metadataMu.Lock()
	defer s.metadataMu.Unlock()
	if entry, ok := s.metadata[id]; ok && s.cfg.Now().Before(entry.expires) {
		return entry.client, nil
	}
	data, err := s.fetchMetadata(ctx, id)
	if err != nil {
		return Client{}, err
	}
	var doc struct {
		ID        string   `json:"client_id"`
		Redirects []string `json:"redirect_uris"`
		Methods   []string `json:"token_endpoint_auth_methods_supported"`
		Method    string   `json:"token_endpoint_auth_method"`
		Grants    []string `json:"grant_types"`
		Responses []string `json:"response_types"`
	}
	if json.Unmarshal(data, &doc) != nil || doc.ID != id || !slices.Contains(doc.Redirects, provider.callback) {
		return Client{}, ErrUnknownClient
	}
	// OpenAI publishes the methods it supports as well as a legacy preference.
	if doc.Methods == nil {
		doc.Methods = []string{doc.Method}
	}
	if !slices.Contains(doc.Methods, "none") ||
		(doc.Grants != nil && !slices.Contains(doc.Grants, "authorization_code")) ||
		(doc.Responses != nil && !slices.Contains(doc.Responses, "code")) {
		return Client{}, ErrUnknownClient
	}
	client := Client{ID: id, Name: provider.name, RedirectURIs: []string{provider.callback}}
	s.metadata[id] = cachedClient{client, s.cfg.Now().Add(5 * time.Minute)}
	return client, nil
}
