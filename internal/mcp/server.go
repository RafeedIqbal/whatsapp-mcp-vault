// Package mcp wires mark3labs/mcp-go to the internal/client and internal/store
// packages, exposing the WhatsApp bridge over MCP Streamable HTTP.
package mcp

import (
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/oauth"
)

// pairingCache is the minimal pairing-state surface pairing_status needs.
// *daemon.PairCache satisfies it. The smoke command and tests pass nil, in
// which case pairing_status reports an "error" envelope.
type pairingCache interface {
	Paired() bool
	QR() string
	Expired() bool
}

// Server holds the MCP server, its bound WhatsApp client, and an optional
// pairing cache (used only by pairing_status).
type Server struct {
	client        *client.Client
	mcp           *server.MCPServer
	cache         pairingCache
	access        *Access // present on the hosted OAuth endpoint
	readOnly      bool
	labelsEnabled bool
	files         *Files // nil: no link fetching, upload page or download links

	confirm        ConfirmMode
	drafts         *DraftStore
	confirmable    map[string]bool
	isNewRecipient func(recipient string) bool
}

// NewServer constructs an MCP server with all tools registered against the
// provided WhatsApp client. cache may be nil (smoke/tests); pairing_status is
// the only tool that consults it.
// Version is reported as serverInfo.version. cmd/whatsapp-mcp sets it from its
// -ldflags build version so the two cannot drift.
var Version = "dev"

func NewServer(c *client.Client, cache pairingCache, labelsEnabled bool) *Server {
	return newServer(c, cache, false, labelsEnabled, nil)
}

// NewReadOnlyServer excludes tools that can mutate the WhatsApp account.
func NewReadOnlyServer(c *client.Client, cache pairingCache, labelsEnabled bool) *Server {
	return newServer(c, cache, true, labelsEnabled, nil)
}

// NewServerWithAccess exposes only the tools a signed-in client was granted:
// read-only tools always, send and manage tools only with those grants.
// Calling a tool outside the grant fails as an unknown tool.
func NewServerWithAccess(c *client.Client, cache pairingCache, labelsEnabled bool, access Access) *Server {
	return newServer(c, cache, !access.Send && !access.Manage, labelsEnabled, &access)
}

func newServer(c *client.Client, cache pairingCache, readOnly, labelsEnabled bool, access *Access) *Server {
	instructions := baseInstructions
	if readOnly {
		instructions += " This server is in read-only mode: tools cannot send messages or mutate the WhatsApp account. Downloads and history requests can still retrieve data and write the local cache. An explicit media download may ask your own phone to re-upload an expired attachment; it never notifies the sender or chat. Pairing remains an operator action through /pair."
	}
	s := &Server{access: access, client: c, cache: cache, readOnly: readOnly, labelsEnabled: labelsEnabled,
		drafts: NewDraftStore(), confirmable: defaultConfirmable()}
	s.isNewRecipient = func(recipient string) bool { return s.client != nil && s.client.RecipientIsNew(recipient) }
	s.mcp = server.NewMCPServer(
		"whatsapp",
		Version,
		server.WithToolCapabilities(true),
		server.WithInstructions(instructions),
		server.WithToolHandlerMiddleware(s.confirmMiddleware),
	)
	s.registerTools()
	var tools []server.ServerTool
	for name, tool := range s.mcp.ListTools() {
		if readOnly && !readOnlyToolAccess[name] || access != nil && !access.allows(name) {
			continue
		}
		if access != nil {
			scopes := []string{oauth.ScopeRead}
			if manageToolAccess[name] {
				scopes = append(scopes, oauth.ScopeManage)
			} else if !readOnlyToolAccess[name] {
				scopes = append(scopes, oauth.ScopeSend)
			}
			tool.Tool.Meta = &mcp.Meta{AdditionalFields: map[string]any{"securitySchemes": []map[string]any{{"type": "oauth2", "scopes": scopes}}}}
		}
		tools = append(tools, *tool)
	}
	s.mcp.SetTools(tools...)
	s.registerResources()
	return s
}

// MCP returns the underlying mcp-go server (tests only).
func (s *Server) MCP() *server.MCPServer { return s.mcp }

// AttachHTTP mounts the MCP Streamable HTTP handler on mux at /mcp. The
// actual listener lifecycle is owned by the caller (internal/daemon).
func (s *Server) AttachHTTP(mux *http.ServeMux) {
	// Stateless: nothing here is session-scoped (the pairing cache is process-wide
	// device state), so legacy clients get no Mcp-Session-Id either.
	// No long-lived GET stream either: the server never pushes anything, and
	// an open stream would count as the instance being in use, so it could
	// never lock when idle.
	httpHandler := server.NewStreamableHTTPServer(s.mcp, server.WithStateLess(true), server.WithDisableStreaming(true))
	mux.Handle("/mcp", httpHandler)
}
