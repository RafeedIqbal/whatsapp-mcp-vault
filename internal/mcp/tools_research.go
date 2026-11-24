package mcp

import (
	"context"
	"database/sql"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sealjay/mcp-whatsapp/internal/store"
)

type citation struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

type searchResult struct {
	Results []citation `json:"results"`
}

type sourceMetadata struct {
	MessageID string     `json:"message_id"`
	ChatJID   string     `json:"chat_jid"`
	Sender    string     `json:"sender"`
	Timestamp time.Time  `json:"timestamp"`
	FromMe    bool       `json:"is_from_me"`
	MediaType string     `json:"media_type,omitempty"`
	Edited    bool       `json:"edited"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type fetchResult struct {
	citation
	Text     string         `json:"text"`
	Metadata sourceMetadata `json:"metadata"`
}

func summarizeSource(base string, source store.SourceSummary) citation {
	return citation{ID: source.ID, Title: source.Title(), URL: base + store.SourcePath + source.ID}
}

func (s *Server) registerResearchTools(base string) {
	search := mcp.NewTool("search",
		mcp.WithDescription(offlineSafePrefix+"Find up to 20 archived messages matching a text query, newest first. This read-only search returns results with an opaque ID, title and owner-only citation URL for each match. Use fetch for message text or list_messages for chat filters and pagination."),
		mcp.WithString("query", mcp.Required(), mcp.Description("words or literal symbols to find in message text, up to 1,024 characters")),
		mcp.WithOutputSchema[searchResult](),
		mcp.WithReadOnlyHintAnnotation(true), mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true), mcp.WithOpenWorldHintAnnotation(false),
	)
	s.mcp.AddTool(search, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := req.RequireString("query")
		if err != nil || utf8.RuneCountInString(query) > 1024 {
			return mcp.NewToolResultError("query must be text of up to 1,024 characters"), nil
		}
		sources, err := s.client.Store().SearchSources(ctx, query)
		if err != nil {
			return mcp.NewToolResultError("Could not search the archive."), nil
		}
		out := searchResult{Results: make([]citation, 0, len(sources))}
		for _, src := range sources {
			out.Results = append(out.Results, summarizeSource(base, src))
		}
		return mcp.NewToolResultStructuredOnly(out), nil
	})

	fetch := mcp.NewTool("fetch",
		mcp.WithDescription(offlineSafePrefix+"Read one archived message by the opaque ID returned by search. Returns its ID, title, retained text, owner-only citation URL and message metadata, including edit and deletion markers. Use get_message_context with the returned message and chat IDs for surrounding messages."),
		mcp.WithString("id", mcp.Required(), mcp.Description("opaque source ID returned by search")),
		mcp.WithOutputSchema[fetchResult](),
		mcp.WithReadOnlyHintAnnotation(true), mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true), mcp.WithOpenWorldHintAnnotation(false),
	)
	s.mcp.AddTool(fetch, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id := req.GetString("id", "")
		if !store.ValidSourceID(id) {
			return mcp.NewToolResultError("Source not found."), nil
		}
		src, err := s.client.Store().Source(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return mcp.NewToolResultError("Source not found."), nil
		}
		if err != nil {
			return mcp.NewToolResultError("Could not read the archive."), nil
		}
		out := fetchResult{
			citation: summarizeSource(base, src.SourceSummary),
			Text:     src.Text(),
			Metadata: sourceMetadata{
				MessageID: src.MessageID, ChatJID: src.ChatJID, Sender: src.Sender,
				Timestamp: src.Timestamp.UTC(), FromMe: src.FromMe, MediaType: src.MediaType,
				Edited: src.Edited, Revoked: src.RevokedAt != nil, RevokedAt: src.RevokedAt,
			},
		}
		return mcp.NewToolResultStructuredOnly(out), nil
	})
}
