package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Source IDs live inside the encrypted archive. A message can be redelivered
// or edited, and two chats can contain the same WhatsApp message ID.
const messageSourcesSchema = `
CREATE TABLE IF NOT EXISTS message_sources (
	message_id TEXT NOT NULL,
	chat_jid TEXT NOT NULL,
	source_id TEXT NOT NULL UNIQUE DEFAULT (lower(hex(randomblob(16)))),
	PRIMARY KEY (message_id, chat_jid),
	FOREIGN KEY (message_id, chat_jid) REFERENCES messages(id, chat_jid) ON DELETE CASCADE
);
CREATE TRIGGER IF NOT EXISTS add_message_source AFTER INSERT ON messages
WHEN new.id IS NOT NULL AND new.chat_jid IS NOT NULL BEGIN
	INSERT INTO message_sources(message_id, chat_jid) VALUES (new.id, new.chat_jid)
	ON CONFLICT(message_id, chat_jid) DO NOTHING;
END;
INSERT INTO message_sources(message_id, chat_jid)
SELECT id, chat_jid FROM messages WHERE id IS NOT NULL AND chat_jid IS NOT NULL
ON CONFLICT(message_id, chat_jid) DO NOTHING;
`

// SourcePath is the owner-only browser route for a research citation.
const SourcePath = "/sources/"

func ValidSourceID(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

type SourceSummary struct {
	ID        string
	Chat      string
	Timestamp time.Time
	Edited    bool
	RevokedAt *time.Time
}

func (s SourceSummary) Title() string {
	title := s.Chat + " · " + s.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
	return formatMessageContent(title, s.Edited, s.RevokedAt != nil, s.RevokedAt)
}

type Source struct {
	SourceSummary
	MessageID string
	ChatJID   string
	Sender    string
	Content   string
	MediaType string
	FromMe    bool
}

func (s Source) Text() string {
	text := s.Content
	if text == "" && s.MediaType != "" {
		text = "[" + s.MediaType + "]"
	}
	return formatMessageContent(text, s.Edited, s.RevokedAt != nil, s.RevokedAt)
}

const sourceColumns = `message_sources.source_id, COALESCE(NULLIF(chats.name, ''), 'WhatsApp chat'),
	messages.timestamp, messages.edited_at IS NOT NULL, messages.revoked_at`
const sourceJoin = ` FROM messages JOIN message_sources
	ON message_sources.message_id=messages.id AND message_sources.chat_jid=messages.chat_jid
	LEFT JOIN chats ON chats.jid=messages.chat_jid`

// SearchSources returns only citation fields for the twenty newest matches.
func (s *Store) SearchSources(ctx context.Context, query string) ([]SourceSummary, error) {
	sources := []SourceSummary{}
	query = strings.TrimSpace(query)
	if query == "" {
		return sources, nil
	}
	predicate, term := messageSearchPredicate(query)
	rows, err := s.db.QueryContext(ctx, "SELECT "+sourceColumns+sourceJoin+" WHERE "+predicate+" ORDER BY "+listMessageOrder+" LIMIT 20", term)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var src SourceSummary
		if err := rows.Scan(&src.ID, &src.Chat, &src.Timestamp, &src.Edited, &src.RevokedAt); err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	return sources, rows.Err()
}

func (s *Store) Source(ctx context.Context, id string) (Source, error) {
	if !ValidSourceID(id) {
		return Source{}, sql.ErrNoRows
	}
	var src Source
	err := s.db.QueryRowContext(ctx, "SELECT "+sourceColumns+`, messages.id, messages.chat_jid,
		COALESCE(messages.sender,''), COALESCE(messages.content,''), COALESCE(messages.media_type,''), COALESCE(messages.is_from_me,0)`+
		sourceJoin+" WHERE message_sources.source_id=?", id).Scan(&src.ID, &src.Chat, &src.Timestamp,
		&src.Edited, &src.RevokedAt, &src.MessageID, &src.ChatJID, &src.Sender, &src.Content, &src.MediaType, &src.FromMe)
	return src, err
}
