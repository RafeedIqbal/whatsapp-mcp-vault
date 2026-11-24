package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault/vaulttest"
)

const searchChat = "15550001111@s.whatsapp.net"

func openSearchStore(t *testing.T, contents map[string]string) *Store {
	t.Helper()
	s, err := Open(t.TempDir(), vaulttest.Key())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	if err := s.StoreChat(searchChat, "Search", at); err != nil {
		t.Fatal(err)
	}
	for id, content := range contents {
		m := Message{ID: id, ChatJID: searchChat, Sender: "15550001111", Content: content, Timestamp: at}
		if err := s.StoreMessage(context.Background(), m, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Minute)
	}
	return s
}

func searchIDs(t *testing.T, s *Store, q string) map[string]bool {
	t.Helper()
	msgs, err := s.ListMessages(context.Background(), ListMessagesParams{Query: q, Limit: 50})
	if err != nil {
		t.Fatalf("ListMessages(%q): %v", q, err)
	}
	ids := map[string]bool{}
	for _, m := range msgs {
		ids[m.ID] = true
	}
	return ids
}

func TestSearchMatchesAllWordsEvenWhenNotAdjacent(t *testing.T) {
	s := openSearchStore(t, map[string]string{
		"both":  "lunch tomorrow at noon?",
		"lunch": "lunch was great",
		"noon":  "call me at noon",
	})
	got := searchIDs(t, s, "lunch noon")
	if len(got) != 1 || !got["both"] {
		t.Fatalf(`search "lunch noon" = %v, want only the message containing both words`, got)
	}
}

func TestSearchIgnoresCaseAndAccents(t *testing.T) {
	s := openSearchStore(t, map[string]string{"cafe": "Meet at Café Central", "other": "see you there"})
	for _, q := range []string{"cafe", "CAFÉ", "central"} {
		if got := searchIDs(t, s, q); len(got) != 1 || !got["cafe"] {
			t.Errorf("search %q = %v, want the café message", q, got)
		}
	}
}

func TestSearchMatchesWordPrefixes(t *testing.T) {
	s := openSearchStore(t, map[string]string{"m": "see you tomorrow", "other": "today works"})
	if got := searchIDs(t, s, "tomor"); len(got) != 1 || !got["m"] {
		t.Fatalf(`search "tomor" = %v, want the message containing "tomorrow"`, got)
	}
}

func TestSearchTreatsOperatorsAndPunctuationAsPlainText(t *testing.T) {
	s := openSearchStore(t, map[string]string{"m": "lunch or dinner, not both", "other": "breakfast"})
	// None of these may be an error or be read as query syntax.
	for _, q := range []string{`lunch OR`, `NOT lunch`, `"lunch`, `lunch*)`, `lunch NEAR/2 dinner`, `(lunch AND`, `don't`} {
		if _, err := s.ListMessages(context.Background(), ListMessagesParams{Query: q, Limit: 10}); err != nil {
			t.Errorf("query %q returned an error: %v", q, err)
		}
	}
	if got := searchIDs(t, s, "NOT lunch"); !got["m"] || got["other"] {
		t.Fatalf(`"NOT lunch" = %v: NOT was applied as an operator instead of a word`, got)
	}
}

func TestSearchFindsEmojiAndSymbols(t *testing.T) {
	// Symbols are not indexed as words, so these queries fall back to a
	// substring scan rather than returning nothing.
	s := openSearchStore(t, map[string]string{"thumb": "sounds good 👍", "price": "it costs $40", "other": "plain"})
	if got := searchIDs(t, s, "👍"); len(got) != 1 || !got["thumb"] {
		t.Errorf("emoji search = %v, want the thumbs-up message", got)
	}
	if got := searchIDs(t, s, "$"); len(got) != 1 || !got["price"] {
		t.Errorf("symbol search = %v, want the price message", got)
	}
}

func TestSearchFindsWordsInsideUnspacedScripts(t *testing.T) {
	// Chinese, Japanese and Thai are written without spaces, so a word can
	// sit in the middle of a run of characters.
	s := openSearchStore(t, map[string]string{"zh": "明天中午一起吃饭", "other": "下周见"})
	if got := searchIDs(t, s, "中午"); len(got) != 1 || !got["zh"] {
		t.Fatalf("search for a mid-sentence Chinese word = %v, want the first message", got)
	}
}

func TestSearchFollowsEditsAndDeletes(t *testing.T) {
	s := openSearchStore(t, map[string]string{"m": "original wording"})
	if _, err := s.db.Exec(`UPDATE messages SET content = 'replacement text' WHERE id = 'm'`); err != nil {
		t.Fatal(err)
	}
	if got := searchIDs(t, s, "original"); len(got) != 0 {
		t.Errorf("old text still searchable after an edit: %v", got)
	}
	if got := searchIDs(t, s, "replacement"); !got["m"] {
		t.Errorf("new text not searchable after an edit: %v", got)
	}
	if _, err := s.db.Exec(`DELETE FROM messages WHERE id = 'm'`); err != nil {
		t.Fatal(err)
	}
	if got := searchIDs(t, s, "replacement"); len(got) != 0 {
		t.Errorf("deleted message still searchable: %v", got)
	}
}

func TestSearchCoversMessagesStoredBeforeTheIndexExisted(t *testing.T) {
	// An archive written by a build without the search index: messages
	// present, no index. Opening it must make them searchable.
	dir := t.TempDir()
	old, err := vaulttest.OpenDB(filepath.Join(dir, "messages.db"), MessagesDBName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO chats (jid, name) VALUES (?, 'Old');
		INSERT INTO messages (id, chat_jid, sender, content, timestamp, is_from_me)
		VALUES ('old-1', ?, '15550001111', 'archived before indexing', '2026-01-01 09:00:00', 0)`, searchChat, searchChat); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := Open(dir, vaulttest.Key())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := searchIDs(t, s, "archived indexing"); !got["old-1"] {
		t.Fatalf("pre-existing message not searchable after Open: %v", got)
	}
}
