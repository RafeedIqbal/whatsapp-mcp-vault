package store

import (
	"database/sql"
	"fmt"
	"strings"
	"unicode"
)

// searchSchema is a full-text index over message text. It is an FTS4
// "external content" table: the words are indexed, the text itself stays only
// in messages. Triggers keep it in step with every insert, edit and delete.
// It lives inside the encrypted messages database like everything else.
//
// FTS4 (not FTS5) because the bundled SQLCipher build compiles it in without
// a build tag; a missing tag would otherwise silently drop search.
const searchSchema = `
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts4(
	content="messages", content, tokenize=unicode61 "remove_diacritics=2"
);
CREATE TRIGGER IF NOT EXISTS messages_fts_before_update BEFORE UPDATE ON messages BEGIN
	DELETE FROM messages_fts WHERE docid = old.rowid;
END;
CREATE TRIGGER IF NOT EXISTS messages_fts_before_delete BEFORE DELETE ON messages BEGIN
	DELETE FROM messages_fts WHERE docid = old.rowid;
END;
CREATE TRIGGER IF NOT EXISTS messages_fts_after_update AFTER UPDATE ON messages BEGIN
	INSERT INTO messages_fts(docid, content) VALUES (new.rowid, new.content);
END;
CREATE TRIGGER IF NOT EXISTS messages_fts_after_insert AFTER INSERT ON messages BEGIN
	INSERT INTO messages_fts(docid, content) VALUES (new.rowid, new.content);
END;
`

// ensureSearchIndex creates the index if it is missing and rebuilds it when it
// does not cover every stored message (an archive from before the index
// existed, or one whose index was lost).
func ensureSearchIndex(db *sql.DB) error {
	if _, err := db.Exec(searchSchema); err != nil {
		return fmt.Errorf("create search index: %w", err)
	}
	var messages, indexed int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM messages), (SELECT count(*) FROM messages_fts_docsize)`).Scan(&messages, &indexed); err != nil {
		return fmt.Errorf("check search index: %w", err)
	}
	if messages == indexed {
		return nil
	}
	if _, err := db.Exec(`INSERT INTO messages_fts(messages_fts) VALUES ('rebuild')`); err != nil {
		return fmt.Errorf("rebuild search index: %w", err)
	}
	return nil
}

// maxSearchTerms bounds how many words of a query are used.
const maxSearchTerms = 16

// searchMatchExpr turns free text into an index query that requires every
// word (as a prefix) to be present, in any order. It returns "" when the text
// cannot be answered from the word index and needs a substring scan instead:
// queries with no letters or digits (emoji, symbols), and scripts written
// without spaces between words, where a word can sit mid-run.
//
// Only lower-cased letter/digit runs are emitted, so nothing the caller typed
// can act as query syntax (AND/OR/NOT/NEAR, quotes, parentheses, '*', '-').
func searchMatchExpr(query string) string {
	var terms []string
	var cur strings.Builder
	sawNonWord := false
	flush := func() {
		if cur.Len() > 0 {
			terms = append(terms, cur.String()+"*")
			cur.Reset()
		}
	}
	for _, r := range query {
		switch {
		case unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Thai, unicode.Lao, unicode.Khmer, unicode.Myanmar):
			return ""
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			cur.WriteRune(unicode.ToLower(r))
		case unicode.IsMark(r):
			// Combining accents belong to the letter before them.
			if cur.Len() > 0 {
				cur.WriteRune(r)
			}
		default:
			if !unicode.IsSpace(r) && !unicode.IsPunct(r) {
				sawNonWord = true // emoji, currency and other symbols
			}
			flush()
		}
	}
	flush()
	if len(terms) == 0 || sawNonWord {
		return ""
	}
	if len(terms) > maxSearchTerms {
		terms = terms[:maxSearchTerms]
	}
	return strings.Join(terms, " ")
}
