package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSourceMigrationBackfillsExistingArchive(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec("PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchema(s.db); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := s.db.QueryRow("SELECT source_id FROM message_sources WHERE message_id='a3'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	src, err := s.Source(ctx, id)
	if err != nil || !ValidSourceID(id) || src.MessageID != "a3" {
		t.Fatalf("backfill: %#v, %v", src, err)
	}
	if err := migrateSchema(s.db); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Source(ctx, id); err != nil {
		t.Fatalf("source lost after migration: %v", err)
	}
}

func TestSourcesDisambiguateMessagesAndRetainHistory(t *testing.T) {
	s := openSearchStore(t, map[string]string{"same": "match 10%", "z": "match late", "a": "match early"})
	ctx := context.Background()
	other := "15550002222@s.whatsapp.net"
	at := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	if err := s.StoreChat(other, "Other chat", at); err != nil {
		t.Fatal(err)
	}
	msg := Message{ID: "same", ChatJID: other, Sender: "other", Content: "match _ticket", Timestamp: at}
	if err := s.StoreMessage(ctx, msg, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	matches, err := s.SearchSources(ctx, "match")
	if err != nil || len(matches) != 4 {
		t.Fatalf("search: %v, %v", matches, err)
	}
	ids := map[string]bool{}
	for _, m := range matches {
		if !ValidSourceID(m.ID) || ids[m.ID] {
			t.Fatalf("duplicate or invalid source ID %q", m.ID)
		}
		ids[m.ID] = true
	}
	for query, wantChat := range map[string]string{"%": searchChat, "_": other} {
		results, err := s.SearchSources(ctx, query)
		if err != nil || len(results) != 1 {
			t.Fatalf("literal %q: %v, %v", query, results, err)
		}
		src, err := s.Source(ctx, results[0].ID)
		if err != nil || src.ChatJID != wantChat {
			t.Fatalf("wrong source for %q: %+v, %v", query, src, err)
		}
	}
	if _, err := s.GetMessageContext(ctx, "same", 1, 1); err == nil || !strings.Contains(err.Error(), "chat_jid") {
		t.Fatal("ambiguous ID did not require its chat")
	}
	c, err := s.GetMessageContextInChat(ctx, "same", other, 1, 1)
	if err != nil || c.Message.Content != msg.Content || len(c.After)+len(c.Before) != 0 {
		t.Fatalf("wrong context: %#v, %v", c, err)
	}
	if _, err := s.ListMessages(ctx, ListMessagesParams{Query: "match", IncludeContext: true}); err != nil {
		t.Fatal(err)
	}
	id := matches[0].ID
	author := Author{Senders: []string{"other"}}
	if ok, err := s.ApplyEdit(ctx, other, "same", author, "revised", at.Add(time.Minute)); err != nil || !ok {
		t.Fatal("edit failed", err)
	}
	if err := s.StoreMessage(ctx, msg, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	edited, err := s.Source(ctx, id)
	if err != nil || edited.Text() != "[edited] revised" {
		t.Fatalf("edited source: %q %v", edited.Text(), err)
	}
	if ok, err := s.ApplyRevoke(ctx, other, "same", author, at.Add(2*time.Minute)); err != nil || !ok {
		t.Fatal("revoke failed", err)
	}
	retained, err := s.SearchSources(ctx, "revised")
	if err != nil || len(retained) != 1 || retained[0].ID != id || !strings.Contains(retained[0].Title(), "[deleted ") {
		t.Fatalf("deleted citation: %v, %v", retained, err)
	}
	src, err := s.Source(ctx, id)
	if err != nil || !src.Edited || src.RevokedAt == nil || !strings.Contains(src.Text(), "[deleted 2026-03-02 09:02:00 UTC] revised") {
		t.Fatalf("deleted source: %#v, %v", src, err)
	}
	if _, err := s.Source(ctx, "same"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("raw WhatsApp ID resolved")
	}
}

func TestSourceSearchIsBoundedAndContextOrdersTimeTies(t *testing.T) {
	s := openSearchStore(t, nil)
	at := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	ctx := context.Background()
	for i := 0; i < 21; i++ {
		m := Message{ID: fmt.Sprintf("m%02d", i), ChatJID: searchChat, Sender: "fixture", Content: "matching", Timestamp: at}
		if err := s.StoreMessage(ctx, m, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	hits, err := s.SearchSources(ctx, "match")
	if err != nil || len(hits) != 20 {
		t.Fatalf("bound: %d, %v", len(hits), err)
	}
	for i, h := range hits {
		src, err := s.Source(ctx, h.ID)
		if err != nil || src.MessageID != fmt.Sprintf("m%02d", 20-i) {
			t.Fatal("unstable search order", i, err)
		}
	}
	c, err := s.GetMessageContextInChat(ctx, "m08", searchChat, 1, 1)
	if err != nil || len(c.Before) != 1 || len(c.After) != 1 || c.Before[0].ID != "m07" || c.After[0].ID != "m09" {
		t.Fatalf("context time tie: %#v, %v", c, err)
	}
	hits, err = s.SearchSources(ctx, " ")
	if err != nil || len(hits) != 0 {
		t.Fatal("blank search returned messages")
	}
}
