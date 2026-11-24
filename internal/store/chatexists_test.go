package store

import (
	"testing"
	"time"
)

func TestChatExistsOnlyForChatsInTheArchive(t *testing.T) {
	s := openTestStore(t)
	const known, unknown = "15550009999@s.whatsapp.net", "15550001234@s.whatsapp.net"
	if err := s.StoreChat(known, "Known", time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ChatExists(known); err != nil || !ok {
		t.Fatalf("ChatExists(known) = %v err=%v", ok, err)
	}
	if ok, err := s.ChatExists(unknown); err != nil || ok {
		t.Fatalf("ChatExists(unknown) = %v err=%v", ok, err)
	}
	if ok, _ := s.ChatExists(""); ok {
		t.Fatal("ChatExists(\"\") = true")
	}
}
