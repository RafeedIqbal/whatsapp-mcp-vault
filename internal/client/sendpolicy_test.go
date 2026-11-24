package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"github.com/sealjay/mcp-whatsapp/internal/ratelimit"
)

// sendFixture is a client whose network send is replaced by a counter.
func sendFixture(t *testing.T) (*Client, *int) {
	t.Helper()
	c := newClientWithStore(t, newTestStoreWithLIDMap(t, nil))
	sent := 0
	c.waSend = func(context.Context, types.JID, *waProto.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
		sent++
		return whatsmeow.SendResponse{ID: "SENT"}, nil
	}
	return c, &sent
}

var helloMsg = &waProto.Message{Conversation: proto.String("hello")}

// A hijacked assistant's obvious move is to send your data to a number it was
// given in a message. With the block on, only chats that already exist in the
// archive can be written to.
func TestSendingToAChatWithNoHistoryIsBlocked(t *testing.T) {
	c, sent := sendFixture(t)
	c.blockNewRecipients = true
	stranger := types.NewJID("15550001234", types.DefaultUserServer)

	_, err := c.sendMessage(context.Background(), stranger, helloMsg)
	if err == nil {
		t.Fatal("a message to a never-contacted number was sent")
	}
	if !strings.Contains(err.Error(), "ALLOW_NEW_RECIPIENTS") {
		t.Fatalf("the refusal does not say how to change it: %v", err)
	}
	if *sent != 0 {
		t.Fatal("the message reached the network before the policy check")
	}
}

func TestSendingToAnExistingChatIsAllowed(t *testing.T) {
	c, sent := sendFixture(t)
	c.blockNewRecipients = true
	friend := types.NewJID("15550009999", types.DefaultUserServer)
	if err := c.store.StoreChat(friend.String(), "Friend", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.sendMessage(context.Background(), friend, helloMsg); err != nil {
		t.Fatalf("send to an existing chat: %v", err)
	}
	group := types.NewJID("120363000000000042", types.GroupServer)
	if _, err := c.sendMessage(context.Background(), group, helloMsg); err == nil {
		t.Fatal("a message to a group with no history was sent")
	}
	if *sent != 1 {
		t.Fatalf("sent %d messages, want 1", *sent)
	}
}

func TestNewRecipientsAreAllowedWhenTheBlockIsOff(t *testing.T) {
	c, sent := sendFixture(t)
	stranger := types.NewJID("15550001234", types.DefaultUserServer)
	if _, err := c.sendMessage(context.Background(), stranger, helloMsg); err != nil || *sent != 1 {
		t.Fatalf("err=%v sent=%d", err, *sent)
	}
	if !c.IsNewRecipient(stranger) {
		t.Fatal("IsNewRecipient = false for a chat that is not in the archive")
	}
}

// The limiter's refusal used to tell the caller which HTTP header bypasses
// it. There is no bypass any more, and nothing should suggest one.
func TestRateLimitRefusalOffersNoBypass(t *testing.T) {
	c, _ := sendFixture(t)
	c.limiter = ratelimit.New(ratelimit.DefaultConfig())
	friend := types.NewJID("15550009999", types.DefaultUserServer)
	if _, err := c.sendMessage(context.Background(), friend, helloMsg); err != nil {
		t.Fatalf("first send: %v", err)
	}
	_, err := c.sendMessage(context.Background(), friend, helloMsg)
	if err == nil {
		t.Fatal("second immediate send was not rate limited")
	}
	for _, hint := range []string{"Override", "override", "bypass", "header"} {
		if strings.Contains(err.Error(), hint) {
			t.Fatalf("rate-limit refusal mentions a bypass (%q): %v", hint, err)
		}
	}
}

// --- attachments from memory ----------------------------------------------

func uploadFixture(t *testing.T) (*Client, *[]byte) {
	t.Helper()
	c, _ := sendFixture(t)
	var uploaded []byte
	c.uploadMedia = func(_ context.Context, data []byte, _ whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
		uploaded = data
		return whatsmeow.UploadResponse{URL: "https://mmg.example/x", DirectPath: "/x", MediaKey: []byte{1}, FileEncSHA256: []byte{2}, FileSHA256: []byte{3}, FileLength: uint64(len(data))}, nil
	}
	return c, &uploaded
}

func TestAttachmentIsBuiltFromBytesNotAPath(t *testing.T) {
	c, uploaded := uploadFixture(t)
	msg := &waProto.Message{}
	payload := []byte("\x89PNG fake image bytes")
	if err := c.attachMedia(context.Background(), msg, attachment{name: "holiday.png", data: payload}, "look at this", false); err != nil {
		t.Fatalf("attachMedia: %v", err)
	}
	if string(*uploaded) != string(payload) {
		t.Fatal("the bytes given were not the bytes uploaded")
	}
	if msg.ImageMessage == nil || msg.ImageMessage.GetCaption() != "look at this" || msg.ImageMessage.GetMimetype() != "image/png" {
		t.Fatalf("image message = %+v", msg.ImageMessage)
	}
}

func TestDocumentKeepsASanitisedNameOnly(t *testing.T) {
	c, _ := uploadFixture(t)
	msg := &waProto.Message{}
	if err := c.attachMedia(context.Background(), msg, attachment{name: "../../etc/Q3 report.pdf", data: []byte("%PDF")}, "", false); err != nil {
		t.Fatal(err)
	}
	doc := msg.DocumentMessage
	if doc == nil {
		t.Fatal("no document message built")
	}
	if strings.ContainsAny(doc.GetFileName(), `/\`) || !strings.HasSuffix(doc.GetFileName(), "Q3 report.pdf") {
		t.Fatalf("document file name = %q", doc.GetFileName())
	}
}

func TestEmptyAttachmentIsRefused(t *testing.T) {
	c, uploaded := uploadFixture(t)
	if err := c.attachMedia(context.Background(), &waProto.Message{}, attachment{name: "a.png"}, "", false); err == nil {
		t.Fatal("an empty attachment was accepted")
	}
	if *uploaded != nil {
		t.Fatal("an empty attachment was uploaded")
	}
}

// A message to status@broadcast is delivered to everyone who can see the
// account's status. Receiving a status creates a chat row for that address,
// so "the chat exists" must not be enough to make it a send target.
func TestBroadcastAndChannelAddressesAreNeverSendTargets(t *testing.T) {
	for _, block := range []bool{true, false} {
		c, sent := sendFixture(t)
		c.blockNewRecipients = block
		targets := []types.JID{
			types.StatusBroadcastJID,
			types.NewJID("1234567890", types.BroadcastServer),
			types.NewJID("120363000000000001", types.NewsletterServer),
		}
		for _, jid := range targets {
			if err := c.store.StoreChat(jid.String(), "seen before", time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := c.sendMessage(context.Background(), jid, helloMsg); err == nil {
				t.Errorf("block=%v: a message to %s was sent", block, jid)
			}
		}
		if *sent != 0 {
			t.Fatalf("block=%v: %d messages reached the network", block, *sent)
		}
	}
}

// WhatsApp addresses the same person by phone number or by a hidden ID. A
// chat stored under one form must be recognised when addressed by the other.
func TestAChatIsRecognisedUnderEitherIDForm(t *testing.T) {
	const lidUser, phone = "99887766", "15550009999"
	lid := types.NewJID(lidUser, types.HiddenUserServer)
	pn := types.NewJID(phone, types.DefaultUserServer)

	storedAsHiddenID := newClientWithStore(t, newTestStoreWithLIDMap(t, map[string]string{lidUser: phone}))
	if err := storedAsHiddenID.store.StoreChat(lid.String(), "Friend", time.Now()); err != nil {
		t.Fatal(err)
	}
	if storedAsHiddenID.IsNewRecipient(pn) {
		t.Error("a chat stored under the hidden ID is treated as new when addressed by phone number")
	}
	if storedAsHiddenID.IsNewRecipient(lid) {
		t.Error("a chat stored under the hidden ID is treated as new when addressed by that ID")
	}

	storedAsPhone := newClientWithStore(t, newTestStoreWithLIDMap(t, map[string]string{lidUser: phone}))
	if err := storedAsPhone.store.StoreChat(pn.String(), "Friend", time.Now()); err != nil {
		t.Fatal(err)
	}
	if storedAsPhone.IsNewRecipient(lid) {
		t.Error("a chat stored under the phone number is treated as new when addressed by the hidden ID")
	}
	stranger := types.NewJID("15550001234", types.DefaultUserServer)
	if !storedAsPhone.IsNewRecipient(stranger) {
		t.Error("an unrelated number is treated as an existing chat")
	}
}
