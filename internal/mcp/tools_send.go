package mcp

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/media"
	"github.com/sealjay/mcp-whatsapp/internal/oauth"
)

// registerSendTools wires outbound-message tools: send_message, send_file,
// send_audio_message, send_reaction, send_reply, send_contact_card,
// send_typing.
func (s *Server) registerSendTools() {
	s.registerSendMessage()
	s.registerSendFile()
	s.registerCreateUploadLink()
	s.registerConfirmSend()
	s.registerSendAudioMessage()
	s.registerSendReaction()
	s.registerSendReply()
	s.registerSendTyping()
}

// -- send_message -----------------------------------------------------------

type sendMessageArgs struct {
	Recipient    string `json:"recipient"`
	Message      string `json:"message"`
	MarkChatRead bool   `json:"mark_chat_read,omitempty"`
}

func (s *Server) registerSendMessage() {
	tool := mcp.NewTool("send_message",
		mcp.WithDescription("Send a new WhatsApp text message to a person or group; recipients see it as a fresh message from the paired account and the row is also stored in the local cache. Reversible via delete_message (revoke) or edit_message (correct text); to quote a previous message use send_reply, for emoji acknowledgement use send_reaction. Returns a JSON object `{Success, Message, ID}` where `ID` is the WhatsApp message ID on success."),
		mcp.WithString("recipient", mcp.Required(), mcp.Description(recipientDesc)),
		mcp.WithString("message", mcp.Required(), mcp.Description("message body text")),
		mcp.WithBoolean("mark_chat_read", mcp.DefaultBool(false), mcp.Description("if true, also ack recent incoming messages in the chat to clear the unread badge (defaults to false)")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, req mcp.CallToolRequest, a sendMessageArgs) (*mcp.CallToolResult, error) {
		if a.Recipient == "" {
			return mcp.NewToolResultError("recipient must be provided"), nil
		}
		r := s.client.Send(ctx, a.Recipient, a.Message)
		s.maybeMarkChatRead(ctx, r, a.Recipient, a.MarkChatRead)
		return resultJSON(r)
	}))
}

// -- send_file --------------------------------------------------------------

type sendFileArgs struct {
	Recipient    string `json:"recipient"`
	URL          string `json:"url,omitempty"`
	UploadID     string `json:"upload_id,omitempty"`
	DataBase64   string `json:"data_base64,omitempty"`
	Filename     string `json:"filename,omitempty"`
	Caption      string `json:"caption,omitempty"`
	MarkChatRead bool   `json:"mark_chat_read,omitempty"`
	ViewOnce     bool   `json:"view_once,omitempty"`
}

// attachmentArgs are the "where is the file" arguments shared by the tools
// that send one. Files never come from a path on the server.
func attachmentArgs() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("url", mcp.Description("public https link to the file; the server downloads it (links to private or local addresses are refused)")),
		mcp.WithString("upload_id", mcp.Description("id from create_upload_link, once the user has uploaded the file on that page; works once")),
		mcp.WithString("data_base64", mcp.Description("the file itself, base64-encoded, for small files (up to 5 MB); requires filename")),
		mcp.WithString("filename", mcp.Description("name for the file, with its extension (for example photo.jpg, report.pdf); required with data_base64, optional otherwise")),
	}
}

func (s *Server) registerSendFile() {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Send a picture, video, document or raw audio attachment via WhatsApp; the recipient sees a media message and the outgoing row is saved to the local archive. Supply the file by exactly one of url, upload_id or data_base64: when the user wants to send a file from their own device, call create_upload_link first. The file is held in memory only. Reversible via delete_message (revoke for everyone). Returns `{success, message, id}`. Use send_audio_message for voice notes."),
		mcp.WithString("recipient", mcp.Required(), mcp.Description(recipientDesc)),
	}
	opts = append(opts, attachmentArgs()...)
	opts = append(opts,
		mcp.WithString("caption", mcp.Description("optional caption for image/video/document submessages; ignored for raw audio")),
		mcp.WithBoolean("mark_chat_read", mcp.DefaultBool(false), mcp.Description("if true, also ack recent incoming messages in the chat to clear the unread badge (defaults to false)")),
		mcp.WithBoolean("view_once", mcp.DefaultBool(false), mcp.Description("if true, mark image/video/audio submessages as view-once; silently ignored for documents (defaults to false)")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	tool := mcp.NewTool("send_file", opts...)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, req mcp.CallToolRequest, a sendFileArgs) (*mcp.CallToolResult, error) {
		if a.Recipient == "" {
			return mcp.NewToolResultError("recipient is required"), nil
		}
		file, err := s.resolveAttachment(ctx, attachmentSource{URL: a.URL, UploadID: a.UploadID, DataBase64: a.DataBase64, Filename: a.Filename})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		r := s.client.SendMediaWithOptions(ctx, client.SendMediaOptions{
			Recipient: a.Recipient,
			Caption:   a.Caption,
			Filename:  file.Filename,
			Data:      file.Data,
			ViewOnce:  a.ViewOnce,
		})
		s.maybeMarkChatRead(ctx, r, a.Recipient, a.MarkChatRead)
		return resultJSON(r)
	}))
}

// -- create_upload_link -----------------------------------------------------

func (s *Server) registerCreateUploadLink() {
	tool := mcp.NewTool("create_upload_link",
		mcp.WithDescription("Create a one-time page where the user can upload a file from their own device, so it can be sent with send_file or send_audio_message. Give the user upload_url to open; after they say the upload is done, pass upload_id to the send tool. The link works once, expires after a few minutes, and the file is held in memory only. Nothing is sent to WhatsApp by this tool. Returns `{upload_url, upload_id, expires_in_seconds, max_bytes}`."),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
	)
	s.mcp.AddTool(tool, func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if s.files == nil || s.files.Transfers == nil {
			return mcp.NewToolResultError("this server has no upload page; send small files with data_base64 or give a public https link"), nil
		}
		id, link, err := s.files.Transfers.NewUploadSlot(oauth.GrantFamily(ctx))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return resultJSON(map[string]any{
			"upload_url":         link,
			"upload_id":          id,
			"expires_in_seconds": int(s.files.Transfers.TTL().Seconds()),
			"max_bytes":          s.files.Transfers.MaxItem(),
		})
	})
}

// -- send_audio_message -----------------------------------------------------

type sendAudioArgs struct {
	Recipient    string `json:"recipient"`
	URL          string `json:"url,omitempty"`
	UploadID     string `json:"upload_id,omitempty"`
	DataBase64   string `json:"data_base64,omitempty"`
	Filename     string `json:"filename,omitempty"`
	MarkChatRead bool   `json:"mark_chat_read,omitempty"`
	ViewOnce     bool   `json:"view_once,omitempty"`
}

func (s *Server) registerSendAudioMessage() {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Send an audio clip as a WhatsApp voice note (waveform UI, push-to-play). Supply the clip by exactly one of url, upload_id or data_base64. Audio that is not already Ogg Opus is converted in memory with ffmpeg; formats that cannot be read as a stream (some .m4a files) fail with an error, in which case use send_file to send the audio as a plain attachment. Reversible via delete_message (revoke for everyone). Returns `{success, message, id}`."),
		mcp.WithString("recipient", mcp.Required(), mcp.Description(recipientDesc)),
	}
	opts = append(opts, attachmentArgs()...)
	opts = append(opts,
		mcp.WithBoolean("mark_chat_read", mcp.DefaultBool(false), mcp.Description("if true, also ack recent incoming messages in the chat to clear the unread badge (defaults to false)")),
		mcp.WithBoolean("view_once", mcp.DefaultBool(false), mcp.Description("if true, mark the voice note as view-once (defaults to false)")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	tool := mcp.NewTool("send_audio_message", opts...)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, req mcp.CallToolRequest, a sendAudioArgs) (*mcp.CallToolResult, error) {
		if a.Recipient == "" {
			return mcp.NewToolResultError("recipient is required"), nil
		}
		// A voice note is named by us; the caller's filename only matters
		// for detecting input that is already Ogg.
		src := attachmentSource{URL: a.URL, UploadID: a.UploadID, DataBase64: a.DataBase64, Filename: a.Filename}
		if src.DataBase64 != "" && strings.TrimSpace(src.Filename) == "" {
			src.Filename = "voice"
		}
		file, err := s.resolveAttachment(ctx, src)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		audio := file.Data
		if !bytes.HasPrefix(audio, []byte("OggS")) {
			converted, err := media.ConvertToOpusOggBytes(ctx, audio)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("audio conversion failed: %v (use send_file to send the audio as a plain attachment)", err)), nil
			}
			audio = converted
		}
		r := s.client.SendMediaWithOptions(ctx, client.SendMediaOptions{
			Recipient: a.Recipient,
			Filename:  "voice.ogg",
			Data:      audio,
			ViewOnce:  a.ViewOnce,
		})
		s.maybeMarkChatRead(ctx, r, a.Recipient, a.MarkChatRead)
		return resultJSON(r)
	}))
}

// -- send_reaction ----------------------------------------------------------

type sendReactionArgs struct {
	ChatJID   string `json:"chat_jid"`
	MessageID string `json:"message_id"`
	SenderJID string `json:"sender_jid,omitempty"`
	Emoji     string `json:"emoji"`
}

func (s *Server) registerSendReaction() {
	tool := mcp.NewTool("send_reaction",
		mcp.WithDescription("Add or replace an emoji reaction on an existing message; recipients see the small emoji badge attached to the original message. Reversible by calling again with an empty `emoji` string (clears the reaction); for a fresh message use send_message and for a quoted reply use send_reply. Returns the plain-text string `Reaction sent` on success."),
		mcp.WithString("chat_jid", mcp.Required(), mcp.Description(jidDesc)),
		mcp.WithString("message_id", mcp.Required(), mcp.Description("WhatsApp message ID of the target message (use `message_id` from list_messages)")),
		mcp.WithString("sender_jid", mcp.Description("JID of the original sender; optional when the message is in the local cache (the sender is then looked up), pass it for a message that is not cached ("+jidDesc+")")),
		mcp.WithString("emoji", mcp.Description("single emoji to react with; pass an empty string to clear an existing reaction")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, req mcp.CallToolRequest, a sendReactionArgs) (*mcp.CallToolResult, error) {
		if err := s.client.SendReaction(ctx, a.ChatJID, a.MessageID, a.SenderJID, a.Emoji); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("Reaction sent"), nil
	}))
}

// -- send_reply -------------------------------------------------------------

type sendReplyArgs struct {
	ChatJID         string `json:"chat_jid"`
	TargetMessageID string `json:"target_message_id"`
	TargetSenderJID string `json:"target_sender_jid,omitempty"`
	Body            string `json:"body"`
}

func (s *Server) registerSendReply() {
	tool := mcp.NewTool("send_reply",
		mcp.WithDescription("Send a text message that visibly quotes a previous message; recipients see the new text with the quoted message attached. Reversible via delete_message (revoke) or edit_message (correct text). Use send_message for a fresh non-quoting message and send_reaction for an emoji acknowledgement. Returns the plain-text string `Reply sent` on success."),
		mcp.WithString("chat_jid", mcp.Required(), mcp.Description(jidDesc)),
		mcp.WithString("target_message_id", mcp.Required(), mcp.Description("WhatsApp message ID of the message being quoted (use `message_id` from list_messages)")),
		mcp.WithString("target_sender_jid", mcp.Description("JID of the quoted message's original sender; required in group chats, omit in 1:1 chats ("+jidDesc+")")),
		mcp.WithString("body", mcp.Required(), mcp.Description("reply text body")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, req mcp.CallToolRequest, a sendReplyArgs) (*mcp.CallToolResult, error) {
		if err := s.client.SendReply(ctx, a.ChatJID, a.TargetMessageID, a.TargetSenderJID, a.Body); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("Reply sent"), nil
	}))
}

// -- send_typing ------------------------------------------------------------

type sendTypingArgs struct {
	ChatJID string `json:"chat_jid"`
	Active  bool   `json:"active"`
	Kind    string `json:"kind,omitempty"`
}

func (s *Server) registerSendTyping() {
	tool := mcp.NewTool("send_typing",
		mcp.WithDescription("Show or hide the per-chat typing or recording presence indicator; the recipient sees a transient `typing...` or `recording audio...` hint that auto-expires after roughly 25 seconds. Reversible by calling again with `active=false`. Use send_presence to set global online/offline availability instead. Returns the plain-text string `Presence active for <chat_jid>` or `Presence paused for <chat_jid>`."),
		mcp.WithString("chat_jid", mcp.Required(), mcp.Description(jidDesc)),
		mcp.WithBoolean("active", mcp.Required(), mcp.Description("true to show the indicator (composing or recording), false to pause it")),
		mcp.WithString("kind", mcp.Enum("", "audio"), mcp.Description("indicator kind: empty string for text typing (default) or `audio` for voice-note recording")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
	s.mcp.AddTool(tool, mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a sendTypingArgs) (*mcp.CallToolResult, error) {
		if err := s.client.SendTyping(ctx, a.ChatJID, a.Active, a.Kind); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		state := "paused"
		if a.Active {
			state = "active"
		}
		return mcp.NewToolResultText(fmt.Sprintf("Presence %s for %s", state, a.ChatJID)), nil
	}))
}
