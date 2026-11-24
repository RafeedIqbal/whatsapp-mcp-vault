package mcp

import "strings"

// Every tool is explicitly reviewed; unknown tools fail closed in read-only mode.
var readOnlyToolAccess = map[string]bool{
	"block_contact":             false,
	"create_group":              false,
	"delete_message":            false,
	"download_media":            true,
	"edit_message":              false,
	"get_blocklist":             true,
	"get_chat":                  true,
	"get_chat_labels":           true,
	"get_group_info":            true,
	"get_group_invite_link":     false,
	"get_message_context":       true,
	"get_poll_results":          true,
	"get_privacy_settings":      true,
	"get_status":                true,
	"is_on_whatsapp":            true,
	"join_group_with_link":      false,
	"leave_group":               false,
	"list_chats":                true,
	"list_chats_by_label":       true,
	"list_labels":               true,
	"list_groups":               true,
	"list_messages":             true,
	"mark_chat_read":            false,
	"mark_read":                 false,
	"pairing_status":            true,
	"request_sync":              true,
	"resync_labels":             true,
	"search_contacts":           true,
	"send_audio_message":        false,
	"send_contact_card":         false,
	"send_file":                 false,
	"send_message":              false,
	"send_poll":                 false,
	"send_poll_vote":            false,
	"send_presence":             false,
	"send_reaction":             false,
	"send_reply":                false,
	"send_typing":               false,
	"set_group_announce":        false,
	"set_group_locked":          false,
	"set_group_name":            false,
	"set_group_topic":           false,
	"set_privacy_setting":       false,
	"set_status_message":        false,
	"transcribe_audio":          false,
	"unblock_contact":           false,
	"update_group_participants": false,
}

// manageToolAccess is the "manage" tier: tools that change groups, blocks,
// privacy settings or the profile. Every other tool that is not read-only is
// in the "send" tier (messages and their state).
var manageToolAccess = map[string]bool{
	"block_contact":             true,
	"create_group":              true,
	"get_group_invite_link":     true,
	"join_group_with_link":      true,
	"leave_group":               true,
	"set_group_announce":        true,
	"set_group_locked":          true,
	"set_group_name":            true,
	"set_group_topic":           true,
	"set_privacy_setting":       true,
	"set_status_message":        true,
	"unblock_contact":           true,
	"update_group_participants": true,
}

// Access is what a signed-in client was granted beyond reading.
type Access struct {
	Send   bool // send, reply, react, edit, delete, mark read
	Manage bool // groups, blocks, privacy, profile
}

// AccessFromScope maps an OAuth scope string to tool access.
func AccessFromScope(scope string) Access {
	var a Access
	for _, sc := range strings.Fields(scope) {
		switch sc {
		case "whatsapp.send":
			a.Send = true
		case "whatsapp.manage":
			a.Manage = true
		}
	}
	return a
}

// allows reports whether a tool is available at this access level. Unknown
// tools are treated as send-tier, so a new tool is never exposed to a
// read-only sign-in by accident.
func (a Access) allows(tool string) bool {
	switch {
	case readOnlyToolAccess[tool]:
		return true
	case manageToolAccess[tool]:
		return a.Manage
	default:
		return a.Send
	}
}

// registerTools wires every MCP tool to the bound WhatsApp client.
//
// Tool registrations are split by domain:
//   - tools_query.go   — read-only data retrieval (list_chats, search_contacts, …)
//   - tools_send.go    — outbound messages (send_message, send_file, send_reaction, …)
//   - tools_message.go — message mutation & history (edit, delete, mark_read, sync, …)
//   - tools_groups.go  — group management (create, leave, participants, settings, …)
//   - tools_media.go   — polls + contact cards
//   - tools_privacy.go — blocklist, presence, privacy settings, status message
//
// Shared helpers live in tools_core.go (parseTimestamp, normalizeRecipientToChatJID,
// maybeMarkChatRead). Common result helpers live in result.go.
func (s *Server) registerTools() {
	s.registerQueryTools()
	s.registerSendTools()
	s.registerMessageTools()

	// Phase 1 — group management + blocklist.
	s.registerGroupTools()
	s.registerPrivacyTools()

	// Phase 2 — polls + contact cards.
	s.registerMediaTools()

	if s.labelsEnabled {
		s.registerLabelTools()
	}
	// Speech-to-text for voice notes (opt-in; needs WHATSAPP_MCP_TRANSCRIBE_URL).
	s.registerTranscribeTools()
}
