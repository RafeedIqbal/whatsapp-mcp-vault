package mcp

import (
	"encoding/json"
	"slices"
	"sort"
	"testing"
)

func toolNames(s *Server) map[string]bool {
	out := map[string]bool{}
	for name := range s.MCP().ListTools() {
		out[name] = true
	}
	return out
}

// Every tool that can change something is in exactly one of two tiers:
// "send" (messages and their state) or "manage" (groups, blocks, privacy,
// profile). A tool in neither would be unreachable by any sign-in; a tool that
// changes the account but is classified read-only would leak past consent.
func TestEveryMutatingToolBelongsToExactlyOneTier(t *testing.T) {
	all := toolNames(NewServer(nil, nil, true))
	for name := range all {
		if readOnlyToolAccess[name] && manageToolAccess[name] {
			t.Errorf("tool %q is both read-only and manage", name)
		}
	}
	for name := range manageToolAccess {
		if !all[name] {
			t.Errorf("manage tier names unregistered tool %q", name)
		}
	}
}

func TestAccessTiersExposeOnlyWhatWasGranted(t *testing.T) {
	const (
		readTool   = "list_messages"
		sendTool   = "send_message"
		manageTool = "create_group"
	)
	for name, tc := range map[string]struct {
		access                     Access
		wantRead, wantSend, wantMg bool
	}{
		"read only":       {Access{}, true, false, false},
		"read and send":   {Access{Send: true}, true, true, false},
		"read and manage": {Access{Manage: true}, true, false, true},
		"everything":      {Access{Send: true, Manage: true}, true, true, true},
	} {
		got := toolNames(NewServerWithAccess(nil, nil, false, tc.access, "https://wa.example.test"))
		if got[readTool] != tc.wantRead || got[sendTool] != tc.wantSend || got[manageTool] != tc.wantMg {
			t.Errorf("%s: read=%v send=%v manage=%v, want %v %v %v", name,
				got[readTool], got[sendTool], got[manageTool], tc.wantRead, tc.wantSend, tc.wantMg)
		}
	}
}

func TestReadOnlyAccessHasNoToolThatChangesAnything(t *testing.T) {
	for name := range toolNames(NewServerWithAccess(nil, nil, true, Access{}, "https://wa.example.test")) {
		if !readOnlyToolAccess[name] {
			t.Errorf("read-only access exposes %q", name)
		}
	}
}

func TestSendAccessNeverIncludesManageTools(t *testing.T) {
	got := toolNames(NewServerWithAccess(nil, nil, true, Access{Send: true}, "https://wa.example.test"))
	var leaked []string
	for name := range manageToolAccess {
		if got[name] {
			leaked = append(leaked, name)
		}
	}
	sort.Strings(leaked)
	if len(leaked) > 0 {
		t.Fatalf("send access exposes manage tools: %v", leaked)
	}
	// The manage tier is the group, block, privacy and profile tools.
	for _, want := range []string{"create_group", "leave_group", "update_group_participants", "block_contact", "unblock_contact", "set_privacy_setting", "set_status_message", "join_group_with_link"} {
		if !manageToolAccess[want] {
			t.Errorf("%q is not in the manage tier", want)
		}
	}
}

func TestFullAccessMatchesTheUnrestrictedServer(t *testing.T) {
	full := toolNames(NewServerWithAccess(nil, nil, true, Access{Send: true, Manage: true}, "https://wa.example.test"))
	plain := toolNames(NewServer(nil, nil, true))
	for _, name := range []string{"search", "fetch"} {
		if !full[name] || plain[name] {
			t.Fatalf("unexpected research tool availability for %s", name)
		}
		delete(full, name)
	}
	for name := range plain {
		if !full[name] {
			t.Errorf("hosted server missing %s", name)
		}
	}
	if len(full) != len(plain) {
		t.Fatalf("full access has %d tools, unrestricted server has %d", len(full), len(plain))
	}
}

func TestAccessFromScope(t *testing.T) {
	for scope, want := range map[string]Access{
		"":                              {},
		"whatsapp.read":                 {},
		"whatsapp.read whatsapp.send":   {Send: true},
		"whatsapp.manage whatsapp.read": {Manage: true},
		"whatsapp.read whatsapp.send whatsapp.manage": {Send: true, Manage: true},
		"whatsapp.sendx admin":                        {},
	} {
		if got := AccessFromScope(scope); got != want {
			t.Errorf("AccessFromScope(%q) = %+v, want %+v", scope, got, want)
		}
	}
}

func TestResearchToolDiscovery(t *testing.T) {
	s := NewServerWithAccess(nil, nil, false, Access{}, "https://wa.example.test")
	for name, fields := range map[string][]string{"search": {"results"}, "fetch": {"id", "title", "url", "text", "metadata"}} {
		desc := s.MCP().GetTool(name)
		b, err := json.Marshal(desc.Tool)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Meta struct {
				Schemes []struct {
					Type   string
					Scopes []string
				} `json:"securitySchemes"`
			} `json:"_meta"`
			Output struct {
				Properties map[string]json.RawMessage
				Required   []string
			} `json:"outputSchema"`
			Annotations struct {
				ReadOnly bool `json:"readOnlyHint"`
			} `json:"annotations"`
		}
		if err := json.Unmarshal(b, &wire); err != nil {
			t.Fatal(err)
		}
		if !wire.Annotations.ReadOnly || len(wire.Meta.Schemes) != 1 || wire.Meta.Schemes[0].Type != "oauth2" ||
			len(wire.Meta.Schemes[0].Scopes) != 1 || wire.Meta.Schemes[0].Scopes[0] != "whatsapp.read" {
			t.Fatalf("%s discovery: %s", name, b)
		}
		for _, field := range fields {
			if wire.Output.Properties[field] == nil || !slices.Contains(wire.Output.Required, field) {
				t.Errorf("%s output lacks required %s: %s", name, field, b)
			}
		}
	}
}
