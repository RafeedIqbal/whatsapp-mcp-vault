//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/store"
	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

func seedResearchArchive(t *testing.T, dir string) {
	t.Helper()
	ctx := context.Background()
	meta, err := vault.OpenMeta(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	key, _, err := meta.Initialize(ctx, e2ePassphrase)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const chat = "15550001111@s.whatsapp.net"
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if err := st.StoreChat(chat, "Test archive", at); err != nil {
		t.Fatal(err)
	}
	msg := store.Message{ID: "shared-message", ChatJID: chat, Sender: "fixture", Timestamp: at, Content: "workshop <b>notes</b>"}
	if err := st.StoreMessage(ctx, msg, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ApplyRevoke(ctx, chat, msg.ID, store.Author{Senders: []string{msg.Sender}}, at.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("seed revoked message: %v", err)
	}
}

// structuredReply also checks the JSON text fallback consumed by older clients.
func structuredReply(t *testing.T, d *signInDaemon, token, tool string, args map[string]any) map[string]any {
	t.Helper()
	code, out, _ := d.call(token, tool, args)
	result, _ := out["result"].(map[string]any)
	data, ok := result["structuredContent"].(map[string]any)
	blocks, _ := result["content"].([]any)
	var fallback map[string]any
	if code != 200 || result["isError"] == true || !ok || len(blocks) != 1 || json.Unmarshal([]byte(toolText(out)), &fallback) != nil || !reflect.DeepEqual(fallback, data) {
		t.Fatalf("%s returned invalid structured/text reply: %v", tool, out)
	}
	return data
}

func TestTwoAssistantsReadSameSourceAfterRestart(t *testing.T) {
	dir := t.TempDir()
	seedResearchArchive(t, dir)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	d := startSignInDaemonAt(t, "1s", dir, addr)
	chatgpt := d.connect("ChatGPT", "https://chatgpt.com/connector_platform_oauth_redirect", "whatsapp.read")
	claude := d.connect("Claude", "https://claude.ai/api/mcp/auth_callback", "whatsapp.read", "whatsapp.send")

	if d.toolNames(chatgpt.Access)["send_message"] || !d.toolNames(claude.Access)["send_message"] {
		t.Fatal("different grants received the same send permissions")
	}
	first := structuredReply(t, d, chatgpt.Access, "search", map[string]any{"query": "workshop"})
	results, ok := first["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("search results: %v", first)
	}
	hit := results[0].(map[string]any)
	id, _ := hit["id"].(string)
	link, _ := hit["url"].(string)
	title, _ := hit["title"].(string)
	if !store.ValidSourceID(id) || link != d.base+store.SourcePath+id || !strings.Contains(title, "[deleted ") {
		t.Fatalf("invalid citation: %v", hit)
	}
	args := map[string]any{"id": id}
	want := structuredReply(t, d, chatgpt.Access, "fetch", args)
	if want["url"] != link || want["id"] != id || want["title"] != title || want["text"] != "[deleted 2026-11-01 12:01:00 UTC] workshop <b>notes</b>" {
		t.Fatalf("fetch: %v", want)
	}
	metadata := want["metadata"].(map[string]any)
	if metadata["revoked"] != true || metadata["message_id"] != "shared-message" || metadata["revoked_at"] != "2026-11-01T12:01:00Z" {
		t.Fatalf("metadata: %v", metadata)
	}

	// Each client can read concurrently through its own grant.
	t.Run("concurrent reads", func(t *testing.T) {
		for name, token := range map[string]string{"ChatGPT": chatgpt.Access, "Claude": claude.Access} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				client := *d
				client.t = t
				if got := structuredReply(t, &client, token, "fetch", args); !reflect.DeepEqual(got, want) {
					t.Errorf("different document: %v", got)
				}
			})
		}
	})
	req, _ := http.NewRequest("GET", link, nil)
	req.Header.Set("Authorization", "Bearer "+chatgpt.Access)
	resp, page := d.do(req)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/setup?source="+id || strings.Contains(page, "workshop") {
		t.Fatal("citation did not require the owner browser")
	}
	req, _ = http.NewRequest("GET", d.base+resp.Header.Get("Location"), nil)
	resp, page = d.do(req)
	if resp.StatusCode != 200 || !strings.Contains(page, `name="source" value="`+id+`"`) {
		t.Fatal("sign-in dropped the source")
	}
	resp, _ = d.postForm("/setup", url.Values{"action": {"login"}, "passphrase": {e2ePassphrase}, "source": {id}})
	if resp.StatusCode != 303 || resp.Header.Get("Location") != store.SourcePath+id {
		t.Fatal("owner sign-in did not return to the citation")
	}
	req, _ = http.NewRequest("GET", link, nil)
	resp, page = d.do(req)
	if resp.StatusCode != 200 || !strings.Contains(page, "workshop &lt;b&gt;notes&lt;/b&gt;") || !strings.Contains(page, "[deleted ") ||
		resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("owner citation headers %v, page %s", resp.Header, page)
	}
	req, _ = http.NewRequest("GET", d.base+store.SourcePath+strings.Repeat("0", 32), nil)
	if resp, _ := d.do(req); resp.StatusCode != 404 {
		t.Fatalf("unknown source status %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", d.base+"/setup?source=https%3A%2F%2Fother.example", nil)
	if resp, _ := d.do(req); resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
		t.Fatal("invalid source acted as redirect")
	}

	d.waitForLog("instance locked", 1, 15*time.Second)
	if got := structuredReply(t, d, claude.Access, "fetch", args); !reflect.DeepEqual(got, want) {
		t.Fatal("source changed after idle lock")
	}
	d.stop()
	restarted := startSignInDaemonAt(t, "1m", dir, addr)
	for _, token := range []string{chatgpt.Access, claude.Access} {
		if got := structuredReply(t, restarted, token, "search", map[string]any{"query": "workshop"}); !reflect.DeepEqual(got, first) {
			t.Fatal("citations changed on restart")
		}
		if got := structuredReply(t, restarted, token, "fetch", args); !reflect.DeepEqual(got, want) {
			t.Fatal("fetch changed on restart")
		}
	}
}
