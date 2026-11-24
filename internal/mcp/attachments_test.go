package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/ingest"
)

func testFiles(fetch func(context.Context, string) (ingest.Blob, error)) *Files {
	return &Files{Fetch: fetch, Transfers: ingest.NewTransfers("https://wa.example.test", 1<<20, 4<<20, 10*time.Minute)}
}

func serverWithFiles(access Access, f *Files) *Server {
	s := NewServerWithAccess(nil, nil, false, access, "https://wa.example.test")
	s.SetFiles(f)
	return s
}

// --- where an attachment comes from ---------------------------------------

func TestAttachmentNeedsExactlyOneSource(t *testing.T) {
	s := serverWithFiles(Access{Send: true}, testFiles(nil))
	b64 := base64.StdEncoding.EncodeToString([]byte("data"))
	for name, src := range map[string]attachmentSource{
		"none":            {},
		"url and upload":  {URL: "https://example.com/a.png", UploadID: "abc"},
		"url and inline":  {URL: "https://example.com/a.png", DataBase64: b64, Filename: "a.png"},
		"all three":       {URL: "https://example.com/a.png", UploadID: "abc", DataBase64: b64},
		"only a filename": {Filename: "a.png"},
	} {
		if _, err := s.resolveAttachment(context.Background(), src); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInlineAttachmentIsDecodedAndNeedsAName(t *testing.T) {
	s := serverWithFiles(Access{Send: true}, testFiles(nil))
	payload := []byte("\x89PNG\r\n\x1a\n image bytes")
	for name, enc := range map[string]string{
		"standard":        base64.StdEncoding.EncodeToString(payload),
		"url-safe":        base64.RawURLEncoding.EncodeToString(payload),
		"with line wraps": strings.Join(strings.SplitAfterN(base64.StdEncoding.EncodeToString(payload), "", 9), "\n"),
		"data URL":        "data:image/png;base64," + base64.StdEncoding.EncodeToString(payload),
	} {
		got, err := s.resolveAttachment(context.Background(), attachmentSource{DataBase64: enc, Filename: "pic.png"})
		if err != nil || string(got.Data) != string(payload) || got.Filename != "pic.png" {
			t.Errorf("%s: got %q named %q err=%v", name, got.Data, got.Filename, err)
		}
	}
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{DataBase64: base64.StdEncoding.EncodeToString(payload)}); err == nil {
		t.Error("inline data without a filename was accepted")
	}
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{DataBase64: "!!! not base64 !!!", Filename: "a.png"}); err == nil {
		t.Error("invalid base64 was accepted")
	}
	huge := base64.StdEncoding.EncodeToString(make([]byte, maxInlineAttachmentBytes+1))
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{DataBase64: huge, Filename: "a.bin"}); err == nil {
		t.Error("inline data over the limit was accepted")
	}
}

func TestLinkedAttachmentIsFetchedThroughTheSafeFetcher(t *testing.T) {
	var asked string
	s := serverWithFiles(Access{Send: true}, testFiles(func(_ context.Context, u string) (ingest.Blob, error) {
		asked = u
		return ingest.Blob{Filename: "from-link.pdf", Data: []byte("%PDF")}, nil
	}))
	got, err := s.resolveAttachment(context.Background(), attachmentSource{URL: "https://example.com/docs/from-link.pdf"})
	if err != nil || asked != "https://example.com/docs/from-link.pdf" || got.Filename != "from-link.pdf" || string(got.Data) != "%PDF" {
		t.Fatalf("got %+v asked %q err=%v", got, asked, err)
	}
	// A caller-chosen name replaces the one from the link, but never as a path.
	got, _ = s.resolveAttachment(context.Background(), attachmentSource{URL: "https://example.com/x", Filename: "../../Quarterly report.pdf"})
	if got.Filename != "Quarterly report.pdf" {
		t.Fatalf("filename override = %q", got.Filename)
	}
	// A refused link is reported, not retried some other way.
	s = serverWithFiles(Access{Send: true}, testFiles(func(context.Context, string) (ingest.Blob, error) {
		return ingest.Blob{}, ingest.ErrBlockedAddress
	}))
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{URL: "https://169.254.169.254/x"}); !errors.Is(err, ingest.ErrBlockedAddress) {
		t.Fatalf("blocked link err = %v", err)
	}
}

func TestUploadedAttachmentIsTakenOnce(t *testing.T) {
	f := testFiles(nil)
	s := serverWithFiles(Access{Send: true}, f)
	id, _, _ := f.Transfers.NewUploadSlot("")
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{UploadID: id}); !errors.Is(err, ingest.ErrNotUploaded) {
		t.Fatalf("before the upload err = %v, want ErrNotUploaded", err)
	}
	f.Transfers.FillUpload(id, ingest.Blob{Filename: "voice memo.m4a", Data: []byte("audio")})
	got, err := s.resolveAttachment(context.Background(), attachmentSource{UploadID: id})
	if err != nil || got.Filename != "voice memo.m4a" || string(got.Data) != "audio" {
		t.Fatalf("got %+v err=%v", got, err)
	}
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{UploadID: id}); err == nil {
		t.Fatal("the same upload was used twice")
	}
}

func TestLinksAndUploadsNeedTheFileServiceButInlineDoesNot(t *testing.T) {
	s := NewServerWithAccess(nil, nil, false, Access{Send: true}, "https://wa.example.test") // no SetFiles
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{URL: "https://example.com/a.png"}); err == nil {
		t.Error("a link was accepted with no fetcher configured")
	}
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{UploadID: "abc"}); err == nil {
		t.Error("an upload id was accepted with no upload store configured")
	}
	if _, err := s.resolveAttachment(context.Background(), attachmentSource{DataBase64: "aGk=", Filename: "a.txt"}); err != nil {
		t.Errorf("inline data refused without the file service: %v", err)
	}
}

// --- tool surface ----------------------------------------------------------

func toolSchemaProps(t *testing.T, s *Server, name string) map[string]any {
	t.Helper()
	tool := s.MCP().ListTools()[name]
	if tool == nil {
		t.Fatalf("tool %q is not registered", name)
	}
	raw, _ := json.Marshal(tool.Tool.InputSchema)
	var schema struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	return schema.Properties
}

func TestFileToolsTakeLinksUploadsOrDataAndNeverAServerPath(t *testing.T) {
	s := serverWithFiles(Access{Send: true}, testFiles(nil))
	for _, name := range []string{"send_file", "send_audio_message"} {
		props := toolSchemaProps(t, s, name)
		for _, want := range []string{"recipient", "url", "upload_id", "data_base64", "filename"} {
			if _, ok := props[want]; !ok {
				t.Errorf("%s has no %q argument", name, want)
			}
		}
		for _, gone := range []string{"media_path", "path", "output_path"} {
			if _, ok := props[gone]; ok {
				t.Errorf("%s still takes a server path (%q)", name, gone)
			}
		}
	}
}

func callTool(t *testing.T, s *Server, name string, args map[string]any) (text string, isError bool) {
	t.Helper()
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	raw, _ := json.Marshal(s.MCP().HandleMessage(context.Background(), req))
	var env struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("bad reply: %s", raw)
	}
	if env.Error != nil {
		return env.Error.Message, true
	}
	if len(env.Result.Content) == 0 {
		return "", env.Result.IsError
	}
	return env.Result.Content[0].Text, env.Result.IsError
}

func TestCreateUploadLinkReturnsAOneTimePage(t *testing.T) {
	f := testFiles(nil)
	s := serverWithFiles(Access{Send: true}, f)
	text, isErr := callTool(t, s, "create_upload_link", nil)
	if isErr {
		t.Fatalf("create_upload_link failed: %s", text)
	}
	var out struct {
		UploadURL string `json:"upload_url"`
		UploadID  string `json:"upload_id"`
		ExpiresIn int    `json:"expires_in_seconds"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("not JSON: %s", text)
	}
	if !strings.HasPrefix(out.UploadURL, "https://wa.example.test/upload/") || out.UploadID == "" || out.ExpiresIn != 600 {
		t.Fatalf("result = %+v", out)
	}
	// The id it returned is a live upload slot.
	if err := f.Transfers.FillUpload(out.UploadID, ingest.Blob{Filename: "a.txt", Data: []byte("x")}); err != nil {
		t.Fatalf("returned upload_id is not a usable slot: %v", err)
	}
}

func TestCreateUploadLinkIsASendTierTool(t *testing.T) {
	if toolNames(serverWithFiles(Access{}, testFiles(nil)))["create_upload_link"] {
		t.Error("a read-only sign-in can create upload links")
	}
	if !toolNames(serverWithFiles(Access{Send: true}, testFiles(nil)))["create_upload_link"] {
		t.Error("a sign-in with sending cannot create upload links")
	}
	// Without the file service the tool says so instead of pretending.
	if text, isErr := callTool(t, NewServerWithAccess(nil, nil, false, Access{Send: true}, "https://wa.example.test"), "create_upload_link", nil); !isErr {
		t.Errorf("create_upload_link succeeded with no upload store: %s", text)
	}
}

func TestConfirmationFreezesLinkedAttachment(t *testing.T) {
	payload := "original"
	fetches := 0
	s := serverWithFiles(Access{Send: true}, testFiles(func(context.Context, string) (ingest.Blob, error) {
		fetches++
		return ingest.Blob{Filename: "note.txt", Data: []byte(payload)}, nil
	}))
	s.SetSendConfirmation(ConfirmAlways)
	var sent string
	s.mcp.AddTool(mcp.NewTool("send_file"), func(ctx context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		blob, err := s.resolveAttachment(ctx, attachmentSource{UploadID: r.GetString("upload_id", ""), URL: r.GetString("url", "")})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		sent = string(blob.Data)
		return mcp.NewToolResultText("sent"), nil
	})
	preview, failed := callTool(t, s, "send_file", map[string]any{"recipient": "15550009999", "url": "https://example.test/changeable", "caption": "review this"})
	if failed || strings.Contains(preview, "changeable") || !strings.Contains(preview, "note.txt") || !strings.Contains(preview, "review this") {
		t.Fatalf("unexpected draft: %s", preview)
	}
	payload = "replacement"
	if _, failed := callTool(t, s, "confirm_send", map[string]any{"draft_id": draftID(t, preview)}); failed || sent != "original" || fetches != 1 {
		t.Fatalf("confirmed attachment %q, fetches %d, failed %v", sent, fetches, failed)
	}
}

// --- large media out -------------------------------------------------------

func TestLargeMediaComesBackAsAOneTimeDownloadLink(t *testing.T) {
	f := &Files{Transfers: ingest.NewTransfers("https://wa.example.test", 64<<20, 128<<20, 10*time.Minute)}
	big := make([]byte, inlineMediaMaxBytes+1)
	copy(big, "big video bytes")
	res, err := downloadMediaResult("", client.DownloadResult{Success: true, Message: "ok", MediaType: "video", Filename: "clip.mp4", Size: len(big), Data: big}, testMediaURI, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("expected the summary only, got %d blocks", len(res.Content))
	}
	sum := summary(t, res)
	link, _ := sum["download_url"].(string)
	if !strings.HasPrefix(link, "https://wa.example.test/media/") || sum["download_expires_in_seconds"] != float64(600) {
		t.Fatalf("summary = %v", sum)
	}
	id := strings.TrimPrefix(link, "https://wa.example.test/media/")
	got, ok := f.Transfers.TakeDownload(id)
	if !ok || len(got.Data) != len(big) || got.Filename != "clip.mp4" {
		t.Fatalf("the link does not serve the media: ok=%v len=%d name=%q", ok, len(got.Data), got.Filename)
	}
}

func TestLargeMediaWithoutTheFileServiceSaysWhy(t *testing.T) {
	big := make([]byte, inlineMediaMaxBytes+1)
	res, _ := downloadMediaResult("", client.DownloadResult{Success: true, MediaType: "video", Filename: "clip.mp4", Size: len(big), Data: big}, testMediaURI, nil)
	sum := summary(t, res)
	if _, has := sum["download_url"]; has || !strings.Contains(sum["note"].(string), "too large") {
		t.Fatalf("summary = %v", sum)
	}
}

var _ = mcp.NewTextContent // keep the import used if helpers change

// The tool endpoint answers requests; it must not also keep a long-lived
// listening stream open. An open stream would count as the instance being in
// use and stop it from ever locking when idle.
func TestToolEndpointOffersNoLongLivedStream(t *testing.T) {
	mux := http.NewServeMux()
	NewServerWithAccess(nil, nil, false, Access{}, "https://wa.example.test").AttachHTTP(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET /mcp did not answer promptly (a stream was held open?): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mcp = %d, want 405", resp.StatusCode)
	}
}
