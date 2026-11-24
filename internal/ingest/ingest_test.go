package ingest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- which addresses a link may point at ----------------------------------

func TestOnlyPublicAddressesMayBeFetched(t *testing.T) {
	// A link the model supplies must never make the server talk to itself,
	// its host's network or the cloud metadata service.
	blocked := []string{
		"127.0.0.1", "127.8.9.1", "::1", // loopback
		"10.0.0.5", "172.16.3.4", "172.31.255.255", "192.168.1.1", // private
		"169.254.169.254", "169.254.0.1", "fe80::1", // link-local, cloud metadata
		"100.64.0.1",    // carrier-grade NAT
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "ff02::1", // multicast
		"fc00::1", "fd12:3456::1", // unique local
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4-mapped
		"192.0.2.1", "198.18.0.1", "240.0.0.1", "255.255.255.255", // documentation, benchmarking, reserved, broadcast
	}
	for _, s := range blocked {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s is treated as a public address", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"} {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s is treated as non-public", s)
		}
	}
	if isPublicIP(nil) {
		t.Error("a missing address is treated as public")
	}
}

// fetcherFor returns a fetcher that trusts srv's certificate and, because
// test servers live on loopback, is allowed to dial it.
func fetcherFor(srv *httptest.Server, maxBytes int64) *Fetcher {
	f := NewFetcher(maxBytes)
	f.tlsConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	f.allowIP = func(net.IP) bool { return true }
	return f
}

func TestFetchReturnsTheFileAndAName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		io.WriteString(w, "%PDF-1.4 body")
	}))
	defer srv.Close()
	got, err := fetcherFor(srv, 1<<20).Fetch(context.Background(), srv.URL+"/files/report%20final.pdf?token=abc")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got.Data) != "%PDF-1.4 body" || got.Filename != "report final.pdf" {
		t.Fatalf("got %q named %q", got.Data, got.Filename)
	}
}

func TestFetchRefusesNonHTTPSAndBlockedAddresses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "secret") }))
	defer srv.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "secret") }))
	defer plain.Close()

	// The production rule: the test server is on loopback, so it is refused.
	strict := NewFetcher(1 << 20)
	strict.tlsConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	if _, err := strict.Fetch(context.Background(), srv.URL+"/x"); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("loopback https err = %v, want ErrBlockedAddress", err)
	}
	// With addresses out of the picture (everything allowed), plain http is
	// still refused: the scheme rule stands on its own.
	anyAddress := NewFetcher(1 << 20)
	anyAddress.allowIP = func(net.IP) bool { return true }
	if _, err := anyAddress.Fetch(context.Background(), plain.URL+"/x"); err == nil {
		t.Error("a plain http link was fetched")
	}
	for name, u := range map[string]string{
		"plain http":       plain.URL + "/x",
		"file scheme":      "file:///etc/passwd",
		"no scheme":        "example.com/x",
		"with credentials": "https://user:pass@example.com/x",
		"metadata by IP":   "https://169.254.169.254/latest/meta-data/",
		"empty":            "",
	} {
		if _, err := strict.Fetch(context.Background(), u); err == nil {
			t.Errorf("%s (%s) was fetched", name, u)
		}
	}
}

func TestFetchChecksEveryRedirectHop(t *testing.T) {
	inner := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "internal secret") }))
	defer inner.Close()
	var redirectTo string
	outer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}))
	defer outer.Close()

	f := fetcherFor(outer, 1<<20)
	innerPort := inner.Listener.Addr().(*net.TCPAddr).Port
	// Allow only the first server: the redirect target must be refused.
	f.allowIP = nil
	f.allowPort = outer.Listener.Addr().(*net.TCPAddr).Port
	redirectTo = inner.URL + "/secret"
	if _, err := f.Fetch(context.Background(), outer.URL+"/start"); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to a blocked address (port %d) err = %v, want ErrBlockedAddress", innerPort, err)
	}
	// A redirect that downgrades to plain http is refused too, even when the
	// address itself would be allowed.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "over plain http") }))
	defer plain.Close()
	f = fetcherFor(outer, 1<<20)
	redirectTo = plain.URL + "/x"
	if got, err := f.Fetch(context.Background(), outer.URL+"/start"); err == nil {
		t.Errorf("redirect to plain http was followed: got %q", got.Data)
	}
}

func TestFetchEnforcesTheSizeLimit(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 5000)
	declared := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(big) }))
	defer declared.Close()
	if _, err := fetcherFor(declared, 1000).Fetch(context.Background(), declared.URL+"/big"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized (declared) err = %v, want ErrTooLarge", err)
	}
	// A server that does not say how much it will send is cut off at the limit.
	chunked := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fl := w.(http.Flusher)
		for i := 0; i < 50; i++ {
			w.Write(big[:100])
			fl.Flush()
		}
	}))
	defer chunked.Close()
	if _, err := fetcherFor(chunked, 1000).Fetch(context.Background(), chunked.URL+"/big"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized (streamed) err = %v, want ErrTooLarge", err)
	}
}

func TestFetchRejectsErrorResponsesAndEmptyFiles(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f := fetcherFor(srv, 1<<20)
	if _, err := f.Fetch(context.Background(), srv.URL+"/missing"); err == nil {
		t.Error("a 404 page was accepted as the file")
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"/empty"); err == nil {
		t.Error("an empty response was accepted as the file")
	}
}

// --- transfers held in memory ----------------------------------------------

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTransfers(c *clock) *Transfers {
	tr := NewTransfers("https://wa.example.test", 1000, 2500, 10*time.Minute)
	tr.now = c.now
	return tr
}

func TestUploadSlotIsFilledOnceAndTakenOnce(t *testing.T) {
	tr := newTransfers(&clock{t: time.Now()})
	id, link, err := tr.NewUploadSlot("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "https://wa.example.test/upload/") || !strings.HasSuffix(link, id) || len(id) < 40 {
		t.Fatalf("link %q id %q", link, id)
	}
	if _, err := tr.TakeUpload("", id); !errors.Is(err, ErrNotUploaded) {
		t.Fatalf("taking before upload err = %v, want ErrNotUploaded", err)
	}
	if err := tr.FillUpload(id, Blob{Filename: "a.txt", Data: []byte("hello")}); err != nil {
		t.Fatalf("FillUpload: %v", err)
	}
	if err := tr.FillUpload(id, Blob{Filename: "b.txt", Data: []byte("swap")}); err == nil {
		t.Fatal("a filled slot accepted a second file")
	}
	got, err := tr.TakeUpload("", id)
	if err != nil || got.Filename != "a.txt" || string(got.Data) != "hello" {
		t.Fatalf("TakeUpload = %+v err=%v", got, err)
	}
	if _, err := tr.TakeUpload("", id); !errors.Is(err, ErrNoSuchTransfer) {
		t.Fatalf("second take err = %v, want ErrNoSuchTransfer", err)
	}
}

func TestTransfersExpireAndUnknownIDsFail(t *testing.T) {
	c := &clock{t: time.Now()}
	tr := newTransfers(c)
	up, _, _ := tr.NewUploadSlot("")
	tr.FillUpload(up, Blob{Filename: "a", Data: []byte("x")})
	down, _, _ := tr.OfferDownload("", Blob{Filename: "v.mp4", Data: []byte("video")})
	c.t = c.t.Add(11 * time.Minute)
	if _, err := tr.TakeUpload("", up); !errors.Is(err, ErrNoSuchTransfer) {
		t.Errorf("expired upload err = %v", err)
	}
	if _, ok := tr.TakeDownload(down); ok {
		t.Error("expired download was served")
	}
	if err := tr.FillUpload("made-up-id", Blob{Data: []byte("x")}); !errors.Is(err, ErrNoSuchTransfer) {
		t.Errorf("fill of unknown slot err = %v", err)
	}
	if _, ok := tr.TakeDownload(up); ok {
		t.Error("an upload id was served as a download")
	}
}

func TestDownloadIsServedExactlyOnce(t *testing.T) {
	tr := newTransfers(&clock{t: time.Now()})
	id, link, err := tr.OfferDownload("", Blob{Filename: "clip.mp4", ContentType: "video/mp4", Data: []byte("video")})
	if err != nil || !strings.HasPrefix(link, "https://wa.example.test/media/") {
		t.Fatalf("OfferDownload link %q err=%v", link, err)
	}
	if b, ok := tr.TakeDownload(id); !ok || string(b.Data) != "video" {
		t.Fatalf("first take = %+v ok=%v", b, ok)
	}
	if _, ok := tr.TakeDownload(id); ok {
		t.Fatal("download served twice")
	}
}

func TestTransfersAreBoundedInMemory(t *testing.T) {
	tr := newTransfers(&clock{t: time.Now()})
	if _, _, err := tr.OfferDownload("", Blob{Data: make([]byte, 1001)}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized item err = %v, want ErrTooLarge", err)
	}
	for i := 0; i < 2; i++ {
		if _, _, err := tr.OfferDownload("", Blob{Data: make([]byte, 1000)}); err != nil {
			t.Fatalf("item %d: %v", i, err)
		}
	}
	if _, _, err := tr.OfferDownload("", Blob{Data: make([]byte, 1000)}); !errors.Is(err, ErrBusy) {
		t.Errorf("third item past the total cap err = %v, want ErrBusy", err)
	}
	slot, _, _ := tr.NewUploadSlot("")
	if err := tr.FillUpload(slot, Blob{Data: make([]byte, 1000)}); !errors.Is(err, ErrBusy) {
		t.Errorf("upload past the total cap err = %v, want ErrBusy", err)
	}
	tr.Clear()
	if _, _, err := tr.OfferDownload("", Blob{Data: make([]byte, 1000)}); err != nil {
		t.Errorf("after Clear: %v", err)
	}
}

// --- the upload page and the download link ---------------------------------

func transfersServer(t *testing.T) (*Transfers, *httptest.Server) {
	t.Helper()
	tr := NewTransfers("", 1000, 5000, 10*time.Minute)
	mux := http.NewServeMux()
	tr.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return tr, srv
}

func postFile(t *testing.T, url, filename string, data []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", filename)
	fw.Write(data)
	mw.Close()
	resp, err := http.Post(url, mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestUploadPageAcceptsOneFileForItsSlot(t *testing.T) {
	tr, srv := transfersServer(t)
	id, _, _ := tr.NewUploadSlot("")

	page, err := http.Get(srv.URL + "/upload/" + id)
	if err != nil || page.StatusCode != http.StatusOK {
		t.Fatalf("GET upload page: %v status %d", err, page.StatusCode)
	}
	page.Body.Close()
	if page.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(page.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("upload page headers: XFO=%q CC=%q", page.Header.Get("X-Frame-Options"), page.Header.Get("Cache-Control"))
	}

	if resp := postFile(t, srv.URL+"/upload/"+id, "../../etc/passwd", []byte("contents")); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload: status %d", resp.StatusCode)
	}
	got, err := tr.TakeUpload("", id)
	if err != nil || string(got.Data) != "contents" {
		t.Fatalf("TakeUpload = %+v err=%v", got, err)
	}
	if strings.ContainsAny(got.Filename, `/\`) || strings.Contains(got.Filename, "..") {
		t.Fatalf("uploaded filename kept path parts: %q", got.Filename)
	}
}

func TestUploadPageRejectsUnknownSlotsAndOversizedFiles(t *testing.T) {
	tr, srv := transfersServer(t)
	if resp, _ := http.Get(srv.URL + "/upload/not-a-real-slot"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown slot page: status %d", resp.StatusCode)
	}
	if resp := postFile(t, srv.URL+"/upload/not-a-real-slot", "a.txt", []byte("x")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("upload to unknown slot: status %d", resp.StatusCode)
	}
	id, _, _ := tr.NewUploadSlot("")
	if resp := postFile(t, srv.URL+"/upload/"+id, "big.bin", make([]byte, 2000)); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized upload: status %d, want 413", resp.StatusCode)
	}
	if _, err := tr.TakeUpload("", id); !errors.Is(err, ErrNotUploaded) {
		t.Errorf("an oversized upload filled the slot (err=%v)", err)
	}
}

func TestDownloadLinkForcesASaveAndNeverRendersTheFile(t *testing.T) {
	// The file came from a WhatsApp contact. Served from this server's own
	// address it must never be rendered as a page, or a hostile HTML file
	// could act with the owner's sign-in.
	tr, srv := transfersServer(t)
	id, _, _ := tr.OfferDownload("", Blob{Filename: `evil".html`, ContentType: "text/html", Data: []byte("<script>alert(1)</script>")})

	resp, err := http.Get(srv.URL + "/media/" + id)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: %v status %d", err, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "<script>alert(1)</script>" {
		t.Fatalf("body = %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment") || strings.Contains(cd, `evil".html`) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("missing nosniff/sandbox: %v", resp.Header)
	}
	if again, _ := http.Get(srv.URL + "/media/" + id); again.StatusCode != http.StatusNotFound {
		t.Errorf("second download: status %d, want 404", again.StatusCode)
	}
}

// Link previewers and download managers probe a link with HEAD before
// fetching it. That probe must not use up the one-time download.
func TestAHeadRequestDoesNotUseUpTheDownload(t *testing.T) {
	tr, srv := transfersServer(t)
	id, _, _ := tr.OfferDownload("", Blob{Filename: "clip.mp4", Data: []byte("video")})

	head, err := http.Head(srv.URL + "/media/" + id)
	if err != nil {
		t.Fatal(err)
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK || head.Header.Get("Content-Length") != "5" || !strings.HasPrefix(head.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("HEAD: status %d length %q disposition %q", head.StatusCode, head.Header.Get("Content-Length"), head.Header.Get("Content-Disposition"))
	}
	resp, err := http.Get(srv.URL + "/media/" + id)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "video" {
		t.Fatalf("GET after HEAD: status %d body %q (the probe consumed the download)", resp.StatusCode, body)
	}
	if again, _ := http.Head(srv.URL + "/media/" + id); again.StatusCode != http.StatusNotFound {
		t.Fatalf("HEAD after the download: status %d, want 404", again.StatusCode)
	}
}

func TestIdleTransfersReleaseBytesAtExpiry(t *testing.T) {
	transfers := NewTransfers("https://example.test", 100, 200, 10*time.Millisecond)
	if _, _, err := transfers.OfferDownload("", Blob{Data: []byte("test")}); err != nil {
		t.Fatal(err)
	}
	go transfers.Run(t.Context())
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		transfers.mu.Lock()
		empty := transfers.total == 0 && len(transfers.items) == 0
		transfers.mu.Unlock()
		if empty {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("expired payload retained without traffic")
}
