package ingest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNoSuchTransfer: the id is unknown, already used, or expired.
	ErrNoSuchTransfer = errors.New("ingest: no such upload or download (it may have expired or been used)")
	// ErrNotUploaded: the upload link exists but no file has been sent to it yet.
	ErrNotUploaded = errors.New("ingest: nothing has been uploaded to that link yet")
	// ErrBusy: too much is being held in memory already.
	ErrBusy = errors.New("ingest: too many files are waiting; try again in a few minutes")
)

// maxOpenUploads bounds upload links that have been created but not used.
const maxOpenUploads = 32

// Transfers holds files in memory on their way in (an upload waiting to be
// sent) or out (media waiting to be downloaded). Each is addressed by an
// unguessable one-time id, works once, expires after a few minutes, and the
// total held is capped. Nothing is ever written to disk.
type Transfers struct {
	baseURL  string
	maxItem  int64
	maxTotal int64
	ttl      time.Duration
	now      func() time.Time

	mu    sync.Mutex
	items map[string]*transfer
	total int64
}

type transfer struct {
	upload  bool
	filled  bool
	blob    Blob
	expires time.Time
}

// NewTransfers returns an empty store. baseURL is the public address of the
// instance (links are built from it); maxItem and maxTotal bound one file and
// everything held at once.
func NewTransfers(baseURL string, maxItem, maxTotal int64, ttl time.Duration) *Transfers {
	return &Transfers{
		baseURL: strings.TrimRight(baseURL, "/"), maxItem: maxItem, maxTotal: maxTotal, ttl: ttl,
		now: time.Now, items: map[string]*transfer{},
	}
}

// MaxItem is the largest file a transfer can hold.
func (t *Transfers) MaxItem() int64 { return t.maxItem }

// TTL is how long a link stays valid.
func (t *Transfers) TTL() time.Duration { return t.ttl }

func newID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("ingest: could not read random bytes")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// expireLocked drops everything past its time. mu must be held.
func (t *Transfers) expireLocked() {
	now := t.now()
	for id, it := range t.items {
		if !now.Before(it.expires) {
			t.total -= int64(len(it.blob.Data))
			delete(t.items, id)
		}
	}
}

// Run drops expired payloads even when nobody visits the instance.
func (t *Transfers) Run(ctx context.Context) {
	ticker := time.NewTicker(min(t.ttl, time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.mu.Lock()
			t.expireLocked()
			t.mu.Unlock()
		}
	}
}

// NewUploadSlot creates an empty upload and returns its id and the page
// address the person opens to choose a file.
func (t *Transfers) NewUploadSlot() (id, link string, err error) {
	id, err = newID()
	if err != nil {
		return "", "", err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	open := 0
	for _, it := range t.items {
		if it.upload && !it.filled {
			open++
		}
	}
	if open >= maxOpenUploads {
		return "", "", ErrBusy
	}
	t.items[id] = &transfer{upload: true, expires: t.now().Add(t.ttl)}
	return id, t.baseURL + "/upload/" + id, nil
}

// FillUpload stores the file sent to an upload link. A link takes one file.
func (t *Transfers) FillUpload(id string, b Blob) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	it, ok := t.items[id]
	if !ok || !it.upload {
		return ErrNoSuchTransfer
	}
	if it.filled {
		return errors.New("ingest: a file was already uploaded to that link")
	}
	if int64(len(b.Data)) > t.maxItem {
		return ErrTooLarge
	}
	if t.total+int64(len(b.Data)) > t.maxTotal {
		return ErrBusy
	}
	b.Filename = SafeName(b.Filename)
	it.blob, it.filled = b, true
	t.total += int64(len(b.Data))
	return nil
}

// uploadOpen reports whether id is an upload link still waiting for its file.
func (t *Transfers) uploadOpen(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	it, ok := t.items[id]
	return ok && it.upload && !it.filled
}

// TakeUpload returns the uploaded file and forgets it.
func (t *Transfers) TakeUpload(id string) (Blob, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	it, ok := t.items[id]
	if !ok || !it.upload {
		return Blob{}, ErrNoSuchTransfer
	}
	if !it.filled {
		return Blob{}, ErrNotUploaded
	}
	t.total -= int64(len(it.blob.Data))
	delete(t.items, id)
	return it.blob, nil
}

// OfferDownload holds a file for one download and returns its id and link.
func (t *Transfers) OfferDownload(b Blob) (id, link string, err error) {
	if int64(len(b.Data)) > t.maxItem {
		return "", "", ErrTooLarge
	}
	id, err = newID()
	if err != nil {
		return "", "", err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	if t.total+int64(len(b.Data)) > t.maxTotal {
		return "", "", ErrBusy
	}
	b.Filename = SafeName(b.Filename)
	t.items[id] = &transfer{blob: b, filled: true, expires: t.now().Add(t.ttl)}
	t.total += int64(len(b.Data))
	return id, t.baseURL + "/media/" + id, nil
}

// TakeDownload returns the file for a download link and forgets it.
func (t *Transfers) TakeDownload(id string) (Blob, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	it, ok := t.items[id]
	if !ok || it.upload {
		return Blob{}, false
	}
	t.total -= int64(len(it.blob.Data))
	delete(t.items, id)
	return it.blob, true
}

// peekDownload describes a waiting download without using it up.
func (t *Transfers) peekDownload(id string) (name string, size int, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked()
	it, found := t.items[id]
	if !found || it.upload {
		return "", 0, false
	}
	return it.blob.Filename, len(it.blob.Data), true
}

// Clear forgets everything. Called when the instance locks.
func (t *Transfers) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items = map[string]*transfer{}
	t.total = 0
}

// Mount serves the upload page and the download link on mux. Neither needs a
// sign-in: the unguessable one-time id in the address is the permission.
func (t *Transfers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /upload/{id}", t.handleUploadPage)
	mux.HandleFunc("POST /upload/{id}", t.handleUpload)
	mux.HandleFunc("GET /media/{id}", t.handleDownload)
}

func pageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

func (t *Transfers) renderUpload(w http.ResponseWriter, status int, v uploadView) {
	pageHeaders(w)
	w.WriteHeader(status)
	_ = uploadTemplate.Execute(w, v)
}

func (t *Transfers) handleUploadPage(w http.ResponseWriter, r *http.Request) {
	if !t.uploadOpen(r.PathValue("id")) {
		t.renderUpload(w, http.StatusNotFound, uploadView{Gone: true})
		return
	}
	t.renderUpload(w, http.StatusOK, uploadView{MaxMB: t.maxItem >> 20})
}

func (t *Transfers) handleUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !t.uploadOpen(id) {
		t.renderUpload(w, http.StatusNotFound, uploadView{Gone: true})
		return
	}
	// Read the file part straight into memory. ParseMultipartForm is avoided
	// on purpose: it spills large parts into temporary files on disk.
	r.Body = http.MaxBytesReader(w, r.Body, t.maxItem+(64<<10))
	mr, err := r.MultipartReader()
	if err != nil {
		t.renderUpload(w, http.StatusBadRequest, uploadView{MaxMB: t.maxItem >> 20, Error: "No file was received."})
		return
	}
	for {
		part, err := mr.NextPart()
		if err != nil {
			t.renderUpload(w, http.StatusBadRequest, uploadView{MaxMB: t.maxItem >> 20, Error: "No file was received."})
			return
		}
		if part.FormName() != "file" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(part, t.maxItem+1))
		if err != nil || int64(len(data)) > t.maxItem {
			t.renderUpload(w, http.StatusRequestEntityTooLarge, uploadView{MaxMB: t.maxItem >> 20, Error: "That file is too large."})
			return
		}
		if len(data) == 0 {
			t.renderUpload(w, http.StatusBadRequest, uploadView{MaxMB: t.maxItem >> 20, Error: "That file is empty."})
			return
		}
		err = t.FillUpload(id, Blob{Filename: part.FileName(), ContentType: part.Header.Get("Content-Type"), Data: data})
		switch {
		case err == nil:
			t.renderUpload(w, http.StatusOK, uploadView{Done: true})
		case errors.Is(err, ErrBusy):
			t.renderUpload(w, http.StatusServiceUnavailable, uploadView{MaxMB: t.maxItem >> 20, Error: "The server is holding too many files right now. Try again in a few minutes."})
		case errors.Is(err, ErrTooLarge):
			t.renderUpload(w, http.StatusRequestEntityTooLarge, uploadView{MaxMB: t.maxItem >> 20, Error: "That file is too large."})
		default:
			t.renderUpload(w, http.StatusNotFound, uploadView{Gone: true})
		}
		return
	}
}

func (t *Transfers) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Link previewers and download managers probe with HEAD first. Answer
	// that without spending the one-time download.
	if r.Method == http.MethodHead {
		name, size, ok := t.peekDownload(id)
		if !ok {
			http.Error(w, "This download link has expired or was already used.", http.StatusNotFound)
			return
		}
		downloadHeaders(w, name)
		w.Header().Set("Content-Length", strconv.Itoa(size))
		return
	}
	b, ok := t.TakeDownload(id)
	if !ok {
		http.Error(w, "This download link has expired or was already used.", http.StatusNotFound)
		return
	}
	downloadHeaders(w, b.Filename)
	_, _ = w.Write(b.Data)
}

// downloadHeaders marks a response as a file to save. The file came from a
// WhatsApp contact and is served from this server's own address, so it is
// always a download, never something the browser renders: fixed generic type,
// no sniffing, and a sandbox as a backstop.
func downloadHeaders(w http.ResponseWriter, filename string) {
	name := SafeName(filename)
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+ascii+`"; filename*=UTF-8''`+url.PathEscape(name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

type uploadView struct {
	MaxMB int64
	Error string
	Done  bool
	Gone  bool
}

var uploadTemplate = template.Must(template.New("upload").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attach a file</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a;background:#fafafa}
h1{font-size:1.3rem;margin:0 0 .5rem}
.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:1.25rem}
p{color:#444}
input[type=file]{display:block;margin:1rem 0;font-size:1rem}
button{font-size:1rem;padding:.6rem 1.1rem;border-radius:6px;border:1px solid #0b6e4f;background:#0b6e4f;color:#fff;cursor:pointer}
.error{background:#fdecea;border:1px solid #f5c2c0;border-radius:6px;padding:.6rem;color:#1a1a1a}
@media (prefers-color-scheme:dark){body{background:#151515;color:#eee}.card{background:#1f1f1f;border-color:#3a3a3a}p{color:#bbb}.error{background:#4a1f1d;border-color:#7a302d;color:#eee}}
</style></head><body><div class="card">
{{if .Done}}<h1>File received</h1><p>You can close this page and go back to your chat. The file is held for a few minutes and is used once.</p>
{{else if .Gone}}<h1>This link is no longer valid</h1><p>Upload links work once and expire after a few minutes. Ask for a new one in your chat.</p>
{{else}}<h1>Attach a file</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<p>Choose the file to send through WhatsApp (up to {{.MaxMB}} MB). It is held in memory only, used once, and never saved on the server.</p>
<form method="post" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit">Upload</button>
</form>{{end}}
</div></body></html>`))
