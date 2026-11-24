package gateway

import (
	"database/sql"
	"errors"
	"html/template"
	"net/http"

	"github.com/sealjay/mcp-whatsapp/internal/oauth"
	"github.com/sealjay/mcp-whatsapp/internal/store"
)

// OwnerPages runs behind the gateway's owner cookie and unlocked session lease.
func OwnerPages(pairing http.Handler, archive *store.Store) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", pairing)
	mux.HandleFunc("GET "+store.SourcePath+"{id}", func(w http.ResponseWriter, r *http.Request) {
		oauth.PageHeaders(w, "")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		src, err := archive.Source(r.Context(), r.PathValue("id"))
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "The archive is temporarily unavailable.", http.StatusServiceUnavailable)
			return
		}
		_ = sourceTemplate.Execute(w, src)
	})
	return mux
}

var sourceTemplate = template.Must(template.New("source").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WhatsApp message</title>` + oauth.PageStyle + `</head><body><main>
<h1>{{.Chat}}</h1>
<p>{{if .FromMe}}You{{else}}{{.Sender}}{{end}} · {{.Timestamp.UTC.Format "2006-01-02 15:04:05 UTC"}}</p>
<p dir="auto" style="white-space:pre-wrap;overflow-wrap:anywhere">{{.Text}}</p>
</main></body></html>`))
