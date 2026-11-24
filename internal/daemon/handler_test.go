package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Handler exposes the pairing pages, probes and the mounted MCP endpoint
// without binding a listener, so another server can sit in front of them
// (the sign-in gateway does, once the instance is unlocked).
func TestHandlerServesRoutesWithoutAListener(t *testing.T) {
	d, err := New(Config{Addr: "127.0.0.1:0", Driver: &healthDriver{}})
	if err != nil {
		t.Fatal(err)
	}
	mounted := false
	d.SetMCPMount(func(mux *http.ServeMux) {
		mux.HandleFunc("/mcp", func(w http.ResponseWriter, _ *http.Request) { mounted = true; w.WriteHeader(http.StatusNoContent) })
	})
	h := d.Handler()

	for path, want := range map[string]int{"/healthz": http.StatusOK, "/readyz": http.StatusServiceUnavailable, "/mcp": http.StatusNoContent, "/pair": http.StatusOK} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
		}
	}
	if !mounted {
		t.Error("the MCP mount was not used")
	}
	if d.BoundAddr() != "" {
		t.Error("Handler bound a listener")
	}
}
