// Package ingest moves files in and out of the instance without touching its
// disk: fetching an attachment from a link, accepting one through a one-time
// upload page, and handing large media back through a one-time download link.
// Everything is held in memory, briefly, and bounded.
package ingest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

var (
	// ErrBlockedAddress: the link points somewhere a fetch must never go
	// (this machine, a private network, the cloud metadata service).
	ErrBlockedAddress = errors.New("ingest: that address is not allowed")
	// ErrTooLarge: the file is over the size limit.
	ErrTooLarge = errors.New("ingest: file is too large")
)

// Blob is a file held in memory.
type Blob struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Fetcher downloads a file from a link the model or user supplied. Because
// the link is untrusted, it only ever connects to public internet addresses,
// over https, and reads at most a fixed number of bytes.
type Fetcher struct {
	maxBytes int64

	// Test seams. In production all three are zero.
	tlsConfig *tls.Config
	allowIP   func(net.IP) bool // replaces the public-address rule
	allowPort int               // additionally allows loopback on this port
}

// NewFetcher returns a fetcher that accepts files of up to maxBytes.
func NewFetcher(maxBytes int64) *Fetcher { return &Fetcher{maxBytes: maxBytes} }

// blockedPrefixes are the address ranges that are never public internet.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// isPublicIP reports whether ip is a routable public internet address.
func isPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap() // ::ffff:10.0.0.1 is 10.0.0.1
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

func (f *Fetcher) allowed(ip net.IP, port string) bool {
	if f.allowIP != nil {
		return f.allowIP(ip)
	}
	if f.allowPort != 0 && port == strconv.Itoa(f.allowPort) && ip != nil && ip.IsLoopback() {
		return true
	}
	return isPublicIP(ip)
}

// Fetch downloads the file at rawURL.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (Blob, error) {
	u, err := checkFetchURL(rawURL)
	if err != nil {
		return Blob{}, err
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !f.allowed(ip, u.Port()) {
		return Blob{}, ErrBlockedAddress
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		// Control sees the address actually being connected to, after DNS.
		// Checking here (and not the hostname) is what defeats a name that
		// resolves to a private address, including one that changes between
		// lookups.
		Control: func(_, address string, _ syscall.RawConn) error {
			host, port, err := net.SplitHostPort(address)
			if err != nil || !f.allowed(net.ParseIP(host), port) {
				return ErrBlockedAddress
			}
			return nil
		},
	}
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil, // never through an environment-configured proxy
			DialContext:           dialer.DialContext,
			TLSClientConfig:       f.tlsConfig,
			ResponseHeaderTimeout: 20 * time.Second,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("ingest: too many redirects")
			}
			_, err := checkFetchURL(req.URL.String())
			return err
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Blob{}, errors.New("ingest: link could not be used")
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlockedAddress) {
			return Blob{}, ErrBlockedAddress
		}
		return Blob{}, fmt.Errorf("ingest: could not download the link: %w", scrubURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Blob{}, fmt.Errorf("ingest: the link answered with status %d", resp.StatusCode)
	}
	if resp.ContentLength > f.maxBytes {
		return Blob{}, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return Blob{}, errors.New("ingest: the download was interrupted")
	}
	if int64(len(data)) > f.maxBytes {
		return Blob{}, ErrTooLarge
	}
	if len(data) == 0 {
		return Blob{}, errors.New("ingest: the link returned an empty file")
	}
	return Blob{
		Filename:    SafeName(nameFromResponse(resp, u)),
		ContentType: resp.Header.Get("Content-Type"),
		Data:        data,
	}, nil
}

// checkFetchURL accepts only plain https links.
func checkFetchURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, errors.New("ingest: not a usable link")
	}
	if u.Scheme != "https" {
		return nil, errors.New("ingest: only https links can be fetched")
	}
	if u.User != nil {
		return nil, errors.New("ingest: links with embedded credentials are not accepted")
	}
	return u, nil
}

// scrubURLError drops the URL (which may carry a secret token in its query)
// from a transport error.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func nameFromResponse(resp *http.Response, u *url.URL) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil && params["filename"] != "" {
			return params["filename"]
		}
	}
	return path.Base(u.Path)
}

// SafeName reduces a filename from an untrusted source to a plain name: no
// directories, no control characters, no quotes, bounded length.
func SafeName(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	name = path.Base(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case unicode.IsControl(r), r == '"', r == '\'', r == '/', r == '<', r == '>', r == ':', r == '|', r == '?', r == '*':
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Trim(strings.TrimSpace(b.String()), ".")
	if out == "" {
		return "file"
	}
	if r := []rune(out); len(r) > 120 {
		out = string(r[len(r)-120:])
	}
	return out
}
