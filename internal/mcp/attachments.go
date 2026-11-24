package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/sealjay/mcp-whatsapp/internal/ingest"
	"github.com/sealjay/mcp-whatsapp/internal/oauth"
)

// Files is how tools move attachments in and out without the server's disk:
// fetching from a link, taking a file sent to a one-time upload page, and
// handing large media back through a one-time download link.
type Files struct {
	// Fetch downloads an attachment from a link. It must refuse anything
	// that is not a public https address (see ingest.Fetcher).
	Fetch func(ctx context.Context, url string) (ingest.Blob, error)
	// Transfers holds uploads and downloads in memory.
	Transfers *ingest.Transfers
}

// SetFiles gives the server its file service. Without one, attachments can
// only be sent inline and large media cannot be returned.
func (s *Server) SetFiles(f *Files) { s.files = f }

// maxInlineAttachmentBytes bounds an attachment passed inline as base64.
// Larger files go through a link or the upload page.
// It stays well under the request size limit once base64 has inflated it.
const maxInlineAttachmentBytes = 5 << 20

// attachmentSource is the part of a send tool's arguments that says where the
// file comes from. Exactly one of URL, UploadID and DataBase64 must be set.
type attachmentSource struct {
	URL        string
	UploadID   string
	DataBase64 string
	Filename   string
}

const attachmentSourceHelp = "give exactly one of: url (a public https link), upload_id (from create_upload_link, after the file was uploaded), or data_base64 with filename"

// resolveAttachment turns a tool's attachment arguments into the file to send.
func (s *Server) resolveAttachment(ctx context.Context, src attachmentSource) (ingest.Blob, error) {
	given := 0
	for _, v := range []string{src.URL, src.UploadID, src.DataBase64} {
		if strings.TrimSpace(v) != "" {
			given++
		}
	}
	if given != 1 {
		return ingest.Blob{}, errors.New("an attachment needs one source: " + attachmentSourceHelp)
	}

	var blob ingest.Blob
	switch {
	case src.DataBase64 != "":
		if strings.TrimSpace(src.Filename) == "" {
			return ingest.Blob{}, errors.New("filename is required with data_base64 (its extension decides how WhatsApp shows the file)")
		}
		data, err := decodeBase64(src.DataBase64)
		if err != nil {
			return ingest.Blob{}, err
		}
		blob = ingest.Blob{Data: data}
	case src.URL != "":
		if s.files == nil || s.files.Fetch == nil {
			return ingest.Blob{}, errors.New("this server cannot fetch attachments from links; send the file with data_base64 instead")
		}
		b, err := s.files.Fetch(ctx, src.URL)
		if err != nil {
			return ingest.Blob{}, err
		}
		blob = b
	default:
		if s.files == nil || s.files.Transfers == nil {
			return ingest.Blob{}, errors.New("this server has no upload page; send the file with data_base64 instead")
		}
		b, err := s.files.Transfers.TakeUpload(oauth.GrantFamily(ctx), strings.TrimSpace(src.UploadID))
		if err != nil {
			return ingest.Blob{}, err
		}
		blob = b
	}
	if name := strings.TrimSpace(src.Filename); name != "" {
		blob.Filename = name
	}
	blob.Filename = ingest.SafeName(blob.Filename)
	if len(blob.Data) == 0 {
		return ingest.Blob{}, errors.New("the attachment is empty")
	}
	return blob, nil
}

// decodeBase64 accepts what models actually produce: standard or URL-safe
// alphabets, with or without padding, wrapped lines, or a whole data: URL.
func decodeBase64(in string) ([]byte, error) {
	if i := strings.Index(in, ";base64,"); strings.HasPrefix(in, "data:") && i >= 0 {
		in = in[i+len(";base64,"):]
	}
	in = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, in)
	if base64.StdEncoding.DecodedLen(len(in)) > maxInlineAttachmentBytes+3 {
		return nil, errors.New("inline attachment is too large; use a link or create_upload_link instead")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := enc.DecodeString(in); err == nil {
			if len(data) > maxInlineAttachmentBytes {
				return nil, errors.New("inline attachment is too large; use a link or create_upload_link instead")
			}
			return data, nil
		}
	}
	return nil, errors.New("data_base64 is not valid base64")
}
