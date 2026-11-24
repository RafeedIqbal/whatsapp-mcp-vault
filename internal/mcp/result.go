package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/ingest"
)

// resultJSON serialises v to JSON and wraps it in a text tool result.
func resultJSON(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal: %v", err)), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

// inlineMediaMaxBytes is the size cap for returning decrypted media in a
// download_media tool result. Media is never written to disk, so the result
// is the only way it leaves the server; anything larger is refused with an
// explanation rather than blowing up the model's context or the transport.
const inlineMediaMaxBytes = 5 * 1024 * 1024

// mediaSummary is the JSON block that leads every download_media result. It
// describes the media; it carries neither the bytes nor any server path.
type mediaSummary struct {
	client.DownloadResult
	Note string `json:"note,omitempty"`
	// DownloadURL is a one-time link for media too large to return in the
	// result itself.
	DownloadURL       string `json:"download_url,omitempty"`
	DownloadExpiresIn int    `json:"download_expires_in_seconds,omitempty"`
}

// downloadMediaResult builds the CallToolResult returned by the download_media
// tool. Media over inlineMediaMaxBytes is offered as a one-time download link
// when a file service is available. The first content block is always the JSON summary. For a successful
// download of at most inlineMediaMaxBytes the bytes follow in a second block:
// an ImageContent or AudioContent for images and audio, and an embedded
// resource (addressed by uri) for videos and documents, which have no content
// type of their own.
func downloadMediaResult(family string, r client.DownloadResult, uri string, files *Files) (*mcp.CallToolResult, error) {
	sum := mediaSummary{DownloadResult: r}
	var media mcp.Content
	if r.Success && len(r.Data) > 0 {
		if len(r.Data) > inlineMediaMaxBytes {
			sum.Note = fmt.Sprintf("media is too large to return (%d bytes; the limit is %d)", len(r.Data), inlineMediaMaxBytes)
			if files != nil && files.Transfers != nil {
				_, link, err := files.Transfers.OfferDownload(family, ingest.Blob{Filename: r.Filename, ContentType: sniffResourceMIME(r.Data, r.MediaType), Data: r.Data})
				if err == nil {
					sum.DownloadURL = link
					sum.DownloadExpiresIn = int(files.Transfers.TTL().Seconds())
					sum.Note = "media is too large to return here; give the user download_url, which works once and expires soon"
				} else {
					sum.Note += "; a download link could not be created: " + err.Error()
				}
			}
		} else {
			media = inlineMedia(r, uri)
		}
	}

	b, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal: %v", err)), nil
	}
	contents := []mcp.Content{mcp.NewTextContent(string(b))}
	if media != nil {
		contents = append(contents, media)
	}
	return &mcp.CallToolResult{Content: contents}, nil
}

// inlineMedia wraps decrypted bytes in the content block that suits their
// kind. The MIME type is sniffed via sniffResourceMIME (resources.go) so we
// get the real format regardless of the filename WhatsApp assigns (all photos
// are named `.jpg` even when the underlying bytes are WebP, and all voice
// notes are named `.ogg`).
func inlineMedia(r client.DownloadResult, uri string) mcp.Content {
	mimeType := sniffResourceMIME(r.Data, r.MediaType)
	encoded := base64.StdEncoding.EncodeToString(r.Data)
	switch r.MediaType {
	case "image":
		return mcp.NewImageContent(encoded, mimeType)
	case "audio":
		return mcp.NewAudioContent(encoded, mimeType)
	default:
		return mcp.NewEmbeddedResource(mcp.BlobResourceContents{URI: uri, MIMEType: mimeType, Blob: encoded})
	}
}
