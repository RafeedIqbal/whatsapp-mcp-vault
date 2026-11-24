package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"go.mau.fi/whatsmeow"
)

// maxMediaBytes caps a single media download. Decrypted media is only ever
// held in memory (it is never written to disk), so the cap bounds how much of
// the instance's RAM one request can take.
const maxMediaBytes uint64 = 64 << 20

// DownloadResult is the public return value from Download. Data holds the
// decrypted bytes; it is the only copy, and it is not serialised.
type DownloadResult struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	MediaType string `json:"media_type,omitempty"`
	Filename  string `json:"filename,omitempty"`
	Size      int    `json:"size_bytes,omitempty"`
	Data      []byte `json:"-"`
}

// MediaDownloader implements whatsmeow.DownloadableMessage for cached media.
type MediaDownloader struct {
	URL           string
	DirectPath    string
	MediaKey      []byte
	FileLength    uint64
	FileSHA256    []byte
	FileEncSHA256 []byte
	MediaType     whatsmeow.MediaType
}

func (d *MediaDownloader) GetDirectPath() string    { return d.DirectPath }
func (d *MediaDownloader) GetURL() string           { return d.URL }
func (d *MediaDownloader) GetMediaKey() []byte      { return d.MediaKey }
func (d *MediaDownloader) GetFileLength() uint64    { return d.FileLength }
func (d *MediaDownloader) GetFileSHA256() []byte    { return d.FileSHA256 }
func (d *MediaDownloader) GetFileEncSHA256() []byte { return d.FileEncSHA256 }
func (d *MediaDownloader) GetMediaType() whatsmeow.MediaType {
	return d.MediaType
}

// Download fetches and decrypts the media of a previously-cached message and
// returns the bytes. Nothing is written to disk and nothing is cached: every
// call fetches from WhatsApp again. Download never contacts the phone; see
// DownloadWithMediaRetry.
func (c *Client) Download(ctx context.Context, messageID, chatJID string) DownloadResult {
	return c.download(ctx, messageID, chatJID, false)
}

// DownloadWithMediaRetry is Download for an explicit request for one message
// (the download_media tool and media resource reads). When the CDN refuses
// the stored link (403/404/410) it asks the account's own phone once to
// re-upload the media and retries with the returned link. It persists that
// link only after the payload passes validation. Automatic or bulk callers
// use Download, so they never send retry receipts.
func (c *Client) DownloadWithMediaRetry(ctx context.Context, messageID, chatJID string) DownloadResult {
	return c.download(ctx, messageID, chatJID, true)
}

func (c *Client) download(ctx context.Context, messageID, chatJID string, mediaRetry bool) DownloadResult {
	fail := func(format string, args ...any) DownloadResult {
		return DownloadResult{Success: false, Message: fmt.Sprintf(format, args...)}
	}

	mediaType, filename, url, directPath, mediaKey, fileSHA256, fileEncSHA256, fileLength, err :=
		c.store.GetMediaInfo(messageID, chatJID)
	if err != nil {
		return fail("failed to find message: %v", err)
	}
	if mediaType == "" {
		return fail("not a media message")
	}
	if url == "" || len(mediaKey) == 0 || len(fileSHA256) == 0 || len(fileEncSHA256) == 0 || fileLength == 0 {
		return fail("incomplete media information for download")
	}
	if fileLength > maxMediaBytes {
		return fail("media is %d bytes, over the %d byte limit for media handled in memory", fileLength, maxMediaBytes)
	}

	var waMediaType whatsmeow.MediaType
	switch mediaType {
	case "image":
		waMediaType = whatsmeow.MediaImage
	case "video":
		waMediaType = whatsmeow.MediaVideo
	case "audio":
		waMediaType = whatsmeow.MediaAudio
	case "document":
		waMediaType = whatsmeow.MediaDocument
	default:
		return fail("unsupported media type: %s", mediaType)
	}

	c.log.Infof("Attempting to download media for message %s in chat %s...", c.redactor.MsgID(messageID), c.redactor.JID(chatJID))

	downloader := &MediaDownloader{
		URL:           url,
		DirectPath:    preferredDirectPath(directPath, url),
		MediaKey:      mediaKey,
		FileLength:    fileLength,
		FileSHA256:    fileSHA256,
		FileEncSHA256: fileEncSHA256,
		MediaType:     waMediaType,
	}

	data, err := c.fetchMedia(ctx, downloader)
	var retriedDirectPath string
	if err != nil && mediaRetry && isExpiredMediaError(err) {
		// The stored CDN path has expired (typical for history-synced
		// messages) or the CDN dropped the file. Ask the phone to re-upload
		// it, then try once more with the fresh path.
		c.log.Infof("Media link for message %s no longer works (%s)", c.redactor.MsgID(messageID), c.redactor.Err(err))
		newPath, retryErr := c.recoverMediaPath(ctx, messageID, chatJID, mediaKey)
		if retryErr != nil {
			return fail("failed to download media: %v; asking the phone to re-upload it failed: %v", err, retryErr)
		}
		downloader.DirectPath = newPath
		retriedDirectPath = newPath
		data, err = c.fetchMedia(ctx, downloader)
	}
	if err != nil {
		return fail("failed to download media: %v", err)
	}

	if err := validateMediaPayload(data, fileLength, fileSHA256); err != nil {
		return fail("downloaded media failed validation: %v", err)
	}
	if retriedDirectPath != "" {
		if err := c.store.UpdateMediaDirectPath(messageID, chatJID, retriedDirectPath); err != nil {
			c.log.Warnf("Failed to store re-uploaded media path for message %s: %s", c.redactor.MsgID(messageID), c.redactor.Err(err))
		}
	}

	c.log.Infof("Successfully downloaded %s media (%d bytes)", mediaType, len(data))
	return DownloadResult{
		Success:   true,
		Message:   fmt.Sprintf("Successfully downloaded %s media", mediaType),
		MediaType: mediaType,
		Filename:  filename,
		Size:      len(data),
		Data:      data,
	}
}

// fetchMedia downloads and decrypts the payload described by d.
func (c *Client) fetchMedia(ctx context.Context, d *MediaDownloader) ([]byte, error) {
	if c.downloadMedia != nil {
		return c.downloadMedia(ctx, d)
	}
	if c.waClient() != nil {
		return c.waClient().Download(ctx, d)
	}
	return nil, errors.New("media downloader is unavailable")
}

func validateMediaPayload(data []byte, fileLength uint64, fileSHA256 []byte) error {
	if fileLength > maxMediaBytes {
		return fmt.Errorf("media exceeds download limit of %d bytes", maxMediaBytes)
	}
	if uint64(len(data)) > maxMediaBytes {
		return fmt.Errorf("payload exceeds download limit of %d bytes", maxMediaBytes)
	}
	if fileLength > 0 && uint64(len(data)) != fileLength {
		return fmt.Errorf("size mismatch: got %d bytes, want %d", len(data), fileLength)
	}
	if len(fileSHA256) > 0 {
		digest := sha256.Sum256(data)
		if !bytes.Equal(digest[:], fileSHA256) {
			return errors.New("SHA-256 mismatch")
		}
	}
	return nil
}

// preferredDirectPath picks the value handed to whatsmeow as the download's
// DirectPath. New rows carry a stored directPath captured verbatim from the
// media protobuf (including the signed `?ccb=&oh=&oe=&_nc_sid=` CDN auth
// query), which is authoritative. Legacy rows written before the
// direct_path column existed fall back to parsing URL — the same behaviour
// prior daemon builds had.
func preferredDirectPath(stored, url string) string {
	if stored != "" {
		return stored
	}
	return extractDirectPathFromURL(url)
}

// extractDirectPathFromURL turns a CDN URL into the /direct/path/form that
// whatsmeow's Download requires when the URL does not already contain it.
//
// The query string MUST be preserved: whatsmeow builds the request URL as
// `https://<host><directPath>&hash=…&mms-type=…&__wa-mms=`, which assumes
// directPath already ends in `?ccb=…&oh=…&oe=…&_nc_sid=…` (WhatsApp's signed
// CDN auth params). Stripping the query yields a malformed URL and every
// download returns 403.
func extractDirectPathFromURL(url string) string {
	parts := strings.SplitN(url, ".net/", 2)
	if len(parts) < 2 {
		return url
	}
	return "/" + parts[1]
}
