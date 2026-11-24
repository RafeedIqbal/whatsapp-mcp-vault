package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/ingest"
	mcpsrv "github.com/sealjay/mcp-whatsapp/internal/mcp"
)

// sendPolicy is how cautious the instance is about outgoing messages.
type sendPolicy struct {
	// blockNewRecipients refuses sends to chats with no history.
	blockNewRecipients bool
	// confirm says which sends are held as a draft until confirm_send.
	confirm mcpsrv.ConfirmMode
}

// effectiveConfirm is the confirm mode to run with. Confirming sends to new
// recipients is pointless while they are refused outright, so that mode only
// takes effect once new recipients are allowed.
func (p sendPolicy) effectiveConfirm() mcpsrv.ConfirmMode {
	if p.blockNewRecipients && p.confirm == mcpsrv.ConfirmNewRecipients {
		return mcpsrv.ConfirmOff
	}
	return p.confirm
}

// sendPolicyFromEnv reads ALLOW_NEW_RECIPIENTS (default false) and
// SEND_CONFIRM (new_recipients by default; always; off).
func sendPolicyFromEnv(getenv func(string) string) (sendPolicy, error) {
	p := sendPolicy{blockNewRecipients: true, confirm: mcpsrv.ConfirmNewRecipients}
	if v := strings.TrimSpace(getenv("ALLOW_NEW_RECIPIENTS")); v != "" {
		allow, err := strconv.ParseBool(v)
		if err != nil {
			return sendPolicy{}, errors.New("ALLOW_NEW_RECIPIENTS must be a boolean (for example, true or false)")
		}
		p.blockNewRecipients = !allow
	}
	switch strings.ToLower(strings.TrimSpace(getenv("SEND_CONFIRM"))) {
	case "", "new_recipients":
	case "always":
		p.confirm = mcpsrv.ConfirmAlways
	case "off":
		p.confirm = mcpsrv.ConfirmOff
	default:
		return sendPolicy{}, errors.New("SEND_CONFIRM must be new_recipients, always or off")
	}
	return p, nil
}

const (
	// maxTransferBytes bounds one attachment or download held in memory. It
	// matches the largest media the client will fetch, so anything that can be
	// downloaded can also be offered as a link.
	maxTransferBytes = 64 << 20
	// maxTransfersHeldBytes bounds everything held at once.
	maxTransfersHeldBytes = 128 << 20
	transferTTL           = 10 * time.Minute
)

// newFiles builds the in-memory file service: link fetching, the upload page
// and download links, all addressed under publicURL.
func newFiles(publicURL string) *mcpsrv.Files {
	fetcher := ingest.NewFetcher(maxTransferBytes)
	return &mcpsrv.Files{
		Fetch:     func(ctx context.Context, url string) (ingest.Blob, error) { return fetcher.Fetch(ctx, url) },
		Transfers: ingest.NewTransfers(publicURL, maxTransferBytes, maxTransfersHeldBytes, transferTTL),
	}
}
