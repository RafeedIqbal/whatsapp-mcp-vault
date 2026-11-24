package main

import (
	"testing"

	mcpsrv "github.com/sealjay/mcp-whatsapp/internal/mcp"
)

func TestSendPolicyDefaultsAreTheSafeOnes(t *testing.T) {
	p, err := sendPolicyFromEnv(envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !p.blockNewRecipients {
		t.Error("new recipients are allowed by default")
	}
	if p.confirm != mcpsrv.ConfirmNewRecipients {
		t.Errorf("default confirm mode = %v, want ConfirmNewRecipients", p.confirm)
	}
}

func TestSendPolicyFromEnv(t *testing.T) {
	for name, tc := range map[string]struct {
		env     map[string]string
		block   bool
		confirm mcpsrv.ConfirmMode
		ok      bool
	}{
		"allow new":        {map[string]string{"ALLOW_NEW_RECIPIENTS": "true"}, false, mcpsrv.ConfirmNewRecipients, true},
		"allow new (1)":    {map[string]string{"ALLOW_NEW_RECIPIENTS": "1"}, false, mcpsrv.ConfirmNewRecipients, true},
		"explicitly block": {map[string]string{"ALLOW_NEW_RECIPIENTS": "false"}, true, mcpsrv.ConfirmNewRecipients, true},
		"confirm always":   {map[string]string{"SEND_CONFIRM": "always"}, true, mcpsrv.ConfirmAlways, true},
		"confirm off":      {map[string]string{"SEND_CONFIRM": "off"}, true, mcpsrv.ConfirmOff, true},
		"confirm new":      {map[string]string{"SEND_CONFIRM": " New_Recipients "}, true, mcpsrv.ConfirmNewRecipients, true},
		"bad boolean":      {map[string]string{"ALLOW_NEW_RECIPIENTS": "sometimes"}, false, 0, false},
		"bad mode":         {map[string]string{"SEND_CONFIRM": "maybe"}, false, 0, false},
	} {
		p, err := sendPolicyFromEnv(envOf(tc.env))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
			continue
		}
		if tc.ok && (p.blockNewRecipients != tc.block || p.confirm != tc.confirm) {
			t.Errorf("%s: got block=%v confirm=%v, want %v %v", name, p.blockNewRecipients, p.confirm, tc.block, tc.confirm)
		}
	}
}

// Holding a send for confirmation "because the recipient is new" makes no
// sense while new recipients are refused outright: the draft could never be
// sent. The confirm step for new recipients only applies once they are allowed.
func TestConfirmForNewRecipientsOnlyAppliesWhenTheyAreAllowed(t *testing.T) {
	blocked, _ := sendPolicyFromEnv(envOf(nil))
	if got := blocked.effectiveConfirm(); got != mcpsrv.ConfirmOff {
		t.Errorf("blocked + new_recipients: effective mode = %v, want ConfirmOff", got)
	}
	allowed, _ := sendPolicyFromEnv(envOf(map[string]string{"ALLOW_NEW_RECIPIENTS": "true"}))
	if got := allowed.effectiveConfirm(); got != mcpsrv.ConfirmNewRecipients {
		t.Errorf("allowed + new_recipients: effective mode = %v, want ConfirmNewRecipients", got)
	}
	always, _ := sendPolicyFromEnv(envOf(map[string]string{"SEND_CONFIRM": "always"}))
	if got := always.effectiveConfirm(); got != mcpsrv.ConfirmAlways {
		t.Errorf("always: effective mode = %v, want ConfirmAlways", got)
	}
}
