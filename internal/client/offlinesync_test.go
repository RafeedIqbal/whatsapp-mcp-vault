package client

import (
	"context"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types/events"
)

// After an unlock the instance reconnects and WhatsApp delivers what arrived
// while it was away. A request should be able to wait (briefly) for that to
// finish, so the first answer after an idle period includes the new messages.
func TestWaitForOfflineSyncReturnsOnceTheBacklogHasArrived(t *testing.T) {
	c := &Client{}
	done := make(chan bool, 1)
	go func() { done <- c.WaitForOfflineSync(context.Background(), 5*time.Second) }()

	select {
	case <-done:
		t.Fatal("returned before the offline sync completed")
	case <-time.After(30 * time.Millisecond):
	}
	c.trackConnectionEvent(&events.OfflineSyncCompleted{Count: 3})
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("reported a timeout although the sync completed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not return after the offline sync completed")
	}
	// Later callers do not wait at all.
	if !c.WaitForOfflineSync(context.Background(), time.Millisecond) {
		t.Fatal("a second wait did not see the completed sync")
	}
}

func TestWaitForOfflineSyncGivesUpAfterTheTimeout(t *testing.T) {
	c := &Client{}
	start := time.Now()
	if c.WaitForOfflineSync(context.Background(), 40*time.Millisecond) {
		t.Fatal("reported completion although no sync happened")
	}
	if time.Since(start) > time.Second {
		t.Fatal("waited far longer than the timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.WaitForOfflineSync(ctx, time.Minute) {
		t.Fatal("reported completion on a cancelled request")
	}
}
