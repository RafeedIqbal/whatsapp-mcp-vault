package client

import (
	"context"
	"sync"
	"time"
)

// offlineSync records that WhatsApp has finished delivering what arrived
// while this client was disconnected.
type offlineSync struct {
	mu   sync.Mutex
	done chan struct{}
	once sync.Once
}

func (o *offlineSync) channel() chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done == nil {
		o.done = make(chan struct{})
	}
	return o.done
}

func (o *offlineSync) mark() {
	ch := o.channel()
	o.once.Do(func() { close(ch) })
}

// WaitForOfflineSync blocks until WhatsApp has delivered the backlog queued
// while this client was away, the timeout passes, or ctx ends. It reports
// whether the backlog arrived. A freshly unlocked instance calls it so the
// first answer after an idle period already includes the new messages.
func (c *Client) WaitForOfflineSync(ctx context.Context, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-c.offline.channel():
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}
