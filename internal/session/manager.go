// Package session decides when the instance is unlocked.
//
// Locked is the resting state: no key in memory, no database open, no
// connection to WhatsApp. A request that presents a valid token brings the
// key with it; the manager then builds the runtime (the stores, the WhatsApp
// client and the tool server) and shares it with every request until the
// instance has been idle for a while, at which point the runtime is closed and
// the key forgotten again.
package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

// Runtime is everything that exists only while the instance is unlocked.
type Runtime interface {
	// Close releases it all: disconnects, closes the databases.
	Close() error
}

// unlockTimeout bounds how long building the runtime may take. Without it a
// stalled network call during unlock would hold every request forever.
const unlockTimeout = 2 * time.Minute

// ErrKeyMismatch is returned when a request presents a key other than the one
// the running runtime was built with.
var ErrKeyMismatch = errors.New("session: key does not match the unlocked instance")

type state int

const (
	locked state = iota
	building
	ready
	closing
)

// Manager owns the runtime's lifetime.
type Manager[R Runtime] struct {
	build func(context.Context, vault.Key) (R, error)
	idle  time.Duration
	now   func() time.Time

	mu       sync.Mutex
	cond     *sync.Cond
	state    state
	rt       R
	key      vault.Key
	leases   int
	lastUsed time.Time
	// buildGen counts builds; failedGen/failedErr record the last one that
	// failed so requests that waited on it get its error instead of each
	// starting a build of their own.
	buildGen  int
	failedGen int
	failedErr error
}

// New returns a locked manager. build creates the runtime from the instance
// key; idle is how long the instance may sit unused before it locks.
func New[R Runtime](build func(context.Context, vault.Key) (R, error), idle time.Duration) *Manager[R] {
	m := &Manager[R]{build: build, idle: idle, now: time.Now}
	m.cond = sync.NewCond(&m.mu)
	return m
}

// Unlocked reports whether a runtime is currently up.
func (m *Manager[R]) Unlocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state == ready || m.state == closing
}

// Acquire returns the runtime, unlocking the instance with key if it is
// locked. Concurrent callers share one unlock. The caller must call release
// when its request is finished; the instance never locks while a request
// holds the runtime.
func (m *Manager[R]) Acquire(ctx context.Context, key vault.Key) (rt R, release func(), err error) {
	var zero R
	m.mu.Lock()
	for {
		switch m.state {
		case ready:
			if key != m.key {
				m.mu.Unlock()
				return zero, nil, ErrKeyMismatch
			}
			m.leases++
			rt = m.rt
			m.mu.Unlock()
			return rt, m.releaser(), nil

		case locked:
			m.state = building
			m.buildGen++
			gen := m.buildGen
			m.mu.Unlock()
			// One caller going away must not abort the unlock the others
			// are waiting on.
			built, berr := m.runBuild(ctx, key)
			m.mu.Lock()
			if berr != nil {
				m.state = locked
				m.failedGen, m.failedErr = gen, berr
				m.cond.Broadcast()
				m.mu.Unlock()
				return zero, nil, berr
			}
			m.rt, m.key, m.state = built, key, ready
			m.lastUsed = m.now()
			m.cond.Broadcast()
			// Loop round to take a lease in the ready case.

		case building:
			gen := m.buildGen
			m.cond.Wait()
			if m.failedGen == gen {
				ferr := m.failedErr
				m.mu.Unlock()
				return zero, nil, ferr
			}

		case closing:
			m.cond.Wait()
		}
	}
}

// runBuild builds the runtime with a deadline, detached from the caller's
// cancellation (one caller going away must not abort the unlock the others
// are waiting on), and turns a panic into an error so the manager can return
// to the locked state instead of staying stuck mid-unlock.
func (m *Manager[R]) runBuild(ctx context.Context, key vault.Key) (rt R, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero R
			rt, err = zero, fmt.Errorf("session: unlocking failed unexpectedly: %v", r)
		}
	}()
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unlockTimeout)
	defer cancel()
	return m.build(bctx, key)
}

func (m *Manager[R]) releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			m.leases--
			m.lastUsed = m.now()
			m.cond.Broadcast()
			m.mu.Unlock()
		})
	}
}

// ExpireIdle locks the instance if it is unlocked, unused, and has been for
// the idle period as of now. It reports whether it locked.
func (m *Manager[R]) ExpireIdle(now time.Time) bool {
	m.mu.Lock()
	if m.state != ready || m.leases > 0 || now.Sub(m.lastUsed) < m.idle {
		m.mu.Unlock()
		return false
	}
	m.closeLocked()
	return true
}

// Lock locks the instance now, after any running requests finish.
func (m *Manager[R]) Lock() {
	m.mu.Lock()
	for m.state == building || m.state == closing {
		m.cond.Wait()
	}
	if m.state != ready {
		m.mu.Unlock()
		return
	}
	m.closeLocked()
}

// closeLocked tears the runtime down. It is entered with mu held and state
// ready, and returns with mu released and state locked.
func (m *Manager[R]) closeLocked() {
	m.state = closing
	for m.leases > 0 {
		m.cond.Wait()
	}
	rt := m.rt
	var zero R
	m.rt = zero
	m.key = vault.Key{} // forget the key
	m.mu.Unlock()

	func() {
		// Whatever Close does, the manager must end up locked.
		defer func() { _ = recover() }()
		_ = rt.Close()
	}()

	m.mu.Lock()
	m.state = locked
	m.cond.Broadcast()
	m.mu.Unlock()
}

// Run locks the instance whenever it goes idle, checking every interval, and
// locks it for good when ctx ends.
func (m *Manager[R]) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Lock()
			return
		case <-t.C:
			m.ExpireIdle(m.now())
		}
	}
}
