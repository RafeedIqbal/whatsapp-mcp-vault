package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/vault"
)

// fakeRuntime stands in for the store + WhatsApp client + MCP server.
type fakeRuntime struct {
	id     int
	key    vault.Key
	closed atomic.Int32
}

func (r *fakeRuntime) Close() error { r.closed.Add(1); return nil }

type fixture struct {
	m      *Manager[*fakeRuntime]
	builds atomic.Int32
	built  []*fakeRuntime
	mu     sync.Mutex
	now    time.Time
	// gate, when non-nil, blocks every build until it is closed.
	gate chan struct{}
	// fail, when set, makes builds return it.
	fail error
}

func newFixture(idle time.Duration) *fixture {
	f := &fixture{now: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	f.m = New(func(_ context.Context, key vault.Key) (*fakeRuntime, error) {
		n := int(f.builds.Add(1))
		if f.gate != nil {
			<-f.gate
		}
		if f.fail != nil {
			return nil, f.fail
		}
		rt := &fakeRuntime{id: n, key: key}
		f.mu.Lock()
		f.built = append(f.built, rt)
		f.mu.Unlock()
		return rt, nil
	}, idle)
	f.m.now = func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	return f
}

func (f *fixture) advance(d time.Duration) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	return f.now
}

func testKey(b byte) vault.Key {
	var k vault.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func TestAcquireUnlocksOnceAndReuses(t *testing.T) {
	f := newFixture(15 * time.Minute)
	if f.m.Unlocked() {
		t.Fatal("a new manager is unlocked")
	}
	rt1, release1, err := f.m.Acquire(context.Background(), testKey(1))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if rt1.key != testKey(1) {
		t.Fatal("the runtime was not built with the presented key")
	}
	rt2, release2, err := f.m.Acquire(context.Background(), testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if rt1 != rt2 || f.builds.Load() != 1 {
		t.Fatalf("second Acquire built again (builds=%d)", f.builds.Load())
	}
	if !f.m.Unlocked() {
		t.Fatal("not unlocked after Acquire")
	}
	release1()
	release2()
}

func TestConcurrentAcquiresShareOneUnlock(t *testing.T) {
	// Several requests arriving at a locked instance must not each open the
	// databases and connect to WhatsApp.
	f := newFixture(15 * time.Minute)
	f.gate = make(chan struct{})
	const n = 8
	var wg sync.WaitGroup
	rts := make([]*fakeRuntime, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rt, release, err := f.m.Acquire(context.Background(), testKey(1))
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			rts[i] = rt
			release()
		}()
	}
	// Let them all reach the manager, then let the single build finish.
	deadline := time.Now().Add(2 * time.Second)
	for f.builds.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(f.gate)
	wg.Wait()
	if got := f.builds.Load(); got != 1 {
		t.Fatalf("built %d times for %d concurrent requests, want 1", got, n)
	}
	for i := 1; i < n; i++ {
		if rts[i] != rts[0] {
			t.Fatal("concurrent requests got different runtimes")
		}
	}
}

func TestFailedUnlockLeavesTheInstanceLockedAndCanBeRetried(t *testing.T) {
	f := newFixture(15 * time.Minute)
	f.fail = errors.New("database will not open")
	if _, _, err := f.m.Acquire(context.Background(), testKey(1)); err == nil {
		t.Fatal("Acquire succeeded although the build failed")
	}
	if f.m.Unlocked() {
		t.Fatal("unlocked after a failed build")
	}
	f.fail = nil
	rt, release, err := f.m.Acquire(context.Background(), testKey(1))
	if err != nil || rt == nil {
		t.Fatalf("retry after a failed build: %v", err)
	}
	release()
}

func TestIdleInstanceLocksAndForgetsItsRuntime(t *testing.T) {
	f := newFixture(15 * time.Minute)
	rt, release, _ := f.m.Acquire(context.Background(), testKey(1))
	release()

	if f.m.ExpireIdle(f.advance(14 * time.Minute)) {
		t.Fatal("locked before the idle period passed")
	}
	if !f.m.ExpireIdle(f.advance(2 * time.Minute)) {
		t.Fatal("did not lock after the idle period")
	}
	if rt.closed.Load() != 1 {
		t.Fatalf("runtime closed %d times, want 1", rt.closed.Load())
	}
	if f.m.Unlocked() {
		t.Fatal("still unlocked after idle lock")
	}
	// Locking again is a no-op.
	if f.m.ExpireIdle(f.advance(time.Hour)) || rt.closed.Load() != 1 {
		t.Fatal("an already locked instance was locked again")
	}
}

func TestInstanceInUseIsNeverLocked(t *testing.T) {
	f := newFixture(15 * time.Minute)
	rt, release, _ := f.m.Acquire(context.Background(), testKey(1))
	// A long tool call: far past the idle period, but still running.
	if f.m.ExpireIdle(f.advance(time.Hour)) {
		t.Fatal("locked while a request was still using the runtime")
	}
	if rt.closed.Load() != 0 {
		t.Fatal("runtime closed under a running request")
	}
	release()
	// Idle time counts from when the last request finished.
	if f.m.ExpireIdle(f.advance(14 * time.Minute)) {
		t.Fatal("idle period was not restarted when the request finished")
	}
	if !f.m.ExpireIdle(f.advance(2 * time.Minute)) {
		t.Fatal("did not lock once idle after the request finished")
	}
}

func TestUnlockAfterALockBuildsAFreshRuntime(t *testing.T) {
	f := newFixture(15 * time.Minute)
	first, release, _ := f.m.Acquire(context.Background(), testKey(1))
	release()
	f.m.ExpireIdle(f.advance(16 * time.Minute))

	second, release2, err := f.m.Acquire(context.Background(), testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	if second == first || f.builds.Load() != 2 {
		t.Fatalf("a locked instance reused its old runtime (builds=%d)", f.builds.Load())
	}
}

func TestLockWaitsForRunningRequests(t *testing.T) {
	f := newFixture(15 * time.Minute)
	rt, release, _ := f.m.Acquire(context.Background(), testKey(1))

	locked := make(chan struct{})
	go func() { f.m.Lock(); close(locked) }()

	select {
	case <-locked:
		t.Fatal("Lock returned while a request still held the runtime")
	case <-time.After(50 * time.Millisecond):
	}
	if rt.closed.Load() != 0 {
		t.Fatal("runtime closed while a request still held it")
	}
	release()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		t.Fatal("Lock did not finish after the request released")
	}
	if rt.closed.Load() != 1 || f.m.Unlocked() {
		t.Fatalf("after Lock: closed=%d unlocked=%v", rt.closed.Load(), f.m.Unlocked())
	}
}

func TestReleaseIsSafeToCallTwice(t *testing.T) {
	f := newFixture(15 * time.Minute)
	_, release, _ := f.m.Acquire(context.Background(), testKey(1))
	_, release2, _ := f.m.Acquire(context.Background(), testKey(1))
	release()
	release() // must not count as releasing the second request
	if f.m.ExpireIdle(f.advance(time.Hour)) {
		t.Fatal("a double release let the instance lock under a running request")
	}
	release2()
}

func TestAnUnexpectedKeyIsRefused(t *testing.T) {
	// One instance has one key. A different one while unlocked means
	// something is badly wrong; it must not be served the running runtime.
	f := newFixture(15 * time.Minute)
	_, release, _ := f.m.Acquire(context.Background(), testKey(1))
	defer release()
	if _, _, err := f.m.Acquire(context.Background(), testKey(2)); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("err = %v, want ErrKeyMismatch", err)
	}
}

func TestRunLocksOnShutdown(t *testing.T) {
	f := newFixture(15 * time.Minute)
	rt, release, _ := f.m.Acquire(context.Background(), testKey(1))
	release()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.m.Run(ctx, time.Millisecond); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if rt.closed.Load() != 1 || f.m.Unlocked() {
		t.Fatal("shutdown left the instance unlocked")
	}
}

func TestRunLocksAnIdleInstanceByItself(t *testing.T) {
	f := newFixture(10 * time.Millisecond)
	f.m.now = time.Now // real clock for this one
	rt, release, _ := f.m.Acquire(context.Background(), testKey(1))
	release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.m.Run(ctx, 2*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for rt.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if rt.closed.Load() != 1 {
		t.Fatal("the idle instance was never locked")
	}
}

// A bug or a stalled network call while unlocking must not wedge the
// instance: it has to end up locked and able to try again.
func TestAPanicWhileUnlockingLeavesTheInstanceLockedAndRetryable(t *testing.T) {
	explode := true
	m := New(func(context.Context, vault.Key) (*fakeRuntime, error) {
		if explode {
			panic("nil map in the builder")
		}
		return &fakeRuntime{}, nil
	}, 15*time.Minute)

	if _, _, err := m.Acquire(context.Background(), testKey(1)); err == nil {
		t.Fatal("Acquire reported success although unlocking panicked")
	}
	if m.Unlocked() {
		t.Fatal("unlocked after a panic")
	}
	explode = false
	done := make(chan error, 1)
	go func() {
		_, release, err := m.Acquire(context.Background(), testKey(1))
		if err == nil {
			release()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retry after a panic: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the instance is wedged after a panic: Acquire never returned")
	}
}

func TestUnlockingHasADeadline(t *testing.T) {
	var deadline time.Time
	var has bool
	m := New(func(ctx context.Context, _ vault.Key) (*fakeRuntime, error) {
		deadline, has = ctx.Deadline()
		return &fakeRuntime{}, nil
	}, 15*time.Minute)
	_, release, err := m.Acquire(context.Background(), testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if !has || time.Until(deadline) > unlockTimeout || time.Until(deadline) <= 0 {
		t.Fatalf("unlock ran with deadline=%v (set=%v), want one within %v", deadline, has, unlockTimeout)
	}
}

// A request that gives up must not cancel the unlock the others wait on.
func TestUnlockSurvivesTheFirstCallerGoingAway(t *testing.T) {
	m := New(func(ctx context.Context, _ vault.Key) (*fakeRuntime, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &fakeRuntime{}, nil
	}, 15*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, release, err := m.Acquire(ctx, testKey(1)); err != nil {
		t.Fatalf("a cancelled caller aborted the unlock: %v", err)
	} else {
		release()
	}
}

type panickyRuntime struct{}

func (panickyRuntime) Close() error { panic("close blew up") }

func TestAPanicWhileLockingStillLeavesTheInstanceLocked(t *testing.T) {
	m := New(func(context.Context, vault.Key) (panickyRuntime, error) { return panickyRuntime{}, nil }, 15*time.Minute)
	_, release, err := m.Acquire(context.Background(), testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	release()
	done := make(chan struct{})
	go func() { m.Lock(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Lock never returned after the runtime's Close panicked")
	}
	if m.Unlocked() {
		t.Fatal("still unlocked after Lock")
	}
}
