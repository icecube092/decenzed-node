// Package xrayrt wraps the embedded xray-core instance.
//
// Per the design decision (NODE-CLI §2), xray-core is embedded as a library and
// run inside a SUPERVISED goroutine with panic recovery, so a crash in the data
// plane does not take down the agent/billing. The real implementation will wrap
// xray-core's core.Instance (core.New / Start / Close) and its StatsManager /
// HandlerService; StubRuntime is used for tests and until that dependency is
// wired.
package xrayrt

import (
	"context"
	"log"
	"sync"
	"time"

	"decenzed/node_app/internal/traffic"
)

// Runtime is the surface the agent uses to drive xray.
type Runtime interface {
	// Start launches xray with the given generated config JSON.
	Start(ctx context.Context, xrayConfigJSON []byte) error
	// Stop shuts xray down.
	Stop() error
	// Stats returns current cumulative per-UUID counters (from xray Stats API).
	Stats() (traffic.Snapshot, error)
	// SetActiveUUIDs adds/removes clients without a full restart (HandlerService),
	// used for quota revocation and new subscriptions.
	SetActiveUUIDs(uuids []string) error
}

// Supervise runs fn, restarting it on panic or error, until ctx is cancelled.
// This is the recover()+watchdog pattern that isolates xray crashes from the
// control plane. backoff caps restart churn.
func Supervise(ctx context.Context, name string, backoff time.Duration, fn func(context.Context) error) {
	for {
		if ctx.Err() != nil {
			return
		}
		runOnce(ctx, name, fn)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// runOnce isolates a single invocation so a panic is recovered and turned into
// a restart rather than a process crash.
func runOnce(ctx context.Context, name string, fn func(context.Context) error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("supervise[%s]: recovered panic: %v", name, r)
		}
	}()
	if err := fn(ctx); err != nil {
		log.Printf("supervise[%s]: exited: %v", name, err)
	}
}

// StubRuntime is an in-memory Runtime for tests/dev. It does not run real xray;
// tests set the counters it returns.
type StubRuntime struct {
	mu       sync.Mutex
	started  bool
	snapshot traffic.Snapshot
	active   []string
}

func NewStub() *StubRuntime { return &StubRuntime{snapshot: traffic.Snapshot{}} }

func (s *StubRuntime) Start(_ context.Context, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = true
	return nil
}

func (s *StubRuntime) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = false
	return nil
}

func (s *StubRuntime) Stats() (traffic.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// return a copy so callers can't mutate internal state
	out := make(traffic.Snapshot, len(s.snapshot))
	for k, v := range s.snapshot {
		out[k] = v
	}
	return out, nil
}

func (s *StubRuntime) SetActiveUUIDs(uuids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = append([]string(nil), uuids...)
	return nil
}

// SetStats is a test helper to inject cumulative counters.
func (s *StubRuntime) SetStats(snap traffic.Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snap
}
