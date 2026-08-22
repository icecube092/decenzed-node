// Real Runtime backed by an EMBEDDED xray-core instance (the design decision in
// NODE-CLI §2). The blank import of distro/all registers every protocol and
// transport (vless, reality, freedom, blackhole, tcp, …) — without it core.New
// cannot construct the handlers.
package xrayrt

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"decenzed/node_app/internal/traffic"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// XrayRuntime embeds a xray-core instance.
type XrayRuntime struct {
	mu       sync.Mutex
	inst     *core.Instance
	statsMgr stats.Manager
	uuids    []string // users to query stats for (see Stats)
}

// NewXray returns a not-yet-started runtime.
func NewXray() *XrayRuntime { return &XrayRuntime{} }

// compile-time assertion that XrayRuntime satisfies Runtime.
var _ Runtime = (*XrayRuntime)(nil)

// Start loads the generated JSON config and starts xray. If an instance is
// already running it is closed first (restart / hot-reload semantics).
func (x *XrayRuntime) Start(_ context.Context, configJSON []byte) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.inst != nil {
		_ = x.inst.Close()
		x.inst = nil
		x.statsMgr = nil
	}

	cfg, err := serial.LoadJSONConfig(bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("xray: load config: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("xray: new instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("xray: start: %w", err)
	}
	x.inst = inst
	if m, ok := inst.GetFeature(stats.ManagerType()).(stats.Manager); ok {
		x.statsMgr = m
	}
	return nil
}

// Stop closes the instance.
func (x *XrayRuntime) Stop() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.inst == nil {
		return nil
	}
	err := x.inst.Close()
	x.inst = nil
	x.statsMgr = nil
	return err
}

// Stats reads per-user cumulative counters for the tracked UUIDs.
//
// xray names user traffic counters "user>>>{email}>>>traffic>>>{uplink|downlink}".
// The generated config sets email == uuid, so we can look each one up directly.
// This version of xray's stats.Manager has no counter enumeration, hence the
// per-UUID GetCounter lookups (nil counter -> user has no traffic yet -> zero).
func (x *XrayRuntime) Stats() (traffic.Snapshot, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	out := traffic.Snapshot{}
	if x.statsMgr == nil {
		return out, nil
	}
	for _, id := range x.uuids {
		up := counterValue(x.statsMgr, "user>>>"+id+">>>traffic>>>uplink")
		down := counterValue(x.statsMgr, "user>>>"+id+">>>traffic>>>downlink")
		if up == 0 && down == 0 {
			continue
		}
		out[id] = traffic.Counter{Up: up, Down: down}
	}
	return out, nil
}

func counterValue(m stats.Manager, name string) uint64 {
	c := m.GetCounter(name)
	if c == nil {
		return 0
	}
	if v := c.Value(); v > 0 {
		return uint64(v)
	}
	return 0
}

// SetActiveUUIDs records which users to track for stats. Applying the change to
// the running xray (adding/removing clients) is done by the agent via config
// regeneration + Start (restart); a future optimization is xray's
// inbound.Manager user API for zero-downtime add/remove.
func (x *XrayRuntime) SetActiveUUIDs(uuids []string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.uuids = append([]string(nil), uuids...)
	return nil
}
