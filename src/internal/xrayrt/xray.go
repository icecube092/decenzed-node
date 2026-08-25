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
	"sync/atomic"

	"decenzed/node_app/internal/traffic"

	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// LogSink receives xray-core log lines, already mapped to a level string
// ("error"/"warn"/"info"/"debug").
type LogSink func(level, text string)

// XrayRuntime embeds a xray-core instance.
type XrayRuntime struct {
	mu       sync.Mutex
	inst     *core.Instance
	statsMgr stats.Manager
	uuids    []string // users to query stats for (see Stats)
	tags     []string // inbound tags to query stats for (see InboundStats)

	sink  LogSink     // where captured xray logs go (nil = discard)
	debug atomic.Bool // when false, xray info/debug lines are dropped
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
	// core.New built xray's app/log, which registered its own log handler. Override
	// it BEFORE Start so we capture every xray log line — including startup banners
	// and any startup errors — into the node's log file instead of the console.
	// Re-done on each (re)start because a fresh app/log re-registers.
	if x.sink != nil {
		xlog.RegisterHandler(xrayLogHandler{x})
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

// SetLogSink installs the destination for captured xray logs (takes effect on
// the next Start). SetDebug toggles whether xray info/debug lines are kept.
func (x *XrayRuntime) SetLogSink(sink LogSink) { x.sink = sink }

// SetDebug controls xray log verbosity: when false, only warnings and errors are
// forwarded to the sink; when true, info and debug lines are kept too.
func (x *XrayRuntime) SetDebug(on bool) { x.debug.Store(on) }

// xrayLogHandler adapts xray's common/log.Handler to the node's LogSink,
// mapping severity to a level string and dropping info/debug unless debug mode
// is on.
type xrayLogHandler struct{ rt *XrayRuntime }

func (h xrayLogHandler) Handle(msg xlog.Message) {
	sev := xlog.Severity_Info
	if gm, ok := msg.(*xlog.GeneralMessage); ok {
		sev = gm.Severity
	}
	// Lower numeric severity is more severe (Error < Warning < Info < Debug).
	if sev > xlog.Severity_Warning && !h.rt.debug.Load() {
		return
	}
	var level string
	switch sev {
	case xlog.Severity_Error:
		level = "error"
	case xlog.Severity_Warning:
		level = "warn"
	case xlog.Severity_Debug:
		level = "debug"
	default:
		level = "info"
	}
	h.rt.sink(level, msg.String())
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

// InboundStats reads per-inbound cumulative counters for the tracked tags.
//
// xray names inbound traffic counters "inbound>>>{tag}>>>traffic>>>{uplink|
// downlink}" (enabled by the system stats policy). These aggregate ALL users on
// that inbound — xray does not expose a per-inbound-per-user cross, so a full
// protocol×client matrix is not available from the core.
func (x *XrayRuntime) InboundStats() (traffic.Snapshot, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	out := traffic.Snapshot{}
	if x.statsMgr == nil {
		return out, nil
	}
	for _, tag := range x.tags {
		up := counterValue(x.statsMgr, "inbound>>>"+tag+">>>traffic>>>uplink")
		down := counterValue(x.statsMgr, "inbound>>>"+tag+">>>traffic>>>downlink")
		if up == 0 && down == 0 {
			continue
		}
		out[tag] = traffic.Counter{Up: up, Down: down}
	}
	return out, nil
}

// SetInboundTags records which inbound tags to track for per-inbound stats.
func (x *XrayRuntime) SetInboundTags(tags []string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.tags = append([]string(nil), tags...)
	return nil
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
