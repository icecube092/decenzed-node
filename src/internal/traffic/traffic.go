// Package traffic computes per-subscription traffic deltas from the cumulative
// counters exposed by xray-core's Stats API and packages them into canonical,
// idempotent reports for the root server (ROOT-SERVER §6.5).
package traffic

import (
	"encoding/json"
	"sort"
	"time"
)

// Counter holds cumulative bytes for one subscription (VLESS UUID) per
// direction, as read from xray Stats.
type Counter struct {
	Up   uint64
	Down uint64
}

// Total returns up+down. Billing and payout use the SUM of both directions —
// the node carried traffic both ways (the "трафик = up+down" convention).
func (c Counter) Total() uint64 { return c.Up + c.Down }

// Snapshot maps subscription UUID -> cumulative counter at a point in time.
type Snapshot map[string]Counter

// ComputeDeltas returns the traffic consumed since the previous snapshot.
//
// TRICKY: xray's counters are cumulative and RESET TO ZERO when xray restarts.
// A naive (current - previous) subtraction on uint64 would underflow to a huge
// bogus value after a restart. We detect a reset per-direction: if the current
// value is LOWER than the previous one, xray restarted and the current value is
// itself the delta (it has been counting up from zero). UUIDs absent from prev
// are new clients and also count from zero.
func ComputeDeltas(prev, cur Snapshot) Snapshot {
	out := make(Snapshot, len(cur))
	for uuid, c := range cur {
		p := prev[uuid] // zero value {0,0} if the UUID is new
		out[uuid] = Counter{
			Up:   deltaOne(p.Up, c.Up),
			Down: deltaOne(p.Down, c.Down),
		}
	}
	return out
}

func deltaOne(prev, cur uint64) uint64 {
	if cur < prev {
		// counter reset (xray restart) -> the current value IS the delta
		return cur
	}
	return cur - prev
}

// Item is a single subscription's delta in a report.
type Item struct {
	UUID string `json:"uuid"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// Report is one epoch's signed-and-shipped traffic batch.
type Report struct {
	NodeID  string `json:"node_id"`
	EpochID uint64 `json:"epoch_id"`
	TS      int64  `json:"ts"` // unix seconds
	Items   []Item `json:"items"`
}

// BuildReport turns a delta snapshot into a canonical report ready to sign.
// Zero-delta entries are omitted (keeps reports small). Items are sorted by
// UUID so the marshalled bytes are DETERMINISTIC — the same deltas always
// produce the same signature input, which matters for idempotent dedup on root.
func BuildReport(nodeID string, epoch uint64, ts time.Time, deltas Snapshot) Report {
	items := make([]Item, 0, len(deltas))
	for uuid, c := range deltas {
		if c.Up == 0 && c.Down == 0 {
			continue
		}
		items = append(items, Item{UUID: uuid, Up: c.Up, Down: c.Down})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UUID < items[j].UUID })
	return Report{NodeID: nodeID, EpochID: epoch, TS: ts.Unix(), Items: items}
}

// SigningBytes returns the canonical JSON encoding used as the signed message.
func (r Report) SigningBytes() ([]byte, error) { return json.Marshal(r) }
