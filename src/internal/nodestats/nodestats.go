// Package nodestats persists a small runtime snapshot the daemon writes and the
// CLI reads. The `decenzed-node stats` command runs as a SEPARATE process from
// the running daemon, so it cannot read xray's in-memory counters directly;
// instead the daemon writes this snapshot (traffic totals, quota, last root
// status) to stats.json every tick, and the CLI renders it.
package nodestats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Snapshot is the daemon's last-known runtime state.
type Snapshot struct {
	UpdatedAt time.Time `json:"updated_at"`
	StartedAt time.Time `json:"started_at"`

	// Whether the daemon loop is currently running (set false on clean shutdown).
	Running bool `json:"running"`

	// Clients configured vs. active in the last ~30 min.
	ClientsConfigured int `json:"clients_configured"`
	ActiveClients     int `json:"active_clients"`

	// Approximate current load: average throughput over the last ~10 minutes,
	// and the configured per-user cap (bytes/sec; 0 = uncapped).
	RecentBps    float64 `json:"recent_bps"`
	BandwidthCap float64 `json:"bandwidth_cap_bps"`

	// Traffic (bytes). Total* are lifetime and persist across restarts; Period*
	// are the current monthly period.
	TotalUp    uint64 `json:"total_up"`
	TotalDown  uint64 `json:"total_down"`
	PeriodUsed uint64 `json:"period_used"`

	// Monthly quota context.
	MonthlyLimit uint64    `json:"monthly_limit"`
	Paused       bool      `json:"paused"`
	PeriodStart  time.Time `json:"period_start"`

	Port int `json:"port"`
}

// Path returns the stats file location given the config file path.
func Path(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "stats.json")
}

// Load reads the snapshot; a missing file returns a zero Snapshot and os.ErrNotExist.
func Load(path string) (Snapshot, error) {
	var s Snapshot
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	return s, nil
}

// Save writes the snapshot atomically (0600).
func Save(path string, s Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
