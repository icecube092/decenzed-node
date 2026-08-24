package commands

import (
	"fmt"
	"os"
	"time"

	"decenzed/node_app/internal/nodestats"
)

func cmdStats() error {
	path, _ := configPath()
	st, err := nodestats.Load(nodestats.Path(path))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no stats yet — run 'service install' and let it run a minute")
		}
		return err
	}
	freshness := "live"
	if st.UpdatedAt.IsZero() {
		freshness = "no updates yet"
	} else if age := time.Since(st.UpdatedAt); age > 3*time.Minute {
		freshness = fmt.Sprintf("STALE — last update %s ago", age.Round(time.Second))
	}

	fmt.Printf("run:             %s\n", runStatus(st))
	fmt.Printf("clients:         %d configured · %d active\n", st.ClientsConfigured, st.ActiveClients)
	if st.Running && !st.StartedAt.IsZero() {
		fmt.Printf("uptime:          %s\n", time.Since(st.StartedAt).Round(time.Second))
	}
	fmt.Printf("data feed:       %s\n", freshness)

	fmt.Println("traffic (up+down):")
	fmt.Printf("  lifetime:      up %s / down %s  (total %s)\n",
		humanBytes(st.TotalUp), humanBytes(st.TotalDown), humanBytes(st.TotalUp+st.TotalDown))
	fmt.Printf("  load (10 min): %s\n", loadLine(st))
	return nil
}

func runStatus(st nodestats.Snapshot) string {
	svcState := "unknown"
	if svc, err := newService(); err == nil {
		if s, sErr := svc.Status(); sErr == nil {
			svcState = statusString(s)
		}
	}
	switch {
	case svcState == "running":
		return "running (service)"
	case st.Running && time.Since(st.UpdatedAt) < 3*time.Minute:
		return "running (foreground)"
	case svcState == "stopped":
		return "stopped (service installed, not running)"
	default:
		return "stopped"
	}
}

func loadLine(st nodestats.Snapshot) string {
	cur := mbit(st.RecentBps)
	if st.BandwidthCap > 0 {
		return fmt.Sprintf("%.1f Mbit/s of %.0f Mbit/s cap (%.0f%%)", cur, mbit(st.BandwidthCap), st.RecentBps/st.BandwidthCap*100)
	}
	return fmt.Sprintf("%.1f Mbit/s (uncapped)", cur)
}

func mbit(bps float64) float64 { return bps * 8 / 1e6 }

func humanBytes(b uint64) string {
	const k = 1000.0
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	f := float64(b)
	i := 0
	for f >= k && i < len(units)-1 {
		f /= k
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", b)
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}
