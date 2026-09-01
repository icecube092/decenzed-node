package commands

import (
	"fmt"
	"os"
	"sort"
	"time"

	"decenzed/node_app/internal/config"
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

	// Enabled protocols + debug mode (from the saved config, if present).
	c, cfgErr := loadConfig()
	if cfgErr == nil {
		fmt.Printf("protocols:       %s\n", enabledProtocolsLine(c))
		fmt.Printf("debug mode:      %s\n", onOff(c.Debug))
	}

	fmt.Println("traffic (up+down):")
	fmt.Printf("  lifetime:      up %s / down %s  (total %s)\n",
		humanBytes(st.TotalUp), humanBytes(st.TotalDown), humanBytes(st.TotalUp+st.TotalDown))
	fmt.Printf("  load (10 min): %.1f Mbit/s total (overall bandwidth is not capped)\n", mbit(st.RecentBps))

	if cfgErr == nil {
		printPerInbound(c, st)
		printPerClient(c, st)
	}
	return nil
}

// enabledProtocolsLine lists the node's enabled inbounds as "label:port".
func enabledProtocolsLine(c config.AppConfig) string {
	ibs := c.PublicInbounds()
	if len(ibs) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ibs))
	for _, ib := range ibs {
		// Show the public (dialed) port; note the bind port when a forward remaps it.
		if ib.Remapped() {
			parts = append(parts, fmt.Sprintf("%s:%d(->%d)", protoLabel(ib), ib.PublicPort, ib.Port))
		} else {
			parts = append(parts, fmt.Sprintf("%s:%d", protoLabel(ib), ib.PublicPort))
		}
	}
	return joinComma(parts)
}

// printPerInbound shows lifetime traffic per protocol (across all clients). xray
// counts per-inbound and per-user separately, so this is a per-protocol total,
// not a per-protocol-per-client breakdown.
func printPerInbound(c config.AppConfig, st nodestats.Snapshot) {
	if len(st.PerInbound) == 0 {
		return
	}
	fmt.Println("per protocol (up+down):")
	for _, ib := range c.PublicInbounds() {
		label := protoLabel(ib)
		d := st.PerInbound[label]
		fmt.Printf("  %-14s %s  (up %s / down %s)\n",
			label+":", humanBytes(d.Total()), humanBytes(d.Up), humanBytes(d.Down))
	}
}

// printPerClient shows lifetime traffic per client (across all protocols they
// used), most traffic first. Names come from the config; unnamed clients show a
// short UUID prefix.
func printPerClient(c config.AppConfig, st nodestats.Snapshot) {
	if len(st.PerClient) == 0 {
		return
	}
	name := map[string]string{}
	for _, cl := range c.Clients {
		n := cl.Name
		if n == "" {
			n = cl.UUID[:8]
		}
		name[cl.UUID] = n
	}
	type row struct {
		label string
		d     nodestats.DirBytes
	}
	rows := make([]row, 0, len(st.PerClient))
	for uuid, d := range st.PerClient {
		label, ok := name[uuid]
		if !ok {
			label = uuid[:8] // a client removed since it last used traffic
		}
		rows = append(rows, row{label, d})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].d.Total() > rows[j].d.Total() })

	// The speed cap is applied PER CLIENT, so it belongs here (not on the overall
	// load, which is uncapped).
	capNote := "  ·  no per-user speed cap"
	if c.MaxUserBps > 0 {
		capNote = fmt.Sprintf("  ·  per-user speed cap: %.0f Mbit/s each", mbit(c.MaxUserBps))
	}
	fmt.Printf("per client (up+down)%s:\n", capNote)
	for _, r := range rows {
		fmt.Printf("  %-14s %s  (up %s / down %s)\n",
			r.label+":", humanBytes(r.d.Total()), humanBytes(r.d.Up), humanBytes(r.d.Down))
	}
}

// joinComma joins parts with ", ".
func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

func runStatus(st nodestats.Snapshot) string {
	svcState := "unknown"
	if procdAvailable() {
		svcState = procdStatusString()
	} else if svc, err := newService(); err == nil {
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
