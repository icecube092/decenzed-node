package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/domainlist"
	"decenzed/node_app/internal/duckdns"
	"decenzed/node_app/internal/nodestats"
	"decenzed/node_app/internal/throttle"
	"decenzed/node_app/internal/traffic"
	"decenzed/node_app/internal/xraygen"
	"decenzed/node_app/internal/xrayrt"
)

func cmdStart() error {
	c, err := loadConfig()
	if err != nil || c.RealityPublicKey == "" {
		return fmt.Errorf("run 'setup' first")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runNode(ctx)
}

// runNode is the core loop, run by the OS service and by `start`. It starts
// xray with the configured clients, the per-user throttle proxy, tallies
// traffic, keeps DuckDNS pointed at the current IP, and writes stats. No server.
func runNode(ctx context.Context) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if closeLog := setupDaemonLog(path); closeLog != nil {
		defer closeLog()
	}
	c, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config: %w — run 'setup' first", err)
	}

	rt := xrayrt.NewXray()
	xcfg, err := xraygen.Generate(inputFromConfig(c)).JSON()
	if err != nil {
		return fmt.Errorf("generate xray config: %w", err)
	}
	if err := rt.Start(ctx, xcfg); err != nil {
		return fmt.Errorf("start xray: %w", err)
	}
	defer rt.Stop()

	if c.MaxUserBps > 0 {
		inner := innerPortFor(c.Port)
		px := throttle.NewProxy(fmt.Sprintf(":%d", c.Port), fmt.Sprintf("127.0.0.1:%d", inner), c.MaxUserBps)
		go func() {
			log.Printf("throttle: per-user cap %.0f Mbit/s, proxy :%d -> 127.0.0.1:%d", mbit(c.MaxUserBps), c.Port, inner)
			if err := px.Run(ctx); err != nil {
				log.Println("throttle proxy exited:", err)
			}
		}()
	}

	var lastSnap traffic.Snapshot
	log.Printf("node started; %d client(s)", len(c.Clients))

	statsPath := nodestats.Path(path)
	st, _ := nodestats.Load(statsPath)
	st.StartedAt = time.Now()
	st.Running = true
	st.Port = c.Port
	st.ClientsConfigured = len(c.Clients)
	st.BandwidthCap = c.MaxUserBps
	_ = nodestats.Save(statsPath, st)

	var load loadWindow
	lastActive := map[string]time.Time{}

	// Point DuckDNS at our current IP right away, then keep it fresh on each tick.
	lastPublicIP := c.PublicIP
	updateDuckDNS(ctx, c, &lastPublicIP)

	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			st.Running = false
			st.UpdatedAt = time.Now()
			_ = nodestats.Save(statsPath, st)
			return nil
		case now := <-tick.C:
			cur, sErr := rt.Stats()
			if sErr != nil {
				log.Println("stats:", sErr)
				continue
			}
			deltas := traffic.ComputeDeltas(lastSnap, cur)
			lastSnap = cur
			var tickBytes uint64
			for uuid, d := range deltas {
				st.TotalUp += d.Up
				st.TotalDown += d.Down
				tickBytes += d.Total()
				if d.Total() > 0 {
					lastActive[uuid] = now
				}
			}
			st.RecentBps = load.add(now, tickBytes)
			st.ActiveClients = len(activeSince(lastActive, now.Add(-30*time.Minute)))
			st.UpdatedAt = now
			_ = nodestats.Save(statsPath, st)

			updateDuckDNS(ctx, c, &lastPublicIP)
		}
	}
}

// pointDuckDNS updates the node's DuckDNS domain to the current public IP once,
// unconditionally, and returns the IP it set. Used by the interactive setup/check
// flows so they can report success or failure to the operator.
func pointDuckDNS(ctx context.Context, c config.AppConfig) (string, error) {
	if c.DuckDNSHost() == "" {
		return "", fmt.Errorf("duckdns is not configured")
	}
	ip := fetchPublicIP()
	if ip == "" {
		return "", fmt.Errorf("could not detect your public IP")
	}
	if err := duckdns.Update(ctx, c.DuckDNSDomain(), c.DuckDNSToken, ip); err != nil {
		return "", err
	}
	return ip, nil
}

// updateDuckDNS points the node's DuckDNS domain at its current IP, but ONLY
// when the IP changed since the last successful update (avoids needless calls).
func updateDuckDNS(ctx context.Context, c config.AppConfig, lastIP *string) {
	if c.DuckDNSHost() == "" {
		return
	}
	ip := fetchPublicIP()
	if ip == "" || ip == *lastIP {
		return
	}
	if err := duckdns.Update(ctx, c.DuckDNSDomain(), c.DuckDNSToken, ip); err != nil {
		log.Println("duckdns:", err)
		return
	}
	*lastIP = ip
	log.Printf("duckdns: %s -> %s", c.DuckDNSHost(), ip)
}

// --- xray input ---

func inputFromConfig(c config.AppConfig) xraygen.Input {
	eff := domainlist.Policy{OverrideAllow: c.DomainAllow, OverrideDeny: c.DomainDeny}.Resolve()
	in := xraygen.Input{
		Port:            c.Port,
		UUIDs:           c.UUIDs(),
		RealityDest:     c.RealityDest,
		RealityNames:    c.RealityServerName,
		RealityPrivKey:  c.RealityPrivateKey,
		RealityShortIDs: c.RealityShortIDs,
		BlockBittorrent: c.BlocksBittorrent(),
		DomainAllow:     eff.Allow,
		DomainDeny:      eff.Deny,
		StatsEnabled:    true,
	}
	if c.MaxUserBps > 0 {
		in.Port = innerPortFor(c.Port)
		in.ListenAddr = "127.0.0.1"
	}
	return in
}

func innerPortFor(p int) int {
	ip := p + 10000
	if ip > 65535 {
		ip = p - 10000
	}
	if ip < 1 {
		ip = 24443
	}
	return ip
}

// --- load window ---

type loadWindow struct{ samples []loadSample }
type loadSample struct {
	t     time.Time
	bytes uint64
}

func (w *loadWindow) add(now time.Time, bytes uint64) float64 {
	w.samples = append(w.samples, loadSample{now, bytes})
	cutoff := now.Add(-10 * time.Minute)
	i := 0
	for i < len(w.samples) && w.samples[i].t.Before(cutoff) {
		i++
	}
	w.samples = w.samples[i:]
	if len(w.samples) == 0 {
		return 0
	}
	var total uint64
	for _, s := range w.samples {
		total += s.bytes
	}
	span := now.Sub(w.samples[0].t).Seconds()
	if span < 1 {
		span = 30
	}
	return float64(total) / span
}

func activeSince(m map[string]time.Time, cutoff time.Time) []string {
	var out []string
	for uuid, t := range m {
		if t.Before(cutoff) {
			delete(m, uuid)
			continue
		}
		out = append(out, uuid)
	}
	return out
}
