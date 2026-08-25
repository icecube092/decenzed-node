package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"decenzed/node_app/internal/acme"
	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/domainlist"
	"decenzed/node_app/internal/duckdns"
	"decenzed/node_app/internal/nodestats"
	"decenzed/node_app/internal/site"
	"decenzed/node_app/internal/throttle"
	"decenzed/node_app/internal/traffic"
	"decenzed/node_app/internal/xraygen"
	"decenzed/node_app/internal/xrayrt"
)

func cmdStart() error {
	c, err := loadConfig()
	if err != nil || !c.IsConfigured() {
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

	// TLS camouflage: obtain the certificate (blocking, so the files exist before
	// xray starts) and serve the decoy website xray falls back to.
	if c.CamouflageTLS() {
		if err := provisionTLS(ctx, c); err != nil {
			return fmt.Errorf("tls camouflage: %w", err)
		}
		go func() {
			log.Printf("site: serving decoy website + subscriptions on %s (xray fallback target)", c.SiteAddr())
			if err := site.Serve(ctx, c.SiteAddr(), subscriptionFunc(c)); err != nil {
				log.Println("site server exited:", err)
			}
		}()
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

	// Tell the runtime which users to read stats for; without this the per-UUID
	// counter lookups have nothing to iterate and traffic always reads zero.
	if err := rt.SetActiveUUIDs(c.UUIDs()); err != nil {
		log.Println("stats: track users:", err)
	}

	// Track per-inbound counters too, and map each xray tag to a display label
	// (the two Shadowsocks variants share a protocol id but differ by cipher).
	var inboundTags []string
	tagLabel := map[string]string{}
	for _, ib := range c.PublicInbounds() {
		tag := xraygen.InboundTag(ib.Protocol, ib.Method)
		inboundTags = append(inboundTags, tag)
		tagLabel[tag] = protoLabel(ib)
	}
	if err := rt.SetInboundTags(inboundTags); err != nil {
		log.Println("stats: track inbounds:", err)
	}

	if c.MaxUserBps > 0 {
		// One throttle proxy per public inbound: xray listens on 127.0.0.1:inner
		// (see inputFromConfig) and each proxy fronts the real public port.
		for _, ib := range c.PublicInbounds() {
			inner := innerPortFor(ib.Port)
			px := throttle.NewProxy(fmt.Sprintf(":%d", ib.Port), fmt.Sprintf("127.0.0.1:%d", inner), c.MaxUserBps)
			proto, pub := ib.Protocol, ib.Port
			go func() {
				log.Printf("throttle: per-user cap %.0f Mbit/s, %s proxy :%d -> 127.0.0.1:%d", mbit(c.MaxUserBps), proto, pub, inner)
				if err := px.Run(ctx); err != nil {
					log.Println("throttle proxy exited:", err)
				}
			}()
		}
	}

	var lastSnap, lastInbound traffic.Snapshot
	log.Printf("node started; %d client(s)", len(c.Clients))

	statsPath := nodestats.Path(path)
	st, _ := nodestats.Load(statsPath)
	st.StartedAt = time.Now()
	st.Running = true
	st.Port = c.Port
	st.ClientsConfigured = len(c.Clients)
	st.BandwidthCap = c.MaxUserBps
	if st.PerClient == nil {
		st.PerClient = map[string]nodestats.DirBytes{}
	}
	if st.PerInbound == nil {
		st.PerInbound = map[string]nodestats.DirBytes{}
	}
	_ = nodestats.Save(statsPath, st)

	var load loadWindow
	lastActive := map[string]time.Time{}

	// Point DuckDNS at our current IP right away, then keep it fresh on each tick.
	lastPublicIP := c.PublicIP
	updateDuckDNS(ctx, c, &lastPublicIP)

	// Certificate renewal check cadence (TLS mode). We just provisioned above, so
	// start the clock now; EnsureCert is a cheap no-op until <30 days to expiry.
	lastCertCheck := time.Now()

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
				pc := st.PerClient[uuid]
				pc.Up += d.Up
				pc.Down += d.Down
				st.PerClient[uuid] = pc
			}

			// Per-inbound lifetime totals (across all users on that inbound).
			if curIn, iErr := rt.InboundStats(); iErr == nil {
				for tag, d := range traffic.ComputeDeltas(lastInbound, curIn) {
					label := tagLabel[tag]
					if label == "" {
						label = tag
					}
					pi := st.PerInbound[label]
					pi.Up += d.Up
					pi.Down += d.Down
					st.PerInbound[label] = pi
				}
				lastInbound = curIn
			}

			st.RecentBps = load.add(now, tickBytes)
			st.ActiveClients = len(activeSince(lastActive, now.Add(-30*time.Minute)))
			st.UpdatedAt = now
			_ = nodestats.Save(statsPath, st)

			updateDuckDNS(ctx, c, &lastPublicIP)
			maybeRenewCert(ctx, c, &lastCertCheck, now)
		}
	}
}

// provisionTLS obtains (or renews) the node's Let's Encrypt certificate for TLS
// camouflage via the DNS-01 challenge, publishing the TXT record through DuckDNS.
// It blocks until the cert files are in place (or fails).
func provisionTLS(ctx context.Context, c config.AppConfig) error {
	dir, err := dataDir()
	if err != nil {
		return err
	}
	sub, token := c.DuckDNSDomain(), c.DuckDNSToken
	if sub == "" || token == "" {
		return fmt.Errorf("TLS mode needs a DuckDNS token + subdomain for the DNS-01 challenge — re-run setup")
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	_, _, err = acme.EnsureCert(cctx, acme.Params{
		Domain:   c.TLSHost(),
		Email:    c.ACMEEmail,
		AgreeTOS: c.ACMEAgreeTOS,
		Dir:      dir, // decenzed-data: cert.pem / key.pem / account.key live here
		SetTXT:   func(ctx context.Context, v string) error { return duckdns.SetTXT(ctx, sub, token, v) },
		ClearTXT: func(ctx context.Context) error { return duckdns.ClearTXT(ctx, sub, token) },
	})
	return err
}

// maybeRenewCert runs a certificate renewal check about once a day in TLS mode.
// EnsureCert is idempotent and only reaches the CA when the cert is within 30
// days of expiry; on success xray hot-reloads the new files (no restart). Runs
// in the background so the actual renewal never stalls the stats tick.
func maybeRenewCert(ctx context.Context, c config.AppConfig, last *time.Time, now time.Time) {
	if !c.CamouflageTLS() || now.Sub(*last) < 12*time.Hour {
		return
	}
	*last = now
	go func() {
		if err := provisionTLS(ctx, c); err != nil {
			log.Println("cert renewal:", err)
		}
	}()
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

	// Camouflage params shared by the VLESS/Trojan inbounds — either REALITY or
	// real TLS with a fallback to the node's own website. Exactly one is set on
	// each inbound, per the node-wide Camouflage tumbler.
	reality := &xraygen.RealitySpec{
		Dest:     c.RealityDest,
		Names:    c.RealityServerName,
		PrivKey:  c.RealityPrivateKey,
		ShortIDs: c.RealityShortIDs,
	}
	certFile, keyFile := certPaths()
	tls := &xraygen.TLSSpec{
		ServerName:   c.TLSHost(),
		CertFile:     certFile,
		KeyFile:      keyFile,
		FallbackDest: c.SiteAddr(),
	}
	// setCamouflage applies the active mode to a VLESS/Trojan inbound spec.
	setCamouflage := func(spec *xraygen.InboundSpec) {
		if c.CamouflageTLS() {
			spec.TLS = tls
		} else {
			spec.Reality = reality
		}
	}

	var specs []xraygen.InboundSpec
	for _, ib := range c.PublicInbounds() {
		port, listen := ib.Port, ""
		// Behind the per-user throttle, xray listens on localhost and the proxy
		// fronts the real port (see runNode).
		if c.MaxUserBps > 0 {
			port, listen = innerPortFor(ib.Port), "127.0.0.1"
		}
		spec := xraygen.InboundSpec{Protocol: ib.Protocol, Port: port, ListenAddr: listen}
		switch ib.Protocol {
		case config.ProtoVLESS:
			setCamouflage(&spec)
			for _, cl := range c.Clients {
				spec.Clients = append(spec.Clients, xraygen.ClientCred{ID: cl.UUID, Email: cl.UUID})
			}
		case config.ProtoTrojan:
			setCamouflage(&spec)
			for _, cl := range c.Clients {
				spec.Clients = append(spec.Clients, xraygen.ClientCred{Password: cl.UUID, Email: cl.UUID})
			}
		case config.ProtoShadowsocks:
			spec.SSMethod = ib.Method
			if config.IsSS2022(ib.Method) {
				// SS-2022: server-wide key + per-user PSK derived from the UUID.
				spec.SSServerKey = c.SSServerKey
				for _, cl := range c.Clients {
					spec.Clients = append(spec.Clients, xraygen.ClientCred{Password: config.SSUserPSK(cl.UUID), Email: cl.UUID})
				}
			} else {
				// Classic AEAD: per-client password is the UUID.
				for _, cl := range c.Clients {
					spec.Clients = append(spec.Clients, xraygen.ClientCred{Password: cl.UUID, Email: cl.UUID})
				}
			}
		}
		specs = append(specs, spec)
	}

	return xraygen.Input{
		Inbounds:        specs,
		BlockBittorrent: c.BlocksBittorrent(),
		DomainAllow:     eff.Allow,
		DomainDeny:      eff.Deny,
		StatsEnabled:    true,
	}
}

// certPaths returns the cert/key file paths xray reads in TLS mode. They live in
// the data dir next to config.json; the acme manager writes them there.
func certPaths() (certFile, keyFile string) {
	dir, err := dataDir()
	if err != nil {
		return "cert.pem", "key.pem"
	}
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
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
