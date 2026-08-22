// Command decenzed-node is a STANDALONE VLESS + REALITY proxy server you run on
// your own machine. It scans for a camouflage domain, generates its own REALITY
// keys, runs an embedded xray-core, and prints share links you hand to friends.
// There is no coordination server — it is fully self-contained and open source.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"decenzed/node_app/internal/duckdns"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kardianos/service"

	"decenzed/node_app/internal/bytesize"
	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/domainlist"
	"decenzed/node_app/internal/nodestats"
	"decenzed/node_app/internal/quota"
	"decenzed/node_app/internal/realitykeys"
	"decenzed/node_app/internal/realityscan"
	"decenzed/node_app/internal/selfupdate"
	"decenzed/node_app/internal/speedtest"
	"decenzed/node_app/internal/throttle"
	"decenzed/node_app/internal/traffic"
	"decenzed/node_app/internal/winconsole"
	"decenzed/node_app/internal/xraygen"
	"decenzed/node_app/internal/xrayrt"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Daemon mode: launched by the OS service manager (non-interactive).
	if !service.Interactive() {
		if err := runAsService(); err != nil {
			log.Println("service error:", err)
			os.Exit(1)
		}
		return
	}

	stdin := bufio.NewReader(os.Stdin)
	if len(os.Args) < 2 {
		os.Exit(repl(stdin))
	}
	code := 0
	if err := dispatch(stdin, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		code = 1
	}
	winconsole.PauseIfDoubleClicked()
	os.Exit(code)
}

func dispatch(stdin *bufio.Reader, args []string) error {
	switch args[0] {
	case "version":
		fmt.Println("decenzed-node", version)
	case "check":
		return cmdCheck(stdin)
	case "setup":
		return cmdSetup(stdin)
	case "link":
		return cmdLink(args[1:])
	case "start":
		return cmdStart()
	case "service":
		return cmdService(args[1:])
	case "stats":
		return cmdStats()
	case "logs":
		return cmdLogs()
	case "config":
		return cmdConfig(args[1:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}

// repl is the interactive shell: prints stats, then help, then reads commands.
func repl(stdin *bufio.Reader) int {
	fmt.Println("decenzed-node — self-hosted VLESS + REALITY proxy")
	fmt.Println(strings.Repeat("─", 60))
	if err := cmdStats(); err != nil {
		fmt.Println("(no stats yet —", err.Error()+")")
	}
	fmt.Println(strings.Repeat("─", 60))
	usage()
	for {
		fmt.Print("\ndecenzed> ")
		line, err := stdin.ReadString('\n')
		if err != nil {
			return 0
		}
		args := strings.Fields(strings.TrimSpace(line))
		if len(args) == 0 {
			continue
		}
		switch args[0] {
		case "exit", "quit":
			return 0
		case "clear", "cls":
			fmt.Print("\033[H\033[2J")
			continue
		}
		if err := dispatch(stdin, args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	}
}

func usage() {
	fmt.Print(`decenzed-node — run your own proxy, share links with friends

Run with no arguments for an interactive shell (type commands, 'exit' to quit).
Or run one command: decenzed-node <command>

Getting started:
  1. check                  Show public IP, run a speed test, port-forward help.
  2. setup                  Wizard: port, policy, pick a REALITY domain, keys.
  3. service install        Run in the background on boot (needs admin/root).
  4. link                   Print your connection link to share.

Commands:
  link [list]               Print share links for all clients.
  link add [name]           Create a new client (for a friend) and print its link.
  link remove <name|uuid>   Revoke a client.
  start                     Run in the foreground (instead of the service).
  stats                     Traffic totals, quota, load, and run status.
  config node|xray          Show the app-config / generated xray JSON.
  service install|uninstall|start|stop|status
                            Manage the background service.
  logs                      Show the daemon log.
  version · help · exit
`)
}

// --- data dir / config paths ---

// dataDir returns the data directory next to the executable so the OS service
// (which may run as a different user) and your CLI share the same files.
func dataDir() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		if resolved, e := filepath.EvalSymlinks(exe); e == nil {
			exe = resolved
		}
		return filepath.Join(filepath.Dir(exe), "decenzed-data"), nil
	}
	ucd, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(ucd, "decenzed-node"), nil
}

func configPath() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func xrayConfigPath(cfgPath string) string { return filepath.Join(filepath.Dir(cfgPath), "xray.json") }
func logFilePath(cfgPath string) string    { return filepath.Join(filepath.Dir(cfgPath), "node.log") }

// setupDaemonLog sends daemon logs to node.log (the service has no console).
func setupDaemonLog(cfgPath string) func() {
	p := logFilePath(cfgPath)
	flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(p); err == nil && fi.Size() > 4<<20 {
		flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(p, flag, 0o600)
	if err != nil {
		return nil
	}
	// File only — under a Windows service os.Stderr is invalid and an
	// io.MultiWriter would abort the file write on its error.
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
	log.Println("=== daemon log start ===")
	return func() { _ = f.Close() }
}

// --- check ---

func cmdCheck(r *bufio.Reader) error {
	fmt.Println("local IPv4:", localIPv4s())

	ip := fetchPublicIP()
	if ip == "" {
		fmt.Println("public IP:         could not detect (check your internet)")
	} else {
		fmt.Printf("public IP:         %s\n", ip)
		if isCGNATorPrivate(ip) {
			fmt.Println("  ! this looks like a CGNAT/private IP — inbound connections may not")
			fmt.Println("    reach you; ask your ISP for a public ('white') IP, or use a VPS.")
		}
	}

	fmt.Println("\nrunning a speed test (~25 MB up/down)...")
	sctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	sp, sErr := speedtest.Run(sctx)
	cancel()
	if sErr != nil {
		fmt.Println("  ! speed test could not run:", sErr)
	} else {
		fmt.Printf("download:          %.1f Mbit/s\n", sp.DownMbps)
		fmt.Printf("upload:            %.1f Mbit/s\n", sp.UpMbps)
		if sp.Best() < 10 {
			fmt.Printf("  ! upload is low (%.1f Mbit/s) — clients will be slow.\n", sp.Best())
		}
	}

	port := 443
	if c, err := loadConfig(); err == nil && c.Port != 0 {
		port = c.Port
	}
	printPortForwardHelp(port, ip, localIPv4s())
	return nil
}

// --- setup ---

func cmdSetup(r *bufio.Reader) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	c, err := config.Load(path)
	if err != nil {
		c = config.Default()
	}

	fmt.Println("decenzed-node setup — press Enter to accept the [default].")

	c.Port = askPort(r, c.Port)

	if v := ask(r, "Monthly traffic limit (e.g. 500GB, 2TB, unlimited)", bytesize.Format(c.MonthlyLimitBytes)); v != "" {
		if b, perr := bytesize.Parse(v); perr == nil {
			c.MonthlyLimitBytes = b
		} else {
			fmt.Println("  ! keeping previous value:", perr)
		}
	}
	if v := ask(r, "Reset day of month (1-28)", strconv.Itoa(nonZero(c.ResetDay, 1))); v != "" {
		if d, perr := strconv.Atoi(v); perr == nil {
			c.ResetDay = clamp(d, 1, 28)
		}
	}
	if v := ask(r, "Blocked protocols (comma-separated)", strings.Join(orDefault(c.BlockProtocols, []string{"bittorrent"}), ",")); v != "" {
		c.BlockProtocols = splitCSV(v)
	}
	if v := ask(r, "Per-user speed cap (e.g. 10mbit, unlimited)", formatBandwidth(nonZeroF(c.MaxUserBps, 10e6/8))); v != "" {
		if bps, perr := parseBandwidth(v); perr == nil {
			c.MaxUserBps = bps
		} else {
			fmt.Println("  ! keeping previous value:", perr)
		}
	}

	// DuckDNS dynamic DNS (optional but recommended). With a token the node keeps
	// decenzed-node-<id>.duckdns.org pointed at its current IP, and share links
	// use that domain (surviving IP changes) instead of the raw IP.
	c.DuckDNSToken = strings.TrimSpace(ask(r, "DuckDNS token (blank = put the raw IP in links)", c.DuckDNSToken))
	if c.DuckDNSToken != "" && c.NodeID == "" {
		id, iErr := newNodeID()
		if iErr != nil {
			return iErr
		}
		c.NodeID = id
	}
	if h := c.DuckDNSHost(); h != "" {
		fmt.Printf("\n>>> Create the domain '%s' in your DuckDNS account (https://www.duckdns.org).\n", c.DuckDNSDomain())
		fmt.Printf(">>> The node will keep %s pointed at your IP (checked every minute).\n\n", h)
	} else {
		// Public IP for links (only used when DuckDNS is off).
		def := c.PublicIP
		if def == "" {
			def = fetchPublicIP()
		}
		c.PublicIP = ask(r, "Public IP (for share links; blank = auto-detect each time)", def)
	}

	c.Autostart = true // the service always enables boot-start

	// Pick a REALITY camouflage domain (scan for a live TLS1.3+h2 site).
	if err := chooseRealityDomain(r, &c); err != nil {
		return err
	}
	// Generate REALITY keys + short id locally (private key stays here).
	if c.RealityPrivateKey == "" || c.RealityPublicKey == "" {
		kp, kErr := realitykeys.Generate()
		if kErr != nil {
			return fmt.Errorf("reality keys: %w", kErr)
		}
		c.RealityPrivateKey, c.RealityPublicKey = kp.Private, kp.Public
	}
	if len(c.RealityShortIDs) == 0 {
		sid, sErr := realitykeys.ShortID()
		if sErr != nil {
			return fmt.Errorf("reality short id: %w", sErr)
		}
		c.RealityShortIDs = []string{sid}
	}
	// Ensure at least one client (yourself).
	if len(c.Clients) == 0 {
		uuid, uErr := newUUID()
		if uErr != nil {
			return uErr
		}
		c.Clients = []config.Client{{UUID: uuid, Name: "me"}}
	}

	if err := config.Save(path, c); err != nil {
		return err
	}
	if err := writeXrayConfig(path, c); err != nil {
		return fmt.Errorf("generate xray config: %w", err)
	}

	fmt.Println("\nsaved:", path)
	fmt.Printf("REALITY domain: %s  (short id %s)\n", firstOr(c.RealityServerName), first(c.RealityShortIDs))
	fmt.Println("\nnext: 'service install' to run in the background, then 'link' to share.")
	fmt.Println("your connection link:")
	printLinks(c)
	return nil
}

// chooseRealityDomain scans the node's /24 neighbourhood then a seed list for a
// live TLS1.3+h2 site to borrow as REALITY camouflage. Keeps a still-valid pick.
func chooseRealityDomain(r *bufio.Reader, c *config.AppConfig) error {
	if cur := firstOr(c.RealityServerName); cur != "" {
		if _, ok := realityscan.Probe(cur, 443, 4*time.Second); ok {
			fmt.Printf("keeping REALITY domain: %s\n", cur)
			return nil
		}
		fmt.Printf("previous REALITY domain %q is no longer usable — choosing a new one.\n", cur)
	}

	var domains []string
	if pubIP := fetchPublicIP(); pubIP != "" {
		hosts := realityscan.Hosts24(pubIP)
		fmt.Printf("scanning %d neighbours of %s for REALITY targets (TLS1.3+h2)...\n", len(hosts), pubIP)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		domains = dedupDomains(realityscan.Scan(ctx, hosts, 443, 3*time.Second, 64))
		cancel()
		fmt.Printf("  found %d candidate domain(s) near your server\n", len(domains))
	}
	if len(domains) == 0 {
		fmt.Println("scanning the seed list for a REALITY camouflage domain...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		domains = dedupDomains(realityscan.Scan(ctx, shuffledSeeds(), 443, 4*time.Second, 12))
		cancel()
	}
	for _, dom := range domains {
		if _, ok := realityscan.Probe(dom, 443, 4*time.Second); ok {
			c.RealityDest = dom + ":443"
			c.RealityServerName = []string{dom}
			fmt.Printf("selected REALITY domain: %s\n", dom)
			return nil
		}
	}
	return fmt.Errorf("no live REALITY domain found (network blocked?) — try again")
}

func shuffledSeeds() []string {
	s := append([]string(nil), realityscan.DefaultSeeds...)
	for i := len(s) - 1; i > 0; i-- {
		j := int(randInt(int64(i + 1)))
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func dedupDomains(cands []realityscan.Candidate) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cands {
		if c.Domain == "" || seen[c.Domain] {
			continue
		}
		seen[c.Domain] = true
		out = append(out, c.Domain)
	}
	return out
}

func writeXrayConfig(cfgPath string, c config.AppConfig) error {
	b, err := xraygen.Generate(inputFromConfig(c)).JSON()
	if err != nil {
		return err
	}
	tmp := xrayConfigPath(cfgPath) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, xrayConfigPath(cfgPath))
}

// --- link ---

func cmdLink(args []string) error {
	path, _ := configPath()
	c, err := config.Load(path)
	if err != nil || c.RealityPublicKey == "" {
		return fmt.Errorf("run 'setup' first")
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "", "list":
		printLinks(c)
		return nil
	case "add":
		name := ""
		if len(args) > 1 {
			name = strings.Join(args[1:], " ")
		}
		uuid, uErr := newUUID()
		if uErr != nil {
			return uErr
		}
		c.Clients = append(c.Clients, config.Client{UUID: uuid, Name: name})
		if err := saveAndReload(path, c); err != nil {
			return err
		}
		fmt.Println("added client — share this link:")
		fmt.Println(" ", linkFor(c, config.Client{UUID: uuid, Name: name}, linkHost(c)))
		return nil
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: link remove <name|uuid>")
		}
		key := strings.Join(args[1:], " ")
		kept := c.Clients[:0]
		removed := 0
		for _, cl := range c.Clients {
			if cl.UUID == key || cl.Name == key {
				removed++
				continue
			}
			kept = append(kept, cl)
		}
		if removed == 0 {
			return fmt.Errorf("no client matching %q", key)
		}
		c.Clients = kept
		if err := saveAndReload(path, c); err != nil {
			return err
		}
		fmt.Printf("removed %d client(s); the service was reloaded.\n", removed)
		return nil
	default:
		return fmt.Errorf("usage: link [list] | link add [name] | link remove <name|uuid>")
	}
}

// saveAndReload persists the config, rebuilds xray.json, and best-effort
// restarts the service so a client change takes effect immediately.
func saveAndReload(path string, c config.AppConfig) error {
	if err := config.Save(path, c); err != nil {
		return err
	}
	if err := writeXrayConfig(path, c); err != nil {
		return err
	}
	if svc, err := newService(); err == nil {
		_ = svc.Restart() // no-op / error if not installed — ignored
	}
	return nil
}

func printLinks(c config.AppConfig) {
	if len(c.Clients) == 0 {
		fmt.Println("  (no clients — run 'link add')")
		return
	}
	host := linkHost(c)
	if host == "" {
		fmt.Println("  ! could not determine public IP; set it in 'setup'")
	}
	for _, cl := range c.Clients {
		label := cl.Name
		if label == "" {
			label = cl.UUID[:8]
		}
		fmt.Printf("  %-12s %s\n", label, linkFor(c, cl, host))
	}
}

// linkHost is the address that goes in share links: the DuckDNS domain when
// configured (survives IP changes), otherwise the configured/detected public IP.
func linkHost(c config.AppConfig) string {
	if h := c.DuckDNSHost(); h != "" {
		return h
	}
	if c.PublicIP != "" {
		return c.PublicIP
	}
	return fetchPublicIP()
}

// linkFor builds a vless:// REALITY+Vision share link for a client.
func linkFor(c config.AppConfig, cl config.Client, publicIP string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", firstOr(c.RealityServerName))
	q.Set("fp", "chrome")
	q.Set("pbk", c.RealityPublicKey)
	q.Set("sid", first(c.RealityShortIDs))
	q.Set("type", "tcp")
	q.Set("flow", "xtls-rprx-vision")
	name := cl.Name
	if name == "" {
		name = "decenzed"
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", cl.UUID, publicIP, c.Port, q.Encode(), url.PathEscape(name))
}

// --- config ---

func cmdConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: config node|xray  (to change settings, re-run 'setup')")
	}
	c, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w — run 'setup' first", err)
	}
	switch args[0] {
	case "node":
		b, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(b))
	case "xray":
		b, gErr := xraygen.Generate(inputFromConfig(c)).JSON()
		if gErr != nil {
			return gErr
		}
		fmt.Println(string(b))
	default:
		return fmt.Errorf("unknown config subcommand %q (use: node | xray)", args[0])
	}
	return nil
}

// --- logs ---

func cmdLogs() error {
	path, _ := configPath()
	data, err := os.ReadFile(logFilePath(path))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no logs yet — run 'service install' (or 'start') first")
		}
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	const tail = 200
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	fmt.Println(strings.Join(lines, "\n"))
	return nil
}

// --- stats ---

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
	limit := "unlimited"
	if st.MonthlyLimit > 0 {
		limit = humanBytes(st.MonthlyLimit)
	}
	fmt.Printf("  this period:   %s of %s used", humanBytes(st.PeriodUsed), limit)
	if st.MonthlyLimit > 0 {
		fmt.Printf("  (%.1f%%)", float64(st.PeriodUsed)/float64(st.MonthlyLimit)*100)
	}
	fmt.Println(pausedNote(st.Paused))
	fmt.Printf("  load (10 min): %s\n", loadLine(st))
	if !st.PeriodStart.IsZero() {
		fmt.Printf("  period start:  %s\n", st.PeriodStart.Format("2006-01-02"))
	}
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

// --- start (foreground) / service (background) ---

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
// xray with the configured clients, the per-user throttle proxy, accounts
// traffic against the monthly quota, writes stats, and self-updates. No server.
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
	activeUUIDs := c.UUIDs()

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

	q := quota.New(c.MonthlyLimitBytes, c.ResetDay)
	var lastSnap traffic.Snapshot
	log.Printf("node started; %d client(s)", len(c.Clients))

	statsPath := nodestats.Path(path)
	st, _ := nodestats.Load(statsPath)
	st.StartedAt = time.Now()
	st.Running = true
	st.Port = c.Port
	st.ClientsConfigured = len(c.Clients)
	st.MonthlyLimit = c.MonthlyLimitBytes
	st.BandwidthCap = c.MaxUserBps
	_ = nodestats.Save(statsPath, st)

	var load loadWindow
	lastActive := map[string]time.Time{}

	tick := time.NewTicker(30 * time.Second)
	updateTick := time.NewTicker(6 * time.Hour)
	defer tick.Stop()
	defer updateTick.Stop()
	checkSelfUpdate(ctx)

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
			used := q.Add(now, tickBytes)
			paused := q.Paused(now)
			st.PeriodUsed = used
			st.Paused = paused
			st.PeriodStart = q.PeriodStart()
			st.RecentBps = load.add(now, tickBytes)
			st.ActiveClients = len(activeSince(lastActive, now.Add(-30*time.Minute)))
			st.UpdatedAt = now
			_ = nodestats.Save(statsPath, st)

			updateDuckDNS(ctx, c, &c.PublicIP)

			// Enforce the monthly cap by dropping/restoring users (reload xray).
			want := c.UUIDs()
			if paused {
				want = nil
			}
			if !sameStringSet(activeUUIDs, want) {
				if xc, gErr := xraygen.Generate(withUUIDs(c, want)).JSON(); gErr == nil {
					if rErr := rt.Start(ctx, xc); rErr == nil {
						activeUUIDs = want
						if paused {
							log.Println("monthly quota reached — serving paused")
						} else {
							log.Println("new period — serving resumed")
						}
					}
				}
			}
		case <-updateTick.C:
			checkSelfUpdate(ctx)
		}
	}
}

// withUUIDs returns the xray Input for c but with a specific client set (used to
// pause/resume serving without touching the saved config).
func withUUIDs(c config.AppConfig, uuids []string) xraygen.Input {
	in := inputFromConfig(c)
	in.UUIDs = uuids
	return in
}

func checkSelfUpdate(ctx context.Context) {
	url := config.DefaultUpdateManifestURL()
	if url == "" {
		return
	}
	applied, ver, err := selfupdate.CheckAndApply(ctx, version, url)
	if err != nil {
		log.Println("self-update:", err)
		return
	}
	if applied {
		log.Printf("self-update: installed %s — takes effect on next restart", ver)
	}
}

// --- service ---

type program struct{ cancel context.CancelFunc }

func (p *program) Start(_ service.Service) error {
	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())
	go func() {
		if err := runNode(ctx); err != nil {
			log.Println("agent exited:", err)
		}
	}()
	return nil
}
func (p *program) Stop(_ service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

func newService() (service.Service, error) {
	return service.New(&program{}, &service.Config{
		Name:        "decenzed-node",
		DisplayName: "decenzed node",
		Description: "decenzed self-hosted proxy (autostart).",
	})
}

func runAsService() error {
	svc, err := newService()
	if err != nil {
		return err
	}
	return svc.Run()
}

func cmdService(args []string) error {
	svc, err := newService()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: service install|uninstall|start|stop|status")
	}
	switch args[0] {
	case "install":
		c, cErr := loadConfig()
		if cErr != nil || c.RealityPublicKey == "" {
			return fmt.Errorf("run 'setup' first")
		}
		if err := svc.Install(); err != nil {
			return fmt.Errorf("install service (needs admin/root): %w", err)
		}
		if err := svc.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		fmt.Println("installed and started — runs on boot. Share with: decenzed-node link")
		return nil
	case "uninstall":
		_ = svc.Stop()
		return svc.Uninstall()
	case "start":
		return svc.Start()
	case "stop":
		return svc.Stop()
	case "status":
		s, sErr := svc.Status()
		if sErr != nil {
			return sErr
		}
		fmt.Println("service status:", statusString(s))
		return nil
	default:
		return fmt.Errorf("service: unknown subcommand %q", args[0])
	}
}

func statusString(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown (not installed?)"
	}
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

// --- helpers ---

func loadConfig() (config.AppConfig, error) {
	path, err := configPath()
	if err != nil {
		return config.AppConfig{}, err
	}
	return config.Load(path)
}

// fetchPublicIP asks a couple of public echo services for this host's IP.
func fetchPublicIP() string {
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if ip := strings.TrimSpace(string(b)); net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func isCGNATorPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() {
		return true
	}
	// CGNAT 100.64.0.0/10.
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func newNodeID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
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

func randInt(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

func printPortForwardHelp(port int, publicIP string, local []string) {
	lan := "your machine's LAN IP"
	if len(local) > 0 {
		lan = local[0]
	}
	fmt.Printf(`
── open port %d on your router ─────────────────────────────────
Friends connect INBOUND to this machine, so forward TCP port %d:

  1. Open your router admin page (often http://192.168.1.1).
  2. Find "Port Forwarding" / "Virtual Server" / "NAT".
  3. Add: protocol TCP, external port %d, internal port %d,
     internal IP %s (this machine).
  4. Give this machine a STATIC LAN IP (DHCP reservation).

Tips: allow TCP %d in your firewall; if your ISP uses CGNAT
(public IP starts with 100.64–100.127 or is private), forwarding
won't help — ask for a public IP or use a VPS. Some ISPs block
443; port 8443 usually works.
────────────────────────────────────────────────────────────────
`, port, port, port, port, lan, port)
}

func localIPv4s() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
			out = append(out, ipnet.IP.String())
		}
	}
	return out
}

func ask(r *bufio.Reader, q, def string) string {
	fmt.Printf("%s [%s]: ", q, def)
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if err != nil {
			fmt.Println(def)
		}
		return def
	}
	return line
}

var portChoices = []int{443, 8443}

func askPort(r *bufio.Reader, current int) int {
	def := current
	if def == 0 {
		def = portChoices[0]
	}
	fmt.Println("Node port (forward this TCP port on your router):")
	for i, p := range portChoices {
		mark := ""
		if p == def {
			mark = "  <- default"
		}
		fmt.Printf("  %d) %d%s\n", i+1, p, mark)
	}
	fmt.Printf("choose 1-%d, or type a port [%d]: ", len(portChoices), def)
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if err != nil {
			fmt.Println(def)
		}
		return def
	}
	if n, aerr := strconv.Atoi(line); aerr == nil {
		if n >= 1 && n <= len(portChoices) {
			return portChoices[n-1]
		}
		if n >= 1 && n <= 65535 {
			return n
		}
	}
	fmt.Println("  ! invalid — keeping", def)
	return def
}

func parseBandwidth(s string) (float64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "unlimited" || s == "0" {
		return 0, nil
	}
	switch {
	case strings.HasSuffix(s, "gbit"):
		return floatMul(strings.TrimSuffix(s, "gbit"), 1e9/8)
	case strings.HasSuffix(s, "mbit"):
		return floatMul(strings.TrimSuffix(s, "mbit"), 1e6/8)
	case strings.HasSuffix(s, "kbit"):
		return floatMul(strings.TrimSuffix(s, "kbit"), 1e3/8)
	default:
		b, err := bytesize.Parse(s)
		return float64(b), err
	}
}

func formatBandwidth(bps float64) string {
	if bps == 0 {
		return "unlimited"
	}
	return strconv.FormatFloat(bps*8/1e6, 'f', -1, 64) + "mbit"
}

func floatMul(s string, m float64) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return f * m, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

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

func pausedNote(paused bool) string {
	if paused {
		return "  [PAUSED: monthly quota reached]"
	}
	return ""
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

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		if m[s] == 0 {
			return false
		}
		m[s]--
	}
	return true
}

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

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
func firstOr(s []string) string { return first(s) }
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func nonZero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
func nonZeroF(v, def float64) float64 {
	if v == 0 {
		return def
	}
	return v
}
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
func orDefault(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

var _ = firstNonEmpty // reserved for future use
