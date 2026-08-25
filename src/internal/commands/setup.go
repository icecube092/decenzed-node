package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/realitykeys"
	"decenzed/node_app/internal/realityscan"
	"decenzed/node_app/internal/xraygen"
)

func cmdSetup(r *bufio.Reader) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	c, err := config.Load(path)
	if err != nil {
		c = config.Default()
	}

	fmt.Println("decenzed-node setup — Enter keeps the [current] value; type 'no' to clear it.")

	// Network readiness first: public IP -> port -> self-ping -> speed test.
	detectedIP := networkPrecheck(r, &c)

	// Optional extra protocols, each on its own forwarded port.
	configureExtraProtocols(r, &c)

	if v := ask(r, "Blocked protocols (comma-separated, or 'no' to block none)", strings.Join(orDefault(c.BlockProtocols, []string{"bittorrent"}), ",")); v != "" {
		if isNo(v) {
			c.BlockProtocols = nil
		} else {
			c.BlockProtocols = splitCSV(v)
		}
	}
	if v := ask(r, "Per-user speed cap (e.g. 50mbit, 'no' = unlimited)", formatBandwidth(nonZeroF(c.MaxUserBps, 50e6/8))); v != "" {
		if isNo(v) {
			c.MaxUserBps = 0 // clear the cap
		} else if bps, perr := parseBandwidth(v); perr == nil {
			c.MaxUserBps = bps
		} else {
			fmt.Println("  ! keeping previous value:", perr)
		}
	}

	// DuckDNS dynamic DNS (optional but recommended). With a token + a subdomain
	// you created on duckdns.org, the node keeps <subdomain>.duckdns.org pointed at
	// its current IP, and share links use that domain (surviving IP changes)
	// instead of the raw IP.
	c.DuckDNSToken = askClearable(r, "DuckDNS token (Enter keeps current; 'no' = raw IP in links)", c.DuckDNSToken)
	if c.DuckDNSToken != "" {
		if c.NodeID == "" {
			c.NodeID = newNodeID()
		}
		fmt.Println("\n>>> DuckDNS does NOT auto-create subdomains. Sign in at https://www.duckdns.org,")
		fmt.Println(">>> add a subdomain, then enter its label below (without \".duckdns.org\").")
		def := c.DuckDNSSubdomain
		if def == "" {
			def = c.DuckDNSDomain() // legacy decenzed-node-<id> fallback
		}
		c.DuckDNSSubdomain = normalizeDuckDNSLabel(askClearable(r, "DuckDNS subdomain you created (without .duckdns.org)", def))
	}
	if h := c.DuckDNSHost(); h != "" {
		fmt.Printf("\n>>> The node will keep %s pointed at your IP (checked every 30s).\n", h)
		// Point the domain at our current IP right away so links work immediately.
		// The subdomain must already exist in your DuckDNS account, or this fails.
		if ip, dErr := pointDuckDNS(context.Background(), c); dErr != nil {
			fmt.Printf("  ! could not update %s yet: %v\n", h, dErr)
			fmt.Printf("    (create the subdomain on duckdns.org and check the token, then re-run setup or 'check')\n\n")
		} else {
			fmt.Printf("  ok — %s now points at %s\n\n", h, ip)
		}
	} else {
		// Public IP for links (only used when DuckDNS is off).
		def := c.PublicIP
		if def == "" {
			def = detectedIP
		}
		c.PublicIP = askClearable(r, "Public IP (for share links; 'no' = auto-detect each time)", def)
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

	// Final step: install + start the background service so the node runs on boot.
	// Still available on its own via 'service install'. Needs admin/root, so a
	// failure here is a hint, not a hard error — setup already saved everything.
	if ans := ask(r, "\nInstall & start the background service now? (needs admin/root)", "yes"); !isNo(ans) {
		if err := cmdService([]string{"install"}); err != nil {
			fmt.Printf("  ! %v\n", err)
			fmt.Println("    (re-run later with admin/root: decenzed-node service install)")
		}
	} else {
		fmt.Println("skipped — run it later with: decenzed-node service install")
	}

	fmt.Println("\nyour connection link (share with: decenzed-node link):")
	printLinks(c)
	return nil
}

// askClearable asks q showing current as the [default]. Pressing Enter keeps
// current; typing a negative sentinel ("no"/"none"/"off"/"-") clears it to "".
func askClearable(r *bufio.Reader, q, current string) string {
	v := strings.TrimSpace(ask(r, q, current))
	if isNo(v) {
		return ""
	}
	return v
}

// networkPrecheck runs the up-front readiness check at the top of setup, in
// order: detect the public IP, choose (and warn about forwarding) the port,
// self-ping that port via the public IP, then measure speed. Returns the
// detected public IP so callers can reuse it as a default. It mutates c.Port.
func networkPrecheck(r *bufio.Reader, c *config.AppConfig) string {
	// 1. Public IP.
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

	// 2. Warn about forwarding, then pick the port.
	fmt.Println("\nFriends connect INBOUND to this machine, so you must forward one TCP")
	fmt.Println("port on your router to it. Pick that port now:")
	c.Port = askPort(r, c.Port)
	printPortForwardHelp(c.Port, ip, localIPv4s())

	// 3. Self-ping that port from the public IP (temp listener stands in for the
	//    not-yet-running node).
	if ip != "" {
		fmt.Printf("\nself-check:        dialing %s:%d ...\n", ip, c.Port)
		if err := selfPortCheck(ip, c.Port, 6*time.Second); err != nil {
			fmt.Printf("  ! could not reach %s:%d from here: %v\n", ip, c.Port, err)
			fmt.Println("    (this is normal from inside your own LAN — many routers can't")
			fmt.Println("     loop back to your public IP; test from mobile data to be sure.)")
		} else {
			fmt.Printf("  ok — %s:%d accepted a TCP connection.\n", ip, c.Port)
		}
	}

	// 4. Speed test.
	runSpeedTest()
	fmt.Println()
	return ip
}

// configureExtraProtocols asks whether to also expose Trojan (REALITY) and/or
// Shadowsocks-2022, each on its own dedicated TCP port (one port = one
// protocol). VLESS+REALITY on c.Port is always on. Generates the Shadowsocks
// server key on first enable.
func configureExtraProtocols(r *bufio.Reader, c *config.AppConfig) {
	fmt.Println("\nExtra protocols (optional). Each needs its OWN forwarded TCP port,")
	fmt.Println("separate from the VLESS port above. Type 'no' to disable one.")

	c.TrojanPort = askExtraPort(r, "Trojan+REALITY port", c.TrojanPort, c.Port)

	c.SSPort = askExtraPort(r, "Shadowsocks-2022 port (no REALITY masking)", c.SSPort, c.Port, c.TrojanPort)
	if c.SSPort != 0 && c.SSServerKey == "" {
		if k, err := config.NewSSServerKey(); err == nil {
			c.SSServerKey = k
		} else {
			fmt.Println("  ! could not generate Shadowsocks key — disabling SS:", err)
			c.SSPort = 0
		}
	}

	if extra := c.PublicInbounds(); len(extra) > 1 {
		fmt.Println("\n>>> Forward these extra TCP port(s) on your router too:")
		for _, ib := range extra {
			if ib.Port != c.Port {
				fmt.Printf(">>>   TCP %d  (%s)\n", ib.Port, ib.Protocol)
			}
		}
	}
}

// askExtraPort asks for an optional protocol port. Enter keeps the current
// value; 'no' disables it (0). The chosen port must not collide with any of the
// reserved ports (the other enabled inbounds).
func askExtraPort(r *bufio.Reader, q string, current int, reserved ...int) int {
	def := "no"
	if current != 0 {
		def = strconv.Itoa(current)
	}
	v := strings.TrimSpace(ask(r, q+" ('no' = disabled)", def))
	if isNo(v) || v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		fmt.Println("  ! invalid port — leaving disabled")
		return 0
	}
	for _, rp := range reserved {
		if rp != 0 && n == rp {
			fmt.Printf("  ! port %d is already used by another protocol — leaving disabled\n", n)
			return 0
		}
	}
	return n
}

// newNodeID returns a short, globally-unique, sortable id (xid) used as the
// stable node identity (and the legacy DuckDNS label decenzed-node-<id>).
func newNodeID() string {
	return xid.New().String()
}

// normalizeDuckDNSLabel extracts the bare subdomain label a user might paste in
// several shapes: "https://foo.duckdns.org/", "foo.duckdns.org", or just "foo".
func normalizeDuckDNSLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".duckdns.org")
	return strings.TrimSpace(s)
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
