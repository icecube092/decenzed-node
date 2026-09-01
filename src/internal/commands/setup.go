package commands

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"

	"decenzed/node_app/internal/acme"
	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/realitykeys"
	"decenzed/node_app/internal/realityscan"
	"decenzed/node_app/internal/xraygen"
)

func cmdSetup(r *input) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	c, err := config.Load(path)
	if err != nil {
		c = config.Default()
	}
	// A stable node id backs the subscription profile name ("Decenzed-<id>").
	if c.NodeID == "" {
		c.NodeID = newNodeID()
	}

	// Persist progress after every answered field so an interrupted setup (Ctrl+C,
	// or an error partway through) keeps what was entered and offers it as the
	// default on the next run — instead of forcing a full re-entry. Writes are
	// atomic (config.Save renames a temp file), so a partial config is safe. The
	// closure reads the current `c` on each call.
	save := func() {
		if serr := config.Save(path, c); serr != nil {
			fmt.Println("  ! could not save progress:", serr)
		}
	}
	save() // checkpoint the (possibly fresh) NodeID right away

	fmt.Println("decenzed-node setup — Enter keeps the [current] value; type 'no' to clear it.")

	// Network readiness first: public IP -> port -> self-ping -> speed test.
	detectedIP := networkPrecheck(r, &c, save)

	// Optional extra protocols, each on its own forwarded port.
	configureExtraProtocols(r, &c, save)

	if v := ask(r, "Blocked protocols (comma-separated, or 'no' to block none)", strings.Join(orDefault(c.BlockProtocols, []string{"bittorrent"}), ",")); v != "" {
		if isNo(v) {
			c.BlockProtocols = nil
		} else {
			c.BlockProtocols = splitCSV(v)
		}
		save()
	}
	if v := ask(r, "Per-user speed cap (e.g. 50mbit, 'no' = unlimited)", formatBandwidth(nonZeroF(c.MaxUserBps, 50e6/8))); v != "" {
		if isNo(v) {
			c.MaxUserBps = 0 // clear the cap
		} else if bps, perr := parseBandwidth(v); perr == nil {
			c.MaxUserBps = bps
		} else {
			fmt.Println("  ! keeping previous value:", perr)
		}
		save()
	}

	// Domain for share links (survives IP changes): either the operator's own
	// domain, or a DuckDNS one the node keeps pointed at the current IP.
	configureDomain(r, &c, detectedIP, save)

	c.Autostart = true // the service always enables boot-start
	save()

	// Choose how VLESS/Trojan hide: REALITY (borrow a foreign site) or TLS
	// (masquerade behind the node's own website with a Let's Encrypt cert).
	if err := configureCamouflage(r, &c, save); err != nil {
		return err
	}
	// Ensure at least one client (yourself).
	if len(c.Clients) == 0 {
		uuid, uErr := newUUID()
		if uErr != nil {
			return uErr
		}
		c.Clients = []config.Client{{UUID: uuid, Name: "me"}}
		save()
	}

	if err := config.Save(path, c); err != nil {
		return err
	}
	if err := writeXrayConfig(path, c); err != nil {
		return fmt.Errorf("generate xray config: %w", err)
	}

	fmt.Println("\nsaved:", path)
	if c.CamouflageTLS() {
		fmt.Printf("TLS site: %s  (Let's Encrypt%s)\n", c.TLSHost(), stagingSuffix())
	} else {
		fmt.Printf("REALITY domain: %s  (short id %s)\n", firstOr(c.RealityServerName), first(c.RealityShortIDs))
	}

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
	printLinks(c, modeDefault)
	return nil
}

// askClearable asks q showing current as the [default]. Pressing Enter keeps
// current; typing a negative sentinel ("no"/"none"/"off"/"-") clears it to "".
func askClearable(r *input, q, current string) string {
	v := strings.TrimSpace(ask(r, q, current))
	if isNo(v) {
		return ""
	}
	return v
}

// configureDomain sets up the hostname that goes in share links (surviving IP
// changes). It first asks whether the operator wants the node to manage dynamic
// DNS via DuckDNS:
//   - No:  the operator already has a domain (bought, or kept pointed at this IP
//     by their own dynamic-DNS client). They enter it directly (CustomDomain);
//     the node never updates it. If they have no domain either, links fall back
//     to the raw public IP.
//   - Yes: the DuckDNS flow (token + a subdomain created on duckdns.org); the
//     node keeps <subdomain>.duckdns.org pointed at the current IP.
//
// The two are mutually exclusive: choosing one clears the other's state.
func configureDomain(r *input, c *config.AppConfig, detectedIP string, save func()) {
	fmt.Println("\nDomain for your share links (so links keep working when your IP changes).")
	fmt.Println("  Answer 'no' if you already have your own domain (bought, or kept updated")
	fmt.Println("  by another dynamic-DNS program) — you'll just type it in.")

	if !askYesNo(r, "Set up DuckDNS dynamic DNS for you?", c.DuckDNSToken != "") {
		// Bring-your-own domain (or raw IP): clear any DuckDNS state.
		c.DuckDNSToken = ""
		c.DuckDNSSubdomain = ""
		c.CustomDomain = normalizeDomain(askClearable(r,
			"Your domain (e.g. vpn.example.com; 'no' = use the raw IP in links)", c.CustomDomain))
		save()
		if c.CustomDomain != "" {
			fmt.Printf("\n>>> Make sure %s has an A record pointing at this node's IP", c.CustomDomain)
			if detectedIP != "" {
				fmt.Printf(" (%s)", detectedIP)
			}
			fmt.Println(".")
			fmt.Println(">>> Your own DNS or dynamic-DNS client must keep it updated — the node won't.")
			return
		}
		// No domain at all — fall back to a raw public IP in links.
		askPublicIP(r, c, detectedIP)
		save()
		return
	}

	// DuckDNS branch: the node manages the domain, so drop any custom one.
	c.CustomDomain = ""
	c.DuckDNSToken = askClearable(r, "DuckDNS token (from duckdns.org, after signing in)", c.DuckDNSToken)
	save()
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
		save()
	}
	if h := c.DuckDNSHost(); h != "" {
		fmt.Printf("\n>>> The node will keep %s pointed at your IP (checked every 30s).\n", h)
		// Point the domain at our current IP right away so links work immediately.
		// The subdomain must already exist in your DuckDNS account, or this fails.
		if ip, dErr := pointDuckDNS(context.Background(), *c); dErr != nil {
			fmt.Printf("  ! could not update %s yet: %v\n", h, dErr)
			fmt.Printf("    (create the subdomain on duckdns.org and check the token, then re-run setup or 'check')\n\n")
		} else {
			fmt.Printf("  ok — %s now points at %s\n\n", h, ip)
		}
		return
	}
	// DuckDNS declined at the token prompt — fall back to a raw public IP.
	askPublicIP(r, c, detectedIP)
	save()
}

// askPublicIP collects the public IP used in share links when no domain is
// configured ('no' = auto-detect on each link).
func askPublicIP(r *input, c *config.AppConfig, detectedIP string) {
	def := c.PublicIP
	if def == "" {
		def = detectedIP
	}
	c.PublicIP = askClearable(r, "Public IP (for share links; 'no' = auto-detect each time)", def)
}

// normalizeDomain trims a user-entered domain to a bare hostname: lower-cased,
// no scheme, no trailing slash or path.
func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// networkPrecheck runs the up-front readiness check at the top of setup, in
// order: detect the public IP, choose (and warn about forwarding) the port,
// self-ping that port via the public IP, then measure speed. Returns the
// detected public IP so callers can reuse it as a default. It mutates c.Port.
// save is called after each answered field so an interrupt keeps progress.
func networkPrecheck(r *input, c *config.AppConfig, save func()) string {
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

	// Auto-detect the node's country (for the proxy names, e.g. "RS [VLESS]").
	// Best-effort: if it fails, proxy names fall back to the node label.
	if loc := detectLocation(); loc != "" {
		c.Location = loc
		fmt.Printf("location:          %s (auto-detected)\n", loc)
		save()
	}

	// 2. Warn about forwarding, then pick the VLESS port — asked the same way as
	// the other protocols (default 8443).
	fmt.Println("\nFriends connect INBOUND to this machine, so you must forward one TCP")
	fmt.Println("port on your router to it. Pick the VLESS port the node binds locally:")
	c.Port = askProtocolPort(r, "VLESS port", c.Port, vlessDefaultPort)
	save()
	// If the router forwards a different external port to it (e.g. 443 -> 8443),
	// clients must dial that external port; capture it here (default: same).
	c.PublicPort = askPublicPort(r, "VLESS", c.PublicPort, c.Port)
	save()
	pub := c.VLESSPublicPort()
	printPortForwardHelp(ip, localIPv4s(), portForward{Public: pub, Bind: c.Port})

	// 3. Self-ping the EXTERNAL port from the public IP: the router forwards it to
	//    the port the node binds, where a temp listener stands in for the
	//    not-yet-running node.
	if ip != "" {
		fmt.Printf("\nself-check:        dialing %s:%d ...\n", ip, pub)
		if err := selfPortCheck(ip, pub, c.Port, 6*time.Second); err != nil {
			fmt.Printf("  ! could not reach %s:%d from here: %v\n", ip, pub, err)
			fmt.Println("    (this is normal from inside your own LAN — many routers can't")
			fmt.Println("     loop back to your public IP; test from mobile data to be sure.)")
		} else {
			fmt.Printf("  ok — %s:%d accepted a TCP connection.\n", ip, pub)
		}
	}

	// 4. Speed test.
	runSpeedTest()
	fmt.Println()
	return ip
}

// Recommended port ranges for the optional protocols (a random free port in the
// range is offered as the default). VLESS keeps its 443/8443 choice.
const (
	vlessDefaultPort = 8443
	trojanPortLo     = 32000
	trojanPortHi     = 35000
	ssPortLo         = 35000
	ssPortHi         = 38000
)

// configureExtraProtocols asks, per protocol, whether to also expose Trojan,
// Shadowsocks (classic), and/or Shadowsocks-2022 (a y/n question each), and if so
// on which dedicated TCP port (one port = one protocol). VLESS on c.Port is
// always on. Generates the Shadowsocks-2022 server key on first enable.
func configureExtraProtocols(r *input, c *config.AppConfig, save func()) {
	fmt.Println("\nExtra protocols (optional). One TCP port hosts ONE protocol, so each")
	fmt.Println("protocol you enable needs its OWN dedicated TCP port, SEPARATE from the")
	fmt.Println("VLESS port above — and you must forward/open that port too.")

	// Trojan shares VLESS's camouflage (REALITY or TLS), chosen later. The public
	// (external) port is asked only when the protocol is enabled.
	if askYesNo(r, "\nEnable Trojan?", c.TrojanPort != 0) {
		rec := recommendPortInRange(trojanPortLo, trojanPortHi, c.Port)
		c.TrojanPort = askProtocolPort(r, "  Trojan port", c.TrojanPort, rec, c.Port)
		c.TrojanPublicPort = askPublicPort(r, "  Trojan", c.TrojanPublicPort, c.TrojanPort)
	} else {
		c.TrojanPort, c.TrojanPublicPort = 0, 0
	}
	save()

	// Shadowsocks (classic chacha20-ietf-poly1305) — broad client support.
	if askYesNo(r, "Enable Shadowsocks? (chacha20-ietf-poly1305, broad support)", c.SSPort != 0) {
		rec := recommendPortInRange(ssPortLo, ssPortHi, c.Port, c.TrojanPort)
		c.SSPort = askProtocolPort(r, "  Shadowsocks port", c.SSPort, rec, c.Port, c.TrojanPort)
		c.SSPublicPort = askPublicPort(r, "  Shadowsocks", c.SSPublicPort, c.SSPort)
	} else {
		c.SSPort, c.SSPublicPort = 0, 0
	}
	save()

	// Shadowsocks-2022 — stronger, but rejected by many clients; separate inbound.
	if askYesNo(r, "Also enable Shadowsocks-2022? (stronger; fewer clients accept it)", c.SS2022Port != 0) {
		rec := recommendPortInRange(ssPortLo, ssPortHi, c.Port, c.TrojanPort, c.SSPort)
		c.SS2022Port = askProtocolPort(r, "  Shadowsocks-2022 port", c.SS2022Port, rec, c.Port, c.TrojanPort, c.SSPort)
		if c.SS2022Port != 0 && c.SSServerKey == "" {
			if k, err := config.NewSSServerKey(); err == nil {
				c.SSServerKey = k
			} else {
				fmt.Println("  ! could not generate Shadowsocks-2022 key — disabling:", err)
				c.SS2022Port = 0
			}
		}
		if c.SS2022Port != 0 {
			c.SS2022PublicPort = askPublicPort(r, "  Shadowsocks-2022", c.SS2022PublicPort, c.SS2022Port)
		} else {
			c.SS2022PublicPort = 0
		}
	} else {
		c.SS2022Port, c.SS2022PublicPort = 0, 0
	}
	save()

	if extra := c.PublicInbounds(); len(extra) > 1 {
		fmt.Println("\n>>> Forward/open these extra TCP port(s) — one per protocol:")
		for _, ib := range extra {
			if ib.Protocol == config.ProtoVLESS {
				continue
			}
			if ib.Remapped() {
				fmt.Printf(">>>   WAN %d -> LAN %d  (%s)\n", ib.PublicPort, ib.Port, ib.Protocol)
			} else {
				fmt.Printf(">>>   TCP %d  (%s)\n", ib.Port, ib.Protocol)
			}
		}
		fmt.Println(">>> On an OpenWRT edge router, open them on the WAN firewall by re-running")
		fmt.Println(">>> the installer with all ports, e.g. PORT=\"8443 8444 9443\" ./install-openwrt.sh")
	}
}

// askProtocolPort asks for a protocol's TCP port, the same style as the VLESS
// port prompt. On a fresh setup (current == 0) it pre-fills `recommended` (a free
// port the caller already picked, e.g. random-in-range); an existing value is
// kept as the default and never bumped, so re-running setup while the node holds
// that port doesn't move it. Collisions with reserved ports are rejected
// (re-asks); a busy-looking port only warns, without blocking.
func askProtocolPort(r *input, label string, current, recommended int, reserved ...int) int {
	def := current
	if def == 0 {
		def = recommended
	}
	for {
		v := strings.TrimSpace(ask(r, label+" (forward this TCP port)", strconv.Itoa(def)))
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			fmt.Println("  ! invalid port — using", def)
			n = def
		}
		if collidesPort(n, reserved...) {
			fmt.Printf("  ! port %d is already used by another protocol here — pick another.\n", n)
			continue
		}
		return warnIfBusy(n)
	}
}

// askPublicPort asks for the EXTERNAL (WAN) TCP port clients dial for a protocol
// the node binds on `bind`. Most operators forward the same port straight
// through, so the default is the bind port itself. Only when the router forwards
// a DIFFERENT external port to `bind` (e.g. WAN 443 -> LAN 8443) do they enter
// that external port here. Returns the value to store in the matching *PublicPort
// field: 0 when it equals the bind port (no remap), else the external port.
func askPublicPort(r *input, label string, current, bind int) int {
	def := bind
	if current != 0 {
		def = current
	}
	v := strings.TrimSpace(ask(r, label+" — external port clients dial (keep it the same if your router forwards it straight through)", strconv.Itoa(def)))
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		fmt.Println("  ! invalid port — treating it as the same as the bind port")
		return 0
	}
	if n == bind {
		return 0
	}
	return n
}

// collidesPort reports whether n equals any non-zero reserved port.
func collidesPort(n int, reserved ...int) bool {
	for _, rp := range reserved {
		if rp != 0 && n == rp {
			return true
		}
	}
	return false
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

// configureCamouflage asks which masquerade the VLESS/Trojan inbounds use and
// sets up the chosen mode:
//   - reality: scan for a live TLS1.3+h2 site to borrow, generate REALITY keys.
//   - tls:     masquerade behind the node's own website; obtain a Let's Encrypt
//     certificate via DNS-01 (DuckDNS). No domain scan is performed.
//
// TLS mode needs a DuckDNS domain (for both the certificate and the DNS-01
// challenge); without one it falls back to REALITY.
func configureCamouflage(r *input, c *config.AppConfig, save func()) error {
	fmt.Println("\nCamouflage for VLESS/Trojan:")
	fmt.Println("  reality — borrow a stranger's TLS site (no domain/cert needed)")
	fmt.Println("  tls     — masquerade behind YOUR OWN website on your domain. The node")
	fmt.Println("            raises the website itself (you don't create or host anything)")
	fmt.Println("            and gets a Let's Encrypt certificate automatically.")

	def := config.CamouflageReality
	if c.CamouflageTLS() {
		def = config.CamouflageTLSMode
	}
	mode := strings.ToLower(strings.TrimSpace(ask(r, "Camouflage mode (reality/tls)", def)))

	if mode == config.CamouflageTLSMode {
		if c.DuckDNSHost() == "" {
			fmt.Println("  ! TLS mode needs a DuckDNS domain (token + subdomain) for the")
			fmt.Println("    certificate and DNS-01 challenge — none configured. Using REALITY.")
		} else {
			c.Camouflage = config.CamouflageTLSMode
			save()
			return configureTLS(r, c, save)
		}
	}

	// REALITY (default / fallback).
	c.Camouflage = config.CamouflageReality
	save()
	if err := chooseRealityDomain(r, c); err != nil {
		return err
	}
	save()
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
	save()
	return nil
}

// leAgreementURL is the Let's Encrypt Subscriber Agreement shown before we
// register an ACME account on the operator's behalf.
const leAgreementURL = "https://letsencrypt.org/repository/"

// configureTLS collects the Let's Encrypt account registration data interactively
// (contact email + Subscriber Agreement consent) and obtains the certificate now,
// so setup fails loudly if DNS-01 isn't working (rather than at first start). The
// certificate is for the node's own DuckDNS domain; no domain scan is done. The
// CA environment (staging vs production) is fixed at build time, not asked here.
func configureTLS(r *input, c *config.AppConfig, save func()) error {
	fmt.Printf("\n>>> Masquerading behind your own site at https://%s\n", c.TLSHost())
	fmt.Println(">>> (the node hosts this site itself — nothing to set up separately)")

	// If a certificate for this exact domain is already stored and still valid
	// (same CA environment, >30 days to expiry), reuse it — no re-request, and no
	// need to ask the Let's Encrypt account questions again.
	if dir, err := dataDir(); err == nil && acme.CertValid(dir, c.TLSHost()) {
		fmt.Printf(">>> certificate for %s is still valid — reusing it (no new request).\n", c.TLSHost())
		return nil
	}

	fmt.Printf(">>> Certificate CA: Let's Encrypt %s\n", leEnv())

	// Account registration data Let's Encrypt asks for: a contact email (for
	// expiry / urgent notices) and acceptance of the Subscriber Agreement.
	fmt.Println("\nLet's Encrypt account registration:")
	c.ACMEEmail = askClearable(r, "  Contact email (recommended, for expiry & security notices)", c.ACMEEmail)
	save()

	fmt.Printf("  Subscriber Agreement: %s\n", leAgreementURL)
	if isNo(ask(r, "  Do you accept the Let's Encrypt Subscriber Agreement? (yes/no)", "yes")) {
		return fmt.Errorf("TLS camouflage needs the Let's Encrypt agreement accepted — aborting")
	}
	c.ACMEAgreeTOS = true
	save()

	fmt.Printf("\nobtaining a %s certificate for %s (DNS-01 via DuckDNS)...\n", leEnv(), c.TLSHost())
	if err := provisionTLS(context.Background(), *c); err != nil {
		return fmt.Errorf("could not obtain certificate: %w\n"+
			"  check the DuckDNS token/subdomain and try again", err)
	}
	fmt.Printf("  ok — certificate stored in decenzed-data; the node renews it automatically.\n")
	return nil
}

// leEnv names the build-fixed Let's Encrypt environment for display.
func leEnv() string {
	if acme.IsStaging() {
		return "STAGING (test)"
	}
	return "production"
}

func stagingSuffix() string {
	if acme.IsStaging() {
		return " STAGING"
	}
	return ""
}

// chooseRealityDomain scans the node's /24 neighbourhood then a seed list for a
// live TLS1.3+h2 site to borrow as REALITY camouflage. Keeps a still-valid pick.
func chooseRealityDomain(r *input, c *config.AppConfig) error {
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
