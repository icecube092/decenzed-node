package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
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

	fmt.Println("decenzed-node setup — press Enter to accept the [default].")

	c.Port = askPort(r, c.Port)

	if v := ask(r, "Blocked protocols (comma-separated, or 'no' to block none)", strings.Join(orDefault(c.BlockProtocols, []string{"bittorrent"}), ",")); v != "" {
		if isNo(v) {
			c.BlockProtocols = nil
		} else {
			c.BlockProtocols = splitCSV(v)
		}
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
	if isNo(c.DuckDNSToken) {
		c.DuckDNSToken = ""
	}
	if c.DuckDNSToken != "" && c.NodeID == "" {
		c.NodeID = newNodeID()
	}
	if h := c.DuckDNSHost(); h != "" {
		fmt.Printf("\n>>> Registering %s via your DuckDNS token (no manual setup needed).\n", h)
		fmt.Printf(">>> The node will keep it pointed at your IP (checked every 30s).\n")
		// Register + point the domain at our current IP right away so links work
		// immediately; DuckDNS creates decenzed-node-<id> from the token itself.
		if ip, dErr := pointDuckDNS(context.Background(), c); dErr != nil {
			fmt.Printf("  ! could not register %s yet: %v\n", h, dErr)
			fmt.Printf("    (double-check the DuckDNS token, then re-run setup or 'check')\n\n")
		} else {
			fmt.Printf("  ok — %s now points at %s\n\n", h, ip)
		}
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

// newNodeID returns a short, globally-unique, sortable id (xid) used as the
// stable DuckDNS subdomain label: decenzed-node-<id>.
func newNodeID() string {
	return xid.New().String()
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
