package commands

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/speedtest"
)

func cmdCheck(r *input) error {
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

	runSpeedTest()

	var cfg config.AppConfig
	haveCfg := false
	if c, err := loadConfig(); err == nil {
		cfg, haveCfg = c, true
	}

	// When DuckDNS is configured, refresh the record and confirm the domain
	// actually resolves to our current public IP before we test reachability.
	if haveCfg {
		if host := cfg.DuckDNSHost(); host != "" {
			wantIP := ip
			if setIP, dErr := pointDuckDNS(context.Background(), cfg); dErr != nil {
				fmt.Printf("\nduckdns:           could not refresh %s: %v\n", host, dErr)
			} else {
				fmt.Printf("\nduckdns:           %s -> %s (updated)\n", host, setIP)
				wantIP = setIP
			}
			verifyDuckDNSResolves(host, wantIP)
		}
	}

	// Self-reachability, per protocol: connect back to our own domain/IP on each
	// ENABLED inbound's port to confirm it's reachable from outside
	// (port-forwarding). Disabled protocols are reported as such.
	host := selfCheckHost(cfg, ip)
	fmt.Println("\nprotocol ports:")
	var unreachable []portForward
	for _, pr := range checkInbounds(cfg, haveCfg) {
		label := pr.name + ":"
		if pr.public == 0 {
			fmt.Printf("  %-12s disabled\n", label)
			continue
		}
		// Clients reach us on the PUBLIC (external) port; a router forward maps it
		// to the port the node actually binds. Note the mapping when they differ.
		portDesc := strconv.Itoa(pr.public)
		if pr.remapped() {
			portDesc = fmt.Sprintf("%d (-> :%d)", pr.public, pr.bind)
		}
		if host == "" {
			fmt.Printf("  %-12s TCP %s — can't self-check (no public IP/domain)\n", label, portDesc)
			continue
		}
		fmt.Printf("  %-12s dialing %s:%d ... ", label, host, pr.public)
		if err := selfReach(host, pr.public, 6*time.Second); err != nil {
			fmt.Printf("unreachable (%v)\n", err)
			unreachable = append(unreachable, portForward{Public: pr.public, Bind: pr.bind})
		} else {
			fmt.Println("ok — accepted a TCP connection")
		}
	}

	// Only nudge about port-forwarding when an enabled protocol wasn't reachable.
	if len(unreachable) > 0 {
		fmt.Println("\n  ! could not confirm the port(s) above from here. This is normal from")
		fmt.Println("    inside your own LAN — many routers can't loop back to your public IP;")
		fmt.Println("    test from mobile data to be sure. If it really is closed, forward it:")
		printPortForwardHelp(ip, localIPv4s(), unreachable...)
	}
	return nil
}

// checkInbound pairs a protocol name with its external (public) and internal
// (bind) ports. A public port of 0 means the protocol is disabled.
type checkInbound struct {
	name   string
	public int
	bind   int
}

// remapped reports whether the external port differs from the port the node
// binds (a router forward sits in front).
func (ci checkInbound) remapped() bool { return ci.bind != 0 && ci.bind != ci.public }

// checkInbounds lists the protocols to report in `check`, in a stable order
// (VLESS, Trojan, Shadowsocks). Without a saved config we can only assume the
// default VLESS port, so just that one is reported.
func checkInbounds(cfg config.AppConfig, haveCfg bool) []checkInbound {
	if !haveCfg {
		return []checkInbound{{config.ProtoVLESS, 443, 443}}
	}
	return []checkInbound{
		{config.ProtoVLESS, cfg.VLESSPublicPort(), cfg.Port},
		{config.ProtoTrojan, publicOrBind(cfg.TrojanPublicPort, cfg.TrojanPort), cfg.TrojanPort},
		{config.ProtoShadowsocks, publicOrBind(cfg.SSPublicPort, cfg.SSPort), cfg.SSPort},
		{"shadowsocks-2022", publicOrBind(cfg.SS2022PublicPort, cfg.SS2022Port), cfg.SS2022Port},
	}
}

// publicOrBind mirrors config's public-port fallback for the disabled-aware
// listing here: the external override when set, else the bind port (which is 0,
// i.e. "disabled", when the protocol is off).
func publicOrBind(pub, bind int) int {
	if pub != 0 {
		return pub
	}
	return bind
}

// verifyDuckDNSResolves resolves host and reports whether it currently points at
// wantIP (our public IP). DNS propagation can lag a fresh update, so a mismatch
// is a warning, not a hard failure.
func verifyDuckDNSResolves(host, wantIP string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		fmt.Printf("  ! %s does not resolve yet: %v\n", host, err)
		return
	}
	for _, a := range addrs {
		if a == wantIP {
			fmt.Printf("  ok — %s resolves to %s\n", host, wantIP)
			return
		}
	}
	fmt.Printf("  ! %s resolves to %s, not your IP %s (DNS may still be propagating)\n",
		host, strings.Join(addrs, ", "), wantIP)
}

// selfCheckHost is the address to dial back for the reachability test: the
// operator's domain (custom or DuckDNS) when configured, else the
// configured/detected public IP.
func selfCheckHost(c config.AppConfig, detectedIP string) string {
	if h := c.Domain(); h != "" {
		return h
	}
	if c.PublicIP != "" {
		return c.PublicIP
	}
	return detectedIP
}

// selfReach dials host:port over TCP and reports whether it accepts a connection.
func selfReach(host string, port int, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return conn.Close()
}

// selfPortCheck confirms host:publicPort is reachable from here. During setup the
// node isn't listening yet, so it spins up a throwaway TCP listener on bindPort —
// the port the node WILL bind, and the router's forward target — for the duration
// of the dial; if that port is already bound (e.g. the running node), it dials the
// existing listener instead. The dial targets publicPort (the external port the
// router forwards to bindPort). A failure from inside your own LAN is not
// conclusive — many home routers can't hairpin back to their public IP.
func selfPortCheck(host string, publicPort, bindPort int, timeout time.Duration) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", bindPort))
	if err == nil {
		defer ln.Close()
		go func() {
			for {
				conn, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}
	return selfReach(host, publicPort, timeout)
}

// runSpeedTest measures up/down throughput and prints the result, warning when
// upload is too low to serve clients well.
func runSpeedTest() {
	fmt.Println("\nrunning a speed test (~25 MB up/down)...")
	sctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	sp, sErr := speedtest.Run(sctx)
	cancel()
	if sErr != nil {
		fmt.Println("  ! speed test could not run:", sErr)
		return
	}
	fmt.Printf("download:          %.1f Mbit/s\n", sp.DownMbps)
	fmt.Printf("upload:            %.1f Mbit/s\n", sp.UpMbps)
	if sp.Best() < 10 {
		fmt.Printf("  ! upload is low (%.1f Mbit/s) — clients will be slow.\n", sp.Best())
	}
}

// portForward is one router mapping: the external (WAN) port clients dial and
// the internal (LAN) port the node binds. They are equal unless the operator
// deliberately remaps (e.g. WAN 443 -> LAN 8443).
type portForward struct {
	Public int // external / WAN port
	Bind   int // internal / LAN port
}

// remapped reports whether the external and internal ports differ.
func (f portForward) remapped() bool { return f.Bind != 0 && f.Bind != f.Public }

// printPortForwardHelp prints router port-forwarding instructions for one or
// more TCP mappings (one per enabled protocol). When a mapping remaps the port
// (external != internal), the instructions spell out both sides.
func printPortForwardHelp(publicIP string, local []string, fwds ...portForward) {
	lan := "your machine's LAN IP"
	if len(local) > 0 {
		lan = local[0]
	}
	ps := joinForwards(fwds)
	// The per-port rule differs when any mapping remaps: with a straight forward
	// the external and internal port match; with a remap they don't.
	rule := "protocol TCP, external port = internal port"
	if anyRemapped(fwds) {
		rule = "protocol TCP, external port -> internal port as listed above"
	}
	fmt.Printf(`
── open port(s) %s on your router ─────────────────────────────
Friends connect INBOUND to this machine, so forward TCP port(s) %s:

  1. Open your router admin page (often http://192.168.1.1).
  2. Find "Port Forwarding" / "Virtual Server" / "NAT".
  3. For EACH mapping add: %s,
     internal IP %s (this machine).
  4. Give this machine a STATIC LAN IP (DHCP reservation).

Tips: allow those TCP port(s) in your firewall; if your ISP uses CGNAT
(public IP starts with 100.64–100.127 or is private), forwarding
won't help — ask for a public IP or use a VPS. Some ISPs block
443; port 8443 usually works.
────────────────────────────────────────────────────────────────
`, ps, ps, rule, lan)
}

// anyRemapped reports whether any mapping has external != internal.
func anyRemapped(fwds []portForward) bool {
	for _, f := range fwds {
		if f.remapped() {
			return true
		}
	}
	return false
}

// joinForwards renders mappings as a comma-separated list. A straight forward
// shows just the port ("8443"); a remap shows both sides ("443->8443").
func joinForwards(fwds []portForward) string {
	ss := make([]string, len(fwds))
	for i, f := range fwds {
		if f.remapped() {
			ss[i] = fmt.Sprintf("%d->%d", f.Public, f.Bind)
		} else {
			ss[i] = strconv.Itoa(f.Public)
		}
	}
	return strings.Join(ss, ", ")
}
