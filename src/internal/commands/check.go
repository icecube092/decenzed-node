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
	var unreachable []int
	for _, pr := range checkInbounds(cfg, haveCfg) {
		label := pr.name + ":"
		if pr.port == 0 {
			fmt.Printf("  %-12s disabled\n", label)
			continue
		}
		if host == "" {
			fmt.Printf("  %-12s TCP %d — can't self-check (no public IP/domain)\n", label, pr.port)
			continue
		}
		fmt.Printf("  %-12s dialing %s:%d ... ", label, host, pr.port)
		if err := selfReach(host, pr.port, 6*time.Second); err != nil {
			fmt.Printf("unreachable (%v)\n", err)
			unreachable = append(unreachable, pr.port)
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

// checkInbound pairs a protocol name with its configured port (0 = disabled).
type checkInbound struct {
	name string
	port int
}

// checkInbounds lists the protocols to report in `check`, in a stable order
// (VLESS, Trojan, Shadowsocks). Without a saved config we can only assume the
// default VLESS port, so just that one is reported.
func checkInbounds(cfg config.AppConfig, haveCfg bool) []checkInbound {
	if !haveCfg {
		return []checkInbound{{config.ProtoVLESS, 443}}
	}
	return []checkInbound{
		{config.ProtoVLESS, cfg.Port},
		{config.ProtoTrojan, cfg.TrojanPort},
		{config.ProtoShadowsocks, cfg.SSPort},
		{"shadowsocks-2022", cfg.SS2022Port},
	}
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
// DuckDNS domain when configured, else the configured/detected public IP.
func selfCheckHost(c config.AppConfig, detectedIP string) string {
	if h := c.DuckDNSHost(); h != "" {
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

// selfPortCheck confirms host:port is reachable from here. During setup the node
// isn't listening yet, so it spins up a throwaway TCP listener on the port for the
// duration of the dial; if the port is already bound (e.g. the running node), it
// dials the existing listener instead. A failure from inside your own LAN is not
// conclusive — many home routers can't hairpin back to their public IP.
func selfPortCheck(host string, port int, timeout time.Duration) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
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
	return selfReach(host, port, timeout)
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

// printPortForwardHelp prints router port-forwarding instructions for one or
// more TCP ports (one per enabled protocol).
func printPortForwardHelp(publicIP string, local []string, ports ...int) {
	lan := "your machine's LAN IP"
	if len(local) > 0 {
		lan = local[0]
	}
	ps := joinPorts(ports)
	fmt.Printf(`
── open port(s) %s on your router ─────────────────────────────
Friends connect INBOUND to this machine, so forward TCP port(s) %s:

  1. Open your router admin page (often http://192.168.1.1).
  2. Find "Port Forwarding" / "Virtual Server" / "NAT".
  3. For EACH port add: protocol TCP, external port = internal port,
     internal IP %s (this machine).
  4. Give this machine a STATIC LAN IP (DHCP reservation).

Tips: allow those TCP port(s) in your firewall; if your ISP uses CGNAT
(public IP starts with 100.64–100.127 or is private), forwarding
won't help — ask for a public IP or use a VPS. Some ISPs block
443; port 8443 usually works.
────────────────────────────────────────────────────────────────
`, ps, ps, lan)
}

// joinPorts renders ports as a comma-separated list, e.g. "8443, 8444, 9443".
func joinPorts(ports []int) string {
	ss := make([]string, len(ports))
	for i, p := range ports {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ", ")
}
