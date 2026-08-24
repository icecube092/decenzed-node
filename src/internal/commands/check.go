package commands

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/speedtest"
)

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
	var cfg config.AppConfig
	haveCfg := false
	if c, err := loadConfig(); err == nil {
		cfg, haveCfg = c, true
		if c.Port != 0 {
			port = c.Port
		}
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

	// Self-reachability: connect back to our own domain/IP on the node port to
	// confirm the port is actually reachable from the outside (port-forwarding).
	if host := selfCheckHost(cfg, ip); host != "" {
		fmt.Printf("\nself-check:        dialing %s:%d ...\n", host, port)
		if err := selfReach(host, port, 6*time.Second); err != nil {
			fmt.Printf("  ! could not reach %s:%d from here: %v\n", host, port, err)
			fmt.Println("    (this is normal from inside your own LAN — many routers can't")
			fmt.Println("     loop back to your public IP; test from mobile data to be sure.)")
		} else {
			fmt.Printf("  ok — %s:%d accepted a TCP connection.\n", host, port)
		}
	}

	printPortForwardHelp(port, ip, localIPv4s())
	return nil
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
