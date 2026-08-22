// Package realityscan finds a REALITY camouflage target for this node. It is a
// self-contained reimplementation of the core check from XTLS/RealiTLScanner:
// a host qualifies as a REALITY `dest`/`serverName` only if its TLS endpoint
// negotiates TLS 1.3 AND ALPN "h2" (HTTP/2) using an X25519 key exchange —
// exactly what a REALITY client will reproduce when borrowing its handshake.
//
// The node picks ONE such domain at setup; it must be unique across the network
// (checked against root), so different nodes impersonate different sites.
package realityscan

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultSeeds is a curated list of large, globally-reachable sites that serve
// TLS 1.3 + HTTP/2. Setup scans these and picks the first that qualifies AND is
// still free network-wide. Ordered roughly by popularity/reliability.
var DefaultSeeds = []string{
	"www.microsoft.com",
	"www.apple.com",
	"www.amazon.com",
	"www.cloudflare.com",
	"dl.google.com",
	"www.bing.com",
	"www.icloud.com",
	"swdist.apple.com",
	"www.samsung.com",
	"www.tesla.com",
	"www.python.org",
	"addons.mozilla.org",
	"www.nvidia.com",
	"www.intel.com",
	"cdn.jsdelivr.net",
	"www.wikipedia.org",
	"one.one.one.one",
	"www.digitalocean.com",
	"www.linode.com",
	"www.cisco.com",
	"www.oracle.com",
	"www.ibm.com",
	"www.adobe.com",
	"www.qualcomm.com",
}

// Candidate is a host that passed the REALITY suitability check.
type Candidate struct {
	Domain string // the domain to present as serverName (from the leaf cert)
	Host   string // the host we dialed (usually == Domain)
	TLS    string // negotiated TLS version, for display
	ALPN   string // negotiated ALPN, for display
}

// Probe checks a single host:port. ok=true only when the endpoint negotiates
// TLS 1.3 + h2 over X25519 (a valid REALITY target). It returns the certificate
// domain to use as serverName. This doubles as the liveness ("ping") check.
//
// When host is an IP (neighborhood scan) NO SNI is sent — the domain is
// DISCOVERED from the certificate the server presents. When host is a domain
// (seed list / re-probe) SNI is set to it.
func Probe(host string, port int, timeout time.Duration) (Candidate, bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return Candidate{}, false
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	sni := host
	if net.ParseIP(host) != nil {
		sni = "" // scanning a bare IP: don't send SNI, read the cert's domain
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // REALITY does not validate the borrowed cert
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
		// Match XTLS/RealiTLScanner exactly: prefer X25519 / X25519MLKEM768.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
	})
	if err := conn.HandshakeContext(context.Background()); err != nil {
		return Candidate{}, false
	}
	st := conn.ConnectionState()
	if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
		return Candidate{}, false
	}

	domain := host
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		if len(leaf.DNSNames) > 0 {
			domain = pickDNSName(leaf.DNSNames)
		} else if leaf.Subject.CommonName != "" {
			domain = leaf.Subject.CommonName
		}
	}
	// A bare-IP scan must yield an actual domain (not the IP itself).
	if net.ParseIP(host) != nil && net.ParseIP(domain) != nil {
		return Candidate{}, false
	}
	return Candidate{Domain: domain, Host: host, TLS: "1.3", ALPN: "h2"}, true
}

// pickDNSName prefers a concrete hostname over a wildcard (a wildcard like
// *.example.com is not usable as a REALITY serverName).
func pickDNSName(names []string) string {
	for _, n := range names {
		if !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	// Only wildcards: turn "*.example.com" into "www.example.com".
	n := names[0]
	if strings.HasPrefix(n, "*.") {
		return "www." + n[2:]
	}
	return n
}

// Hosts24 returns the other host addresses in the /24 containing ip (1..254,
// excluding the network/broadcast and ip itself). Used to scan a node's own
// public-IP neighborhood for REALITY targets. Non-IPv4 input yields nil.
func Hosts24(ip string) []string {
	p := net.ParseIP(ip)
	if p == nil {
		return nil
	}
	p4 := p.To4()
	if p4 == nil {
		return nil
	}
	self := p4[3]
	out := make([]string, 0, 253)
	for i := 1; i <= 254; i++ {
		if byte(i) == self {
			continue
		}
		out = append(out, net.IPv4(p4[0], p4[1], p4[2], byte(i)).String())
	}
	return out
}

// Scan probes hosts concurrently and returns the qualifying candidates in the
// input order (so the seed priority is preserved). ctx cancels the scan.
func Scan(ctx context.Context, hosts []string, port int, timeout time.Duration, workers int) []Candidate {
	if workers <= 0 {
		workers = 12
	}
	type res struct {
		i int
		c Candidate
	}
	in := make(chan int)
	out := make(chan res)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range in {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if c, ok := Probe(hosts[i], port, timeout); ok {
					out <- res{i, c}
				}
			}
		}()
	}
	go func() {
		defer close(in)
		for i := range hosts {
			select {
			case <-ctx.Done():
				return
			case in <- i:
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()

	var found []res
	for r := range out {
		found = append(found, r)
	}
	sort.Slice(found, func(a, b int) bool { return found[a].i < found[b].i })
	cands := make([]Candidate, len(found))
	for i, r := range found {
		cands[i] = r.c
	}
	return cands
}
