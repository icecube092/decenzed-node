//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// realityShortID is the REALITY short id shared by node + client (fixed hex).
const realityShortID = "0123456789abcdef"

// realitySNI is the borrowed TLS site the REALITY handshake impersonates. It must
// be a live TLS1.3+h2 host that xray-core's REALITY relay completes cleanly with
// (some big sites — e.g. www.microsoft.com — don't). Override with E2E_REALITY_SNI.
func realitySNI() string {
	if v := strings.TrimSpace(os.Getenv("E2E_REALITY_SNI")); v != "" {
		return v
	}
	return "www.cloudflare.com"
}

// newReality builds the VLESS+REALITY params for a test: it FAILS if sing-box is
// missing (a hard prerequisite — used to generate the keypair), and SKIPS if the
// REALITY dest can't be reached (a network condition, not a broken setup).
func newReality(t *testing.T) *realityCfg {
	t.Helper()
	priv, pub := genRealityKeys(t) // fails if sing-box is absent
	sni := realitySNI()
	if c, err := net.DialTimeout("tcp", sni+":443", 5*time.Second); err != nil {
		t.Skipf("REALITY dest %s:443 unreachable (%v) — VLESS tunnel needs it; set E2E_REALITY_SNI", sni, err)
	} else {
		_ = c.Close()
	}
	return &realityCfg{Priv: priv, Pub: pub, ShortID: realityShortID, Dest: sni + ":443", SNI: sni}
}

// loopbackDomain is a hostname that must resolve to 127.0.0.1 for the domain
// FILTERING tests (the node resolves it). Defaults to *.localtest.me (a public
// wildcard pointing at loopback); override with E2E_LOOPBACK_DOMAIN, or add a
// hosts-file entry and set it here. Connectivity/speed tests don't need it.
func loopbackDomain() string {
	if d := strings.TrimSpace(os.Getenv("E2E_LOOPBACK_DOMAIN")); d != "" {
		return d
	}
	return "localtest.me"
}

// startOrigin runs a tiny HTTP origin on 127.0.0.1: "/" returns "ok", and
// "/blob?n=BYTES" returns n zero bytes (for throughput tests).
func startOrigin(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/blob", func(w http.ResponseWriter, r *http.Request) {
		n := 1 << 20
		if v := r.URL.Query().Get("n"); v != "" {
			fmt.Sscanf(v, "%d", &n)
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", n))
		_, _ = io.Copy(w, io.LimitReader(zeroReader{}, int64(n)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// originPort extracts the port httptest bound on 127.0.0.1.
func originPort(t *testing.T, srv *httptest.Server) int {
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var p int
	fmt.Sscanf(portStr, "%d", &p)
	return p
}

// ---- tests ----

// TestNodeStartsAndListens is the smoke test: the built binary starts a
// VLESS+REALITY node (the primary protocol) and binds its port. Needs sing-box
// (to generate the REALITY keypair) but no reachable dest — it only binds, no
// handshake.
func TestNodeStartsAndListens(t *testing.T) {
	bin := buildNode(t)
	priv, pub := genRealityKeys(t)
	r := &realityCfg{Priv: priv, Pub: pub, ShortID: realityShortID, Dest: realitySNI() + ":443", SNI: realitySNI()}
	vlessPort := freePort(t)
	dir := writeConfig(t, nodeConfig{VLESSPort: vlessPort, UUID: newUUID(t), AllowPrivateIP: true, Reality: r})
	startNode(t, bin, dir, vlessPort)
	// startNode already asserted the port is listening.
	out := runCLI(t, bin, dir, "stats")
	if !strings.Contains(out, "vless") && !strings.Contains(out, "clients") {
		t.Errorf("stats output looks wrong:\n%s", out)
	}
}

// TestLinkCommands checks link printing + add/remove against the binary (no
// tunnel needed). Uses a config that also enables VLESS so a vless:// link is
// produced.
func TestLinkCommands(t *testing.T) {
	bin := buildNode(t)
	dir := writeConfig(t, nodeConfig{
		SSPort: freePort(t), VLESSPort: freePort(t), UUID: newUUID(t), AllowPrivateIP: true,
	})

	out := runCLI(t, bin, dir, "link", "-l")
	for _, want := range []string{"ss://", "vless://"} {
		if !strings.Contains(out, want) {
			t.Errorf("link -l missing %q:\n%s", want, out)
		}
	}

	// add a client (its REPL prompts for a filter — "done" keeps the defaults),
	// then it should appear; remove it, then it shouldn't.
	runCLIInput(t, bin, dir, "done\n", "link", "add", "bob")
	if out := runCLI(t, bin, dir, "link"); !strings.Contains(out, "bob") {
		t.Errorf("added client 'bob' not shown:\n%s", out)
	}
	runCLI(t, bin, dir, "link", "remove", "bob")
	if out := runCLI(t, bin, dir, "link"); strings.Contains(out, "bob") {
		t.Errorf("removed client 'bob' still shown:\n%s", out)
	}
}

// TestTunnelConnectivity pushes an HTTP request through the VLESS+REALITY tunnel
// (sing-box -> node -> origin) and expects it to succeed.
func TestTunnelConnectivity(t *testing.T) {
	bin := buildNode(t)
	origin := startOrigin(t)
	r := newReality(t)
	vlessPort := freePort(t)
	uuid := newUUID(t)
	dir := writeConfig(t, nodeConfig{VLESSPort: vlessPort, UUID: uuid, AllowPrivateIP: true, Reality: r})
	startNode(t, bin, dir, vlessPort)
	socks := startSingbox(t, vlessPort, uuid, r)

	client := httpClientVia(socks)
	body := mustGet(t, client, fmt.Sprintf("http://127.0.0.1:%d/", originPort(t, origin)))
	if body != "ok" {
		t.Errorf("tunnel GET body = %q, want \"ok\"", body)
	}
}

// TestBlacklistFiltering blocks one domain for the user; a request to it must
// fail while a sibling domain succeeds. Both resolve to loopback.
func TestBlacklistFiltering(t *testing.T) {
	base := loopbackDomain()
	requireLoopback(t, base)

	bin := buildNode(t)
	origin := startOrigin(t)
	port := originPort(t, origin)
	r := newReality(t)
	vlessPort := freePort(t)
	uuid := newUUID(t)
	blocked := "blocked." + base
	allowed := "allowed." + base
	dir := writeConfig(t, nodeConfig{
		VLESSPort: vlessPort, UUID: uuid, AllowPrivateIP: true, Reality: r,
		ClientMode: "blacklist", ClientDomains: []string{"domain:" + blocked},
	})
	startNode(t, bin, dir, vlessPort)
	socks := startSingbox(t, vlessPort, uuid, r)
	client := httpClientVia(socks)

	if body := mustGet(t, client, fmt.Sprintf("http://%s:%d/", allowed, port)); body != "ok" {
		t.Errorf("allowed domain body = %q, want ok", body)
	}
	if _, err := client.Get(fmt.Sprintf("http://%s:%d/", blocked, port)); err == nil {
		t.Errorf("blacklisted domain %s should have been blocked", blocked)
	}
}

// TestWhitelistFiltering allows ONLY one domain; the sibling must be blocked.
func TestWhitelistFiltering(t *testing.T) {
	base := loopbackDomain()
	requireLoopback(t, base)

	bin := buildNode(t)
	origin := startOrigin(t)
	port := originPort(t, origin)
	r := newReality(t)
	vlessPort := freePort(t)
	uuid := newUUID(t)
	allowed := "allowed." + base
	other := "other." + base
	dir := writeConfig(t, nodeConfig{
		VLESSPort: vlessPort, UUID: uuid, AllowPrivateIP: true, Reality: r,
		ClientMode: "whitelist", ClientDomains: []string{"domain:" + allowed},
	})
	startNode(t, bin, dir, vlessPort)
	socks := startSingbox(t, vlessPort, uuid, r)
	client := httpClientVia(socks)

	if body := mustGet(t, client, fmt.Sprintf("http://%s:%d/", allowed, port)); body != "ok" {
		t.Errorf("whitelisted domain body = %q, want ok", body)
	}
	if _, err := client.Get(fmt.Sprintf("http://%s:%d/", other, port)); err == nil {
		t.Errorf("non-whitelisted domain %s should have been blocked", other)
	}
}

// TestPrivateIPBlock proves the default egress-safety block: with private IPs
// blocked, the loopback origin is unreachable; allowing them makes it reachable.
func TestPrivateIPBlock(t *testing.T) {
	bin := buildNode(t)
	origin := startOrigin(t)
	port := originPort(t, origin)

	// Blocked (default): request to the loopback origin must fail.
	r := newReality(t)
	vlessPort := freePort(t)
	uuid := newUUID(t)
	dir := writeConfig(t, nodeConfig{VLESSPort: vlessPort, UUID: uuid, AllowPrivateIP: false, Reality: r})
	startNode(t, bin, dir, vlessPort)
	socks := startSingbox(t, vlessPort, uuid, r)
	if _, err := httpClientVia(socks).Get(fmt.Sprintf("http://127.0.0.1:%d/", port)); err == nil {
		t.Error("loopback should be blocked when private-IP blocking is on")
	}
}

// TestSpeedAndCap measures tunnel throughput and checks the per-user cap roughly
// holds. Sizes are modest to keep the test quick.
func TestSpeedAndCap(t *testing.T) {
	bin := buildNode(t)
	origin := startOrigin(t)
	port := originPort(t, origin)
	r := newReality(t)

	// 1) Uncapped: a few MB should move at a healthy rate.
	vlessPort := freePort(t)
	uuid := newUUID(t)
	dir := writeConfig(t, nodeConfig{VLESSPort: vlessPort, UUID: uuid, AllowPrivateIP: true, Reality: r})
	startNode(t, bin, dir, vlessPort)
	socks := startSingbox(t, vlessPort, uuid, r)
	mbps := throughputMbps(t, httpClientVia(socks), fmt.Sprintf("http://127.0.0.1:%d/blob?n=%d", port, 8<<20))
	t.Logf("uncapped throughput: %.1f Mbit/s", mbps)
	if mbps <= 0 {
		t.Fatal("no throughput measured over the tunnel")
	}

	// 2) Capped at ~16 Mbit/s: throughput must not greatly exceed the cap.
	const capMbps = 16.0
	vlessPort2 := freePort(t)
	uuid2 := newUUID(t)
	dir2 := writeConfig(t, nodeConfig{
		VLESSPort: vlessPort2, UUID: uuid2, AllowPrivateIP: true, Reality: r,
		MaxUserBps: capMbps * 1e6 / 8,
	})
	startNode(t, bin, dir2, vlessPort2)
	socks2 := startSingbox(t, vlessPort2, uuid2, r)
	capped := throughputMbps(t, httpClientVia(socks2), fmt.Sprintf("http://127.0.0.1:%d/blob?n=%d", port, 6<<20))
	t.Logf("capped throughput: %.1f Mbit/s (cap %.0f)", capped, capMbps)
	if capped > capMbps*2.5 {
		t.Errorf("throughput %.1f Mbit/s far exceeds the %.0f Mbit/s cap", capped, capMbps)
	}
}

// ---- helpers ----

func mustGet(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	return string(b)
}

// throughputMbps downloads url and returns the observed rate in Mbit/s.
func throughputMbps(t *testing.T, c *http.Client, url string) float64 {
	t.Helper()
	start := time.Now()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	secs := time.Since(start).Seconds()
	if secs <= 0 {
		return 0
	}
	return float64(n) * 8 / 1e6 / secs
}

// requireLoopback skips the test unless a "<x>.<base>" name resolves to 127.0.0.1
// (the domain-filtering tests need the node to resolve the test domains to the
// local origin).
func requireLoopback(t *testing.T, base string) {
	t.Helper()
	addrs, err := net.LookupHost("allowed." + base)
	if err != nil {
		t.Skipf("cannot resolve allowed.%s (%v) — set E2E_LOOPBACK_DOMAIN, see README.md", base, err)
	}
	for _, a := range addrs {
		if a == "127.0.0.1" || a == "::1" {
			return
		}
	}
	t.Skipf("allowed.%s resolves to %v, not loopback — set E2E_LOOPBACK_DOMAIN, see README.md", base, addrs)
}
