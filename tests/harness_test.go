//go:build e2e

// Package e2e drives the REAL decenzed-node binary as a black box: it builds the
// binary, writes a config, runs the node, connects a sing-box client, and pushes
// traffic through the tunnel to assert connectivity, filtering and speed. See
// README.md for what you must install/configure first.
//
// Everything here is standard-library only and gated behind the `e2e` build tag,
// so `go test ./...` in the app module never runs it.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- paths / build ----

// srcDir is the app module (relative to this test package's dir).
const srcDir = "../src"

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// buildNode compiles the decenzed-node binary once per test run into a temp dir
// and returns its path. A build failure fails the test loudly (that's a real
// regression, not a missing prerequisite).
func buildNode(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "decenzed-node"+exeSuffix())
	cmd := exec.Command("go", "build", "-o", out, "./cmd/decenzed-node")
	cmd.Dir = srcDir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build decenzed-node: %v\n%s", err, b)
	}
	return out
}

// ---- node config ----

// realityCfg holds the VLESS + REALITY parameters shared by the node inbound and
// the sing-box client (they must match exactly).
type realityCfg struct {
	Priv    string // server private key
	Pub     string // public key (client + link)
	ShortID string // short id (hex)
	Dest    string // borrowed TLS site "host:443"
	SNI     string // serverName the client sends (a Dest hostname)
}

// nodeConfig is the subset of the app config the e2e suite sets. It is marshalled
// to the app's config.json shape (json tags below mirror internal/config).
type nodeConfig struct {
	VLESSPort      int // VLESS+REALITY inbound (the primary protocol under test)
	SSPort         int // optional, only used by the link-output test
	UUID           string
	AllowPrivateIP bool    // true so a loopback origin is reachable through the node
	MaxUserBps     float64 // 0 = no cap
	ClientMode     string  // "", "blacklist", "whitelist"
	ClientDomains  []string
	Reality        *realityCfg // set for a startable VLESS node; nil = link-only config
	Debug          bool        // verbose xray logging
}

// writeConfig writes config.json + returns the data dir. With Reality set it is a
// real, startable VLESS+REALITY node; without it a dummy public key just satisfies
// IsConfigured() for the link-output test (no REALITY inbound is started).
func writeConfig(t *testing.T, cfg nodeConfig) string {
	t.Helper()
	dir := t.TempDir()
	client := map[string]any{"uuid": cfg.UUID, "name": "alice"}
	if cfg.ClientMode != "" {
		client["domain_mode"] = cfg.ClientMode
		client["domains"] = cfg.ClientDomains
	}
	m := map[string]any{
		"node_id":          "e2e",
		"port":             cfg.VLESSPort,
		"ss_port":          cfg.SSPort,
		"camouflage":       "reality",
		"block_protocols":  []string{},
		"allow_private_ip": cfg.AllowPrivateIP,
		"max_user_bps":     cfg.MaxUserBps,
		"debug":            cfg.Debug,
		"clients":          []any{client},
	}
	if r := cfg.Reality; r != nil {
		m["reality_private_key"] = r.Priv
		m["reality_public_key"] = r.Pub
		m["reality_dest"] = r.Dest
		m["reality_server_names"] = []string{r.SNI}
		m["reality_short_ids"] = []string{r.ShortID}
	} else {
		m["reality_public_key"] = "e2e-dummy-pubkey" // link output only
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ---- running the node ----

// nodeEnv is the environment every node/CLI invocation runs with: an isolated
// data dir, no privilege elevation, and (harmless) staging-safe defaults.
func nodeEnv(dataDir string) []string {
	return append(os.Environ(),
		"DECENZED_DATA="+dataDir,
		"DECENZED_NO_ELEVATE=1",
	)
}

// startNode runs `decenzed-node start` in the foreground and waits until the
// given port accepts connections. It is killed on test cleanup.
func startNode(t *testing.T, bin, dataDir string, waitPort int) {
	t.Helper()
	cmd := exec.Command(bin, "start")
	cmd.Env = nodeEnv(dataDir)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr // surface node logs on failure
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	if !waitListening(fmt.Sprintf("127.0.0.1:%d", waitPort), 15*time.Second) {
		t.Fatalf("node did not start listening on port %d", waitPort)
	}
}

// runCLI runs a one-shot CLI command against the given data dir and returns its
// combined output.
func runCLI(t *testing.T, bin, dataDir string, args ...string) string {
	return runCLIInput(t, bin, dataDir, "", args...)
}

// runCLIInput is runCLI with data fed to the command's stdin — needed for the
// interactive commands (e.g. `link add`/`edit` open a small REPL; feed "done\n"
// to accept and commit).
func runCLIInput(t *testing.T, bin, dataDir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = nodeEnv(dataDir)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cli %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func waitListening(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

// ---- sing-box client ----

// singboxBinary returns the sing-box binary the tunnel tests use. It is NOT
// auto-installed: provide it at tests/bin/sing-box[.exe] (or via $SINGBOX_BIN).
// A missing binary FAILS the test — sing-box is a hard prerequisite for the
// tunnel path, so a silent skip would hide a broken setup.
func singboxBinary(t *testing.T) string {
	t.Helper()
	if b := strings.TrimSpace(os.Getenv("SINGBOX_BIN")); b != "" {
		if fileExistsNonEmpty(b) {
			return b
		}
		t.Fatalf("SINGBOX_BIN=%s not found or empty", b)
	}
	p := filepath.Join("bin", "sing-box"+exeSuffix())
	if !fileExistsNonEmpty(p) {
		abs, _ := filepath.Abs(p)
		t.Fatalf("sing-box not found at %s\n"+
			"download it from https://github.com/sagernet/sing-box/releases and put it there "+
			"(or set SINGBOX_BIN) — see README.md", abs)
	}
	return p
}

// genRealityKeys generates a fresh REALITY x25519 keypair using sing-box, so the
// node and the client agree without importing the app's internal keygen.
func genRealityKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	out, err := exec.Command(singboxBinary(t), "generate", "reality-keypair").CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box generate reality-keypair: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PrivateKey:"); ok {
			priv = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PublicKey:"); ok {
			pub = strings.TrimSpace(v)
		}
	}
	if priv == "" || pub == "" {
		t.Fatalf("could not parse REALITY keypair from:\n%s", out)
	}
	return priv, pub
}

// startSingbox launches sing-box with a SOCKS inbound and a VLESS + REALITY +
// Vision outbound pointing at the node (the app's primary protocol), and returns
// the local SOCKS port. Killed on cleanup.
func startSingbox(t *testing.T, vlessPort int, uuid string, r *realityCfg) int {
	t.Helper()
	bin := singboxBinary(t)
	socksPort := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "in",
			"listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "vless", "tag": "out",
			"server": "127.0.0.1", "server_port": vlessPort,
			"uuid": uuid, "flow": "xtls-rprx-vision",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": r.SNI,
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{
					"enabled":    true,
					"public_key": r.Pub,
					"short_id":   r.ShortID,
				},
			},
		}},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	path := filepath.Join(t.TempDir(), "singbox.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sing-box: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	if !waitListening(fmt.Sprintf("127.0.0.1:%d", socksPort), 10*time.Second) {
		t.Fatalf("sing-box SOCKS did not come up on %d", socksPort)
	}
	return socksPort
}

// ---- HTTP over the tunnel (SOCKS5, no local DNS) ----

// httpClientVia builds an http.Client whose connections are made by CONNECTing
// through the sing-box SOCKS proxy. The target host is sent to SOCKS verbatim, so
// the NODE resolves it (no local DNS) — which is what lets domain filtering apply.
func httpClientVia(socksPort int) *http.Client {
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return socks5Connect(socksAddr, addr)
			},
		},
	}
}

// socks5Connect opens a SOCKS5 CONNECT tunnel to addr ("host:port") via the
// sing-box proxy at socksAddr. host is kept as a domain (ATYP=domain) so the node
// sees and can filter on it.
func socks5Connect(socksAddr, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	// greeting: VER=5, 1 method, NO_AUTH
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := readFull(c, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks greeting failed: %v %v", resp, err)
	}
	// request: CONNECT, ATYP=domain
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	// reply: VER REP RSV ATYP BND.ADDR BND.PORT
	head := make([]byte, 4)
	if _, err := readFull(c, head); err != nil {
		c.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks connect rejected: rep=0x%02x", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := readFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0])
	}
	if _, err := readFull(c, make([]byte, skip+2)); err != nil { // addr + port
		c.Close()
		return nil, err
	}
	return c, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	return io.ReadFull(c, b)
}

// ---- misc ----

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func fileExistsNonEmpty(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func newUUID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
