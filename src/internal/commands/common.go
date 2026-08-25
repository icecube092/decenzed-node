package commands

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"decenzed/node_app/internal/config"
)

// --- data dir / config paths ---

// dataDir returns the data directory. By default it sits next to the executable
// so the OS service (which may run as a different user) and your CLI share the
// same files. On flash-constrained systems (e.g. an OpenWRT router) set
// DECENZED_DATA to relocate the data onto writable storage (USB/extroot); the
// generated service inherits the same value so CLI and daemon stay in sync.
func dataDir() (string, error) {
	if d := strings.TrimSpace(os.Getenv("DECENZED_DATA")); d != "" {
		return d, nil
	}
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

// logFilePath is where the daemon log is written. On OpenWRT (procd) it lives in
// /tmp (tmpfs/RAM) so rotating logs never wear out or fill the router's flash;
// everywhere else it sits next to the config in decenzed-data.
func logFilePath(cfgPath string) string {
	if procdAvailable() {
		return "/tmp/decenzed-node.log"
	}
	return filepath.Join(filepath.Dir(cfgPath), "node.log")
}

func loadConfig() (config.AppConfig, error) {
	path, err := configPath()
	if err != nil {
		return config.AppConfig{}, err
	}
	return config.Load(path)
}

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

// --- public/local IP helpers ---

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

// detectLocation best-effort resolves the node's 2-letter country code (e.g.
// "RS") from a public geo endpoint, used to label proxies in share links.
// Returns "" on any failure so callers fall back to the node label.
func detectLocation() string {
	// Cloudflare's trace includes a "loc=XX" line — HTTPS, no key.
	if body := httpGetString("https://www.cloudflare.com/cdn-cgi/trace", 1024); body != "" {
		for _, line := range strings.Split(body, "\n") {
			if cc, ok := strings.CutPrefix(line, "loc="); ok {
				if c := normCountry(cc); c != "" {
					return c
				}
			}
		}
	}
	// Fallback: ipinfo returns the code directly.
	return normCountry(httpGetString("https://ipinfo.io/country", 16))
}

// httpGetString GETs u and returns the trimmed body (up to limit bytes), or "".
func httpGetString(u string, limit int64) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return strings.TrimSpace(string(b))
}

// normCountry upper-cases s and returns it only if it is a 2-letter code.
func normCountry(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z' {
		return s
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

// --- port availability (setup helpers) ---

// portAvailable reports whether we can bind the given TCP port right now — a
// rough "is this port free on this machine" probe used to recommend a default
// during setup. Binding all interfaces (":port") mirrors how the node listens.
func portAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// recommendPortInRange returns a RANDOM free TCP port in [lo, hi] not in `taken`.
// Random (rather than first-free) so different nodes don't all land on the same
// port. Tries a handful of random picks, then a linear scan, then falls back to
// lo.
func recommendPortInRange(lo, hi int, taken ...int) int {
	isTaken := func(p int) bool {
		for _, t := range taken {
			if t != 0 && t == p {
				return true
			}
		}
		return false
	}
	span := int64(hi - lo + 1)
	for i := 0; i < 20; i++ {
		p := lo + int(randInt(span))
		if !isTaken(p) && portAvailable(p) {
			return p
		}
	}
	for p := lo; p <= hi; p++ {
		if !isTaken(p) && portAvailable(p) {
			return p
		}
	}
	return lo
}

// firstAvailablePort returns the first free port from choices, or choices[0] if
// none are free (so the caller still has a usable default).
func firstAvailablePort(choices []int) int {
	for _, p := range choices {
		if portAvailable(p) {
			return p
		}
	}
	return choices[0]
}

// --- ids ---

// newUUID returns a random (v4) UUID for a client credential.
func newUUID() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return u.String(), nil
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
