package commands

import (
	"context"
	"crypto/rand"
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

// dataDir returns the data directory next to the executable so the OS service
// (which may run as a different user) and your CLI share the same files.
func dataDir() (string, error) {
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
func logFilePath(cfgPath string) string    { return filepath.Join(filepath.Dir(cfgPath), "node.log") }

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
