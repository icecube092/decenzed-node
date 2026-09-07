// Package geodata manages the xray-core data files that back "geosite:" (domain
// lists) and "geoip:" (IP/country lists) routing rules: geosite.dat and
// geoip.dat. Each is downloaded on demand from a public GitHub Release and
// verified against the release's SHA-256 sidecar; updates are detected by
// comparing the installed file's hash with the latest release's.
//
// These are SEPARATE external endpoints from the self-updater and are only
// touched when the operator opts in (an interactive download prompt, or the
// `update` command). The daemon never downloads on its own. geoip.dat is needed
// only for COUNTRY codes (geoip:ru, …); "geoip:private" is built into xray-core
// and needs no asset.
package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxDatBytes = 128 << 20 // sanity cap on a downloaded .dat

// Asset describes one downloadable xray data file.
type Asset struct {
	File       string // filename in the asset dir, e.g. "geosite.dat"
	envVar     string // env var that overrides the source URL
	defaultURL string // built-in source URL
}

// Geosite and GeoIP are the two assets we manage. Both ship at a stable "latest"
// release URL with a ".sha256sum" sidecar (the Loyalsoldier community rules).
var (
	Geosite = Asset{
		File:       "geosite.dat",
		envVar:     "DECENZED_GEOSITE_URL",
		defaultURL: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
	}
	GeoIP = Asset{
		File:       "geoip.dat",
		envVar:     "DECENZED_GEOIP_URL",
		defaultURL: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
	}
)

// URL is the asset's source: the env override, else the built-in default.
func (a Asset) URL() string {
	if u := strings.TrimSpace(os.Getenv(a.envVar)); u != "" {
		return u
	}
	return a.defaultURL
}

// Path is the installed file's path inside the asset dir.
func (a Asset) Path(dir string) string { return filepath.Join(dir, a.File) }

// Installed reports whether a non-empty copy is present in dir.
func (a Asset) Installed(dir string) bool {
	fi, err := os.Stat(a.Path(dir))
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// meta records the installed file's hash and when it was last checked/updated.
type meta struct {
	SHA256    string    `json:"sha256"`
	CheckedAt time.Time `json:"checked_at"`
}

func (a Asset) metaPath(dir string) string { return filepath.Join(dir, a.File+".meta.json") }

func (a Asset) readMeta(dir string) meta {
	var m meta
	if b, err := os.ReadFile(a.metaPath(dir)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func (a Asset) writeMeta(dir string, m meta) {
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = os.WriteFile(a.metaPath(dir), b, 0o600)
	}
}

// localSHA returns the SHA-256 of the installed file (hex).
func (a Asset) localSHA(dir string) (string, error) {
	f, err := os.Open(a.Path(dir))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxDatBytes)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// remoteSHA fetches the expected SHA-256 from the release's ".sha256sum" sidecar.
func (a Asset) remoteSHA(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL()+".sha256sum", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("sha256sum: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return parseSumFile(string(b))
}

// parseSumFile extracts the first hex digest from a sha256sum file body.
func parseSumFile(s string) (string, error) {
	for _, line := range strings.Split(s, "\n") {
		if f := strings.Fields(line); len(f) > 0 && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("no sha256 digest found in sidecar")
}

// UpdateAvailable reports whether the latest release differs from the installed
// file. It records the check time when the remote fetch succeeds. A missing
// local file counts as "update available". Network/remote errors are returned
// (callers treat them as best-effort).
func (a Asset) UpdateAvailable(ctx context.Context, dir string) (bool, error) {
	remote, err := a.remoteSHA(ctx)
	if err != nil {
		return false, err
	}
	m := a.readMeta(dir)
	m.CheckedAt = time.Now()
	a.writeMeta(dir, m)

	if !a.Installed(dir) {
		return true, nil
	}
	local, err := a.localSHA(dir)
	if err != nil {
		return true, nil
	}
	return !strings.EqualFold(local, remote), nil
}

// Download fetches the asset, verifies it against its SHA-256 sidecar, and
// installs it atomically into dir. Returns the number of bytes written.
func (a Asset) Download(ctx context.Context, dir string) (int64, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	want, sumErr := a.remoteSHA(ctx) // verify when the sidecar is available

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL(), nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("download: %s", resp.Status)
	}

	h := sha256.New()
	data, err := io.ReadAll(io.LimitReader(io.TeeReader(resp.Body, h), maxDatBytes))
	if err != nil {
		return 0, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if sumErr == nil && !strings.EqualFold(got, want) {
		return 0, fmt.Errorf("checksum mismatch: got %s want %s", got, want)
	}

	tmp := a.Path(dir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, a.Path(dir)); err != nil {
		return 0, err
	}
	a.writeMeta(dir, meta{SHA256: got, CheckedAt: time.Now()})
	return int64(len(data)), nil
}
