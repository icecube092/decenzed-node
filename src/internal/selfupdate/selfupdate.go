// Package selfupdate lets the node daemon update its own binary from a signed
// manifest of release assets. Cross-platform binary replacement (including the
// Windows "can't overwrite a running exe" dance) is handled by minio/selfupdate;
// integrity is enforced with a per-asset SHA-256.
//
// The manifest URL is baked into the binary (config.DefaultUpdateManifestURL);
// point it at a public GitHub Release asset (or any HTTPS URL). Empty = disabled.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/minio/selfupdate"
)

// Asset is one platform's downloadable binary + its expected checksum.
type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Manifest lists the latest version and its per-platform assets, keyed by
// "GOOS_GOARCH" (e.g. "windows_amd64", "linux_amd64", "darwin_arm64").
type Manifest struct {
	Version string           `json:"version"`
	Assets  map[string]Asset `json:"assets"`
}

// platformKey is this build's manifest key.
func platformKey() string { return runtime.GOOS + "_" + runtime.GOARCH }

// CheckAndApply fetches the manifest and, if it advertises a newer version with
// an asset for this platform, downloads + verifies + replaces this binary. The
// new binary takes effect on the next (re)start. Returns the new version when an
// update was applied.
func CheckAndApply(ctx context.Context, currentVersion, manifestURL string) (applied bool, newVersion string, err error) {
	if manifestURL == "" {
		return false, "", nil
	}
	m, err := fetchManifest(ctx, manifestURL)
	if err != nil {
		return false, "", err
	}
	if !isNewer(m.Version, currentVersion) {
		return false, m.Version, nil
	}
	asset, ok := m.Assets[platformKey()]
	if !ok || asset.URL == "" {
		return false, m.Version, fmt.Errorf("no update asset for %s", platformKey())
	}
	if err := downloadAndApply(ctx, asset); err != nil {
		return false, m.Version, err
	}
	return true, m.Version, nil
}

func fetchManifest(ctx context.Context, url string) (Manifest, error) {
	var m Manifest
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return m, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return m, fmt.Errorf("manifest: %s", resp.Status)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m)
	return m, err
}

func downloadAndApply(ctx context.Context, a Asset) error {
	dctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(dctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("download: %s", resp.Status)
	}

	// Buffer to memory while hashing so we can verify BEFORE replacing.
	h := sha256.New()
	data, err := io.ReadAll(io.LimitReader(io.TeeReader(resp.Body, h), 256<<20))
	if err != nil {
		return err
	}
	if a.SHA256 != "" {
		if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, a.SHA256) {
			return fmt.Errorf("checksum mismatch: got %s want %s", got, a.SHA256)
		}
	}
	return selfupdate.Apply(strings.NewReader(string(data)), selfupdate.Options{})
}

// isNewer reports whether candidate > current using a lenient semver compare.
// "dev"/empty current never updates (local builds); a non-numeric candidate
// updates only if it differs from current.
func isNewer(candidate, current string) bool {
	if current == "" || current == "dev" {
		return false
	}
	cand := strings.TrimPrefix(strings.TrimSpace(candidate), "v")
	cur := strings.TrimPrefix(strings.TrimSpace(current), "v")
	if cand == "" || cand == cur {
		return false
	}
	cp, cerr := parseSemver(cand)
	up, uerr := parseSemver(cur)
	if cerr != nil || uerr != nil {
		return cand != cur // fall back to "different means newer"
	}
	for i := 0; i < 3; i++ {
		if cp[i] != up[i] {
			return cp[i] > up[i]
		}
	}
	return false
}

func parseSemver(s string) ([3]int, error) {
	var out [3]int
	// Drop any pre-release/build suffix.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, fmt.Errorf("bad semver %q", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, err
		}
		out[i] = n
	}
	return out, nil
}
