package commands

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/geodata"
)

// hasGeositeToken reports whether any source is a "geosite:" reference (needs
// geosite.dat).
func hasGeositeToken(sources []string) bool {
	for _, s := range sources {
		if strings.HasPrefix(strings.TrimSpace(s), "geosite:") {
			return true
		}
	}
	return false
}

// hasCountryGeoIPToken reports whether any source is a COUNTRY "geoip:" reference
// (needs geoip.dat). "geoip:private" is built into xray-core, so it does not
// count.
func hasCountryGeoIPToken(sources []string) bool {
	for _, s := range sources {
		if code, ok := strings.CutPrefix(strings.TrimSpace(s), "geoip:"); ok {
			if !strings.EqualFold(strings.TrimSpace(code), "private") {
				return true
			}
		}
	}
	return false
}

// sourcesInConfig visits the new-user default list and every client's list.
func sourcesInConfig(c config.AppConfig, pred func([]string) bool) bool {
	if pred(c.DefaultDomains) {
		return true
	}
	for _, cl := range c.Clients {
		if pred(cl.Domains) {
			return true
		}
	}
	return false
}

func configUsesGeosite(c config.AppConfig) bool {
	return sourcesInConfig(c, hasGeositeToken)
}
func configUsesCountryGeoIP(c config.AppConfig) bool {
	return sourcesInConfig(c, hasCountryGeoIPToken)
}

// ensureGeodataForSources offers to download the data files a freshly entered
// source needs, if they aren't installed yet: geosite.dat for a geosite: source,
// geoip.dat for a COUNTRY geoip: source. Called from the setup default prompt
// and the `link edit`/`add` REPL. No-op for sources that need no asset
// (geoip:private, custom files, bare domains) or when the asset is present.
func ensureGeodataForSources(in *input, sources []string) {
	dir := setXrayAssetDir()
	if dir == "" {
		return
	}
	if hasGeositeToken(sources) && !geodata.Geosite.Installed(dir) {
		offerGeodataDownload(in, dir, geodata.Geosite, "geosite: lists need geosite.dat (curated domain lists) — download it now?")
	}
	if hasCountryGeoIPToken(sources) && !geodata.GeoIP.Installed(dir) {
		offerGeodataDownload(in, dir, geodata.GeoIP, "geoip:<country> lists need geoip.dat (IP-by-country data) — download it now?")
	}
}

// updateGeodata checks for and offers updates to the data files that are
// actually in use. It runs as the first step of `update`, before the binary
// self-update, and touches geosite.dat / geoip.dat only when a corresponding
// source is configured. Best-effort: a network/remote error is reported, not
// fatal.
func updateGeodata(in *input) {
	c, err := loadConfig()
	if err != nil {
		return
	}
	dir := setXrayAssetDir()
	if dir == "" {
		return
	}
	if configUsesGeosite(c) {
		refreshGeodata(in, dir, geodata.Geosite)
	}
	if configUsesCountryGeoIP(c) {
		refreshGeodata(in, dir, geodata.GeoIP)
	}
	// Re-fetch any url: custom lists referenced in the config.
	updateRemoteLists(c)
}

// refreshGeodata installs the asset if missing, else checks the release for a
// newer version and offers the update.
func refreshGeodata(in *input, dir string, a geodata.Asset) {
	fmt.Printf("checking for %s updates...\n", a.File)
	if !a.Installed(dir) {
		offerGeodataDownload(in, dir, a, fmt.Sprintf("%s is not installed — download it now?", a.File))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	upd, err := a.UpdateAvailable(ctx, dir)
	if err != nil {
		fmt.Printf("  ! could not check %s: %v\n", a.File, err)
		return
	}
	if !upd {
		fmt.Printf("  %s is up to date.\n", a.File)
		return
	}
	offerGeodataDownload(in, dir, a, fmt.Sprintf("a newer %s is available — update it now?", a.File))
}

// offerGeodataDownload asks (y/n, default yes) and, if accepted, downloads and
// installs the asset into dir.
func offerGeodataDownload(in *input, dir string, a geodata.Asset, prompt string) {
	if !askYesNo(in, prompt, true) {
		fmt.Printf("  skipped — those lists won't match until %s is installed (from %s)\n", a.File, hostOf(a.URL()))
		return
	}
	fmt.Printf("  downloading %s from %s ...\n", a.File, hostOf(a.URL()))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	n, err := a.Download(ctx, dir)
	if err != nil {
		fmt.Printf("  ! could not download %s: %v\n", a.File, err)
		return
	}
	fmt.Printf("  ok — %s installed (%s)\n", a.File, humanBytes(uint64(n)))
}

// hostOf returns the host of a URL for display, or the raw string on parse error.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}
