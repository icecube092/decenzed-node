// Package domainlist resolves a user's filter SOURCES into the concrete matchers
// xray routes on, split into DOMAIN matchers (rule "domain" field) and IP
// matchers (rule "ip" field). A source is one of:
//
//	geosite:CATEGORY        a category in xray's geosite.dat            -> domain
//	ext:FILE.dat:CATEGORY   a category in an external .dat              -> domain
//	domain:… full:… keyword:… regexp:…   an explicit xray domain matcher -> domain
//	file:NAME / list:NAME / @NAME        a custom text file <Dir>/NAME.txt
//	url:https://…            a remote text list, cached in <Dir> (see URLCacheName)
//	geoip:CODE              a country in geoip.dat                       -> ip
//	geoip:private           expands to literal private CIDRs (no asset)  -> ip
//	<anything else>         a bare domain (xray treats it as domain:)   -> domain
//
// A url: list is fetched and CACHED to a file by the CLI (on add, and on
// `update`); the resolver only ever reads that cache, so config generation stays
// offline and works with no network at daemon start. A not-yet-cached url: (or a
// missing custom file / uninstalled .dat) is skipped with a warning.
//
// The .dat forms are matched by xray itself at runtime (it reads the asset dir
// XRAY_LOCATION_ASSET, which the node points at decenzed-data/domains). Custom
// text files are expanded HERE, at config-generation time, so several files plus
// geosite/geoip categories all collapse into the routing rule's arrays (a
// logical OR — this is how the modes "combine" lists). Each line of a custom
// file is classified the same way (a "geoip:" line becomes an IP matcher).
// Results are flattened in order and de-duplicated per field.
package domainlist

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// URLCacheName is the deterministic cache filename (inside Dir) for a remote
// list URL. Kept stable so the resolver, the downloader, and `update` all agree
// on where a url: list is stored.
func URLCacheName(rawURL string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawURL)))
	return "url-" + hex.EncodeToString(sum[:8]) + ".txt"
}

// PrivateIPCIDRs is the canonical set of private / loopback / link-local /
// reserved destination ranges used for the "block private IPs" egress safety and
// for expanding a "geoip:private" source. We emit literal CIDRs (not the
// "geoip:private" token) so the rule needs NO geoip.dat and works on every
// xray-core version — some load even "private" from the asset file.
var PrivateIPCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",  // CGNAT
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4", // reserved
	"::1/128",     // IPv6 loopback
	"fc00::/7",    // IPv6 ULA
	"fe80::/10",   // IPv6 link-local
}

// Resolver expands sources, reading custom lists from Dir (decenzed-data/domains).
type Resolver struct {
	Dir string
}

// Resolved is the outcome of resolving a source list: domain matchers, IP
// (geoip) matchers, and any warnings about sources that were skipped (a missing
// custom file or an uninstalled .dat).
type Resolved struct {
	Domains  []string
	IPs      []string
	Warnings []string
}

// Resolve flattens sources into a Resolved. Custom-file references are read from
// disk and inlined; every other token is classified and passed through. A
// problem with one source is recorded as a warning (that source is skipped) so a
// single bad reference never voids the whole filter.
func (r Resolver) Resolve(sources []string) Resolved {
	var res Resolved
	seenD, seenI := map[string]struct{}{}, map[string]struct{}{}
	addTo := func(list *[]string, seen map[string]struct{}, e string) {
		if _, dup := seen[e]; dup {
			return
		}
		seen[e] = struct{}{}
		*list = append(*list, e)
	}

	// classify routes a single token to the domain or ip field, applying the
	// asset-presence guard so a missing .dat can't abort xray startup.
	classify := func(tok string) {
		if tok = strings.TrimSpace(tok); tok == "" {
			return
		}
		// List references nested inside a list are not expanded (one level only).
		if _, ok := customRef(tok); ok {
			res.Warnings = append(res.Warnings, fmt.Sprintf("nested list reference %q ignored", tok))
			return
		}
		if _, ok := urlRef(tok); ok {
			res.Warnings = append(res.Warnings, fmt.Sprintf("nested list reference %q ignored", tok))
			return
		}
		// geoip:private -> literal private CIDRs (no asset, every xray version).
		if code, ok := strings.CutPrefix(tok, "geoip:"); ok && strings.EqualFold(strings.TrimSpace(code), "private") {
			for _, cidr := range PrivateIPCIDRs {
				addTo(&res.IPs, seenI, cidr)
			}
			return
		}
		field := &res.Domains
		seen := seenD
		if strings.HasPrefix(tok, "geoip:") {
			field = &res.IPs
			seen = seenI
		}
		if asset, ok := datAsset(tok); ok && !r.assetPresent(asset) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%q skipped: %s not installed in %s", tok, asset, r.Dir))
			return
		}
		addTo(field, seen, tok)
	}

	for _, s := range sources {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if name, ok := customRef(s); ok {
			lines, err := r.readList(name)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("domain list %q: %v", name, err))
				continue
			}
			for _, l := range lines {
				classify(l)
			}
			continue
		}
		if raw, ok := urlRef(s); ok {
			lines, err := r.readListFile(URLCacheName(raw))
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("remote list %q not cached yet (run 'update' or re-add it): %v", raw, err))
				continue
			}
			for _, l := range lines {
				classify(l)
			}
			continue
		}
		classify(s)
	}
	return res
}

// datAsset returns the .dat filename a source depends on, if any: "geosite.dat"
// for geosite:, "FILE.dat" for ext:FILE.dat:category, "geoip.dat" for a geoip:
// COUNTRY code. "geoip:private" is built into xray-core and needs no asset.
func datAsset(s string) (string, bool) {
	if strings.HasPrefix(s, "geosite:") {
		return "geosite.dat", true
	}
	if rest, ok := strings.CutPrefix(s, "ext:"); ok {
		if i := strings.IndexByte(rest, ':'); i > 0 {
			return rest[:i], true
		}
	}
	if code, ok := strings.CutPrefix(s, "geoip:"); ok {
		if strings.EqualFold(strings.TrimSpace(code), "private") {
			return "", false // built-in, no asset needed
		}
		return "geoip.dat", true
	}
	return "", false
}

// assetPresent reports whether the named .dat exists in Dir. When Dir is unset
// (the caller can't tell us where assets live) it can't verify, so it assumes
// present and passes the token through unchanged.
func (r Resolver) assetPresent(name string) bool {
	if r.Dir == "" {
		return true
	}
	fi, err := os.Stat(filepath.Join(r.Dir, name))
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// customRef reports whether s references a custom text file and returns its bare
// name. Accepts "file:NAME", "list:NAME", or "@NAME".
func customRef(s string) (string, bool) {
	for _, p := range []string{"file:", "list:", "@"} {
		if name, ok := strings.CutPrefix(s, p); ok {
			return strings.TrimSpace(name), true
		}
	}
	return "", false
}

// urlRef reports whether s references a remote list ("url:https://…") and returns
// the raw URL.
func urlRef(s string) (string, bool) {
	if u, ok := strings.CutPrefix(s, "url:"); ok {
		return strings.TrimSpace(u), true
	}
	return "", false
}

// readList reads the custom text list <Dir>/<name>.txt. The name is reduced to a
// single path element so a source can never escape Dir.
func (r Resolver) readList(name string) ([]string, error) {
	base := filepath.Base(strings.TrimSuffix(name, ".txt"))
	if base == "" || base == "." || base == ".." {
		return nil, fmt.Errorf("invalid list name %q", name)
	}
	return r.readListFile(base + ".txt")
}

// readListFile reads <Dir>/<filename> and returns its entries: non-empty,
// non-comment lines, trimmed (a trailing '# comment' on a line is stripped).
// filename is reduced to a single path element so it can never escape Dir.
func (r Resolver) readListFile(filename string) ([]string, error) {
	if r.Dir == "" {
		return nil, fmt.Errorf("no domains directory configured")
	}
	base := filepath.Base(filename)
	if base == "" || base == "." || base == ".." {
		return nil, fmt.Errorf("invalid list file %q", filename)
	}
	f, err := os.Open(filepath.Join(r.Dir, base))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 { // strip inline comment
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}
