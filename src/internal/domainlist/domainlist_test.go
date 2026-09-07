package domainlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePassthroughAndDedup(t *testing.T) {
	r := Resolver{}
	res := r.Resolve([]string{"geosite:ads", "domain:example.com", "geosite:ads", " ", "bad.com"})
	assert.Empty(t, res.Warnings)
	assert.Equal(t, []string{"geosite:ads", "domain:example.com", "bad.com"}, res.Domains)
	assert.Empty(t, res.IPs)
}

func TestResolveSplitsGeoIP(t *testing.T) {
	// geoip: tokens go to the IP field; geoip:private expands to literal CIDRs
	// (no asset) even with a Dir.
	r := Resolver{Dir: t.TempDir()}
	res := r.Resolve([]string{"domain:example.com", "geoip:private", "keyword:ads"})
	assert.Empty(t, res.Warnings)
	assert.Equal(t, []string{"domain:example.com", "keyword:ads"}, res.Domains)
	assert.Equal(t, PrivateIPCIDRs, res.IPs, "geoip:private expands to the private CIDR set")
}

func TestResolveExpandsCustomFilesAndCombines(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "blocked.txt"),
		[]byte("# my blocklist\nads.example\n\n  tracker.example  # inline comment\n"), 0o600))
	// geosite.dat present so the top-level geosite: token passes through.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite.dat"), []byte("x"), 0o600))

	r := Resolver{Dir: dir}
	// combine a geosite category, a custom file, the same file again (@), an inline
	// domain, and geoip:private (expands to CIDRs on the IP side).
	res := r.Resolve([]string{"geosite:google", "file:blocked", "@blocked", "domain:extra.com", "geoip:private"})
	assert.Empty(t, res.Warnings)
	assert.Equal(t, []string{"geosite:google", "ads.example", "tracker.example", "domain:extra.com"}, res.Domains)
	assert.Equal(t, PrivateIPCIDRs, res.IPs)
}

func TestResolveMissingFileWarnsButKeepsRest(t *testing.T) {
	r := Resolver{Dir: t.TempDir()}
	res := r.Resolve([]string{"domain:keep.com", "file:nope"})
	assert.Equal(t, []string{"domain:keep.com"}, res.Domains)
	require.Len(t, res.Warnings, 1)
	assert.Contains(t, res.Warnings[0], "nope")
}

func TestResolveSkipsMissingDatAsset(t *testing.T) {
	// With a Dir but no geosite.dat / geoip.dat / ext .dat, those tokens are skipped
	// (so xray won't fail to load) while plain tokens pass through.
	r := Resolver{Dir: t.TempDir()}
	res := r.Resolve([]string{"geosite:ads", "geoip:ru", "ext:custom.dat:cat", "domain:example.com"})
	assert.Equal(t, []string{"domain:example.com"}, res.Domains)
	assert.Empty(t, res.IPs, "geoip:ru skipped (no geoip.dat)")
	require.Len(t, res.Warnings, 3)
}

func TestResolvePassesDatWhenPresent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geosite.dat"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("x"), 0o600))
	res := Resolver{Dir: dir}.Resolve([]string{"geosite:ads", "geoip:ru"})
	assert.Empty(t, res.Warnings)
	assert.Equal(t, []string{"geosite:ads"}, res.Domains)
	assert.Equal(t, []string{"geoip:ru"}, res.IPs)
}

func TestResolveURLListFromCache(t *testing.T) {
	dir := t.TempDir()
	const listURL = "https://raw.githubusercontent.com/you/repo/main/blocked.txt"
	// The CLI caches the fetched body under this deterministic name.
	require.NoError(t, os.WriteFile(filepath.Join(dir, URLCacheName(listURL)),
		[]byte("# remote list\nads.example\ngeoip:private\n"), 0o600))

	res := Resolver{Dir: dir}.Resolve([]string{"url:" + listURL, "domain:x.com"})
	assert.Empty(t, res.Warnings)
	assert.Equal(t, []string{"ads.example", "domain:x.com"}, res.Domains)
	assert.Equal(t, PrivateIPCIDRs, res.IPs, "a geoip:private line from the cached list expands")
}

func TestResolveURLListNotCachedWarns(t *testing.T) {
	res := Resolver{Dir: t.TempDir()}.Resolve([]string{"url:https://example.com/list.txt", "domain:keep.com"})
	assert.Equal(t, []string{"domain:keep.com"}, res.Domains)
	require.Len(t, res.Warnings, 1)
	assert.Contains(t, res.Warnings[0], "not cached")
}

func TestURLCacheNameStable(t *testing.T) {
	const u = "https://example.com/a.txt"
	assert.Equal(t, URLCacheName(u), URLCacheName(u), "deterministic")
	assert.NotEqual(t, URLCacheName(u), URLCacheName("https://example.com/b.txt"))
	assert.True(t, strings.HasSuffix(URLCacheName(u), ".txt"))
}

func TestResolveIgnoresNestedListReference(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "outer.txt"),
		[]byte("good.com\nfile:inner\nurl:https://example.com/x.txt\n"), 0o600))
	res := Resolver{Dir: dir}.Resolve([]string{"file:outer"})
	assert.Equal(t, []string{"good.com"}, res.Domains)
	require.Len(t, res.Warnings, 2, "nested file:/url: lines are ignored with a warning")
}

func TestResolveRejectsPathEscape(t *testing.T) {
	r := Resolver{Dir: t.TempDir()}
	// "../secret" must not read outside Dir — base name reduces it to "secret".txt,
	// which doesn't exist, so it warns rather than escaping.
	res := r.Resolve([]string{"file:../secret"})
	require.Len(t, res.Warnings, 1)
}
