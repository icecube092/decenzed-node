package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := Default()
	c.PublicIP = "203.0.113.7"
	c.MaxUserBps = 1_250_000
	c.Clients = []Client{
		{UUID: "u-1", Name: "me"},
		{UUID: "u-2", Name: "friend", DomainMode: DomainModeBlacklist, Domains: []string{"geosite:category-ads-all", "bad.com"}},
	}

	require.NoError(t, Save(path, c))
	got, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, c.PublicIP, got.PublicIP)
	assert.Equal(t, c.MaxUserBps, got.MaxUserBps)
	assert.Equal(t, []string{"u-1", "u-2"}, got.UUIDs())
	// Per-user domain filter round-trips.
	assert.Equal(t, DomainModeBlacklist, got.Clients[1].DomainMode)
	assert.Equal(t, []string{"geosite:category-ads-all", "bad.com"}, got.Clients[1].Domains)
	assert.True(t, got.Clients[1].FiltersDomains())
	assert.False(t, got.Clients[0].FiltersDomains())
}

func TestNewClientAppliesDefaults(t *testing.T) {
	c := Default()
	c.DefaultDomainMode = DomainModeWhitelist
	c.DefaultDomains = []string{"geosite:google", "file:work"}

	cl := c.NewClient("u-9", "alice")
	assert.Equal(t, DomainModeWhitelist, cl.DomainMode)
	assert.Equal(t, []string{"geosite:google", "file:work"}, cl.Domains)

	// The new client's list is a copy — mutating it must not touch the defaults.
	cl.Domains[0] = "changed"
	assert.Equal(t, "geosite:google", c.DefaultDomains[0])

	// No default => an unfiltered client.
	plain := Default().NewClient("u-10", "bob")
	assert.False(t, plain.FiltersDomains())
	assert.Equal(t, DomainModeOff, plain.DomainMode)
}

func TestPublicInboundsPortRemap(t *testing.T) {
	// Node binds 8443 for VLESS but the router forwards WAN 443 -> LAN 8443;
	// Trojan is forwarded straight through (no remap).
	c := AppConfig{Port: 8443, PublicPort: 443, TrojanPort: 8444}
	ibs := c.PublicInbounds()
	require.Len(t, ibs, 2)

	vless := ibs[0]
	assert.Equal(t, 8443, vless.Port, "binds the internal port")
	assert.Equal(t, 443, vless.DialPort(), "clients dial the external port")
	assert.True(t, vless.Remapped())
	assert.Equal(t, 443, c.VLESSPublicPort())

	trojan := ibs[1]
	assert.Equal(t, 8444, trojan.Port)
	assert.Equal(t, 8444, trojan.DialPort(), "no override falls back to the bind port")
	assert.False(t, trojan.Remapped())
}

func TestBlocksBittorrent(t *testing.T) {
	c := Default()
	assert.True(t, c.BlocksBittorrent(), "default blocks bittorrent")
	c.BlockProtocols = nil
	assert.False(t, c.BlocksBittorrent())
}

func TestCamouflageHelpers(t *testing.T) {
	c := Default()
	// Default (empty) is REALITY, not TLS.
	assert.False(t, c.CamouflageTLS())

	c.Camouflage = CamouflageTLSMode
	assert.True(t, c.CamouflageTLS())
}

func TestTLSHostPrefersOverrideThenDuckDNS(t *testing.T) {
	c := Default()
	assert.Equal(t, "", c.TLSHost(), "no domain configured")

	c.DuckDNSToken = "tok"
	c.DuckDNSSubdomain = "mynode"
	assert.Equal(t, "mynode.duckdns.org", c.TLSHost())

	c.TLSDomain = "example.org"
	assert.Equal(t, "example.org", c.TLSHost(), "explicit override wins")
}

func TestTLSHostFallsBackToCustomDomain(t *testing.T) {
	c := Default()
	c.CustomDomain = "vpn.example.com"
	// No DuckDNS, no override: the operator's own domain is the TLS host.
	assert.Equal(t, "vpn.example.com", c.TLSHost())
}

func TestTLSManualCert(t *testing.T) {
	// REALITY mode: never a manual cert.
	c := Default()
	c.CustomDomain = "vpn.example.com"
	assert.False(t, c.TLSManualCert())

	// TLS behind the operator's own domain (no DuckDNS): manual cert.
	c.Camouflage = CamouflageTLSMode
	assert.True(t, c.TLSManualCert())

	// TLS with DuckDNS: automatic cert, not manual.
	d := Default()
	d.Camouflage = CamouflageTLSMode
	d.DuckDNSToken = "tok"
	d.DuckDNSSubdomain = "mynode"
	assert.False(t, d.TLSManualCert())
}

func TestIsConfiguredTLSCustomDomain(t *testing.T) {
	c := Default()
	c.Camouflage = CamouflageTLSMode
	c.CustomDomain = "vpn.example.com"
	assert.True(t, c.IsConfigured(), "TLS mode is configured once a domain exists")
}

func TestSiteAddrDefaultAndOverride(t *testing.T) {
	c := Default()
	assert.Equal(t, "127.0.0.1:8080", c.SiteAddr())
	c.SitePort = 9000
	assert.Equal(t, "127.0.0.1:9000", c.SiteAddr())
}

func TestFallbackAddr(t *testing.T) {
	c := Default()
	// No override: fall back to the built-in site.
	assert.Equal(t, c.SiteAddr(), c.FallbackAddr())

	// Override wins and leaves the built-in site address untouched.
	c.TLSFallbackDest = "127.0.0.1:8081"
	assert.Equal(t, "127.0.0.1:8081", c.FallbackAddr())
	assert.Equal(t, "127.0.0.1:8080", c.SiteAddr(), "built-in site still runs for /sub/")
}

func TestIsConfigured(t *testing.T) {
	// REALITY mode needs a public key.
	c := Default()
	assert.False(t, c.IsConfigured())
	c.RealityPublicKey = "pubkey"
	assert.True(t, c.IsConfigured())

	// TLS mode needs a domain, not REALITY keys.
	tls := Default()
	tls.Camouflage = CamouflageTLSMode
	assert.False(t, tls.IsConfigured(), "no domain yet")
	tls.DuckDNSToken = "tok"
	tls.DuckDNSSubdomain = "mynode"
	assert.True(t, tls.IsConfigured())
}
