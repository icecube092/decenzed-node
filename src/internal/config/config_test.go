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
	c.DomainDeny = []string{"bad.com"}
	c.Clients = []Client{{UUID: "u-1", Name: "me"}, {UUID: "u-2", Name: "friend"}}

	require.NoError(t, Save(path, c))
	got, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, c.PublicIP, got.PublicIP)
	assert.Equal(t, c.MaxUserBps, got.MaxUserBps)
	assert.Equal(t, []string{"bad.com"}, got.DomainDeny)
	assert.Equal(t, []string{"u-1", "u-2"}, got.UUIDs())
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

func TestSiteAddrDefaultAndOverride(t *testing.T) {
	c := Default()
	assert.Equal(t, "127.0.0.1:8080", c.SiteAddr())
	c.SitePort = 9000
	assert.Equal(t, "127.0.0.1:9000", c.SiteAddr())
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
