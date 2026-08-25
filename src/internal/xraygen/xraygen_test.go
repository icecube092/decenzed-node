package xraygen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vlessIn is a convenience: an Input with a single VLESS+REALITY inbound.
func vlessIn(port int, uuids ...string) Input {
	var clients []ClientCred
	for _, u := range uuids {
		clients = append(clients, ClientCred{ID: u, Email: u})
	}
	return Input{Inbounds: []InboundSpec{{
		Protocol: "vless",
		Port:     port,
		Clients:  clients,
		Reality:  &RealitySpec{Dest: "example.com:443", Names: []string{"example.com"}},
	}}}
}

func TestGenerateBlocksBittorrent(t *testing.T) {
	in := vlessIn(443)
	in.BlockBittorrent = true
	in.StatsEnabled = true
	cfg := Generate(in)
	found := false
	for _, r := range cfg.Routing.Rules {
		for _, p := range r.Protocol {
			if p == "bittorrent" && r.OutboundTag == "block" {
				found = true
			}
		}
	}
	assert.True(t, found, "expected a bittorrent->block routing rule")
}

func TestGenerateAllowlistAddsDefaultBlock(t *testing.T) {
	in := vlessIn(443)
	in.DomainAllow = []string{"x.com"}
	cfg := Generate(in)
	rules := cfg.Routing.Rules
	require.GreaterOrEqual(t, len(rules), 2, "allow-list mode needs allow + default block")

	last := rules[len(rules)-1]
	assert.Equal(t, "block", last.OutboundTag)
	assert.NotEmpty(t, last.Network, "last rule is the default (network) block")

	allowOK := false
	for _, r := range rules {
		if len(r.Domain) == 1 && r.Domain[0] == "x.com" && r.OutboundTag == "direct" {
			allowOK = true
		}
	}
	assert.True(t, allowOK, "expected an allow(x.com)->direct rule")
}

func TestGenerateNoAllowlistNoDefaultBlock(t *testing.T) {
	cfg := Generate(vlessIn(443))
	for _, r := range cfg.Routing.Rules {
		assert.False(t, r.Network != "" && r.OutboundTag == "block", "no default block without an allow-list")
	}
}

func TestGenerateStatsAndInbound(t *testing.T) {
	in := vlessIn(8443, "uuid-1")
	in.StatsEnabled = true
	cfg := Generate(in)
	require.NotNil(t, cfg.Stats)
	require.NotNil(t, cfg.Policy)
	require.Len(t, cfg.Inbounds, 1)

	ib := cfg.Inbounds[0]
	assert.Equal(t, 8443, ib.Port)
	assert.Equal(t, "vless", ib.Protocol)
	require.NotNil(t, ib.StreamSettings)
	assert.Equal(t, "reality", ib.StreamSettings.Security)
	require.NotNil(t, ib.Sniffing)
	assert.True(t, ib.Sniffing.Enabled, "sniffing needed for protocol/domain routing")

	b, err := cfg.JSON()
	require.NoError(t, err)
	assert.Contains(t, string(b), "uuid-1")
}

// TestGenerateMultiProtocol checks that VLESS, Trojan, and Shadowsocks inbounds
// are emitted together with the right shape: REALITY on VLESS/Trojan only, and
// SS carrying method + server key + no stream settings.
func TestGenerateMultiProtocol(t *testing.T) {
	in := Input{
		StatsEnabled: true,
		Inbounds: []InboundSpec{
			{Protocol: "vless", Port: 443, Clients: []ClientCred{{ID: "u1", Email: "u1"}}, Reality: &RealitySpec{Dest: "e.com:443"}},
			{Protocol: "trojan", Port: 8443, Clients: []ClientCred{{Password: "u1", Email: "u1"}}, Reality: &RealitySpec{Dest: "e.com:443"}},
			{Protocol: "shadowsocks", Port: 9443, SSMethod: "2022-blake3-aes-128-gcm", SSServerKey: "srv", Clients: []ClientCred{{Password: "psk", Email: "u1"}}},
		},
	}
	cfg := Generate(in)
	require.Len(t, cfg.Inbounds, 3)

	byProto := map[string]inbound{}
	for _, ib := range cfg.Inbounds {
		byProto[ib.Protocol] = ib
	}

	require.NotNil(t, byProto["vless"].StreamSettings)
	require.NotNil(t, byProto["trojan"].StreamSettings)
	assert.Equal(t, "reality", byProto["trojan"].StreamSettings.Security)

	ss := byProto["shadowsocks"]
	assert.Nil(t, ss.StreamSettings, "shadowsocks has no REALITY/TLS stream settings")
	assert.Contains(t, string(ss.Settings), "2022-blake3-aes-128-gcm")
	assert.Contains(t, string(ss.Settings), "srv")

	// tags are unique
	assert.Equal(t, "vless-in", byProto["vless"].Tag)
	assert.Equal(t, "trojan-in", byProto["trojan"].Tag)
	assert.Equal(t, "shadowsocks-in", byProto["shadowsocks"].Tag)
}
