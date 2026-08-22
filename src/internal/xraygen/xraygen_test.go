package xraygen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBlocksBittorrent(t *testing.T) {
	cfg := Generate(Input{Port: 443, BlockBittorrent: true, StatsEnabled: true})
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
	cfg := Generate(Input{Port: 443, DomainAllow: []string{"x.com"}})
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
	cfg := Generate(Input{Port: 443})
	for _, r := range cfg.Routing.Rules {
		assert.False(t, r.Network != "" && r.OutboundTag == "block", "no default block without an allow-list")
	}
}

func TestGenerateStatsAndInbound(t *testing.T) {
	cfg := Generate(Input{Port: 8443, StatsEnabled: true, UUIDs: []string{"uuid-1"}})
	require.NotNil(t, cfg.Stats)
	require.NotNil(t, cfg.Policy)
	require.Len(t, cfg.Inbounds, 1)

	in := cfg.Inbounds[0]
	assert.Equal(t, 8443, in.Port)
	assert.Equal(t, "vless", in.Protocol)
	require.NotNil(t, in.StreamSettings)
	assert.Equal(t, "reality", in.StreamSettings.Security)
	require.NotNil(t, in.Sniffing)
	assert.True(t, in.Sniffing.Enabled, "sniffing needed for protocol/domain routing")

	b, err := cfg.JSON()
	require.NoError(t, err)
	assert.Contains(t, string(b), "uuid-1")
}
