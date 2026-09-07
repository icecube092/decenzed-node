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

func TestGenerateUserBlacklist(t *testing.T) {
	in := vlessIn(443, "u1")
	in.UserDomains = []UserDomainPolicy{{Email: "u1", Mode: "blacklist", Domains: []string{"geosite:category-ads-all", "bad.com"}}}
	cfg := Generate(in)

	require.Len(t, cfg.Routing.Rules, 1, "blacklist is a single user-scoped block rule")
	r := cfg.Routing.Rules[0]
	assert.Equal(t, []string{"u1"}, r.User, "rule is scoped to the user")
	assert.Equal(t, []string{"geosite:category-ads-all", "bad.com"}, r.Domain)
	assert.Equal(t, "block", r.OutboundTag)
	// No catch-all block: a blacklist user's other traffic falls through to direct.
	for _, rr := range cfg.Routing.Rules {
		assert.False(t, rr.Network != "" && rr.OutboundTag == "block", "blacklist must not add a catch-all block")
	}
}

func TestGenerateUserWhitelist(t *testing.T) {
	in := vlessIn(443, "u1")
	in.UserDomains = []UserDomainPolicy{{Email: "u1", Mode: "whitelist", Domains: []string{"good.com"}}}
	cfg := Generate(in)

	require.Len(t, cfg.Routing.Rules, 2, "whitelist = allow rule + user-scoped catch-all block")
	allow, block := cfg.Routing.Rules[0], cfg.Routing.Rules[1]
	assert.Equal(t, []string{"u1"}, allow.User)
	assert.Equal(t, []string{"good.com"}, allow.Domain)
	assert.Equal(t, "direct", allow.OutboundTag)
	// The catch-all block must be scoped to the user so it never affects others.
	assert.Equal(t, []string{"u1"}, block.User, "catch-all block is user-scoped")
	assert.NotEmpty(t, block.Network)
	assert.Equal(t, "block", block.OutboundTag)
}

func TestGenerateUserFilterEmptyIsNoop(t *testing.T) {
	// A mode set but no domains (or no email) must emit no rules — a mis-set empty
	// whitelist can't silently black-hole a user.
	in := vlessIn(443, "u1")
	in.UserDomains = []UserDomainPolicy{
		{Email: "u1", Mode: "whitelist", Domains: nil},
		{Email: "", Mode: "blacklist", Domains: []string{"x.com"}},
	}
	cfg := Generate(in)
	assert.Empty(t, cfg.Routing.Rules)
}

func TestGeneratePrivateIPBlock(t *testing.T) {
	in := vlessIn(443, "u1")
	in.BlockIPs = []string{"10.0.0.0/8", "127.0.0.0/8"}
	cfg := Generate(in)
	require.Len(t, cfg.Routing.Rules, 1)
	r := cfg.Routing.Rules[0]
	assert.Equal(t, []string{"10.0.0.0/8", "127.0.0.0/8"}, r.IP)
	assert.Empty(t, r.User, "the private block is global, not user-scoped")
	assert.Equal(t, "block", r.OutboundTag)
	assert.Equal(t, "AsIs", cfg.Routing.DomainStrategy, "literal-CIDR block needs no domain resolution")
	assert.Nil(t, cfg.DNS)
}

func TestGenerateUserGeoIPSplitsRules(t *testing.T) {
	in := vlessIn(443, "u1")
	in.ResolveDomainIP = true // a country geoip rule is in use
	in.UserDomains = []UserDomainPolicy{{
		Email: "u1", Mode: "blacklist",
		Domains: []string{"bad.com"}, IPs: []string{"geoip:ru"},
	}}
	cfg := Generate(in)

	// domain and ip matchers must be SEPARATE rules (OR, not AND).
	require.Len(t, cfg.Routing.Rules, 2)
	var domainRule, ipRule *rule
	for i := range cfg.Routing.Rules {
		rr := &cfg.Routing.Rules[i]
		if len(rr.Domain) > 0 {
			domainRule = rr
		}
		if len(rr.IP) > 0 {
			ipRule = rr
		}
	}
	require.NotNil(t, domainRule)
	require.NotNil(t, ipRule)
	assert.Equal(t, []string{"u1"}, domainRule.User)
	assert.Equal(t, []string{"u1"}, ipRule.User)
	assert.Empty(t, ipRule.Domain, "one rule can't AND domain+ip")

	// Country geoip needs domain->IP resolution + a dns block.
	assert.Equal(t, "IPIfNonMatch", cfg.Routing.DomainStrategy)
	assert.Contains(t, string(cfg.DNS), "localhost")
}

func TestGenerateWhitelistGeoIPHasUserCatchAll(t *testing.T) {
	in := vlessIn(443, "u1")
	in.UserDomains = []UserDomainPolicy{{
		Email: "u1", Mode: "whitelist", IPs: []string{"geoip:ru"},
	}}
	cfg := Generate(in)
	// allow(ip) + user-scoped catch-all block.
	require.Len(t, cfg.Routing.Rules, 2)
	assert.Equal(t, []string{"geoip:ru"}, cfg.Routing.Rules[0].IP)
	assert.Equal(t, "direct", cfg.Routing.Rules[0].OutboundTag)
	last := cfg.Routing.Rules[1]
	assert.Equal(t, []string{"u1"}, last.User)
	assert.NotEmpty(t, last.Network)
	assert.Equal(t, "block", last.OutboundTag)
}

func TestGenerateBittorrentBeforeUserRules(t *testing.T) {
	in := vlessIn(443, "u1")
	in.BlockBittorrent = true
	in.UserDomains = []UserDomainPolicy{{Email: "u1", Mode: "whitelist", Domains: []string{"good.com"}}}
	cfg := Generate(in)
	require.Len(t, cfg.Routing.Rules, 3)
	// Bittorrent block is global and must be first (wins for everyone).
	assert.Equal(t, []string{"bittorrent"}, cfg.Routing.Rules[0].Protocol)
	assert.Empty(t, cfg.Routing.Rules[0].User, "bittorrent rule is not user-scoped")
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

	// tags are unique; the SS-2022 inbound carries the "2022" tag suffix
	assert.Equal(t, "vless-in", byProto["vless"].Tag)
	assert.Equal(t, "trojan-in", byProto["trojan"].Tag)
	assert.Equal(t, "shadowsocks2022-in", byProto["shadowsocks"].Tag)
}

// TestInboundTagUniqueForTwoShadowsocks guards the tag collision that would stop
// xray from starting: the classic and SS-2022 inbounds must get distinct tags.
func TestInboundTagUniqueForTwoShadowsocks(t *testing.T) {
	classic := InboundTag("shadowsocks", "chacha20-ietf-poly1305")
	ss2022 := InboundTag("shadowsocks", "2022-blake3-aes-128-gcm")
	assert.Equal(t, "shadowsocks-in", classic)
	assert.Equal(t, "shadowsocks2022-in", ss2022)
	assert.NotEqual(t, classic, ss2022)
	assert.Equal(t, "vless-in", InboundTag("vless", ""))
}

// TestGenerateClassicShadowsocks checks the classic AEAD multi-user shape: each
// client carries its own method+password, and there is no top-level server key.
func TestGenerateClassicShadowsocks(t *testing.T) {
	in := Input{
		Inbounds: []InboundSpec{{
			Protocol: "shadowsocks",
			Port:     35123,
			SSMethod: "chacha20-ietf-poly1305",
			Clients:  []ClientCred{{Password: "uuid-1", Email: "uuid-1"}},
		}},
	}
	cfg := Generate(in)
	require.Len(t, cfg.Inbounds, 1)
	s := string(cfg.Inbounds[0].Settings)

	assert.Contains(t, s, "chacha20-ietf-poly1305")
	assert.Contains(t, s, "uuid-1")
	assert.Contains(t, s, `"network":"tcp,udp"`)
	// No SS-2022 server-wide key field: the classic form omits the top-level
	// "password" (the key belongs to each client instead).
	assert.NotContains(t, s, `"password":""`)
}

// TestGenerateTLSFallback checks the TLS-masquerade shape: VLESS and Trojan
// inbounds terminate real TLS (cert files, serverName, alpn http/1.1) and fall
// back to the local website; Shadowsocks is untouched.
func TestGenerateTLSFallback(t *testing.T) {
	tls := &TLSSpec{
		ServerName:   "me.duckdns.org",
		CertFile:     "/data/cert.pem",
		KeyFile:      "/data/key.pem",
		FallbackDest: "127.0.0.1:8080",
	}
	in := Input{
		StatsEnabled: true,
		Inbounds: []InboundSpec{
			{Protocol: "vless", Port: 443, Clients: []ClientCred{{ID: "u1", Email: "u1"}}, TLS: tls},
			{Protocol: "trojan", Port: 8443, Clients: []ClientCred{{Password: "u1", Email: "u1"}}, TLS: tls},
		},
	}
	cfg := Generate(in)
	require.Len(t, cfg.Inbounds, 2)

	byProto := map[string]inbound{}
	for _, ib := range cfg.Inbounds {
		byProto[ib.Protocol] = ib
	}

	for _, proto := range []string{"vless", "trojan"} {
		ss := byProto[proto].StreamSettings
		require.NotNil(t, ss, proto)
		assert.Equal(t, "tls", ss.Security, proto)
		require.NotNil(t, ss.TLSSettings, proto)
		assert.Equal(t, "me.duckdns.org", ss.TLSSettings.ServerName, proto)
		assert.Equal(t, []string{"http/1.1"}, ss.TLSSettings.ALPN, proto)
		require.Len(t, ss.TLSSettings.Certificates, 1, proto)
		assert.Equal(t, "/data/cert.pem", ss.TLSSettings.Certificates[0].CertificateFile, proto)
		assert.Equal(t, "/data/key.pem", ss.TLSSettings.Certificates[0].KeyFile, proto)
		assert.Nil(t, ss.RealitySettings, proto)
		// fallback to the local site is present in settings
		assert.Contains(t, string(byProto[proto].Settings), `"fallbacks"`, proto)
		assert.Contains(t, string(byProto[proto].Settings), "127.0.0.1:8080", proto)
	}

	// VLESS keeps the Vision flow; Trojan does not.
	assert.Contains(t, string(byProto["vless"].Settings), "xtls-rprx-vision")
	assert.NotContains(t, string(byProto["trojan"].Settings), "xtls-rprx-vision")

	// oneTimeLoading must not be emitted (would break hot-reload on renewal).
	b, err := cfg.JSON()
	require.NoError(t, err)
	assert.NotContains(t, string(b), "oneTimeLoading")
}
