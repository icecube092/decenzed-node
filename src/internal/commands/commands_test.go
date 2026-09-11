package commands

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"decenzed/node_app/internal/config"
)

func TestAskProtocolPortKeepsSavedPort(t *testing.T) {
	// A saved (current != 0) port must be offered — and kept on Enter — even if it
	// differs from the recommended one and even if the port is currently busy
	// (e.g. the running service holds it during a re-run of setup).
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	saved := busy.Addr().(*net.TCPAddr).Port // a port that is definitely in use

	r := newInputFrom(strings.NewReader("\n")) // press Enter = keep default
	got := askProtocolPort(r, "test port", saved, 39999 /*recommended, different*/, 443)
	if got != saved {
		t.Errorf("askProtocolPort kept %d, want saved %d", got, saved)
	}
}

func TestAskTLSFallback(t *testing.T) {
	noop := func() {}

	// Enter on a fresh config accepts the offered default (127.0.0.1:8081).
	c := &config.AppConfig{}
	askTLSFallback(newInputFrom(strings.NewReader("\n")), c, noop)
	if c.TLSFallbackDest != defaultTLSFallbackDest {
		t.Errorf("Enter = %q, want default %q", c.TLSFallbackDest, defaultTLSFallbackDest)
	}

	// A typed host:port overrides it.
	c = &config.AppConfig{}
	askTLSFallback(newInputFrom(strings.NewReader("127.0.0.1:9000\n")), c, noop)
	if c.TLSFallbackDest != "127.0.0.1:9000" {
		t.Errorf("typed value = %q, want 127.0.0.1:9000", c.TLSFallbackDest)
	}

	// 'no' clears it back to the built-in site (empty).
	c = &config.AppConfig{TLSFallbackDest: "127.0.0.1:8081"}
	askTLSFallback(newInputFrom(strings.NewReader("no\n")), c, noop)
	if c.TLSFallbackDest != "" {
		t.Errorf("'no' = %q, want empty (built-in site)", c.TLSFallbackDest)
	}

	// A value without a port is rejected and falls back to the built-in site.
	c = &config.AppConfig{}
	askTLSFallback(newInputFrom(strings.NewReader("example.com\n")), c, noop)
	if c.TLSFallbackDest != "" {
		t.Errorf("no-port value = %q, want empty", c.TLSFallbackDest)
	}
}

func TestCheckInbounds(t *testing.T) {
	// Without a config: only the default VLESS port is reported (public == bind).
	got := checkInbounds(config.AppConfig{}, false)
	if len(got) != 1 || got[0].name != config.ProtoVLESS || got[0].public != 443 || got[0].bind != 443 {
		t.Fatalf("no-config case = %+v", got)
	}

	// With a config: all protocols in order; disabled ones keep port 0. VLESS is
	// remapped (router forwards WAN 443 -> LAN 8443), so its public port is 443
	// while it still binds 8443.
	cfg := config.AppConfig{Port: 8443, PublicPort: 443, TrojanPort: 0, SSPort: 35123, SS2022Port: 0}
	got = checkInbounds(cfg, true)
	want := []checkInbound{
		{config.ProtoVLESS, 443, 8443},
		{config.ProtoTrojan, 0, 0},
		{config.ProtoShadowsocks, 35123, 35123},
		{"shadowsocks-2022", 0, 0},
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if !got[0].remapped() || got[2].remapped() {
		t.Errorf("remapped(): VLESS=%v SS=%v, want true/false", got[0].remapped(), got[2].remapped())
	}
}

func TestJoinForwards(t *testing.T) {
	// Straight forwards render as bare ports; a remap shows both sides.
	got := joinForwards([]portForward{{8443, 8443}, {8444, 8444}, {443, 8443}})
	if got != "8443, 8444, 443->8443" {
		t.Errorf("joinForwards = %q", got)
	}
	if got := joinForwards([]portForward{{443, 443}}); got != "443" {
		t.Errorf("joinForwards single = %q", got)
	}
}

func TestIsNo(t *testing.T) {
	for _, s := range []string{"no", "No", "NONE", " none ", "off", "-"} {
		if !isNo(s) {
			t.Errorf("isNo(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "yes", "bittorrent", "n"} {
		if isNo(s) {
			t.Errorf("isNo(%q) = true, want false", s)
		}
	}
}

func TestParseDomainMode(t *testing.T) {
	black := []string{"blacklist", "BL", "block", "deny", "Black"}
	white := []string{"whitelist", "wl", "allow", "WHITE"}
	off := []string{"", "no", "off", "none", "wat"}
	for _, s := range black {
		if got := parseDomainMode(s); got != config.DomainModeBlacklist {
			t.Errorf("parseDomainMode(%q) = %q, want blacklist", s, got)
		}
	}
	for _, s := range white {
		if got := parseDomainMode(s); got != config.DomainModeWhitelist {
			t.Errorf("parseDomainMode(%q) = %q, want whitelist", s, got)
		}
	}
	for _, s := range off {
		if got := parseDomainMode(s); got != config.DomainModeOff {
			t.Errorf("parseDomainMode(%q) = %q, want off", s, got)
		}
	}
}

func TestDomainPolicyAndFilterNote(t *testing.T) {
	// No mode: off, and no stats note.
	plain := config.Client{UUID: "u1"}
	if domainPolicyDesc(plain) != "off (no domain filtering)" {
		t.Errorf("desc(plain) = %q", domainPolicyDesc(plain))
	}
	if domainFilterNote(plain) != "" {
		t.Errorf("note(plain) = %q, want empty", domainFilterNote(plain))
	}

	// Mode set but no sources: inactive, still no stats note (FiltersDomains false).
	empty := config.Client{UUID: "u1", DomainMode: config.DomainModeWhitelist}
	if got := domainPolicyDesc(empty); got != "whitelist (no sources — inactive)" {
		t.Errorf("desc(empty) = %q", got)
	}
	if domainFilterNote(empty) != "" {
		t.Errorf("note(empty) = %q, want empty", domainFilterNote(empty))
	}

	// Active filter: both render the mode + sources.
	active := config.Client{UUID: "u1", DomainMode: config.DomainModeBlacklist,
		Domains: []string{"geosite:ads", "bad.com"}}
	if got := domainPolicyDesc(active); got != "blacklist — geosite:ads, bad.com" {
		t.Errorf("desc(active) = %q", got)
	}
	if got := domainFilterNote(active); got != "filter: blacklist — geosite:ads, bad.com (2)" {
		t.Errorf("note(active) = %q", got)
	}

	// Long lists are truncated in the stats note.
	many := config.Client{UUID: "u1", DomainMode: config.DomainModeBlacklist,
		Domains: []string{"a", "b", "c", "d", "e", "f", "g", "h"}}
	if got := domainFilterNote(many); !strings.Contains(got, "+2 more") || !strings.Contains(got, "(8)") {
		t.Errorf("note(many) = %q, want truncation with +2 more and (8)", got)
	}
}

func TestGeositeReferenceHelpers(t *testing.T) {
	if hasGeositeToken([]string{"domain:example.com", "file:blocked", "bad.com"}) {
		t.Error("no geosite token, want false")
	}
	if !hasGeositeToken([]string{"domain:x", " geosite:category-ads-all "}) {
		t.Error("has a geosite token, want true")
	}

	c := config.AppConfig{
		DefaultDomains: []string{"domain:x"},
		Clients: []config.Client{
			{UUID: "u1", Domains: []string{"file:a"}},
			{UUID: "u2", Domains: []string{"geosite:google"}},
		},
	}
	if !configUsesGeosite(c) {
		t.Error("a client uses geosite, want true")
	}
	c.Clients[1].Domains = []string{"domain:y"}
	if configUsesGeosite(c) {
		t.Error("nobody uses geosite now, want false")
	}
	c.DefaultDomains = []string{"geosite:category-ads-all"}
	if !configUsesGeosite(c) {
		t.Error("default uses geosite, want true")
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("https://github.com/x/y/releases/latest/download/geosite.dat"); got != "github.com" {
		t.Errorf("hostOf = %q, want github.com", got)
	}
	if got := hostOf("not a url"); got != "not a url" {
		t.Errorf("hostOf(bad) = %q", got)
	}
}

func TestFindClientIdx(t *testing.T) {
	clients := []config.Client{{UUID: "uuid-a", Name: "alice"}, {UUID: "uuid-b"}}
	if i := findClientIdx(clients, "alice"); i != 0 {
		t.Errorf("by name = %d, want 0", i)
	}
	if i := findClientIdx(clients, "uuid-b"); i != 1 {
		t.Errorf("by uuid = %d, want 1", i)
	}
	if i := findClientIdx(clients, "nope"); i != -1 {
		t.Errorf("missing = %d, want -1", i)
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" bittorrent , , quic ")
	want := []string{"bittorrent", "quic"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("splitCSV = %v, want %v", got, want)
	}
	if splitCSV("   ,  ") != nil {
		t.Error("all-empty CSV should yield nil")
	}
}

func TestBandwidthRoundTrip(t *testing.T) {
	cases := map[string]float64{
		"10mbit":    10e6 / 8,
		"1gbit":     1e9 / 8,
		"unlimited": 0,
		"0":         0,
	}
	for in, want := range cases {
		got, err := parseBandwidth(in)
		if err != nil {
			t.Errorf("parseBandwidth(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseBandwidth(%q) = %v, want %v", in, got, want)
		}
	}
	if formatBandwidth(10e6/8) != "10mbit" {
		t.Errorf("formatBandwidth = %q", formatBandwidth(10e6/8))
	}
	if formatBandwidth(0) != "unlimited" {
		t.Errorf("formatBandwidth(0) = %q", formatBandwidth(0))
	}
}

func TestInnerPortFor(t *testing.T) {
	if p := innerPortFor(443); p != 10443 {
		t.Errorf("innerPortFor(443) = %d, want 10443", p)
	}
	if p := innerPortFor(60000); p != 50000 {
		t.Errorf("innerPortFor(60000) = %d, want 50000 (wrap down)", p)
	}
}

func TestNewNodeIDUnique(t *testing.T) {
	a, b := newNodeID(), newNodeID()
	if a == "" || b == "" {
		t.Fatal("newNodeID returned empty")
	}
	if a == b {
		t.Errorf("newNodeID not unique: %q == %q", a, b)
	}
	if len(a) != 20 { // xid string form is always 20 chars
		t.Errorf("xid length = %d, want 20 (%q)", len(a), a)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		512:           "512 B",
		1000:          "1.00 KB",
		2_500_000:     "2.50 MB",
		3_000_000_000: "3.00 GB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestSelfCheckHostPriority(t *testing.T) {
	// DuckDNS host wins when configured.
	c := config.AppConfig{NodeID: "abc", DuckDNSToken: "tok", PublicIP: "203.0.113.9"}
	if got := selfCheckHost(c, "9.9.9.9"); got != "decenzed-node-abc.duckdns.org" {
		t.Errorf("selfCheckHost with duckdns = %q", got)
	}
	// Else the configured public IP.
	c = config.AppConfig{PublicIP: "203.0.113.9"}
	if got := selfCheckHost(c, "9.9.9.9"); got != "203.0.113.9" {
		t.Errorf("selfCheckHost with PublicIP = %q", got)
	}
	// Else the detected IP.
	if got := selfCheckHost(config.AppConfig{}, "9.9.9.9"); got != "9.9.9.9" {
		t.Errorf("selfCheckHost fallback = %q", got)
	}
}

func TestLinkFor(t *testing.T) {
	c := config.AppConfig{
		Port:              8443,
		Location:          "RS",
		RealityServerName: []string{"example.com"},
		RealityPublicKey:  "PUBKEY",
		RealityShortIDs:   []string{"beef"},
	}
	ib := config.Inbound{Protocol: config.ProtoVLESS, Port: 8443}
	link := clientLink(c, config.Client{UUID: "uuid-1", Name: "alice"}, "host.example", ib)
	for _, want := range []string{
		"vless://uuid-1@host.example:8443?",
		"security=reality",
		"sni=example.com",
		"pbk=PUBKEY",
		"sid=beef",
		"flow=xtls-rprx-vision",
		"#RS%20%5BVLESS%5D", // proxy name = "RS [VLESS]", not the client name
	} {
		if !strings.Contains(link, want) {
			t.Errorf("link %q missing %q", link, want)
		}
	}
}

func TestClientLinkTrojanAndSS(t *testing.T) {
	c := config.AppConfig{
		Port:              443,
		TrojanPort:        8443,
		SSPort:            9443,
		Location:          "RS",
		SSServerKey:       "c2VydmVya2V5MTIzNDU2",
		RealityServerName: []string{"example.com"},
		RealityPublicKey:  "PUBKEY",
		RealityShortIDs:   []string{"beef"},
	}
	cl := config.Client{UUID: "uuid-1", Name: "bob"}

	trojan := clientLink(c, cl, "host.example", config.Inbound{Protocol: config.ProtoTrojan, Port: 8443})
	for _, want := range []string{"trojan://uuid-1@host.example:8443?", "security=reality", "#RS%20%5BTrojan%5D"} {
		if !strings.Contains(trojan, want) {
			t.Errorf("trojan link %q missing %q", trojan, want)
		}
	}
	if strings.Contains(trojan, "flow=") {
		t.Errorf("trojan link must not carry an XTLS flow: %q", trojan)
	}

	// Classic Shadowsocks (chacha20-ietf-poly1305): userinfo base64 = method:UUID.
	ssSuffix := "@host.example:9443#RS%20%5BShadowsocks%5D"
	ss := clientLink(c, cl, "host.example",
		config.Inbound{Protocol: config.ProtoShadowsocks, Port: 9443, Method: config.SSMethodClassic})
	if !strings.HasPrefix(ss, "ss://") || !strings.Contains(ss, ssSuffix) {
		t.Errorf("unexpected ss link: %q", ss)
	}
	if enc := strings.TrimSuffix(strings.TrimPrefix(ss, "ss://"), ssSuffix); enc != "" {
		raw, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			t.Fatalf("ss userinfo not base64url: %v", err)
		}
		if want := config.SSMethodClassic + ":" + cl.UUID; string(raw) != want {
			t.Errorf("ss userinfo = %q, want %q", string(raw), want)
		}
	}

	// SS-2022 variant: userinfo = method:serverPSK:userPSK.
	ss2022 := clientLink(c, cl, "host.example",
		config.Inbound{Protocol: config.ProtoShadowsocks, Port: 9444, Method: config.SSMethod2022})
	enc := strings.TrimSuffix(strings.TrimPrefix(ss2022, "ss://"), "@host.example:9444#RS%20%5BSS-2022%5D")
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("ss2022 userinfo not base64url: %v", err)
	}
	if want := config.SSMethod2022 + ":" + c.SSServerKey + ":" + config.SSUserPSK(cl.UUID); string(raw) != want {
		t.Errorf("ss2022 userinfo = %q, want %q", string(raw), want)
	}
}

func TestClientLinkTLSMode(t *testing.T) {
	c := config.AppConfig{
		Port:             443,
		TrojanPort:       8443,
		Location:         "RS",
		Camouflage:       config.CamouflageTLSMode,
		DuckDNSToken:     "tok",
		DuckDNSSubdomain: "mynode",
	}
	cl := config.Client{UUID: "uuid-1", Name: "carol"}

	vless := clientLink(c, cl, "mynode.duckdns.org", config.Inbound{Protocol: config.ProtoVLESS, Port: 443})
	for _, want := range []string{
		"vless://uuid-1@mynode.duckdns.org:443?",
		"security=tls",
		"sni=mynode.duckdns.org",
		"flow=xtls-rprx-vision",
		"#RS%20%5BVLESS%5D",
	} {
		if !strings.Contains(vless, want) {
			t.Errorf("vless TLS link %q missing %q", vless, want)
		}
	}
	if strings.Contains(vless, "reality") || strings.Contains(vless, "pbk=") {
		t.Errorf("TLS link must not carry REALITY params: %q", vless)
	}

	trojan := clientLink(c, cl, "mynode.duckdns.org", config.Inbound{Protocol: config.ProtoTrojan, Port: 8443})
	if !strings.Contains(trojan, "security=tls") || strings.Contains(trojan, "flow=") {
		t.Errorf("trojan TLS link wrong: %q", trojan)
	}
}

func TestInputFromConfigTLSMode(t *testing.T) {
	c := config.AppConfig{
		Port:             443,
		TrojanPort:       8443,
		SSPort:           9443,
		SSServerKey:      "c2VydmVya2V5MTIzNDU2",
		Camouflage:       config.CamouflageTLSMode,
		DuckDNSToken:     "tok",
		DuckDNSSubdomain: "mynode",
		Clients:          []config.Client{{UUID: "u1", Name: "me"}},
	}
	in := inputFromConfig(c)

	byProto := map[string]bool{}
	for _, ib := range in.Inbounds {
		byProto[ib.Protocol] = true
		switch ib.Protocol {
		case config.ProtoVLESS, config.ProtoTrojan:
			if ib.TLS == nil {
				t.Errorf("%s should have TLS spec in tls mode", ib.Protocol)
				continue
			}
			if ib.Reality != nil {
				t.Errorf("%s must not carry REALITY in tls mode", ib.Protocol)
			}
			if ib.TLS.ServerName != "mynode.duckdns.org" {
				t.Errorf("%s serverName = %q", ib.Protocol, ib.TLS.ServerName)
			}
			if ib.TLS.FallbackDest != "127.0.0.1:8080" {
				t.Errorf("%s fallback = %q", ib.Protocol, ib.TLS.FallbackDest)
			}
		case config.ProtoShadowsocks:
			if ib.TLS != nil || ib.Reality != nil {
				t.Error("shadowsocks must have neither TLS nor REALITY")
			}
		}
	}
	for _, p := range []string{config.ProtoVLESS, config.ProtoTrojan, config.ProtoShadowsocks} {
		if !byProto[p] {
			t.Errorf("missing inbound %s", p)
		}
	}
}

func TestSubscriptionURLAndBody(t *testing.T) {
	c := config.AppConfig{
		Port:             8443,
		TrojanPort:       8444,
		SSPort:           9443,
		SSServerKey:      "c2VydmVya2V5MTIzNDU2",
		Camouflage:       config.CamouflageTLSMode,
		DuckDNSToken:     "tok",
		DuckDNSSubdomain: "mynode",
		Clients:          []config.Client{{UUID: "uuid-1", Name: "alice"}},
	}
	cl := c.Clients[0]

	url := subscriptionURL(c, cl)
	if url != "https://mynode.duckdns.org:8443/sub/uuid-1" {
		t.Errorf("subscriptionURL = %q", url)
	}

	// The subscription lookup resolves a known id and base64-decodes to the
	// per-protocol links; an unknown id is rejected.
	fn := subscriptionFunc(c, nil)
	body, ok := fn("uuid-1")
	if !ok {
		t.Fatal("known id not found")
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("body is not base64: %v", err)
	}
	dec := string(raw)
	for _, want := range []string{"vless://", "trojan://", "ss://", "mynode.duckdns.org"} {
		if !strings.Contains(dec, want) {
			t.Errorf("subscription missing %q\n%s", want, dec)
		}
	}
	if _, ok := fn("nope"); ok {
		t.Error("unknown id should not resolve")
	}
}

func TestLinkHostPrefersDuckDNS(t *testing.T) {
	c := config.AppConfig{NodeID: "xyz", DuckDNSToken: "tok", PublicIP: "203.0.113.1"}
	if got := linkHost(c); got != "decenzed-node-xyz.duckdns.org" {
		t.Errorf("linkHost = %q", got)
	}
	// An explicit subdomain wins over the legacy decenzed-node-<id> fallback.
	c.DuckDNSSubdomain = "my-vpn"
	if got := linkHost(c); got != "my-vpn.duckdns.org" {
		t.Errorf("linkHost with subdomain = %q", got)
	}
}

func TestNormalizeDuckDNSLabel(t *testing.T) {
	cases := map[string]string{
		"my-vpn":                      "my-vpn",
		" My-VPN ":                    "my-vpn",
		"my-vpn.duckdns.org":          "my-vpn",
		"https://my-vpn.duckdns.org/": "my-vpn",
		"http://my-vpn.duckdns.org":   "my-vpn",
	}
	for in, want := range cases {
		if got := normalizeDuckDNSLabel(in); got != want {
			t.Errorf("normalizeDuckDNSLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadWindowAveragesBytes(t *testing.T) {
	var w loadWindow
	base := time.Now()
	w.add(base, 0)
	got := w.add(base.Add(30*time.Second), 300)
	// 300 bytes over 30s ≈ 10 B/s.
	if got < 9 || got > 11 {
		t.Errorf("loadWindow.add = %v, want ≈10", got)
	}
}

func TestActiveSinceEvictsStale(t *testing.T) {
	now := time.Now()
	m := map[string]time.Time{
		"fresh": now.Add(-1 * time.Minute),
		"stale": now.Add(-40 * time.Minute),
	}
	got := activeSince(m, now.Add(-30*time.Minute))
	if len(got) != 1 || got[0] != "fresh" {
		t.Fatalf("activeSince = %v, want [fresh]", got)
	}
	if _, ok := m["stale"]; ok {
		t.Error("stale entry should have been evicted from the map")
	}
}
