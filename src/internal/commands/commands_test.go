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

func TestCheckInbounds(t *testing.T) {
	// Without a config: only the default VLESS port is reported.
	got := checkInbounds(config.AppConfig{}, false)
	if len(got) != 1 || got[0].name != config.ProtoVLESS || got[0].port != 443 {
		t.Fatalf("no-config case = %+v", got)
	}

	// With a config: all protocols in order; disabled ones keep port 0.
	cfg := config.AppConfig{Port: 8443, TrojanPort: 0, SSPort: 35123, SS2022Port: 0}
	got = checkInbounds(cfg, true)
	want := []checkInbound{
		{config.ProtoVLESS, 8443},
		{config.ProtoTrojan, 0},
		{config.ProtoShadowsocks, 35123},
		{"shadowsocks-2022", 0},
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestJoinPorts(t *testing.T) {
	if got := joinPorts([]int{8443, 8444, 9443}); got != "8443, 8444, 9443" {
		t.Errorf("joinPorts = %q", got)
	}
	if got := joinPorts([]int{443}); got != "443" {
		t.Errorf("joinPorts single = %q", got)
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
