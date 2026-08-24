package commands

import (
	"strings"
	"testing"
	"time"

	"decenzed/node_app/internal/config"
)

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
		RealityServerName: []string{"example.com"},
		RealityPublicKey:  "PUBKEY",
		RealityShortIDs:   []string{"beef"},
	}
	link := linkFor(c, config.Client{UUID: "uuid-1", Name: "alice"}, "host.example")
	for _, want := range []string{
		"vless://uuid-1@host.example:8443?",
		"security=reality",
		"sni=example.com",
		"pbk=PUBKEY",
		"sid=beef",
		"#alice",
	} {
		if !strings.Contains(link, want) {
			t.Errorf("link %q missing %q", link, want)
		}
	}
}

func TestLinkHostPrefersDuckDNS(t *testing.T) {
	c := config.AppConfig{NodeID: "xyz", DuckDNSToken: "tok", PublicIP: "203.0.113.1"}
	if got := linkHost(c); got != "decenzed-node-xyz.duckdns.org" {
		t.Errorf("linkHost = %q", got)
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
