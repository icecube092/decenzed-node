package realityscan

import (
	"context"
	"testing"
	"time"
)

// A closed/unreachable port must not qualify (fast, no external network).
func TestProbeClosedPort(t *testing.T) {
	if _, ok := Probe("127.0.0.1", 1, 500*time.Millisecond); ok {
		t.Fatal("closed port unexpectedly qualified as a REALITY target")
	}
}

func TestHosts24(t *testing.T) {
	h := Hosts24("203.0.113.10")
	if len(h) != 253 { // 1..254 minus self
		t.Fatalf("got %d hosts, want 253", len(h))
	}
	for _, x := range h {
		if x == "203.0.113.10" {
			t.Fatal("neighbour list must exclude the node's own IP")
		}
		if x == "203.0.113.0" || x == "203.0.113.255" {
			t.Fatalf("network/broadcast address leaked: %s", x)
		}
	}
	if Hosts24("not-an-ip") != nil || Hosts24("2001:db8::1") != nil {
		t.Fatal("non-IPv4 input must yield nil")
	}
}

func TestPickDNSName(t *testing.T) {
	if got := pickDNSName([]string{"*.example.com", "cdn.example.com"}); got != "cdn.example.com" {
		t.Fatalf("prefer concrete name, got %q", got)
	}
	if got := pickDNSName([]string{"*.example.com"}); got != "www.example.com" {
		t.Fatalf("wildcard should become www.example.com, got %q", got)
	}
}

// Scan over hosts that all fail returns no candidates and respects ctx.
func TestScanNoCandidates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := Scan(ctx, []string{"127.0.0.1", "127.0.0.1"}, 1, 300*time.Millisecond, 4)
	if len(got) != 0 {
		t.Fatalf("expected 0 candidates, got %d", len(got))
	}
}
