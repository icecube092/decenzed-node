package site

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServeReturnsEmbeddedPage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // Serve reopens it

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub := func(id string) (string, bool) {
		if id == "known-id" {
			return "SUBSCRIPTION-BODY", true
		}
		return "", false
	}
	go func() { _ = Serve(ctx, addr, sub) }()

	// Wait for the listener to come up.
	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		var derr error
		resp, derr = http.Get("http://" + addr + "/")
		if derr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never came up: %v", derr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Personal server") {
		t.Errorf("unexpected body: %q", string(body))
	}

	// Known subscription id returns its body.
	sresp, err := http.Get("http://" + addr + SubPath + "known-id")
	if err != nil {
		t.Fatalf("sub GET: %v", err)
	}
	defer sresp.Body.Close()
	sbody, _ := io.ReadAll(sresp.Body)
	if sresp.StatusCode != http.StatusOK || string(sbody) != "SUBSCRIPTION-BODY" {
		t.Errorf("sub = %d %q", sresp.StatusCode, string(sbody))
	}

	// Unknown id looks like an ordinary 404.
	uresp, err := http.Get("http://" + addr + SubPath + "nope")
	if err != nil {
		t.Fatalf("sub GET unknown: %v", err)
	}
	uresp.Body.Close()
	if uresp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown id status = %d, want 404", uresp.StatusCode)
	}
}

func TestServeShutsDownOnContextCancel(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, addr, nil) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}

func TestIsUnixAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":     false,
		":8080":              false,
		"/dev/shm/site.sock": true,
		"@decenzed-site":     true,
	}
	for addr, want := range cases {
		if got := isUnixAddr(addr); got != want {
			t.Errorf("isUnixAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
