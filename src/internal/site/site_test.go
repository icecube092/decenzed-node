package site

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
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
	go func() { _ = Serve(ctx, addr, sub, "Decenzed-abc123") }()

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
	// Profile name is advertised via the base64 Profile-Title header.
	wantTitle := "base64:" + base64.StdEncoding.EncodeToString([]byte("Decenzed-abc123"))
	if got := sresp.Header.Get("Profile-Title"); got != wantTitle {
		t.Errorf("Profile-Title = %q, want %q", got, wantTitle)
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
	go func() { done <- Serve(ctx, addr, nil, "") }()

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

func TestServeDirHidesDotfilesAndListings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/index.html", "<h1>home</h1>")
	writeFile(t, dir+"/.secret", "TOP SECRET")
	if err := os.MkdirAll(dir+"/private", 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir+"/private/data.txt", "listing bait") // subdir with no index

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServeDir(ctx, addr, dir, nil, "") }()
	waitUp(t, addr)

	cases := map[string]int{
		"/":                 http.StatusOK,       // index.html
		"/.secret":          http.StatusNotFound, // dot-file hidden
		"/private/":         http.StatusNotFound, // no listing for index-less dir
		"/private/data.txt": http.StatusOK,       // explicit files still served
	}
	for p, want := range cases {
		resp, err := http.Get("http://" + addr + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", p, resp.StatusCode, want)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitUp(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if resp, err := http.Get("http://" + addr + "/"); err == nil {
			resp.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("server never came up")
		}
		time.Sleep(20 * time.Millisecond)
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
