package throttle

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// echoServer accepts one connection and echoes everything back.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return ln
}

func startProxy(t *testing.T, backend string, rate float64) (net.Addr, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy("", backend, rate)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = p.serve(ctx, ln) }()
	return ln.Addr(), cancel
}

func TestProxyForwardsDataIntact(t *testing.T) {
	backend := echoServer(t)
	defer backend.Close()
	addr, cancel := startProxy(t, backend.Addr().String(), 0) // unlimited
	defer cancel()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("decenzed-throttle-"), 4096) // ~72 KB
	go func() { _, _ = conn.Write(payload); conn.(*net.TCPConn).CloseWrite() }()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed data mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestProxyRateLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	backend := echoServer(t)
	defer backend.Close()
	// 1 MB/s cap; send 2 MB so the initial burst (~250 KB) is negligible. At
	// 1 MB/s the upload alone is ~1.75s after the burst.
	addr, cancel := startProxy(t, backend.Addr().String(), 1e6)
	defer cancel()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := make([]byte, 2*1024*1024)
	start := time.Now()
	go func() { _, _ = conn.Write(payload); conn.(*net.TCPConn).CloseWrite() }()
	n, _ := io.Copy(io.Discard, conn)
	elapsed := time.Since(start)

	if n != int64(len(payload)) {
		t.Fatalf("got %d bytes, want %d", n, len(payload))
	}
	if elapsed < 1*time.Second {
		t.Fatalf("transfer too fast (%v) — rate limit not applied", elapsed)
	}
}
