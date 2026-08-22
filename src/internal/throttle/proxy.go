package throttle

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
)

// chunk is the copy buffer size; must be <= a connection bucket's burst.
const chunk = 32 * 1024

// LimitedCopy copies src→dst, capping throughput with the token bucket. It
// copies in <=chunk pieces, waiting for tokens before each write. The bucket may
// be SHARED across connections (per-user limiting), in which case they compete
// for tokens and the aggregate is capped.
func LimitedCopy(dst io.Writer, src io.Reader, b *Bucket) (int64, error) {
	buf := make([]byte, chunk)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			b.WaitN(float64(n))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

// Proxy is a transparent TCP forwarder in front of xray (which listens on
// Backend, loopback) that rate-limits each CLIENT to RateBps bytes/sec per
// direction. Buckets are keyed by the client's SOURCE IP, so all connections
// from one user/device share the limit — an application-level per-user cap that
// needs no OS/tc configuration and no xray support (the VLESS user id is
// encrypted, but the source IP is visible at L4). Users behind the same public
// IP share a bucket (acceptable: one household/device = one end-user here).
type Proxy struct {
	Listen  string  // public listen address, e.g. ":8443"
	Backend string  // xray loopback address, e.g. "127.0.0.1:18443"
	RateBps float64 // per-user, per-direction cap (0 = unlimited)

	mu    sync.Mutex
	perIP map[string]*ipLimiter
}

// ipLimiter holds one user's shared up/down buckets and a refcount so it can be
// freed when the user's last connection closes.
type ipLimiter struct {
	up, down *Bucket
	refs     int
}

// NewProxy builds a per-user throttling proxy.
func NewProxy(listen, backend string, rateBps float64) *Proxy {
	return &Proxy{Listen: listen, Backend: backend, RateBps: rateBps, perIP: map[string]*ipLimiter{}}
}

func (p *Proxy) burst() float64 {
	b := p.RateBps * 0.25
	if b < 4*chunk {
		b = 4 * chunk
	}
	return b
}

// acquire returns the (shared) limiter for an IP, creating it on first use.
func (p *Proxy) acquire(ip string) *ipLimiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.perIP[ip]
	if l == nil {
		l = &ipLimiter{up: New(p.RateBps, p.burst()), down: New(p.RateBps, p.burst())}
		p.perIP[ip] = l
	}
	l.refs++
	return l
}

func (p *Proxy) release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l := p.perIP[ip]; l != nil {
		if l.refs--; l.refs <= 0 {
			delete(p.perIP, ip)
		}
	}
}

// Run listens on p.Listen and accepts connections until ctx is cancelled.
func (p *Proxy) Run(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", p.Listen)
	if err != nil {
		return err
	}
	return p.serve(ctx, ln)
}

// serve runs the accept loop on an existing listener (also used by tests).
func (p *Proxy) serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		client, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go p.handle(client)
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	backend, err := net.Dial("tcp", p.Backend)
	if err != nil {
		log.Println("throttle proxy: dial backend:", err)
		return
	}
	defer backend.Close()

	ip, _, _ := net.SplitHostPort(client.RemoteAddr().String())
	lim := p.acquire(ip)
	defer p.release(ip)

	done := make(chan struct{}, 2)
	go func() { // client → backend (upload)
		_, _ = LimitedCopy(backend, client, lim.up)
		halfClose(backend)
		done <- struct{}{}
	}()
	go func() { // backend → client (download)
		_, _ = LimitedCopy(client, backend, lim.down)
		halfClose(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// halfClose shuts the write side so the peer sees EOF but the other direction
// can still drain.
func halfClose(c net.Conn) {
	if t, ok := c.(interface{ CloseWrite() error }); ok {
		_ = t.CloseWrite()
	}
}
