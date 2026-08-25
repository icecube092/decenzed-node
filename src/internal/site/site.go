// Package site serves the node's own decoy website — the real, plausible site
// that xray's TLS fallback points at when the node masquerades behind its own
// domain (Camouflage=tls). Active probing and stray browsers see this page over
// a valid certificate instead of anything proxy-shaped.
//
// The same server also hosts each client's SUBSCRIPTION: a secret per-client path
// (SubPath + client id) that returns their proxy settings. Because it rides the
// TLS fallback, a subscription fetch is just an ordinary HTTPS GET to the node's
// domain — indistinguishable from browsing the site — and needs no extra port.
//
// The content is embedded so the node stays a single binary. Operators can
// override it with a directory via ServeDir.
package site

import (
	"context"
	"embed"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed content
var content embed.FS

// SubPath is the URL prefix for client subscriptions: a GET to SubPath+<id>
// returns that client's subscription body. Unknown ids look like an ordinary
// 404, preserving the masquerade.
const SubPath = "/sub/"

// SubFunc returns the subscription body for a client id, and whether the id is
// known. The body is returned verbatim (already base64 subscription text).
type SubFunc func(id string) (body string, ok bool)

// Serve runs the website (and, if sub != nil, the subscription endpoint) on addr
// until ctx is cancelled. addr is either a TCP "host:port" or a unix socket path
// (absolute path, or "@name" for an abstract socket on Linux). It listens only
// where xray's fallback dials it — typically 127.0.0.1 or a local socket — never
// a public interface.
func Serve(ctx context.Context, addr string, sub SubFunc) error {
	root, err := fs.Sub(content, "content")
	if err != nil {
		return err
	}
	return serveFS(ctx, addr, http.FS(root), sub)
}

// ServeDir is like Serve but serves files from dir instead of the embedded site,
// letting an operator supply their own decoy content.
func ServeDir(ctx context.Context, addr, dir string, sub SubFunc) error {
	return serveFS(ctx, addr, http.Dir(dir), sub)
}

func serveFS(ctx context.Context, addr string, root http.FileSystem, sub SubFunc) error {
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	files := http.FileServer(root)
	if sub != nil {
		mux.HandleFunc(SubPath, func(w http.ResponseWriter, r *http.Request) {
			id := strings.TrimPrefix(r.URL.Path, SubPath)
			body, ok := sub(id)
			if !ok {
				http.NotFound(w, r) // unknown id: ordinary 404, no info leak
				return
			}
			// Header some clients read to name/refresh the subscription.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Profile-Update-Interval", "12")
			_, _ = io.WriteString(w, body)
		})
	}
	mux.Handle("/", files)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// listen opens a TCP or unix listener depending on the shape of addr. A path
// (absolute, or "@" abstract) means unix; anything else is TCP. Stale socket
// files are removed first so a restart doesn't fail with "address in use".
func listen(addr string) (net.Listener, error) {
	if isUnixAddr(addr) {
		if !strings.HasPrefix(addr, "@") {
			_ = os.Remove(addr)
		}
		return net.Listen("unix", addr)
	}
	return net.Listen("tcp", addr)
}

func isUnixAddr(addr string) bool {
	return strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "@")
}
