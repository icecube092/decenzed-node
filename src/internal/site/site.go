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
	"encoding/base64"
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
// a public interface. profileTitle names the subscription profile in the client.
func Serve(ctx context.Context, addr string, sub SubFunc, profileTitle string) error {
	root, err := fs.Sub(content, "content")
	if err != nil {
		return err
	}
	return serveFS(ctx, addr, http.FS(root), sub, profileTitle)
}

// ServeDir is like Serve but serves files from dir instead of the embedded site,
// letting an operator supply their own decoy content.
func ServeDir(ctx context.Context, addr, dir string, sub SubFunc, profileTitle string) error {
	return serveFS(ctx, addr, http.Dir(dir), sub, profileTitle)
}

func serveFS(ctx context.Context, addr string, root http.FileSystem, sub SubFunc, profileTitle string) error {
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	files := http.FileServer(hardenedFS{root})
	if sub != nil {
		mux.HandleFunc(SubPath, func(w http.ResponseWriter, r *http.Request) {
			id := strings.TrimPrefix(r.URL.Path, SubPath)
			body, ok := sub(id)
			if !ok {
				http.NotFound(w, r) // unknown id: ordinary 404, no info leak
				return
			}
			// Headers clients read to name and refresh the subscription profile.
			// Profile-Title carries the display name (base64 form is the widely
			// supported one); Content-Disposition names it for clients that use
			// the filename instead.
			if profileTitle != "" {
				w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(profileTitle)))
				w.Header().Set("Content-Disposition", `attachment; filename="`+profileTitle+`"`)
			}
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

// hardenedFS wraps an http.FileSystem to make the decoy site behave like an
// ordinary website and add defense-in-depth even when serving a real directory
// (ServeDir): it hides dot-files and refuses to list directories that have no
// index.html (http.FileServer would otherwise render a browsable listing). The
// embedded content is already safe on its own — this hardens the ServeDir path
// and blocks directory enumeration.
type hardenedFS struct{ fs http.FileSystem }

func (h hardenedFS) Open(name string) (http.File, error) {
	// Reject any path element starting with "." (dot-files, and "."/".." as a
	// belt-and-suspenders traversal guard on top of http.FileServer's cleaning).
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") {
			return nil, fs.ErrNotExist
		}
	}
	f, err := h.fs.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		// Only allow a directory if it has an index.html to serve; otherwise hide
		// it entirely (no listing).
		index := strings.TrimSuffix(name, "/") + "/index.html"
		idx, ierr := h.fs.Open(index)
		if ierr != nil {
			_ = f.Close()
			return nil, fs.ErrNotExist
		}
		_ = idx.Close()
	}
	return f, nil
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
