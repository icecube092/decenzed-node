package commands

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/domainlist"
)

// maxRemoteListBytes caps a fetched custom list (plain text, one source per line).
const maxRemoteListBytes = 8 << 20

// urlSources returns the raw URLs of the "url:" sources in a list.
func urlSources(sources []string) []string {
	var out []string
	for _, s := range sources {
		if u, ok := strings.CutPrefix(strings.TrimSpace(s), "url:"); ok {
			if u = strings.TrimSpace(u); u != "" {
				out = append(out, u)
			}
		}
	}
	return out
}

// configURLSources gathers every url: source across the new-user default and all
// clients, de-duplicated.
func configURLSources(c config.AppConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ss []string) {
		for _, u := range urlSources(ss) {
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	add(c.DefaultDomains)
	for _, cl := range c.Clients {
		add(cl.Domains)
	}
	return out
}

// ensureRemoteLists fetches + caches any url: source in `sources` that isn't
// cached yet. Called when sources are entered (setup default, link edit/add).
func ensureRemoteLists(sources []string) {
	dir := setXrayAssetDir()
	if dir == "" {
		return
	}
	for _, u := range urlSources(sources) {
		if fileExistsNonEmpty(filepath.Join(dir, domainlist.URLCacheName(u))) {
			continue
		}
		fetchRemoteList(dir, u)
	}
}

// updateRemoteLists re-fetches every url: source in the config (part of `update`).
func updateRemoteLists(c config.AppConfig) {
	dir := setXrayAssetDir()
	if dir == "" {
		return
	}
	urls := configURLSources(c)
	if len(urls) == 0 {
		return
	}
	fmt.Println("refreshing custom domain lists...")
	for _, u := range urls {
		fetchRemoteList(dir, u)
	}
}

// fetchRemoteList downloads a remote text list into the cache atomically, keeping
// any existing cached copy if the fetch fails (so a transient network error never
// wipes a working list).
func fetchRemoteList(dir, rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		fmt.Printf("  ! skipping list %q: only http(s) URLs are supported\n", rawURL)
		return
	}
	fmt.Printf("  fetching domain list from %s ...\n", u.Host)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("  ! could not fetch list: %v (keeping any cached copy)\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		fmt.Printf("  ! list fetch: %s (keeping any cached copy)\n", resp.Status)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteListBytes))
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		fmt.Printf("  ! empty or unreadable list (keeping any cached copy)\n")
		return
	}
	target := filepath.Join(dir, domainlist.URLCacheName(rawURL))
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		fmt.Printf("  ! cache write: %v\n", err)
		return
	}
	if err := os.Rename(tmp, target); err != nil {
		fmt.Printf("  ! cache write: %v\n", err)
		return
	}
	fmt.Printf("  ok — cached %d entries (%s)\n", countListEntries(data), humanBytes(uint64(len(data))))
}

// countListEntries counts the non-empty, non-comment lines in a list body.
func countListEntries(b []byte) int {
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}

func fileExistsNonEmpty(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}
