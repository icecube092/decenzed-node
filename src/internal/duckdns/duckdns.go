// Package duckdns updates a DuckDNS domain to point at the node's current IP
// using the documented query-parameter API (duckdns.org/spec.jsp):
//
//	https://www.duckdns.org/update?domains={domain}&token={token}&ip={ip}
//
// domain is the subdomain label WITHOUT ".duckdns.org". Leaving ip empty lets
// DuckDNS auto-detect the caller's address.
package duckdns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// endpoint is the DuckDNS update base URL; overridable in tests.
var endpoint = "https://www.duckdns.org/update"

// Update points `domain` at `ip`. When ip is empty DuckDNS auto-detects the
// caller's IP. Returns an error unless DuckDNS answers "OK".
func Update(ctx context.Context, domain, token, ip string) error {
	if domain == "" || token == "" {
		return fmt.Errorf("duckdns: domain and token required")
	}
	q := url.Values{}
	q.Set("domains", domain)
	q.Set("token", token)
	if ip != "" {
		q.Set("ip", ip)
	}
	u := endpoint + "?" + q.Encode()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if strings.TrimSpace(string(body)) != "OK" {
		return fmt.Errorf("duckdns: update rejected (%q) — check the token/domain",
			strings.TrimSpace(string(body)))
	}
	return nil
}
