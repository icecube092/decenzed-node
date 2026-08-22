// Package duckdns updates a DuckDNS domain to point at the node's current IP,
// using the "special no-parameter" request format (duckdns.org/spec.jsp):
//
//	https://www.duckdns.org/update/{domain}/{token}/{ip}
//
// domain is the subdomain label WITHOUT ".duckdns.org".
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

// Update points `domain` at `ip`. Returns an error unless DuckDNS answers "OK".
func Update(ctx context.Context, domain, token, ip string) error {
	if domain == "" || token == "" {
		return fmt.Errorf("duckdns: domain and token required")
	}
	u := fmt.Sprintf("https://www.duckdns.org/update/%s/%s/%s",
		url.PathEscape(domain), url.PathEscape(token), url.PathEscape(ip))

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
		return fmt.Errorf("duckdns: update rejected (KO) — check the token/domain")
	}
	return nil
}
