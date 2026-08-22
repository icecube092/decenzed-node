// Package speedtest measures the node's internet throughput by transferring a
// sizeable payload to/from public endpoints and timing it. A serving node
// mostly UPLOADS (it sends data to clients), so upload is the primary metric;
// download is measured as a fallback/secondary. Results are in megabits/sec.
package speedtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Result holds the measured throughput (Mbit/s). A metric is 0 if that test
// could not run (e.g. the endpoint was unreachable).
type Result struct {
	DownMbps float64
	UpMbps   float64
}

// Best returns the metric to gate on: upload if measured, else download.
func (r Result) Best() float64 {
	if r.UpMbps > 0 {
		return r.UpMbps
	}
	return r.DownMbps
}

// downloadEndpoints are tried in order until one works. Each must stream at
// least `bytes` of data.
var downloadEndpoints = []string{
	"https://speed.cloudflare.com/__down?bytes=%d",
	"https://speed.hetzner.de/100MB.bin", // ignores byte count; we read a slice
}

const uploadEndpoint = "https://speed.cloudflare.com/__up"

// Run measures download then upload with sensible defaults (~25 MB each) and a
// bounded total time. Errors from individual tests are swallowed into a zero
// metric so a partial result is still useful; it returns an error only if
// NOTHING could be measured.
func Run(ctx context.Context) (Result, error) {
	const payload = 25 << 20 // 25 MB
	var res Result

	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	res.DownMbps, _ = measureDownload(dctx, payload)
	cancel()

	uctx, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	res.UpMbps, _ = measureUpload(uctx, payload)
	cancel2()

	if res.DownMbps == 0 && res.UpMbps == 0 {
		return res, fmt.Errorf("speedtest: all endpoints unreachable")
	}
	return res, nil
}

func measureDownload(ctx context.Context, want int64) (float64, error) {
	var lastErr error
	for _, tmpl := range downloadEndpoints {
		url := tmpl
		if n := countVerbs(tmpl); n == 1 {
			url = fmt.Sprintf(tmpl, want)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		n, _ := io.CopyN(io.Discard, resp.Body, want)
		resp.Body.Close()
		elapsed := time.Since(start).Seconds()
		if n <= 0 || elapsed <= 0 {
			lastErr = fmt.Errorf("no data")
			continue
		}
		return mbps(n, elapsed), nil
	}
	return 0, lastErr
}

func measureUpload(ctx context.Context, want int64) (float64, error) {
	body := io.LimitReader(rand.Reader, want)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadEndpoint, body)
	if err != nil {
		return 0, err
	}
	req.ContentLength = want
	req.Header.Set("Content-Type", "application/octet-stream")
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0, fmt.Errorf("no timing")
	}
	return mbps(want, elapsed), nil
}

func mbps(bytes int64, seconds float64) float64 {
	return float64(bytes) * 8 / seconds / 1e6
}

func countVerbs(s string) int {
	n := 0
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '%' && s[i+1] == 'd' {
			n++
		}
	}
	return n
}
