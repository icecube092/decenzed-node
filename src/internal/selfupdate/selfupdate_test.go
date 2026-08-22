package selfupdate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		cand, cur string
		want      bool
	}{
		{"v1.2.0", "v1.1.9", true},
		{"1.2.0", "1.2.0", false},
		{"1.2.0", "1.3.0", false},
		{"v2.0.0", "v1.9.9", true},
		{"1.2.1", "1.2.0", true},
		{"1.2.0", "dev", false}, // local/dev builds never auto-update
		{"1.2.0", "", false},
		{"weird", "1.0.0", true}, // non-semver but different -> update
		{"1.0.0", "1.0.0", false},
	}
	for _, c := range cases {
		if got := isNewer(c.cand, c.cur); got != c.want {
			t.Errorf("isNewer(%q,%q)=%v want %v", c.cand, c.cur, got, c.want)
		}
	}
}

func TestFetchManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1.4.0","assets":{"linux_amd64":{"url":"http://x/bin","sha256":"ab"}}}`))
	}))
	defer srv.Close()
	m, err := fetchManifest(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.4.0" || m.Assets["linux_amd64"].SHA256 != "ab" {
		t.Fatalf("bad manifest: %+v", m)
	}
}

func TestCheckAndApplyDisabledOnEmptyURL(t *testing.T) {
	applied, _, err := CheckAndApply(context.Background(), "1.0.0", "")
	if applied || err != nil {
		t.Fatalf("empty manifest URL must be a no-op, got applied=%v err=%v", applied, err)
	}
}
