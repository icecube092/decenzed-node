package duckdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// withEndpoint points the package at a test server and restores it afterwards.
func withEndpoint(t *testing.T, u string) {
	t.Helper()
	prev := endpoint
	endpoint = u
	t.Cleanup(func() { endpoint = prev })
}

func TestUpdateSendsQueryParams(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Write([]byte("OK"))
	}))
	defer srv.Close()
	withEndpoint(t, srv.URL+"/update")

	if err := Update(context.Background(), "decenzed-node-abc", "tok-123", "203.0.113.5"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got.Get("domains") != "decenzed-node-abc" {
		t.Errorf("domains = %q", got.Get("domains"))
	}
	if got.Get("token") != "tok-123" {
		t.Errorf("token = %q", got.Get("token"))
	}
	if got.Get("ip") != "203.0.113.5" {
		t.Errorf("ip = %q", got.Get("ip"))
	}
}

func TestUpdateEmptyIPOmitsParam(t *testing.T) {
	var hasIP bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasIP = r.URL.Query()["ip"]
		w.Write([]byte("OK"))
	}))
	defer srv.Close()
	withEndpoint(t, srv.URL+"/update")

	if err := Update(context.Background(), "dom", "tok", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if hasIP {
		t.Error("ip param should be omitted when ip is empty")
	}
}

func TestUpdateRejectsKO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("KO"))
	}))
	defer srv.Close()
	withEndpoint(t, srv.URL+"/update")

	if err := Update(context.Background(), "dom", "tok", "1.2.3.4"); err == nil {
		t.Fatal("expected error on KO response")
	}
}

func TestUpdateRequiresDomainAndToken(t *testing.T) {
	if err := Update(context.Background(), "", "tok", "1.2.3.4"); err == nil {
		t.Error("expected error for empty domain")
	}
	if err := Update(context.Background(), "dom", "", "1.2.3.4"); err == nil {
		t.Error("expected error for empty token")
	}
}
