package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert writes a self-signed cert for domain valid for `validFor` to
// certPath (+ optional env marker) and returns nothing.
func writeTestCert(t *testing.T, certPath, domain string, validFor time.Duration) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNeedsRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")

	// Missing file -> needs renewal.
	if !needsRenewal(certPath, "me.duckdns.org", false) {
		t.Error("missing cert should need renewal")
	}

	// Fresh, long-lived, matching env -> no renewal.
	writeTestCert(t, certPath, "me.duckdns.org", 60*24*time.Hour)
	os.WriteFile(certPath+".env", []byte("prod\n"), 0o644)
	if needsRenewal(certPath, "me.duckdns.org", false) {
		t.Error("valid fresh cert should not need renewal")
	}

	// Wrong domain -> needs renewal.
	if !needsRenewal(certPath, "other.duckdns.org", false) {
		t.Error("domain mismatch should need renewal")
	}

	// Env switch (prod cert, staging requested) -> needs renewal.
	if !needsRenewal(certPath, "me.duckdns.org", true) {
		t.Error("env switch should need renewal")
	}

	// Near expiry -> needs renewal.
	writeTestCert(t, certPath, "me.duckdns.org", 10*24*time.Hour)
	os.WriteFile(certPath+".env", []byte("prod\n"), 0o644)
	if !needsRenewal(certPath, "me.duckdns.org", false) {
		t.Error("cert within 30 days of expiry should need renewal")
	}
}

func TestEnsureCertSkipsWhenValid(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, filepath.Join(dir, "cert.pem"), "me.duckdns.org", 60*24*time.Hour)
	// Marker must match the build's CA environment, or EnsureCert would try to
	// reissue (and hit the network) instead of skipping.
	os.WriteFile(filepath.Join(dir, "cert.pem.env"), []byte(envName(StagingBuild)+"\n"), 0o644)

	called := false
	cp, kp, err := EnsureCert(context.Background(), Params{
		Domain:   "me.duckdns.org",
		Dir:      dir,
		AgreeTOS: true,
		SetTXT:   func(context.Context, string) error { called = true; return nil },
		ClearTXT: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	if called {
		t.Error("should not touch DNS when cert is still valid")
	}
	if cp != filepath.Join(dir, "cert.pem") || kp != filepath.Join(dir, "key.pem") {
		t.Errorf("paths = %q, %q", cp, kp)
	}
}

func TestEnsureCertRequiresTOSWhenIssuing(t *testing.T) {
	// No cert on disk -> renewal needed -> must fail on missing ToS consent,
	// before any network I/O.
	_, _, err := EnsureCert(context.Background(), Params{
		Domain:   "me.duckdns.org",
		Dir:      t.TempDir(),
		AgreeTOS: false,
		SetTXT:   func(context.Context, string) error { return nil },
		ClearTXT: func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error when ToS is not accepted")
	}
}

func TestCertValid(t *testing.T) {
	dir := t.TempDir()
	// No cert yet.
	if CertValid(dir, "me.duckdns.org") {
		t.Error("missing cert should not be valid")
	}
	// Fresh cert for the domain, matching CA env.
	writeTestCert(t, filepath.Join(dir, "cert.pem"), "me.duckdns.org", 60*24*time.Hour)
	os.WriteFile(filepath.Join(dir, "cert.pem.env"), []byte(envName(StagingBuild)+"\n"), 0o644)
	if !CertValid(dir, "me.duckdns.org") {
		t.Error("fresh matching cert should be valid")
	}
	// Different domain must not be considered valid.
	if CertValid(dir, "other.duckdns.org") {
		t.Error("cert for another domain should not be valid")
	}
}

func TestEnsureCertValidatesParams(t *testing.T) {
	if _, _, err := EnsureCert(context.Background(), Params{Dir: t.TempDir()}); err == nil {
		t.Error("expected error for missing domain")
	}
	if _, _, err := EnsureCert(context.Background(), Params{Domain: "x", Dir: t.TempDir()}); err == nil {
		t.Error("expected error for missing TXT hooks")
	}
}

func TestNewCSRProducesParsableRequest(t *testing.T) {
	csrDER, keyPEM, err := newCSR("me.duckdns.org")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "me.duckdns.org" {
		t.Errorf("DNSNames = %v", csr.DNSNames)
	}
	if block, _ := pem.Decode(keyPEM); block == nil || block.Type != "EC PRIVATE KEY" {
		t.Error("key PEM not an EC PRIVATE KEY block")
	}
}

func TestAccountKeyIsPersistedAndReused(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadOrCreateAccountKey(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadOrCreateAccountKey(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Error("account key should be stable across calls")
	}
	// Staging uses a separate key file.
	ks, _ := loadOrCreateAccountKey(dir, true)
	if ks.Equal(k1) {
		t.Error("staging account key should differ from prod")
	}
}
