// Package acme obtains and renews a Let's Encrypt certificate for the node's own
// domain using the DNS-01 challenge, so it works without any inbound port (the
// node's 443 is taken by xray, and home connections often have no reachable port
// 80). The TXT record is published through a caller-supplied hook — in practice
// DuckDNS (internal/duckdns) — keeping this package free of any provider import.
//
// It is deliberately thin, built on the low-level golang.org/x/crypto/acme
// client (already in the dependency graph), so the single binary stays small
// enough for flash-constrained targets like OpenWRT — no heavy ACME framework.
//
// The certificate and key are written as PEM files; xray-core reads them as
// certificateFile/keyFile and hot-reloads on renewal without a restart.
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// Directory URLs for Let's Encrypt. Staging has far higher rate limits and issues
// certs from an untrusted root — use it to validate the DNS-01 wiring during
// setup before switching to production.
const (
	prodDirectoryURL    = "https://acme-v02.api.letsencrypt.org/directory"
	stagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// renewBefore is how long before expiry we proactively renew.
const renewBefore = 30 * 24 * time.Hour

// IsStaging reports whether this binary uses the Let's Encrypt staging CA. The
// environment is fixed at build time (see StagingBuild), not configured at
// runtime, so a test binary can never accidentally hit production.
func IsStaging() bool { return StagingBuild }

// CertValid reports whether a certificate already stored in dir is usable as-is
// for domain: present, matching the domain, from this build's CA environment,
// and not within renewBefore of expiry. When true, EnsureCert would be a no-op —
// setup uses this to avoid re-requesting a still-valid certificate.
func CertValid(dir, domain string) bool {
	return !needsRenewal(filepath.Join(dir, "cert.pem"), domain, StagingBuild)
}

// Params configures a single EnsureCert call.
type Params struct {
	Domain string // the node's own FQDN, e.g. "me.duckdns.org"
	Email  string // ACME contact ("mailto:" is added if missing); may be empty
	Dir    string // directory for account.key / cert.pem / key.pem (decenzed-data)

	// AgreeTOS MUST be true: it records that the operator accepted the CA's
	// Subscriber Agreement. The interactive setup collects this consent; a false
	// value fails the call rather than silently agreeing on the operator's behalf.
	AgreeTOS bool

	// SetTXT publishes the DNS-01 TXT value for _acme-challenge.<Domain>.
	// ClearTXT removes it afterwards (best-effort). Both are required.
	SetTXT   func(ctx context.Context, value string) error
	ClearTXT func(ctx context.Context) error

	// resolver, if set, is used to poll for TXT propagation; nil uses a default
	// that queries a public resolver directly (bypassing the OS cache).
	resolver *net.Resolver
}

// EnsureCert returns paths to a valid certificate and key for p.Domain, obtaining
// or renewing them through Let's Encrypt if the current files are missing, close
// to expiry, for a different domain, or from a different CA environment (a
// staging<->prod build switch). When the existing certificate is still good it
// does no network I/O. Files are written under p.Dir (the node's decenzed-data).
func EnsureCert(ctx context.Context, p Params) (certPath, keyPath string, err error) {
	if p.Domain == "" {
		return "", "", errors.New("acme: domain required")
	}
	if p.SetTXT == nil || p.ClearTXT == nil {
		return "", "", errors.New("acme: SetTXT and ClearTXT hooks required")
	}
	certPath = filepath.Join(p.Dir, "cert.pem")
	keyPath = filepath.Join(p.Dir, "key.pem")

	if !needsRenewal(certPath, p.Domain, StagingBuild) {
		return certPath, keyPath, nil
	}
	if !p.AgreeTOS {
		return "", "", errors.New("acme: the CA Subscriber Agreement must be accepted (run setup)")
	}
	if err := obtain(ctx, p, certPath, keyPath); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// needsRenewal reports whether we must (re)issue: file missing/unparseable,
// wrong domain, wrong CA environment, or within renewBefore of expiry.
func needsRenewal(certPath, domain string, staging bool) bool {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	leaf, err := leafCert(pemBytes)
	if err != nil {
		return true
	}
	if leaf.VerifyHostname(domain) != nil {
		return true
	}
	if envMarker(certPath, staging) {
		return true
	}
	return time.Now().Add(renewBefore).After(leaf.NotAfter)
}

// envName is the CA environment tag stored beside the cert so a staging<->prod
// build switch forces a reissue.
func envName(staging bool) string {
	if staging {
		return "staging"
	}
	return "prod"
}

// envMarker returns true if the recorded CA environment differs from `staging`,
// forcing a reissue when the binary switches staging<->prod.
func envMarker(certPath string, staging bool) bool {
	got, _ := os.ReadFile(certPath + ".env")
	return strings.TrimSpace(string(got)) != envName(staging)
}

// leafCert parses the first certificate from a PEM chain.
func leafCert(pemBytes []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("acme: no CERTIFICATE block in PEM")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// obtain runs the full ACME DNS-01 order and writes cert.pem/key.pem.
func obtain(ctx context.Context, p Params, certPath, keyPath string) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	accountKey, err := loadOrCreateAccountKey(p.Dir, StagingBuild)
	if err != nil {
		return err
	}
	dir := prodDirectoryURL
	if StagingBuild {
		dir = stagingDirectoryURL
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: dir}

	acct := &acme.Account{}
	if p.Email != "" {
		acct.Contact = []string{ensureMailto(p.Email)}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil &&
		!errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("acme: register account: %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(p.Domain))
	if err != nil {
		return fmt.Errorf("acme: authorize order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := p.solveDNS01(ctx, client, authzURL); err != nil {
			return err
		}
	}

	csr, certKeyPEM, err := newCSR(p.Domain)
	if err != nil {
		return err
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("acme: finalize/get cert: %w", err)
	}

	certPEM := encodeCertChain(der)
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, certKeyPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(certPath+".env", []byte(envName(StagingBuild)+"\n"), 0o644)
}

// solveDNS01 completes one authorization via the dns-01 challenge.
func (p Params) solveDNS01(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("acme: get authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil // already authorized (e.g. a re-run)
	}
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("acme: no dns-01 challenge offered")
	}
	value, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return fmt.Errorf("acme: dns-01 record: %w", err)
	}

	if err := p.SetTXT(ctx, value); err != nil {
		return fmt.Errorf("acme: publish TXT: %w", err)
	}
	defer func() { _ = p.ClearTXT(context.WithoutCancel(ctx)) }()

	if err := waitTXT(ctx, p.resolver, p.Domain, value); err != nil {
		return err
	}
	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("acme: accept challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("acme: wait authorization: %w", err)
	}
	return nil
}

// waitTXT polls until the _acme-challenge TXT record for domain carries value,
// so we only tell the CA to check once DNS has actually propagated.
func waitTXT(ctx context.Context, resolver *net.Resolver, domain, value string) error {
	name := "_acme-challenge." + domain
	if resolver == nil {
		resolver = publicResolver()
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		txts, _ := resolver.LookupTXT(ctx, name)
		for _, t := range txts {
			if t == value {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acme: TXT for %s did not propagate in time", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// publicResolver queries a public DNS server directly, bypassing the OS resolver
// cache so freshly-published TXT records are seen promptly.
func publicResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, "1.1.1.1:53")
		},
	}
}

// loadOrCreateAccountKey loads the per-environment ACME account key, generating
// and persisting one on first use. Staging and prod use separate account keys
// (an ACME account belongs to a single CA).
func loadOrCreateAccountKey(dir string, staging bool) (*ecdsa.PrivateKey, error) {
	name := "account.key"
	if staging {
		name = "account.staging.key"
	}
	path := filepath.Join(dir, name)
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return k, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// newCSR generates a fresh certificate key and a CSR for domain, returning the
// DER-encoded CSR and the PEM-encoded private key.
func newCSR(domain string) (csrDER []byte, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return csrDER, keyPEM, nil
}

// encodeCertChain PEM-encodes the DER certificate chain returned by ACME.
func encodeCertChain(der [][]byte) []byte {
	var out []byte
	for _, b := range der {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	return out
}

func ensureMailto(email string) string {
	if strings.HasPrefix(email, "mailto:") {
		return email
	}
	return "mailto:" + email
}

// writeFileAtomic writes via a temp file + rename so readers never see a partial
// file (xray polls these paths).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
