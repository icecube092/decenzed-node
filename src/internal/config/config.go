// Package config is the single source of truth for a standalone node's policy
// and its self-generated REALITY credentials. It is persisted as JSON with 0600
// perms (it holds the REALITY private key and client UUIDs).
//
// This app is fully self-contained: it runs a VLESS + REALITY server on your
// machine and prints share links you hand to friends. There is no coordination
// server.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultUpdateManifestURL points the auto-updater at a GitHub Release manifest.
// Empty disables auto-update. This is the ONLY external endpoint the app knows,
// and it is optional (edit internal/config/update_manifest.txt).
//
//go:embed update_manifest.txt
var defaultUpdateManifestURL string

// DefaultUpdateManifestURL returns the built-in update manifest URL ("" = off).
func DefaultUpdateManifestURL() string { return strings.TrimSpace(defaultUpdateManifestURL) }

// Client is one connection credential you issue (yourself or a friend). Revoke
// a friend by removing their entry.
type Client struct {
	UUID string `json:"uuid"`
	Name string `json:"name,omitempty"`
}

// AppConfig is the high-level operator config. The xray JSON is DERIVED from it
// (see package xraygen) and never edited by hand.
type AppConfig struct {
	// Identity + dynamic DNS. NodeID is a short stable id. The node keeps its
	// DuckDNS domain pointed at its current IP: DuckDNSSubdomain is the label you
	// created on duckdns.org (without ".duckdns.org"); when empty it falls back to
	// "decenzed-node-<NodeID>" for backward compatibility.
	NodeID           string `json:"node_id"`
	DuckDNSToken     string `json:"duckdns_token"`            // empty = links use the raw IP
	DuckDNSSubdomain string `json:"duckdns_domain,omitempty"` // the subdomain you registered on duckdns.org

	// Networking.
	Port     int    `json:"port"`      // VLESS+REALITY inbound TCP port (forward this on your router)
	PublicIP string `json:"public_ip"` // used in share links when DuckDNS is off; auto-detected if empty

	// Extra protocols (optional). Each runs as its own xray inbound on its own
	// port — one port can host only one protocol, so every enabled protocol
	// needs its own forwarded TCP port. A 0 port means the protocol is disabled.
	//   - Trojan shares the same camouflage as VLESS (REALITY or TLS; no XTLS flow:
	//     Vision is VLESS-only). Its per-client password is the client UUID.
	//   - Shadowsocks (classic) uses chacha20-ietf-poly1305 in multi-user mode
	//     (each client's password is its UUID). Broadest client support.
	//   - Shadowsocks-2022 (2022-blake3-aes-128-gcm) uses per-user PSKs derived
	//     from the UUID plus a server-wide key (SSServerKey). Stronger, but rejected
	//     by many clients — offered as a SEPARATE inbound/port for those that do.
	//   Neither Shadowsocks variant has REALITY/TLS masking — a distinct,
	//   less-stealthy traffic type.
	TrojanPort  int    `json:"trojan_port,omitempty"`
	SSPort      int    `json:"ss_port,omitempty"`
	SS2022Port  int    `json:"ss2022_port,omitempty"`
	SSServerKey string `json:"ss_server_key,omitempty"`

	// Policy.
	MaxUserBps     float64  `json:"max_user_bps"`    // per-user speed cap (bytes/sec); 0 = off
	BlockProtocols []string `json:"block_protocols"` // e.g. ["bittorrent"]; empty = block nothing
	DomainAllow    []string `json:"domain_allow"`    // if set: allow ONLY these
	DomainDeny     []string `json:"domain_deny"`     // always blocked
	Autostart      bool     `json:"autostart"`

	// Camouflage selects how the REALITY-capable protocols (VLESS, Trojan) hide.
	// One tumbler for both — they cannot use different modes. Shadowsocks is never
	// affected (it has no TLS layer).
	//   - "reality" (default/empty): borrow a foreign TLS1.3+h2 site as REALITY dest.
	//   - "tls": terminate real TLS with a Let's Encrypt cert for the node's own
	//     domain and fall back to the node's own website (see the TLS fields below).
	Camouflage string `json:"camouflage,omitempty"`

	// REALITY camouflage — dest/serverName chosen at setup by scanning for a
	// live TLS1.3+h2 site; the keypair is generated locally. Used when
	// Camouflage != "tls".
	RealityDest       string   `json:"reality_dest"`
	RealityServerName []string `json:"reality_server_names"`
	RealityPrivateKey string   `json:"reality_private_key"`
	RealityPublicKey  string   `json:"reality_public_key"`
	RealityShortIDs   []string `json:"reality_short_ids"`

	// TLS camouflage (Camouflage == "tls"): masquerade behind the node's own
	// website with a Let's Encrypt certificate (DNS-01 via DuckDNS). TLSDomain
	// defaults to the DuckDNS host. SitePort is the localhost port the built-in
	// website listens on (xray's fallback target); 0 means the default.
	//
	// ACMEEmail is the account contact given to the CA. ACMEAgreeTOS records that
	// the operator accepted the CA Subscriber Agreement during setup, so unattended
	// renewals can proceed without prompting. The staging-vs-production CA is fixed
	// at BUILD time (see internal/acme.StagingBuild), not stored here.
	TLSDomain    string `json:"tls_domain,omitempty"`
	ACMEEmail    string `json:"acme_email,omitempty"`
	ACMEAgreeTOS bool   `json:"acme_agree_tos,omitempty"`
	SitePort     int    `json:"site_port,omitempty"`

	// Clients — your own + friends' credentials. Each maps to one share link.
	Clients []Client `json:"clients"`
}

// Protocol identifiers used across the app (xray inbound "protocol" values).
const (
	ProtoVLESS       = "vless"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
)

// Camouflage modes for VLESS/Trojan.
const (
	CamouflageReality = "reality"
	CamouflageTLSMode = "tls"
)

// defaultSitePort is the localhost port the built-in decoy website uses when
// SitePort is unset.
const defaultSitePort = 8080

// CamouflageTLS reports whether VLESS/Trojan masquerade behind the node's own
// TLS website (as opposed to REALITY). Empty/unset means REALITY.
func (c AppConfig) CamouflageTLS() bool { return c.Camouflage == CamouflageTLSMode }

// TLSHost is the domain the node's certificate is issued for and clients connect
// to in TLS mode: the explicit override, else the DuckDNS host.
func (c AppConfig) TLSHost() string {
	if c.TLSDomain != "" {
		return c.TLSDomain
	}
	return c.DuckDNSHost()
}

// SiteAddr is the localhost address the built-in website listens on and that
// xray falls back to in TLS mode.
func (c AppConfig) SiteAddr() string {
	p := c.SitePort
	if p == 0 {
		p = defaultSitePort
	}
	return fmt.Sprintf("127.0.0.1:%d", p)
}

// IsConfigured reports whether setup has produced enough state to start the node
// in its selected camouflage mode: REALITY needs a keypair; TLS needs a domain
// (the certificate itself is obtained at runtime).
func (c AppConfig) IsConfigured() bool {
	if c.CamouflageTLS() {
		return c.TLSHost() != ""
	}
	return c.RealityPublicKey != ""
}

// Shadowsocks cipher methods. The classic AEAD cipher has the broadest client
// support; SS-2022 is stronger but many clients reject it, so it is offered as a
// separate inbound for the clients that do.
const (
	SSMethodClassic = "chacha20-ietf-poly1305"
	SSMethod2022    = "2022-blake3-aes-128-gcm"
)

// ss2022KeyLen is the raw key length (bytes) for SSMethod2022.
const ss2022KeyLen = 16

// NewSSServerKey generates a random Shadowsocks-2022 server PSK (base64).
func NewSSServerKey() (string, error) {
	b := make([]byte, ss2022KeyLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// SSUserPSK derives a client's Shadowsocks-2022 per-user PSK deterministically
// from its UUID, so no extra per-client secret needs to be stored. The server
// (xray inbound) and the share link both derive it the same way.
func SSUserPSK(uuid string) string {
	sum := sha256.Sum256([]byte("decenzed-ss-2022|" + uuid))
	return base64.StdEncoding.EncodeToString(sum[:ss2022KeyLen])
}

// IsSS2022 reports whether a Shadowsocks cipher is an SS-2022 method.
func IsSS2022(method string) bool { return strings.HasPrefix(method, "2022-") }

// Inbound is one enabled listener: a protocol on a public TCP port. For
// Shadowsocks, Method carries the cipher (the two SS variants share the protocol
// id but differ by cipher/port); it is empty for VLESS/Trojan.
type Inbound struct {
	Protocol string
	Port     int
	Method   string
}

// PublicInbounds lists the protocol listeners this node exposes, in a stable
// order (VLESS first). Only enabled ones (port != 0) are returned. This is the
// single source of truth for both xray generation and the throttle proxies.
func (c AppConfig) PublicInbounds() []Inbound {
	var out []Inbound
	if c.Port != 0 {
		out = append(out, Inbound{Protocol: ProtoVLESS, Port: c.Port})
	}
	if c.TrojanPort != 0 {
		out = append(out, Inbound{Protocol: ProtoTrojan, Port: c.TrojanPort})
	}
	if c.SSPort != 0 {
		out = append(out, Inbound{Protocol: ProtoShadowsocks, Port: c.SSPort, Method: SSMethodClassic})
	}
	if c.SS2022Port != 0 {
		out = append(out, Inbound{Protocol: ProtoShadowsocks, Port: c.SS2022Port, Method: SSMethod2022})
	}
	return out
}

// Default returns a config populated with sensible defaults.
func Default() AppConfig {
	return AppConfig{
		Port:           443,
		BlockProtocols: []string{"bittorrent"},
		Autostart:      true,
		MaxUserBps:     50e6 / 8, // per-user cap: 50 Mbit/s
	}
}

// DuckDNSDomain is the subdomain label (without ".duckdns.org"): the label you
// registered on duckdns.org, or the legacy "decenzed-node-<NodeID>" fallback.
// Empty if neither is set.
func (c AppConfig) DuckDNSDomain() string {
	if c.DuckDNSSubdomain != "" {
		return c.DuckDNSSubdomain
	}
	if c.NodeID == "" {
		return ""
	}
	return "decenzed-node-" + c.NodeID
}

// DuckDNSHost is the full hostname the node keeps updated, or "" if DuckDNS
// isn't configured (no domain label or no token).
func (c AppConfig) DuckDNSHost() string {
	if c.DuckDNSToken == "" || c.DuckDNSDomain() == "" {
		return ""
	}
	return c.DuckDNSDomain() + ".duckdns.org"
}

// UUIDs returns the client UUIDs (fed to the xray inbound).
func (c AppConfig) UUIDs() []string {
	out := make([]string, 0, len(c.Clients))
	for _, cl := range c.Clients {
		out = append(out, cl.UUID)
	}
	return out
}

// BlocksBittorrent is a convenience used by the xray generator.
func (c AppConfig) BlocksBittorrent() bool {
	for _, p := range c.BlockProtocols {
		if p == "bittorrent" {
			return true
		}
	}
	return false
}

// Load reads and parses the config file.
func Load(path string) (AppConfig, error) {
	var c AppConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

// Save writes the config atomically with 0600 perms (it holds secrets).
func Save(path string, c AppConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
