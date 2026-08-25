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
	//   - Trojan shares the same REALITY camouflage as VLESS (no XTLS flow: Vision
	//     is VLESS-only). Its per-client password is the client UUID.
	//   - Shadowsocks uses SS-2022 (2022-blake3-aes-128-gcm) with per-user keys;
	//     it has NO REALITY/TLS masking — it is a distinct, less-stealthy traffic
	//     type. SSServerKey is the server-wide PSK (base64), generated at setup.
	TrojanPort  int    `json:"trojan_port,omitempty"`
	SSPort      int    `json:"ss_port,omitempty"`
	SSServerKey string `json:"ss_server_key,omitempty"`

	// Policy.
	MaxUserBps     float64  `json:"max_user_bps"`    // per-user speed cap (bytes/sec); 0 = off
	BlockProtocols []string `json:"block_protocols"` // e.g. ["bittorrent"]; empty = block nothing
	DomainAllow    []string `json:"domain_allow"`    // if set: allow ONLY these
	DomainDeny     []string `json:"domain_deny"`     // always blocked
	Autostart      bool     `json:"autostart"`

	// REALITY camouflage — dest/serverName chosen at setup by scanning for a
	// live TLS1.3+h2 site; the keypair is generated locally.
	RealityDest       string   `json:"reality_dest"`
	RealityServerName []string `json:"reality_server_names"`
	RealityPrivateKey string   `json:"reality_private_key"`
	RealityPublicKey  string   `json:"reality_public_key"`
	RealityShortIDs   []string `json:"reality_short_ids"`

	// Clients — your own + friends' credentials. Each maps to one share link.
	Clients []Client `json:"clients"`
}

// Protocol identifiers used across the app (xray inbound "protocol" values).
const (
	ProtoVLESS       = "vless"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
)

// SSMethod is the Shadowsocks-2022 AEAD method we use. Its key length is 16
// bytes, so both the server PSK and every per-user PSK are base64 of 16 bytes.
const SSMethod = "2022-blake3-aes-128-gcm"

// ssKeyLen is the raw key length (bytes) for SSMethod.
const ssKeyLen = 16

// NewSSServerKey generates a random Shadowsocks-2022 server PSK (base64).
func NewSSServerKey() (string, error) {
	b := make([]byte, ssKeyLen)
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
	return base64.StdEncoding.EncodeToString(sum[:ssKeyLen])
}

// Inbound is one enabled listener: a protocol on a public TCP port.
type Inbound struct {
	Protocol string
	Port     int
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
		out = append(out, Inbound{Protocol: ProtoShadowsocks, Port: c.SSPort})
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
