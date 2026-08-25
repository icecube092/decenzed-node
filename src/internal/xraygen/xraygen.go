// Package xraygen compiles the high-level operator app-config into an xray-core
// JSON configuration (NODE-CLI §5 "Конфиг → xray"). The operator never edits
// xray JSON directly; this is the single place that maps policy onto xray
// inbound / routing / policy. Structs mirror xray-core's config schema
// approximately — extend field-by-field as more of xray is exercised.
//
// The node can expose several protocols at once, each as its own inbound on its
// own port (one port hosts one protocol): VLESS+REALITY, Trojan+REALITY, and
// Shadowsocks-2022. All inbounds share the same routing / policy / stats, and
// every client is keyed by the same email (its UUID) so per-user stats aggregate
// across whichever protocol(s) that user connects with.
package xraygen

import (
	"encoding/json"
	"strings"
)

// Input is the subset of app-config relevant to xray generation.
type Input struct {
	// Inbounds is the ordered list of listeners to emit (VLESS first, by
	// convention). At least one is expected.
	Inbounds []InboundSpec

	// Shared routing / policy (applies to every inbound).
	BlockBittorrent bool
	DomainAllow     []string // if non-empty: allow ONLY these, block the rest
	DomainDeny      []string // always blocked
	StatsEnabled    bool     // per-user stats for metering
	Debug           bool     // verbose xray logging (loglevel "debug" vs "warning")
}

// InboundSpec describes one listener to generate.
type InboundSpec struct {
	Protocol   string       // config.ProtoVLESS | ProtoTrojan | ProtoShadowsocks
	Port       int          // listen port
	ListenAddr string       // "" = all interfaces; "127.0.0.1" when behind the throttle proxy
	Clients    []ClientCred // per-user credentials

	// REALITY camouflage — set for VLESS/Trojan when Camouflage=reality.
	// Mutually exclusive with TLS.
	Reality *RealitySpec

	// TLS camouflage — set for VLESS/Trojan when Camouflage=tls: the node
	// terminates real TLS (Let's Encrypt cert) and falls back to its own website.
	// Mutually exclusive with Reality; nil for Shadowsocks.
	TLS *TLSSpec

	// Shadowsocks-2022 only.
	SSMethod    string
	SSServerKey string
}

// ClientCred is one user's credential for an inbound. Which field is used
// depends on the protocol: ID for VLESS (with Vision flow), Password for Trojan
// and Shadowsocks (the SS per-user PSK). Email keys the per-user stats counter
// and is the client's UUID for every protocol.
type ClientCred struct {
	ID       string
	Password string
	Email    string
}

// RealitySpec carries the REALITY camouflage parameters shared by the REALITY
// inbounds.
type RealitySpec struct {
	Dest     string   // e.g. "www.microsoft.com:443"
	Names    []string // serverNames the node impersonates
	PrivKey  string
	ShortIDs []string
}

// TLSSpec carries the real-TLS camouflage parameters shared by the VLESS/Trojan
// inbounds when the node masquerades behind its own website. The inbound
// terminates TLS with a real (Let's Encrypt) certificate and, on any non-proxy
// or bad-credential traffic, falls back to the local site at FallbackDest.
//
// CertFile/KeyFile MUST be file paths (not inline PEM) so xray-core hot-reloads
// them on renewal without a restart (transport/internet/tls setupOcspTicker,
// hourly). Do not enable oneTimeLoading.
type TLSSpec struct {
	ServerName   string // the node's own domain (cert CN/SAN)
	CertFile     string // path to fullchain PEM
	KeyFile      string // path to private key PEM
	FallbackDest string // "127.0.0.1:8080" or a unix socket path
}

// ---- xray-core config schema (minimal subset) ----

type Config struct {
	Log       *logCfg     `json:"log,omitempty"`
	Inbounds  []inbound   `json:"inbounds"`
	Outbounds []outbound  `json:"outbounds"`
	Routing   *routingCfg `json:"routing,omitempty"`
	Policy    *policyCfg  `json:"policy,omitempty"`
	Stats     *struct{}   `json:"stats,omitempty"`
}

type logCfg struct {
	Loglevel string `json:"loglevel"`
}

type inbound struct {
	Tag            string          `json:"tag"`
	Listen         string          `json:"listen,omitempty"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
	Sniffing       *sniffing       `json:"sniffing,omitempty"`
}

type streamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`
	TLSSettings     *tlsSettings     `json:"tlsSettings,omitempty"`
}

type realitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
}

type tlsSettings struct {
	ServerName   string        `json:"serverName,omitempty"`
	ALPN         []string      `json:"alpn,omitempty"`
	Certificates []certificate `json:"certificates"`
}

// certificate uses file paths (not inline PEM) so xray hot-reloads on renewal.
type certificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

type sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type outbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
}

type routingCfg struct {
	DomainStrategy string `json:"domainStrategy"`
	Rules          []rule `json:"rules"`
}

// rule mirrors xray's field-matcher rule. Only the fields we emit are present.
type rule struct {
	Type        string   `json:"type"`
	Protocol    []string `json:"protocol,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type policyCfg struct {
	Levels map[string]policyLevel `json:"levels"`
	System policySystem           `json:"system"`
}

type policyLevel struct {
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
}

type policySystem struct {
	StatsInboundUplink   bool `json:"statsInboundUplink"`
	StatsInboundDownlink bool `json:"statsInboundDownlink"`
}

// Generate builds the xray Config from Input.
//
// Routing rules are ORDER-SENSITIVE (xray evaluates top-to-bottom, first match
// wins). We emit them in this order:
//  1. deny domains        -> block
//  2. bittorrent protocol -> block
//  3. allow domains       -> direct         (only if an allow-list is set)
//  4. default             -> block          (only if an allow-list is set;
//     with an allow-list the policy is "allow only these", so everything not
//     explicitly allowed must be blocked)
//
// Without an allow-list the default is permissive (allow all except deny/bt).
func Generate(in Input) *Config {
	loglevel := "warning"
	if in.Debug {
		loglevel = "debug"
	}
	cfg := &Config{
		Log: &logCfg{Loglevel: loglevel},
		Outbounds: []outbound{
			{Tag: "direct", Protocol: "freedom"},
			{Tag: "block", Protocol: "blackhole"},
		},
		Routing: &routingCfg{DomainStrategy: "AsIs"},
	}

	for _, spec := range in.Inbounds {
		cfg.Inbounds = append(cfg.Inbounds, buildInbound(spec))
	}

	var rules []rule
	if len(in.DomainDeny) > 0 {
		rules = append(rules, rule{Type: "field", Domain: in.DomainDeny, OutboundTag: "block"})
	}
	if in.BlockBittorrent {
		rules = append(rules, rule{Type: "field", Protocol: []string{"bittorrent"}, OutboundTag: "block"})
	}
	if len(in.DomainAllow) > 0 {
		rules = append(rules, rule{Type: "field", Domain: in.DomainAllow, OutboundTag: "direct"})
		// allow-list mode => block everything not explicitly allowed
		rules = append(rules, rule{Type: "field", Network: "tcp,udp", OutboundTag: "block"})
	}
	cfg.Routing.Rules = rules

	if in.StatsEnabled {
		cfg.Stats = &struct{}{}
		cfg.Policy = &policyCfg{
			Levels: map[string]policyLevel{"0": {StatsUserUplink: true, StatsUserDownlink: true}},
			System: policySystem{StatsInboundUplink: true, StatsInboundDownlink: true},
		}
	}
	return cfg
}

// buildInbound renders one protocol listener. Sniffing is enabled on every
// inbound so routing can match the real protocol/destination even though the
// client tunnels it — required to block bittorrent and to apply domain rules.
// InboundTag is the stable xray inbound tag for a protocol (and, for
// Shadowsocks, its cipher variant). Tags MUST be unique across inbounds, so the
// two Shadowsocks variants differ by a "2022" suffix. xray's per-inbound stats
// counters key off these tags ("inbound>>>{tag}>>>traffic>>>...").
func InboundTag(protocol, ssMethod string) string {
	if protocol == "shadowsocks" && strings.HasPrefix(ssMethod, "2022-") {
		return "shadowsocks2022-in"
	}
	return protocol + "-in"
}

func buildInbound(spec InboundSpec) inbound {
	ib := inbound{
		Tag:      InboundTag(spec.Protocol, spec.SSMethod),
		Listen:   spec.ListenAddr,
		Port:     spec.Port,
		Protocol: spec.Protocol,
		Settings: buildSettings(spec),
		Sniffing: &sniffing{Enabled: true, DestOverride: []string{"http", "tls", "quic"}},
	}
	switch {
	case spec.Reality != nil:
		ib.StreamSettings = &streamSettings{
			Network:  "tcp",
			Security: "reality",
			RealitySettings: &realitySettings{
				Dest:        spec.Reality.Dest,
				ServerNames: spec.Reality.Names,
				PrivateKey:  spec.Reality.PrivKey,
				ShortIds:    spec.Reality.ShortIDs,
			},
		}
	case spec.TLS != nil:
		// alpn MUST be set when fallbacks have child elements, and the local site
		// speaks HTTP/1.1 (see xtls fallback docs).
		ib.StreamSettings = &streamSettings{
			Network:  "tcp",
			Security: "tls",
			TLSSettings: &tlsSettings{
				ServerName: spec.TLS.ServerName,
				ALPN:       []string{"http/1.1"},
				Certificates: []certificate{
					{CertificateFile: spec.TLS.CertFile, KeyFile: spec.TLS.KeyFile},
				},
			},
		}
	}
	return ib
}

// buildSettings renders the protocol-specific "settings" object.
func buildSettings(spec InboundSpec) json.RawMessage {
	var m map[string]any
	switch spec.Protocol {
	case "vless":
		clients := make([]map[string]any, 0, len(spec.Clients))
		for _, cl := range spec.Clients {
			// email == UUID so xray's per-user stats counter is keyed by the UUID
			// ("user>>>{email}>>>traffic>>>..."), which the runtime looks up.
			clients = append(clients, map[string]any{"id": cl.ID, "flow": "xtls-rprx-vision", "email": cl.Email})
		}
		m = map[string]any{"clients": clients, "decryption": "none"}
		addFallback(m, spec.TLS)
	case "trojan":
		// Trojan has no XTLS flow (Vision is VLESS-only); it rides REALITY plain
		// or real TLS. In TLS mode it falls back to the local website (Trojan's
		// original design), same as VLESS.
		clients := make([]map[string]any, 0, len(spec.Clients))
		for _, cl := range spec.Clients {
			clients = append(clients, map[string]any{"password": cl.Password, "email": cl.Email})
		}
		m = map[string]any{"clients": clients}
		addFallback(m, spec.TLS)
	case "shadowsocks":
		clients := make([]map[string]any, 0, len(spec.Clients))
		if strings.HasPrefix(spec.SSMethod, "2022-") {
			// SS-2022 multi-user: server-wide key + per-user PSK on each client.
			for _, cl := range spec.Clients {
				clients = append(clients, map[string]any{"password": cl.Password, "email": cl.Email})
			}
			m = map[string]any{"method": spec.SSMethod, "password": spec.SSServerKey, "clients": clients, "network": "tcp,udp"}
		} else {
			// Classic AEAD multi-user: each client carries its own method+password
			// (xray reads the cipher per client for non-2022 ciphers).
			for _, cl := range spec.Clients {
				clients = append(clients, map[string]any{"method": spec.SSMethod, "password": cl.Password, "email": cl.Email})
			}
			m = map[string]any{"clients": clients, "network": "tcp,udp"}
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// addFallback appends the default (catch-all) fallback to the local website when
// the inbound is in TLS mode. With no path/alpn it catches every request that
// isn't valid proxy traffic — the masquerade. Requires the inbound's TLS to set
// alpn (done in buildInbound).
func addFallback(m map[string]any, tls *TLSSpec) {
	if tls == nil || tls.FallbackDest == "" {
		return
	}
	m["fallbacks"] = []map[string]any{{"dest": tls.FallbackDest}}
}

// JSON renders the config as indented xray-core JSON.
func (c *Config) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
