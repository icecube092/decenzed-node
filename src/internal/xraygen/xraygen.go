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

import "encoding/json"

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
}

// InboundSpec describes one listener to generate.
type InboundSpec struct {
	Protocol   string       // config.ProtoVLESS | ProtoTrojan | ProtoShadowsocks
	Port       int          // listen port
	ListenAddr string       // "" = all interfaces; "127.0.0.1" when behind the throttle proxy
	Clients    []ClientCred // per-user credentials

	// REALITY camouflage — set for VLESS/Trojan, nil for Shadowsocks.
	Reality *RealitySpec

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
}

type realitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIds    []string `json:"shortIds"`
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
	cfg := &Config{
		Log: &logCfg{Loglevel: "warning"},
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
func buildInbound(spec InboundSpec) inbound {
	ib := inbound{
		Tag:      spec.Protocol + "-in",
		Listen:   spec.ListenAddr,
		Port:     spec.Port,
		Protocol: spec.Protocol,
		Settings: buildSettings(spec),
		Sniffing: &sniffing{Enabled: true, DestOverride: []string{"http", "tls", "quic"}},
	}
	if spec.Reality != nil {
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
	case "trojan":
		// Trojan has no XTLS flow (Vision is VLESS-only); it rides REALITY plain.
		clients := make([]map[string]any, 0, len(spec.Clients))
		for _, cl := range spec.Clients {
			clients = append(clients, map[string]any{"password": cl.Password, "email": cl.Email})
		}
		m = map[string]any{"clients": clients}
	case "shadowsocks":
		clients := make([]map[string]any, 0, len(spec.Clients))
		for _, cl := range spec.Clients {
			clients = append(clients, map[string]any{"password": cl.Password, "email": cl.Email})
		}
		m = map[string]any{"method": spec.SSMethod, "password": spec.SSServerKey, "clients": clients, "network": "tcp,udp"}
	}
	b, _ := json.Marshal(m)
	return b
}

// JSON renders the config as indented xray-core JSON.
func (c *Config) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
