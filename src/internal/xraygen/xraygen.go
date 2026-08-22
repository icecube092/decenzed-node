// Package xraygen compiles the high-level operator app-config into an xray-core
// JSON configuration (NODE-CLI §5 "Конфиг → xray"). The operator never edits
// xray JSON directly; this is the single place that maps policy onto xray
// inbound / routing / policy. Structs mirror xray-core's config schema
// approximately — extend field-by-field as more of xray is exercised.
package xraygen

import "encoding/json"

// Input is the subset of app-config relevant to xray generation.
type Input struct {
	Port            int
	ListenAddr      string   // "" = all interfaces; "127.0.0.1" when behind the throttle proxy
	UUIDs           []string // active client credentials
	RealityDest     string   // e.g. "www.microsoft.com:443"
	RealityNames    []string // serverNames the node impersonates
	RealityPrivKey  string
	RealityShortIDs []string
	BlockBittorrent bool
	DomainAllow     []string // if non-empty: allow ONLY these, block the rest
	DomainDeny      []string // always blocked
	StatsEnabled    bool     // per-user stats for metering
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
	clients := make([]map[string]any, 0, len(in.UUIDs))
	for _, id := range in.UUIDs {
		// email == id so xray's per-user stats counter is keyed by the UUID
		// ("user>>>{email}>>>traffic>>>..."), which the runtime looks up.
		clients = append(clients, map[string]any{"id": id, "flow": "xtls-rprx-vision", "email": id})
	}
	settings, _ := json.Marshal(map[string]any{
		"clients":    clients,
		"decryption": "none",
	})

	cfg := &Config{
		Log: &logCfg{Loglevel: "warning"},
		Inbounds: []inbound{{
			Tag:      "in",
			Listen:   in.ListenAddr,
			Port:     in.Port,
			Protocol: "vless",
			Settings: settings,
			StreamSettings: &streamSettings{
				Network:  "tcp",
				Security: "reality",
				RealitySettings: &realitySettings{
					Dest:        in.RealityDest,
					ServerNames: in.RealityNames,
					PrivateKey:  in.RealityPrivKey,
					ShortIds:    in.RealityShortIDs,
				},
			},
			// Sniffing lets routing match the real protocol/destination even
			// though the client tunnels it — required to block bittorrent and
			// to apply domain rules.
			Sniffing: &sniffing{Enabled: true, DestOverride: []string{"http", "tls", "quic"}},
		}},
		Outbounds: []outbound{
			{Tag: "direct", Protocol: "freedom"},
			{Tag: "block", Protocol: "blackhole"},
		},
		Routing: &routingCfg{DomainStrategy: "AsIs"},
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

// JSON renders the config as indented xray-core JSON.
func (c *Config) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
