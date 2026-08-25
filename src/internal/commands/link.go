package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"decenzed/node_app/internal/config"
)

func cmdLink(args []string) error {
	path, _ := configPath()
	c, err := config.Load(path)
	if err != nil || c.RealityPublicKey == "" {
		return fmt.Errorf("run 'setup' first")
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "", "list":
		printLinks(c)
		return nil
	case "add":
		name := ""
		if len(args) > 1 {
			name = strings.Join(args[1:], " ")
		}
		uuid, uErr := newUUID()
		if uErr != nil {
			return uErr
		}
		c.Clients = append(c.Clients, config.Client{UUID: uuid, Name: name})
		if err := saveAndReload(path, c); err != nil {
			return err
		}
		cl := config.Client{UUID: uuid, Name: name}
		host := linkHost(c)
		fmt.Println("added client — share the link(s) below:")
		printClient(c, cl, host)
		return nil
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: link remove <name|uuid>")
		}
		key := strings.Join(args[1:], " ")
		kept := c.Clients[:0]
		removed := 0
		for _, cl := range c.Clients {
			if cl.UUID == key || cl.Name == key {
				removed++
				continue
			}
			kept = append(kept, cl)
		}
		if removed == 0 {
			return fmt.Errorf("no client matching %q", key)
		}
		c.Clients = kept
		if err := saveAndReload(path, c); err != nil {
			return err
		}
		fmt.Printf("removed %d client(s); the service was reloaded.\n", removed)
		return nil
	default:
		return fmt.Errorf("usage: link [list] | link add [name] | link remove <name|uuid>")
	}
}

// saveAndReload persists the config, rebuilds xray.json, and best-effort
// restarts the service so a client change takes effect immediately.
func saveAndReload(path string, c config.AppConfig) error {
	if err := config.Save(path, c); err != nil {
		return err
	}
	if err := writeXrayConfig(path, c); err != nil {
		return err
	}
	if svc, err := newService(); err == nil {
		_ = svc.Restart() // no-op / error if not installed — ignored
	}
	return nil
}

func printLinks(c config.AppConfig) {
	if len(c.Clients) == 0 {
		fmt.Println("  (no clients — run 'link add')")
		return
	}
	host := linkHost(c)
	if host == "" {
		fmt.Println("  ! could not determine public IP; set it in 'setup'")
	}
	for _, cl := range c.Clients {
		printClient(c, cl, host)
	}
}

// printClient prints, for one client, a share link + sing-box outbound for every
// protocol the node exposes (VLESS/Trojan/Shadowsocks).
func printClient(c config.AppConfig, cl config.Client, host string) {
	label := cl.Name
	if label == "" {
		label = cl.UUID[:8]
	}
	for _, ib := range c.PublicInbounds() {
		fmt.Printf("\n  %-12s [%s]  %s\n", label, ib.Protocol, clientLink(c, cl, host, ib))
		fmt.Print("\n  sing-box outbound:\n\n")
		fmt.Println(clientSingbox(c, cl, host, ib))
	}
}

// linkHost is the address that goes in share links: the DuckDNS domain when
// configured (survives IP changes), otherwise the configured/detected public IP.
func linkHost(c config.AppConfig) string {
	if h := c.DuckDNSHost(); h != "" {
		return h
	}
	if c.PublicIP != "" {
		return c.PublicIP
	}
	return fetchPublicIP()
}

// clientLink builds the share link for a client on a specific inbound.
func clientLink(c config.AppConfig, cl config.Client, host string, ib config.Inbound) string {
	switch ib.Protocol {
	case config.ProtoVLESS:
		return vlessLink(c, cl, host, ib.Port)
	case config.ProtoTrojan:
		return trojanLink(c, cl, host, ib.Port)
	case config.ProtoShadowsocks:
		return ssLink(c, cl, host, ib.Port)
	}
	return ""
}

// linkName is the fragment/label used in share links for a client.
func linkName(cl config.Client) string {
	if cl.Name != "" {
		return cl.Name
	}
	return "decenzed"
}

// realityQuery fills the REALITY parameters common to the VLESS and Trojan links.
func realityQuery(c config.AppConfig) url.Values {
	q := url.Values{}
	q.Set("security", "reality")
	q.Set("sni", firstOr(c.RealityServerName))
	q.Set("fp", "chrome")
	q.Set("pbk", c.RealityPublicKey)
	q.Set("sid", first(c.RealityShortIDs))
	q.Set("type", "tcp")
	return q
}

// vlessLink builds a vless:// REALITY+Vision share link.
func vlessLink(c config.AppConfig, cl config.Client, host string, port int) string {
	q := realityQuery(c)
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", cl.UUID, host, port, q.Encode(), url.PathEscape(linkName(cl)))
}

// trojanLink builds a trojan:// REALITY share link (no XTLS flow: Vision is
// VLESS-only). The Trojan password is the client UUID.
func trojanLink(c config.AppConfig, cl config.Client, host string, port int) string {
	q := realityQuery(c)
	return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", cl.UUID, host, port, q.Encode(), url.PathEscape(linkName(cl)))
}

// ssLink builds a SIP002 ss:// share link for Shadowsocks-2022. The userinfo is
// url-safe base64 of "method:serverPSK:userPSK" (the SS-2022 client password is
// serverPSK:userPSK).
func ssLink(c config.AppConfig, cl config.Client, host string, port int) string {
	userinfo := config.SSMethod + ":" + c.SSServerKey + ":" + config.SSUserPSK(cl.UUID)
	enc := base64.RawURLEncoding.EncodeToString([]byte(userinfo))
	return fmt.Sprintf("ss://%s@%s:%d#%s", enc, host, port, url.PathEscape(linkName(cl)))
}

// sing-box outbound schema (a subset), so the printed JSON drops straight into a
// sing-box config's "outbounds" array. One struct per supported protocol.
type sbVLESS struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	UUID       string `json:"uuid"`
	Flow       string `json:"flow"`
	Network    string `json:"network"`
	TLS        sbTLS  `json:"tls"`
}

type sbTrojan struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Network    string `json:"network"`
	TLS        sbTLS  `json:"tls"`
}

type sbShadowsocks struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
}

type sbTLS struct {
	Enabled    bool      `json:"enabled"`
	ServerName string    `json:"server_name"`
	Reality    sbReality `json:"reality"`
	UTLS       sbUTLS    `json:"utls"`
}

type sbReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type sbUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

// clientSingbox renders a client as a ready-to-paste sing-box outbound for a
// specific inbound protocol (same credentials as the corresponding share link).
func clientSingbox(c config.AppConfig, cl config.Client, host string, ib config.Inbound) string {
	var ob any
	switch ib.Protocol {
	case config.ProtoVLESS:
		ob = sbVLESS{
			Type: "vless", Tag: singboxTag(cl), Server: host, ServerPort: ib.Port,
			UUID: cl.UUID, Flow: "xtls-rprx-vision", Network: "tcp", TLS: realityTLS(c),
		}
	case config.ProtoTrojan:
		ob = sbTrojan{
			Type: "trojan", Tag: singboxTag(cl), Server: host, ServerPort: ib.Port,
			Password: cl.UUID, Network: "tcp", TLS: realityTLS(c),
		}
	case config.ProtoShadowsocks:
		ob = sbShadowsocks{
			Type: "shadowsocks", Tag: singboxTag(cl), Server: host, ServerPort: ib.Port,
			Method: config.SSMethod, Password: c.SSServerKey + ":" + config.SSUserPSK(cl.UUID),
		}
	default:
		return ""
	}
	b, err := json.MarshalIndent(ob, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// realityTLS builds the shared sing-box REALITY TLS block (VLESS/Trojan).
func realityTLS(c config.AppConfig) sbTLS {
	return sbTLS{
		Enabled:    true,
		ServerName: firstOr(c.RealityServerName),
		Reality:    sbReality{Enabled: true, PublicKey: c.RealityPublicKey, ShortID: first(c.RealityShortIDs)},
		UTLS:       sbUTLS{Enabled: true, Fingerprint: "chrome"},
	}
}

// singboxTag is the outbound "tag": the client's name, or "decenzed" if unnamed.
func singboxTag(cl config.Client) string {
	if cl.Name != "" {
		return cl.Name
	}
	return "decenzed"
}
