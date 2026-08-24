package commands

import (
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
		fmt.Println("added client — share this link:")
		fmt.Println(" ", linkFor(c, cl, host))
		fmt.Println("\nsing-box outbound (paste into your config's \"outbounds\"):")
		fmt.Println(singboxOutbound(c, cl, host))
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
		label := cl.Name
		if label == "" {
			label = cl.UUID[:8]
		}
		fmt.Printf("\n  %-12s %s\n", label, linkFor(c, cl, host))
		fmt.Print("\n  sing-box outbound:\n\n")
		fmt.Println(singboxOutbound(c, cl, host))
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

// linkFor builds a vless:// REALITY+Vision share link for a client.
func linkFor(c config.AppConfig, cl config.Client, publicIP string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", firstOr(c.RealityServerName))
	q.Set("fp", "chrome")
	q.Set("pbk", c.RealityPublicKey)
	q.Set("sid", first(c.RealityShortIDs))
	q.Set("type", "tcp")
	q.Set("flow", "xtls-rprx-vision")
	name := cl.Name
	if name == "" {
		name = "decenzed"
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", cl.UUID, publicIP, c.Port, q.Encode(), url.PathEscape(name))
}

// sing-box outbound schema (a subset of sing-box's vless+REALITY outbound), so
// the printed JSON drops straight into a sing-box config's "outbounds" array.
type sbOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	UUID       string `json:"uuid"`
	Flow       string `json:"flow"`
	Network    string `json:"network"`
	TLS        sbTLS  `json:"tls"`
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

// singboxOutbound renders a client as a ready-to-paste sing-box vless+REALITY
// outbound (same credentials as the vless:// link, JSON form).
func singboxOutbound(c config.AppConfig, cl config.Client, host string) string {
	ob := sbOutbound{
		Type:       "vless",
		Tag:        singboxTag(cl),
		Server:     host,
		ServerPort: c.Port,
		UUID:       cl.UUID,
		Flow:       "xtls-rprx-vision",
		Network:    "tcp",
		TLS: sbTLS{
			Enabled:    true,
			ServerName: firstOr(c.RealityServerName),
			Reality: sbReality{
				Enabled:   true,
				PublicKey: c.RealityPublicKey,
				ShortID:   first(c.RealityShortIDs),
			},
			UTLS: sbUTLS{Enabled: true, Fingerprint: "chrome"},
		},
	}
	b, err := json.MarshalIndent(ob, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// singboxTag is the outbound "tag": the client's name, or "decenzed" if unnamed.
func singboxTag(cl config.Client) string {
	if cl.Name != "" {
		return cl.Name
	}
	return "decenzed"
}
