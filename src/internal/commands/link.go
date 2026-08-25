package commands

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/site"
)

func cmdLink(args []string) error {
	path, _ := configPath()
	c, err := config.Load(path)
	if err != nil || !c.IsConfigured() {
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

// printClient prints one client's SUBSCRIPTION link. In TLS mode the subscription
// is hosted by the node's own website (behind xray's TLS fallback): the client
// adds one URL and its app pulls every protocol automatically. In REALITY mode
// there is no hosted site, so the individual per-protocol links are printed
// instead (the same content a subscription would carry).
func printClient(c config.AppConfig, cl config.Client, host string) {
	label := cl.Name
	if label == "" {
		label = cl.UUID[:8]
	}
	if c.CamouflageTLS() {
		fmt.Printf("\n  %-12s subscription:\n    %s\n", label, subscriptionURL(c, cl))
		return
	}
	fmt.Printf("\n  %s\n", label)
	for _, ib := range c.PublicInbounds() {
		fmt.Printf("    [%-11s] %s\n", protoLabel(ib), clientLink(c, cl, host, ib))
	}
}

// protoLabel is a display label for an inbound, distinguishing the two
// Shadowsocks variants (which share the protocol id but differ by cipher).
func protoLabel(ib config.Inbound) string {
	if ib.Protocol == config.ProtoShadowsocks && config.IsSS2022(ib.Method) {
		return "ss-2022"
	}
	return ib.Protocol
}

// subscriptionURL is the per-client subscription address, served by the decoy
// website behind xray's TLS fallback on the node's own domain and VLESS port.
// Paste it into a client (v2rayN/NG, nekobox, Hiddify, sing-box, …) as a
// subscription; the app fetches every protocol link from it.
func subscriptionURL(c config.AppConfig, cl config.Client) string {
	return fmt.Sprintf("https://%s:%d%s%s", c.TLSHost(), c.Port, site.SubPath, cl.UUID)
}

// subscriptionFunc builds the site's subscription lookup: it maps a client id to
// the base64 subscription body carrying that client's per-protocol links. Bound
// to the config the daemon started with (client changes restart the service, so
// the site is rebuilt with the new set).
func subscriptionFunc(c config.AppConfig) site.SubFunc {
	host := c.TLSHost()
	return func(id string) (string, bool) {
		for _, cl := range c.Clients {
			if cl.UUID == id {
				return subscriptionBody(c, cl, host), true
			}
		}
		return "", false
	}
}

// subscriptionBody is the standard subscription payload: the client's protocol
// links, newline-joined and base64-encoded (what subscription-capable clients
// expect to decode).
func subscriptionBody(c config.AppConfig, cl config.Client, host string) string {
	var links []string
	for _, ib := range c.PublicInbounds() {
		if l := clientLink(c, cl, host, ib); l != "" {
			links = append(links, l)
		}
	}
	plain := strings.Join(links, "\n") + "\n"
	return base64.StdEncoding.EncodeToString([]byte(plain))
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
		return ssLink(c, cl, host, ib.Port, ib.Method)
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

// camouflageQuery fills the transport-security parameters common to the VLESS
// and Trojan links: REALITY, or real TLS when the node masquerades behind its
// own website.
func camouflageQuery(c config.AppConfig) url.Values {
	q := url.Values{}
	q.Set("type", "tcp")
	q.Set("fp", "chrome")
	if c.CamouflageTLS() {
		q.Set("security", "tls")
		q.Set("sni", c.TLSHost())
		return q
	}
	q.Set("security", "reality")
	q.Set("sni", firstOr(c.RealityServerName))
	q.Set("pbk", c.RealityPublicKey)
	q.Set("sid", first(c.RealityShortIDs))
	return q
}

// vlessLink builds a vless:// share link (REALITY or TLS) with the Vision flow.
func vlessLink(c config.AppConfig, cl config.Client, host string, port int) string {
	q := camouflageQuery(c)
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", cl.UUID, host, port, q.Encode(), url.PathEscape(linkName(cl)))
}

// trojanLink builds a trojan:// share link (REALITY or TLS). No XTLS flow: Vision
// is VLESS-only. The Trojan password is the client UUID.
func trojanLink(c config.AppConfig, cl config.Client, host string, port int) string {
	q := camouflageQuery(c)
	return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", cl.UUID, host, port, q.Encode(), url.PathEscape(linkName(cl)))
}

// ssLink builds a SIP002 ss:// share link. The userinfo is url-safe base64 (no
// padding) of "method:password". For SS-2022 the password is serverPSK:userPSK;
// for a classic AEAD cipher it is the client UUID.
func ssLink(c config.AppConfig, cl config.Client, host string, port int, method string) string {
	password := cl.UUID
	if config.IsSS2022(method) {
		password = c.SSServerKey + ":" + config.SSUserPSK(cl.UUID)
	}
	userinfo := method + ":" + password
	enc := base64.RawURLEncoding.EncodeToString([]byte(userinfo))
	return fmt.Sprintf("ss://%s@%s:%d#%s", enc, host, port, url.PathEscape(linkName(cl)))
}
