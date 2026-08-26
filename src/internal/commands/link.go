package commands

import (
	"encoding/base64"
	"encoding/json"
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
	case "", "list", "-l", "-s":
		printLinks(c, linkMode(sub))
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
		fmt.Println("added client — share the link(s) below:")
		printClient(c, cl, linkHost(c), modeLinks)
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
		return fmt.Errorf("usage: link [-l|-s] | link add [name] | link remove <name|uuid>")
	}
}

// linkView selects how much detail `link` prints per client.
type linkView int

const (
	modeDefault linkView = iota // subscription (TLS) or per-protocol links (REALITY)
	modeLinks                   // + one line per per-protocol connection link
	modeSingbox                 // + a sing-box outbound per protocol
)

func linkMode(sub string) linkView {
	switch sub {
	case "-l":
		return modeLinks
	case "-s":
		return modeSingbox
	default:
		return modeDefault
	}
}

// saveAndReload persists the config, rebuilds xray.json, and restarts the
// service so the change (e.g. a new client's subscription) takes effect
// immediately — a subscription doesn't work until the running node reloads it.
func saveAndReload(path string, c config.AppConfig) error {
	if err := config.Save(path, c); err != nil {
		return err
	}
	if err := writeXrayConfig(path, c); err != nil {
		return err
	}
	if err := restartService(); err != nil {
		fmt.Println("  ! could not restart the service automatically:", err)
		fmt.Println("    apply the change with: decenzed-node service restart")
	}
	return nil
}

func printLinks(c config.AppConfig, mode linkView) {
	if len(c.Clients) == 0 {
		fmt.Println("  (no clients — run 'link add')")
		return
	}
	host := linkHost(c)
	if host == "" {
		fmt.Println("  ! could not determine public IP; set it in 'setup'")
	}
	for _, cl := range c.Clients {
		printClient(c, cl, host, mode)
	}
}

// printClient prints one client's connection info. In TLS mode a single
// SUBSCRIPTION link (hosted by the node's own website behind xray's TLS
// fallback) is always shown; -l additionally prints every per-protocol link so
// they can be copied individually, and -s prints a sing-box outbound per
// protocol. In REALITY mode there is no hosted subscription, so per-protocol
// links are always shown.
func printClient(c config.AppConfig, cl config.Client, host string, mode linkView) {
	label := cl.Name
	if label == "" {
		label = cl.UUID[:8]
	}
	fmt.Printf("\n  %s\n", label)

	if c.CamouflageTLS() {
		fmt.Printf("    subscription:  %s\n", subscriptionURL(c, cl))
	}
	// Per-protocol links: always in REALITY (no subscription there); in TLS only
	// when the operator asked for them with -l.
	if !c.CamouflageTLS() || mode == modeLinks {
		for _, ib := range c.PublicInbounds() {
			fmt.Printf("    [%-11s] %s\n", protoLabel(ib), clientLink(c, cl, host, ib))
		}
	}
	if mode == modeSingbox {
		for _, ib := range c.PublicInbounds() {
			fmt.Printf("\n    sing-box outbound [%s]:\n%s\n", protoLabel(ib), clientSingbox(c, cl, host, ib))
		}
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
// the site is rebuilt with the new set). The location label, however, can change
// live while the daemon runs (the node moved to a new country): when loc is
// non-nil each lookup reads the current label from it, so a client re-fetching
// its subscription sees the up-to-date "<Location> [<Protocol>]" names.
func subscriptionFunc(c config.AppConfig, loc *locationHolder) site.SubFunc {
	host := c.TLSHost()
	return func(id string) (string, bool) {
		cfg := c
		if loc != nil {
			cfg.Location = loc.get()
		}
		for _, cl := range cfg.Clients {
			if cl.UUID == id {
				return subscriptionBody(cfg, cl, host), true
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

// clientLink builds the share link for a client on a specific inbound. The
// link's display name (the #fragment) is location+protocol, e.g. "RS [VLESS]" —
// so a client importing the subscription sees named, locatable proxies rather
// than the (shared) client name.
func clientLink(c config.AppConfig, cl config.Client, host string, ib config.Inbound) string {
	tag := linkTag(c, ib)
	switch ib.Protocol {
	case config.ProtoVLESS:
		return vlessLink(c, cl, host, ib.Port, tag)
	case config.ProtoTrojan:
		return trojanLink(c, cl, host, ib.Port, tag)
	case config.ProtoShadowsocks:
		return ssLink(c, cl, host, ib.Port, ib.Method, tag)
	}
	return ""
}

// linkTag is the display name for a proxy in the client: "<Location> [<Protocol>]"
// (e.g. "RS [VLESS]"). Location falls back to the node profile name when unset.
func linkTag(c config.AppConfig, ib config.Inbound) string {
	loc := c.Location
	if loc == "" {
		loc = c.ProfileName()
	}
	return loc + " [" + protoDisplay(ib) + "]"
}

// protoDisplay is the human-facing protocol name used in proxy tags.
func protoDisplay(ib config.Inbound) string {
	switch ib.Protocol {
	case config.ProtoVLESS:
		return "VLESS"
	case config.ProtoTrojan:
		return "Trojan"
	case config.ProtoShadowsocks:
		if config.IsSS2022(ib.Method) {
			return "SS-2022"
		}
		return "Shadowsocks"
	}
	return ib.Protocol
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
func vlessLink(c config.AppConfig, cl config.Client, host string, port int, tag string) string {
	q := camouflageQuery(c)
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", cl.UUID, host, port, q.Encode(), url.PathEscape(tag))
}

// trojanLink builds a trojan:// share link (REALITY or TLS). No XTLS flow: Vision
// is VLESS-only. The Trojan password is the client UUID.
func trojanLink(c config.AppConfig, cl config.Client, host string, port int, tag string) string {
	q := camouflageQuery(c)
	return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", cl.UUID, host, port, q.Encode(), url.PathEscape(tag))
}

// ssLink builds a SIP002 ss:// share link. The userinfo is url-safe base64 (no
// padding) of "method:password". For SS-2022 the password is serverPSK:userPSK;
// for a classic AEAD cipher it is the client UUID.
func ssLink(c config.AppConfig, cl config.Client, host string, port int, method, tag string) string {
	password := cl.UUID
	if config.IsSS2022(method) {
		password = c.SSServerKey + ":" + config.SSUserPSK(cl.UUID)
	}
	userinfo := method + ":" + password
	enc := base64.RawURLEncoding.EncodeToString([]byte(userinfo))
	return fmt.Sprintf("ss://%s@%s:%d#%s", enc, host, port, url.PathEscape(tag))
}

// --- sing-box outbound (for `link -s`) ---

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
	Enabled    bool       `json:"enabled"`
	ServerName string     `json:"server_name"`
	Reality    *sbReality `json:"reality,omitempty"`
	UTLS       sbUTLS     `json:"utls"`
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

// clientSingbox renders a client as a ready-to-paste sing-box outbound for one
// inbound protocol (same credentials as the corresponding share link). The
// outbound tag is the location+protocol name, like the share link.
func clientSingbox(c config.AppConfig, cl config.Client, host string, ib config.Inbound) string {
	tag := linkTag(c, ib)
	var ob any
	switch ib.Protocol {
	case config.ProtoVLESS:
		ob = sbVLESS{
			Type: "vless", Tag: tag, Server: host, ServerPort: ib.Port,
			UUID: cl.UUID, Flow: "xtls-rprx-vision", Network: "tcp", TLS: camouflageTLS(c),
		}
	case config.ProtoTrojan:
		ob = sbTrojan{
			Type: "trojan", Tag: tag, Server: host, ServerPort: ib.Port,
			Password: cl.UUID, Network: "tcp", TLS: camouflageTLS(c),
		}
	case config.ProtoShadowsocks:
		password := cl.UUID
		if config.IsSS2022(ib.Method) {
			password = c.SSServerKey + ":" + config.SSUserPSK(cl.UUID)
		}
		ob = sbShadowsocks{
			Type: "shadowsocks", Tag: tag, Server: host, ServerPort: ib.Port,
			Method: ib.Method, Password: password,
		}
	default:
		return ""
	}
	b, err := json.MarshalIndent(ob, "    ", "  ")
	if err != nil {
		return ""
	}
	return "    " + string(b)
}

// camouflageTLS builds the sing-box TLS block for VLESS/Trojan — a REALITY block,
// or plain TLS to the node's own domain when masquerading behind its website.
func camouflageTLS(c config.AppConfig) sbTLS {
	if c.CamouflageTLS() {
		return sbTLS{
			Enabled:    true,
			ServerName: c.TLSHost(),
			UTLS:       sbUTLS{Enabled: true, Fingerprint: "chrome"},
		}
	}
	return sbTLS{
		Enabled:    true,
		ServerName: firstOr(c.RealityServerName),
		Reality:    &sbReality{Enabled: true, PublicKey: c.RealityPublicKey, ShortID: first(c.RealityShortIDs)},
		UTLS:       sbUTLS{Enabled: true, Fingerprint: "chrome"},
	}
}
