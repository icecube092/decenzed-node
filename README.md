# decenzed-node — run your own proxy, share links with friends

[![tests](https://github.com/icecube092/decenzed-node/actions/workflows/tests.yml/badge.svg)](https://github.com/icecube092/decenzed-node/actions/workflows/tests.yml)
[![version](https://img.shields.io/github/v/release/icecube092/decenzed-node?sort=semver)](https://github.com/icecube092/decenzed-node/releases)
[![license](https://img.shields.io/github/license/icecube092/decenzed-node)](LICENSE)

`decenzed-node` is a **standalone** VLESS proxy server you run on your own machine
(Windows, macOS, Linux). It runs an embedded xray-core and prints **share links**
you hand to friends. There is **no coordination server** — it's fully
self-contained and open source.

It offers **two camouflage modes** for VLESS/Trojan (you pick one in `setup`):
- **REALITY** (default) — scans for a live third-party TLS 1.3 + HTTP/2 site to
  borrow as cover and generates its own REALITY keys. No domain or certificate of
  your own required.
- **TLS + your own website** — masquerades behind **your own domain**. The website
  is **raised automatically by the node** — you don't create or host anything
  yourself: it serves a small built-in site, obtains a **Let's Encrypt**
  certificate automatically (DNS-01 via DuckDNS, so no port 80 needed), and xray
  falls back to that site on any non-proxy traffic. To a probe or a stray browser
  the node is just an ordinary HTTPS website on your domain. The **same domain**
  doubles as your dynamic-DNS host and the certificate/website host — that's by
  design, nothing separate to set up. Needs a DuckDNS domain.

## 1. Requirements
- A **public IP** (static or dynamic). If the machine is on a home LAN, forward
  its port on the router. **CGNAT is not supported** (some ISPs / mobile put you
  behind carrier NAT — inbound connections can't reach you).
- If the node runs on a **desktop/laptop behind a home router**, give that
  machine a **fixed LAN IP via a DHCP reservation** (bind its MAC to one address
  in your router's DHCP settings). Otherwise its LAN IP can change on reboot/lease
  renewal and your port-forward will silently point at the wrong device.
- Open/forward one TCP port for VLESS (default **443**; you can pick **8443**).
  **One TCP port hosts exactly one protocol** — if you also enable **Trojan**
  and/or **Shadowsocks**, each needs its **own additional** forwarded/opened TCP
  port (e.g. VLESS 8443, Trojan 8444, Shadowsocks 9443).
- Admin/root rights only to install the background **service**.

## 2. Get the binary
Download the prebuilt binary for your OS, or build from source (Go 1.26+):
```bash
cd src
go build -o decenzed-node ./cmd/decenzed-node   # Windows: decenzed-node.exe
```
Put it in a folder you can write to — it keeps its data in a `decenzed-data/`
folder next to the executable (config, xray.json, stats, logs).

### On an OpenWRT router (auto-detects CPU architecture)

You can run the node **on the router itself**. One line installs the correct
binary for your router's CPU (`arm64`, `armv7`, `mipsel`, …) from the latest
release, verifies its SHA-256, and puts `decenzed-node` on your PATH:

```sh
wget -O - https://github.com/icecube092/decenzed-node/releases/latest/download/install-openwrt.sh | sh
```

Then, on the router:

```sh
decenzed-node setup   # network check + port 8443 (443 is taken by LuCI) + camouflage
                      # (REALITY or your own TLS site), then installs the procd boot service
decenzed-node link    # the vless:// link to paste into your client
# later: decenzed-node check   # re-verify the RUNNING node is reachable from outside
```

Notes for routers:
- The binary is **~32 MB**. Devices with only 8–16 MB of flash need USB storage +
  [extroot](https://openwrt.org/docs/guide-user/additional-software/extroot_configuration):
  re-run the installer with `DIR=/mnt/usb`, and/or set
  `DECENZED_DATA=/mnt/usb/decenzed-data` so config/logs live off the flash.
- On OpenWRT the background service is managed by **procd** (`/etc/init.d/decenzed-node`),
  so `service install|status|start|stop|restart` work natively, and `update`
  self-replaces the binary and restarts the service.
- Manual control: `/etc/init.d/decenzed-node {start|stop|restart|status}`; logs via `logread -e decenzed`.

**How it works on a router — where the port points.** The node is a TCP server:
it *listens* on your chosen port (e.g. 8443) on the router, and clients connect
**inbound** to it. What you do to expose that port depends on where the node sits:

- **Node on your main/edge router** (the box that holds the public IP — e.g. a
  Routerich AX3000 as your primary router). The listening port is already on the
  WAN edge; there is nothing to "forward". OpenWRT blocks WAN input by default, so
  the port just has to be **allowed through the firewall** — and the installer
  does this for you: it adds an idempotent `Allow-decenzed-node` rule accepting
  inbound TCP `8443` from WAN. Chose a non-default port? Re-run the installer with
  `PORT=<port>` (or edit that rule in LuCI → Network → Firewall → Traffic Rules).
  To skip the automatic rule entirely, install with `NO_FIREWALL=1`.
- **Node on a router *behind* another router/ISP box.** Forward TCP 8443 on the
  upstream box to this router's LAN IP (Port Forwarding / Virtual Server), exactly
  as `decenzed-node check` prints.

Either way you need a real **public IP**. Behind **CGNAT** (your ISP shares one
IP across many customers) inbound connections can't reach you — ask your ISP for
a public/"white" IP, or front the node with a cheap VPS. `decenzed-node check`
detects CGNAT/private IPs and warns you.

### Extra protocols (Trojan / Shadowsocks)

VLESS is always on. `setup` asks a separate **y/n** question for each optional
protocol:
- **Trojan** — shares VLESS's camouflage (REALITY, or TLS with a fallback to your
  website; no XTLS flow).
- **Shadowsocks** — classic `chacha20-ietf-poly1305`, multi-user. The broadest
  client support; no TLS/REALITY masking (a distinct, less-stealthy traffic type).
- **Shadowsocks-2022** — `2022-blake3-aes-128-gcm`, stronger, but **many clients
  reject it**, so it's offered as a **separate** inbound/port for the clients that
  do accept it. (If a client won't import your Shadowsocks entry, use the classic
  one — or VLESS/Trojan.)

If you answer yes, setup asks for that protocol's **port**, pre-filled with a
**random free** port from a recommended range (Trojan `32000–35000`, Shadowsocks
`35000–38000`); on a re-run your **saved** port is offered as the default, even if
it's currently in use. VLESS keeps `8443`.

**One TCP port hosts one protocol**, so each enabled protocol needs its **own
forwarded/opened port**. `decenzed-node link` prints one **subscription link** per
client (TLS mode) covering every enabled protocol. Per-user speed caps and traffic
stats apply across all of them (each client is metered by a single identity
regardless of which protocol it connects with). On OpenWRT open the extra WAN ports
by re-running the installer with the full list, e.g.
`PORT="8443 33001 36001 36002" ./install-openwrt.sh` (space- or comma-separated).

### Supported architectures

Every release ships prebuilt static binaries (pure Go, `CGO_ENABLED=0`, no libc
dependency — they run on glibc and musl/OpenWRT alike). `install-openwrt.sh`
auto-detects the router's CPU (`uname -m` + ELF endianness) and downloads the
matching one.

**Desktop**

| OS | Asset |
| --- | --- |
| Windows x86-64 | `decenzed-node-windows-amd64.exe` |
| macOS (Intel) | `decenzed-node-darwin-amd64` |
| macOS (Apple Silicon) | `decenzed-node-darwin-arm64` |
| Linux x86-64 | `decenzed-node-linux-amd64` |

**Routers / OpenWRT**

| Asset | Go arch | Typical OpenWRT targets & CPUs |
| --- | --- | --- |
| `decenzed-node-linux-arm64` | arm64 (aarch64) | **Filogic MT798x — Routerich AX3000**, mvebu, ipq807x, bcm27xx |
| `decenzed-node-linux-armv7` | arm, GOARM=7 | ipq40xx, mvebu (32-bit), sunxi, bcm53xx |
| `decenzed-node-linux-armv6` | arm, GOARM=6 | bcm2708 / older ARMv6 |
| `decenzed-node-linux-armv5` | arm, GOARM=5 | kirkwood / older ARMv5 |
| `decenzed-node-linux-mipsle-softfloat` | mipsle, softfloat | ramips (mt7620/mt76x8), rt305x — most budget routers |
| `decenzed-node-linux-mips-softfloat` | mips, softfloat | ath79, lantiq (big-endian MIPS) |
| `decenzed-node-linux-mips64le` | mips64le | octeon / newer 64-bit MIPS (LE) |
| `decenzed-node-linux-mips64` | mips64 | 64-bit MIPS (BE) |
| `decenzed-node-linux-amd64` | amd64 | x86_64 routers & VMs |
| `decenzed-node-linux-386` | 386 | legacy x86 |

MIPS builds use `GOMIPS=softfloat` because router SoCs have no FPU. If your device
isn't covered, open an issue with the output of `uname -m` and
`. /etc/openwrt_release; echo "$DISTRIB_TARGET"`.

## 3. How to run it
- **Interactive shell** — double-click the `.exe` (Windows) or run with no
  arguments. A prompt opens where you type commands; it stays open until `exit`.
- **One command** — `decenzed-node <command>`.
- **Service** — once installed, it runs in the background on boot.

## 4. Setup
```bash
decenzed-node setup
```
The wizard starts with a **network readiness check**, in order:
1. Detects your **public IP** (warns if it looks like CGNAT).
2. Asks which **TCP port** to forward, then prints step-by-step **port-forward**
   instructions for your router.
3. **Self-checks** that port from your public IP (it spins up a temporary
   listener, since the node isn't running yet).
4. Runs a **speed test**.

Then it asks the policy questions — press **Enter** to keep the value shown in
`[brackets]`, or type **`no`** to clear/disable it:
- **Blocked protocols** (default `bittorrent`; `no` = block none).
- **Per-user speed cap** (default 50 Mbit/s; `no` = unlimited).
- **DuckDNS token** (optional; keeps a stable domain pointed at your IP). With a
  token it also asks for the **subdomain** you created on
  [duckdns.org](https://www.duckdns.org) — DuckDNS does **not** auto-create it, so
  sign in, add a subdomain, and enter its label without `.duckdns.org`.
- **Public IP** for share links (`no` = auto-detect each time; only asked when
  DuckDNS is off).

Then it asks for the **camouflage mode** (`reality` or `tls`):
- **`reality`** — scans for a REALITY camouflage domain (a live TLS 1.3 + HTTP/2
  site near you) and generates your REALITY keypair.
- **`tls`** — masquerade behind your own website (requires a DuckDNS domain,
  configured just above). It asks the **Let's Encrypt account details**: a contact
  email and acceptance of the Subscriber Agreement, then obtains the certificate
  right away over DNS-01 (so a misconfiguration fails now, not at first start).
  No domain scan is done in this mode.

It then creates your first client, writes the xray config, and — as its **final
step** — offers to **install & start the boot service** (needs admin/root). It
prints your first share link at the end.

> **Testing the TLS mode.** The staging-vs-production Let's Encrypt CA is fixed at
> **build time**. Normal binaries use production; build a test binary with the
> Let's Encrypt **staging** CA (untrusted certs, far higher rate limits) via
> `make build-test` / `make build-test-win`, or `go build -tags staging`.

## 5. Check a running node
```bash
decenzed-node check
```
Run this once the node is up (setup installs the service for you). It shows your
public IP, runs a speed test, refreshes your DuckDNS record, and dials **back to
your own domain/IP** on **every enabled protocol's port** to confirm the **running
service** is reachable from outside; disabled protocols are reported as such. If a
port isn't reachable it prints **port-forward** instructions (listing the ports to
open). (A serving machine mostly uploads, so ≥10 Mbit/s upload is recommended; the
loopback self-check may fail from inside your own LAN even when forwarding is
correct — test from mobile data to be sure.)

## 6. Background service
`setup` already installs and starts the boot service on its last step. To manage
it directly:
```bash
decenzed-node service status
decenzed-node service install     # (re)install + start now (needs admin/root)
decenzed-node service restart     # apply a new binary after 'update'
```
Or run in the foreground for a quick test: `decenzed-node start`.

## 7. Share with friends — the `link` command
```bash
decenzed-node link                 # print the subscription link for all clients
decenzed-node link add alice       # create a client for a friend, print their link
decenzed-node link remove alice    # revoke a friend
```
In **TLS mode** each client gets **one subscription link** —
`https://<your-domain>:<port>/sub/<client-id>` — that you paste into a client
(v2rayN/NG, nekobox, Hiddify, sing-box, …) as a **subscription**. The app fetches
**every enabled protocol** (VLESS/Trojan/Shadowsocks) from it automatically, and
picks up changes on refresh. The subscription is served **by the node's own decoy
website**, behind xray's TLS fallback on your domain — so it needs no extra port
and looks like an ordinary HTTPS request. (In REALITY mode there's no hosted site,
so `link` prints the individual per-protocol links instead.) Removing a client
revokes just that friend. Adding/removing reloads the service automatically.

## 8. Monitor & tune
```bash
decenzed-node stats                # traffic totals, load, run status
decenzed-node logs                 # daemon log
decenzed-node config node|xray     # inspect app-config / generated xray JSON
decenzed-node update               # download the latest release and restart
```
`stats` shows the **enabled protocols** and lifetime traffic broken down two ways:
**per protocol** (across all clients) and **per client** (across all protocols).
xray exposes per-user and per-inbound counters separately but not their cross, so
a full per-protocol-per-client matrix isn't available — these are two independent
breakdowns.
**To change any setting, re-run `decenzed-node setup`** — it re-asks every field
with the current value as the default and rebuilds `xray.json`. You never edit
xray JSON by hand.

## Notes
- **Per-user speed cap** is enforced by a small throttle proxy in front of xray
  (keyed by client source IP) — application-level, no OS/tc config.
- Data lives next to the binary in `decenzed-data/` so the CLI and the service
  (which may run as a different user) share the same files.
- **TLS mode** stores the Let's Encrypt certificate, key, and ACME account key in
  `decenzed-data/` (`cert.pem`, `key.pem`, `account.key`). The node renews the
  certificate automatically (checked daily, renewed ~30 days before expiry) and
  xray hot-reloads it with **no restart** and no dropped connections. The built-in
  decoy website serves on `127.0.0.1` and is reachable only through xray's TLS
  fallback, never directly.
- Uninstall the service: `decenzed-node service uninstall`.

## License

This project is licensed under the GNU Affero General Public License v3.0.
See the LICENSE file for the full license text.

## Support

<a href="https://ko-fi.com/icecube092" target="_blank">
  <img src="https://storage.ko-fi.com/cdn/kofi3.png?v=3" alt="Buy Me a Coffee at ko-fi.com" height="36">
</a>