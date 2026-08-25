# decenzed-node — run your own proxy, share links with friends

[![tests](https://github.com/icecube092/decenzed-node/actions/workflows/tests.yml/badge.svg)](https://github.com/icecube092/decenzed-node/actions/workflows/tests.yml)
[![version](https://img.shields.io/github/v/release/icecube092/decenzed-node?sort=semver)](https://github.com/icecube092/decenzed-node/releases)
[![license](https://img.shields.io/github/license/icecube092/decenzed-node)](LICENSE)

`decenzed-node` is a **standalone** VLESS + REALITY proxy server you run on your
own machine (Windows, macOS, Linux). It scans for a camouflage domain, generates
its own REALITY keys, runs an embedded xray-core, and prints **share links** you
hand to friends. There is **no coordination server** — it's fully self-contained
and open source.

## 1. Requirements
- A **public IP** (static or dynamic). If the machine is on a home LAN, forward
  its port on the router. **CGNAT is not supported** (some ISPs / mobile put you
  behind carrier NAT — inbound connections can't reach you).
- If the node runs on a **desktop/laptop behind a home router**, give that
  machine a **fixed LAN IP via a DHCP reservation** (bind its MAC to one address
  in your router's DHCP settings). Otherwise its LAN IP can change on reboot/lease
  renewal and your port-forward will silently point at the wrong device.
- Open/forward one TCP port (default **443**; you can pick **8443**).
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
decenzed-node setup   # network check + port 8443 (443 is taken by LuCI) + REALITY + keys,
                      # then installs the procd boot service as its last step
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

VLESS+REALITY is always on. `setup` also lets you optionally enable **Trojan**
(same REALITY camouflage, no XTLS flow) and **Shadowsocks-2022**
(`2022-blake3-aes-128-gcm`, no TLS masking — a distinct, less-stealthy traffic
type). One TCP port hosts one protocol, so each enabled protocol needs its **own
forwarded port**. `decenzed-node link` prints a share link + sing-box outbound
for every enabled protocol, per client. Per-user speed caps and traffic stats
apply across all of them (each client is metered by a single identity regardless
of which protocol it connects with). On OpenWRT open the extra WAN ports with
`PORT="8443 9443" ./install-openwrt.sh` (space- or comma-separated).

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

It then **scans for a REALITY camouflage domain** (a live TLS 1.3 + HTTP/2 site
near you), **generates your REALITY keypair**, creates your first client, writes
the xray config, and — as its **final step** — offers to **install & start the
boot service** (needs admin/root). It prints your first share link at the end.

## 5. Check a running node
```bash
decenzed-node check
```
Run this once the node is up (setup installs the service for you). It shows your
public IP, runs a speed test, refreshes your DuckDNS record, and dials **back to
your own domain/IP** on the node port to confirm the **running service** is
reachable from outside. If the self-check passes it stops there; if it can't
confirm reachability it prints **port-forward** instructions to fix. (A serving
machine mostly uploads, so ≥10 Mbit/s upload is recommended; the loopback
self-check may fail from inside your own LAN even when forwarding is correct —
test from mobile data to be sure.)

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
decenzed-node link                 # print share links for all clients
decenzed-node link add alice       # create a client for a friend, print their link
decenzed-node link remove alice    # revoke a friend
```
Each client is a separate `vless://…` link (paste into nekobox, v2rayN/NG,
Hiddify, sing-box, …). Removing a client revokes just that friend. Adding/removing
reloads the service automatically.

## 8. Monitor & tune
```bash
decenzed-node stats                # traffic totals, load, run status
decenzed-node logs                 # daemon log
decenzed-node config node|xray     # inspect app-config / generated xray JSON
decenzed-node update               # download the latest release and restart
```
**To change any setting, re-run `decenzed-node setup`** — it re-asks every field
with the current value as the default and rebuilds `xray.json`. You never edit
xray JSON by hand.

## Notes
- **Per-user speed cap** is enforced by a small throttle proxy in front of xray
  (keyed by client source IP) — application-level, no OS/tc config.
- Data lives next to the binary in `decenzed-data/` so the CLI and the service
  (which may run as a different user) share the same files.
- Uninstall the service: `decenzed-node service uninstall`.

## License

This project is licensed under the GNU Affero General Public License v3.0.
See the LICENSE file for the full license text.

## Support

<a href="https://ko-fi.com/icecube092" target="_blank">
  <img src="https://storage.ko-fi.com/cdn/kofi3.png?v=3" alt="Buy Me a Coffee at ko-fi.com" height="36">
</a>