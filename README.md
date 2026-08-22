# decenzed-node — run your own proxy, share links with friends

`decenzed-node` is a **standalone** VLESS + REALITY proxy server you run on your
own machine (Windows, macOS, Linux). It scans for a camouflage domain, generates
its own REALITY keys, runs an embedded xray-core, and prints **share links** you
hand to friends. There is **no coordination server** — it's fully self-contained
and open source.

## 1. Requirements
- A **public IP** (static or dynamic). If the machine is on a home LAN, forward
  its port on the router. **CGNAT is not supported** (some ISPs / mobile put you
  behind carrier NAT — inbound connections can't reach you).
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

## 3. How to run it
- **Interactive shell** — double-click the `.exe` (Windows) or run with no
  arguments. A prompt opens where you type commands; it stays open until `exit`.
- **One command** — `decenzed-node <command>`.
- **Service** — once installed, it runs in the background on boot.

## 4. Check your machine
```bash
decenzed-node check
```
Shows your public IP, runs a speed test, and prints step-by-step **port-forward**
instructions for your router. Fix forwarding/firewall until friends can reach the
port. (A serving machine mostly uploads, so ≥10 Mbit/s upload is recommended.)

## 5. Setup
```bash
decenzed-node setup
```
A wizard asks (Enter for the default):
- **Port** (443 / 8443 / custom).
- **Monthly traffic limit** (default: unlimited) + **reset day**.
- **Blocked protocols** (default `bittorrent`).
- **Per-user speed cap** (default 10 Mbit/s).
- **Public IP** (blank = auto-detect for links).

Then it automatically **scans for a REALITY camouflage domain** (a live TLS 1.3 +
HTTP/2 site near you), **generates your REALITY keypair**, creates your first
client, and writes the xray config. It prints your first share link at the end.

## 6. Run it in the background
```bash
decenzed-node service install     # enable autostart + start now (needs admin/root)
decenzed-node service status
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
decenzed-node stats                # traffic totals, quota, load, run status
decenzed-node logs                 # daemon log
decenzed-node config node|xray     # inspect app-config / generated xray JSON
```
**To change any setting, re-run `decenzed-node setup`** — it re-asks every field
with the current value as the default and rebuilds `xray.json`. You never edit
xray JSON by hand.

## Notes
- **Per-user speed cap** is enforced by a small throttle proxy in front of xray
  (keyed by client source IP) — application-level, no OS/tc config.
- **Auto-update** (optional): if `internal/config/update_manifest.txt` points at
  a GitHub Release manifest, the service checks it at start and every 6h and
  self-updates (checksum-verified); it takes effect on the next restart.
- Data lives next to the binary in `decenzed-data/` so the CLI and the service
  (which may run as a different user) share the same files.
- Uninstall the service: `decenzed-node service uninstall`.

## License

This project is licensed under the GNU Affero General Public License v3.0.
See the LICENSE file for the full license text.