# Running a decenzed node on your computer

`decenzed-node` turns your machine into a **proxy node**: it runs an embedded
xray-core server, applies your policy (bandwidth / blocked protocols / domains /
monthly traffic cap) and talks to the coordination server. Works on **Windows,
macOS, Linux**.

## 1. Requirements
- A **public IP** on your router — static, or dynamic (the DNS is updated for
  you). If your node is a LAN device, forward its port on the router.
  **CGNAT is not supported** (mobile / some ISPs put you behind carrier NAT —
  then inbound connections can't reach you).
- Open/forward the node port (default **443**; you can set another in setup).
- Admin/root rights only for **autostart** (installing the OS service).

> `decenzed-node check` tells you whether your machine qualifies.

## How to run it
- **Interactive shell** — double-click the `.exe` (Windows) or run it with **no
  arguments**. A prompt opens (`decenzed>`) where you type the commands below;
  the window stays open until you type `exit`. This is the easiest way to
  onboard the node.
- **One command** — from a terminal: `decenzed-node <command>` (e.g.
  `decenzed-node setup`). Good for scripts.
- **Daemon** — once enabled (`install` / on boot) the node runs in the
  background automatically and polls root every minute; the shell/CLI is only
  for configuring it.

### The onboarding flow (run in order)
The four steps are **gated** — each refuses to run until the previous one
completed, and the node remembers how far you got:

```
check  →  setup  →  register  →  install
```

The commands below work the same in the shell or as one-shot arguments.

## 2. Get the binary
**Download** the prebuilt binary for your OS (from the project's distribution)


## 3. Check your machine (step 1)
```bash
decenzed-node check
```
Shows your public IP and whether inbound connections reach you. Fix port
forwarding / firewall until it says the host is suitable — only then does it
record the pass and let `setup` run.

## 4. First-run setup (step 2, interactive)
```bash
decenzed-node setup
```
A wizard asks (press Enter for the default, hints shown):
- **Node port** — the inbound TCP port to forward on your router.
- **Monthly traffic limit** — how much of your connection to donate (default:
  unlimited). e.g. `500GB`, `2TB`.
- **Reset day** of the month (default 1) — match your ISP's billing day.
- **Blocked protocols** (default `bittorrent`) — reduces abuse/liability.
- **Bandwidth cap** — total node speed (default: unlimited).
- **Location** — auto-detected; you can correct it.
- **Payout wallet** — where earnings are paid.
- **Autostart on boot** (default yes).

Then setup automatically:
- **Scans for a REALITY camouflage domain** — it probes the IP neighbourhood of
  your server (the /24 around your public IP) for real sites that speak TLS 1.3 +
  HTTP/2, so the borrowed site is network-close and plausible; if none turn up it
  falls back to a curated seed list. Domains are **unique per node** (checked
  against root), and the chosen one is pinged to confirm it's alive.
- **Generates your REALITY keypair** locally (the private key never leaves your
  machine) and **builds the xray-core config** (`xray.json`) — there is no
  separate "generate" step.

Config is saved **next to the binary**, in a `decenzed-data/` folder beside the
`decenzed-node` executable (config.json, xray.json, stats.json, reports/). This
is so the background service — which may run as a different OS user — reads the
exact same files as your CLI. Put the binary in a folder you can write to.

## 5. Register with the network (step 3)
```bash
decenzed-node register
```
Registration **asks only for your email** — everything else (location, bandwidth,
payout wallet, REALITY public key + domain) comes from the config `setup` built.
Sends your node for approval. Operators are **added manually by an admin**, so
your node starts serving traffic only after it's approved.

**Registration is one-time.** It's keyed to a stable per-machine device id, so
`register` only works once; running it again just prints your node's status and
the data you entered (contact, wallet, location). To change any of that
afterwards, **contact support** — it can't be re-registered from the CLI.

## 6. Install & run (step 4)
```bash
decenzed-node install     # enable autostart + start now (needs admin/root once)
```
This installs the background service and starts it. From then on the node runs
on boot and **polls root every minute** for its status and the set of clients it
may serve — it begins carrying traffic automatically once an admin approves it.
Uptime feeds your reputation and payouts.

To run in the foreground instead (e.g. for a quick test):
```bash
decenzed-node start
```

## 7. Monitor & tune
```bash
decenzed-node stats               # traffic totals, monthly quota, root status
decenzed-node service status      # is the daemon running?
decenzed-node config show         # inspect the current app-config
```
`stats` reads a snapshot the running daemon writes every ~30s (lifetime up/down,
this period's usage vs your monthly limit, current root status / clients /
reputation). If the daemon isn't running it shows the last snapshot marked
**stale**.
**To change any setting (port, bandwidth, quota, protocols, location, or the
REALITY domain): re-run `decenzed-node setup`** — it re-asks every field with the
current value as the default (keeping your domain if it's still valid) and
**rebuilds `xray.json`** for you. You never edit xray JSON by hand; there is no
`config generate`. Restart the service to apply.

The **root server address is baked into the binary** at build time
(`internal/config/root_endpoint.txt`) — setup does not ask for it.

## Notes
- **Per-user speed cap (10 Mbit/s):** the node runs a small throttle proxy on
  your public port that forwards to xray on a loopback port, capping each client
  (keyed by source IP) to 10 Mbit/s per direction. This is application-level (no
  router/OS config). xray-core has no native per-user limit, and neither does
  3x-ui (quota only) — this proxy adds it. Fair-share is also enforced by root
  assigning at most `bandwidth ÷ 5 Mbit/s` clients per node.
- **Auto-update:** the daemon checks a baked-in release manifest at start and
  every 6h; a newer, checksum-verified binary is installed and takes effect on
  the next restart.
- **Domain lists:** the node applies root's signed base allow-list, fetched at
  start and refreshed hourly (not per heartbeat), and hot-reloads xray.
- The node reports its public IP implicitly (root reads it from your signed
  heartbeat), so you don't configure DNS or your IP manually.
- Reaching a full serving state needs the coordination server + admin approval.
  `check` and `setup` (including the domain scan) work standalone for verifying
  your machine before that.
- Uninstall the service: `decenzed-node service uninstall`.
