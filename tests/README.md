# End-to-end tests

Black-box e2e suite for `decenzed-node`. It **builds the real binary**, writes a
config, **runs the node**, connects a **sing-box** client over **VLESS + REALITY +
Vision** (the app's primary protocol), and pushes traffic through the tunnel to
check the main features:

| Test | What it proves | Needs |
| --- | --- | --- |
| `TestNodeStartsAndListens` | the binary starts a VLESS+REALITY node and binds its port | sing-box (keygen) |
| `TestLinkCommands` | `link -l` prints `ss://` + `vless://`; `link add`/`remove` work | — |
| `TestTunnelConnectivity` | HTTP flows client → node → origin over VLESS+REALITY | sing-box + REALITY dest |
| `TestBlacklistFiltering` | a blacklisted domain is blocked, a sibling passes | sing-box + dest + loopback DNS |
| `TestWhitelistFiltering` | only the whitelisted domain passes | sing-box + dest + loopback DNS |
| `TestPrivateIPBlock` | with private-IP block on, a loopback target is unreachable | sing-box + dest |
| `TestSpeedAndCap` | tunnel throughput is measured; the per-user cap roughly holds | sing-box + dest |

This is a **separate Go module** (`decenzed/e2e`, stdlib only) and every file is
behind the `e2e` **build tag**, so the app's own `go test ./...` never runs it.

## Prerequisites

1. **Go** (same toolchain that builds the app) — the suite runs `go build` on
   `../src` itself, so nothing to pre-build.
2. **sing-box** — the VLESS client, and also used to generate the REALITY keypair.
   It is **not** auto-installed: download the build for your OS/arch from
   <https://github.com/sagernet/sing-box/releases> and drop the binary at
   **`tests/bin/sing-box`** (`sing-box.exe` on Windows). `tests/bin/` is gitignored.
   You may instead point **`SINGBOX_BIN`** at a binary elsewhere. **If neither is
   present the tunnel tests FAIL** (with a message telling you where to put it) —
   sing-box is a hard prerequisite, not an optional extra.
3. **A REALITY dest** — REALITY borrows a real TLS 1.3 + HTTP/2 site for its
   handshake, so the tunnel tests need **outbound network** to one. Default
   `www.cloudflare.com:443` (xray-core's REALITY relay completes cleanly with it;
   some big sites like `www.microsoft.com` do **not**). Override with
   **`E2E_REALITY_SNI`**. If the dest is unreachable the tunnel tests **skip**.
4. **DNS to loopback** — only for the two *filtering* tests. They use hostnames
   that must resolve to `127.0.0.1` so the node can dial the local origin. Default
   `*.localtest.me` (a public wildcard pointing at `127.0.0.1` — resolves via
   normal DNS but sends no traffic off-box). If your network can't resolve it, add
   hosts-file entries for `allowed.<base>` / `blocked.<base>` / `other.<base>`
   (all → `127.0.0.1`) and set `E2E_LOOPBACK_DOMAIN=<base>`. These tests **skip**
   automatically if the name doesn't resolve to loopback.
5. **Privileges / ports** — none special. The node runs **unprivileged**
   (`DECENZED_NO_ELEVATE=1` is set for you) and every port is an ephemeral
   `127.0.0.1` port, so nothing is exposed and no firewall/forwarding is needed.
   The data dir is a fresh temp dir per test.

## Does NOT touch a running `decenzed-node` service

Safe to run while your real node service is installed and running:

- Each test uses its **own temp data dir** and **ephemeral `127.0.0.1` ports**, so
  there's no config, stats, log, or port collision with the real install.
- The suite **never** installs / uninstalls / starts / stops / **restarts** the OS
  `decenzed-node` service. The one place the CLI would restart it
  (`link add`/`remove`) is **skipped** because `DECENZED_NO_ELEVATE=1` is set (the
  app skips the service restart under that flag). The only service interaction is a
  **read-only** status query in `stats`, which can't modify or interrupt it.

## Configuration knobs (env vars)

| Var | Default | Meaning |
| --- | --- | --- |
| `SINGBOX_BIN` | `tests/bin/sing-box[.exe]` | path to the sing-box binary |
| `E2E_REALITY_SNI` | `www.cloudflare.com` | REALITY dest (a live TLS1.3+h2 host) |
| `E2E_LOOPBACK_DOMAIN` | `localtest.me` | base domain whose `*.<base>` resolve to `127.0.0.1` |

## Running

```bash
cd tests
# put sing-box in tests/bin first (see Prerequisites #2)

# everything
go test -tags e2e -v ./...

# only the no-client link/format test (doesn't need sing-box or the network)
go test -tags e2e -v -run LinkCommands ./...

# a single tunnel test with a custom dest
E2E_REALITY_SNI=www.apple.com go test -tags e2e -v -run TestTunnelConnectivity ./...
```

Use `-count=1` to bypass the test cache. Because every tunnel connection does a
real REALITY handshake with the dest, throughput numbers are handshake-bound (tens
of Mbit/s), not a raw loopback figure — the speed test only checks that traffic
flows and that the per-user cap roughly holds.

## What it does NOT cover (and why)

- **TLS-camouflage tunnel + hosted subscription.** The TLS mode needs a real
  Let's Encrypt certificate for a public domain, so it isn't run end-to-end here;
  its link/subscription output is checked in `TestLinkCommands` and its inbound is
  booted by the app's `internal/xrayrt` unit tests.
- **geosite/geoip category filtering.** These would download the multi-MB `.dat`
  files; the filtering tests use plain `domain:` rules instead. The download +
  cache logic is unit-tested in `internal/geodata` and `internal/domainlist`.

## How it works

`decenzed-node` (VLESS+REALITY inbound) ← REALITY ← **sing-box** (SOCKS inbound) ←
the test's `http.Client` (dials through SOCKS, so the **node** resolves the target
— which is what lets domain filtering apply). sing-box also generates the REALITY
keypair the node and client share. A local `httptest` origin on `127.0.0.1` is the
destination; `AllowPrivateIP` is on for the connectivity/speed/filtering configs so
the loopback origin is reachable (and off on purpose in `TestPrivateIPBlock`).
