#!/bin/sh
# decenzed-node installer for OpenWRT routers.
#
# It auto-detects your router's CPU architecture, downloads the matching
# prebuilt binary from the latest GitHub release, verifies its SHA-256 against
# the release manifest, installs it, and puts `decenzed-node` on your PATH.
# It does NOT configure the proxy — after it finishes you run `decenzed-node
# setup` (and `decenzed-node service install` to autostart on boot).
#
# Usage (on the router, as root):
#   wget -O - https://github.com/icecube092/decenzed-node/releases/latest/download/install-openwrt.sh | sh
# or download it and run:  sh install-openwrt.sh
#
# Override defaults with env vars:
#   DIR=/mnt/usb   install location for the binary (default /root)
#   REPO=owner/name  release repo (default icecube092/decenzed-node)
#   VERSION=v1.2.3   install a specific tag instead of latest
set -eu

REPO="${REPO:-icecube092/decenzed-node}"
DIR="${DIR:-/root}"
VERSION="${VERSION:-latest}"
PORT="${PORT:-8443}"   # firewall port to open now; setup/service install re-sync it

say()  { printf '%s\n' "$*"; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- pick a downloader (OpenWRT ships uclient-fetch as wget, or full wget/curl) ---
fetch() { # fetch <url> <outfile>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		err "need curl or wget to download"
	fi
}

# --- detect endianness from the ELF header of a known binary (byte 6: 1=LE 2=BE) ---
is_little_endian() {
	b=$(dd if=/bin/busybox bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
	[ "$b" = "1" ]
}

# --- map CPU to release asset name (must match the CI build matrix) ---
detect_asset() {
	m=$(uname -m)
	case "$m" in
		x86_64|amd64)          echo "decenzed-node-linux-amd64" ;;
		i386|i486|i586|i686|x86) echo "decenzed-node-linux-386" ;;
		aarch64|arm64)         echo "decenzed-node-linux-arm64" ;;
		armv7*)                echo "decenzed-node-linux-armv7" ;;
		armv6*)                echo "decenzed-node-linux-armv6" ;;
		armv5*|armv4*)         echo "decenzed-node-linux-armv5" ;;
		arm)                   echo "decenzed-node-linux-armv7" ;;  # generic 32-bit ARM
		mips64|mips64el)
			if is_little_endian; then echo "decenzed-node-linux-mips64le"
			else echo "decenzed-node-linux-mips64"; fi ;;
		mips|mipsel)
			if is_little_endian; then echo "decenzed-node-linux-mipsle-softfloat"
			else echo "decenzed-node-linux-mips-softfloat"; fi ;;
		*) err "unsupported architecture '$m' — please open an issue with the output of 'uname -m'" ;;
	esac
}

# --- manifest key for a given asset (mirrors selfupdate.platformKey / VariantKey) ---
asset_key() { # strip "decenzed-node-" prefix, turn '-' into '_'
	echo "${1#decenzed-node-}" | tr '-' '_'
}

# open_firewall adds/updates an idempotent WAN-input ACCEPT rule for the node
# port. OpenWRT drops WAN input by default, so the node is unreachable without
# it when it runs on the edge router. Same named rule the app's `service install`
# manages, so re-running either just retargets it. Skip with NO_FIREWALL=1.
open_firewall() {
	[ -n "${NO_FIREWALL:-}" ] && { say "firewall:     skipped (NO_FIREWALL set)"; return 0; }
	command -v uci >/dev/null 2>&1 || { say "firewall:     uci not found — open TCP $PORT yourself"; return 0; }
	name="Allow-decenzed-node"
	sec=$(uci show firewall 2>/dev/null | grep -F ".name='$name'" | head -n1 | cut -d. -f1,2)
	if [ -n "$sec" ]; then
		uci set "$sec.dest_port=$PORT"; uci set "$sec.enabled=1"
	else
		s=$(uci add firewall rule)
		uci set "firewall.$s.name=$name"
		uci set "firewall.$s.src=wan"
		uci set "firewall.$s.proto=tcp"
		uci set "firewall.$s.dest_port=$PORT"
		uci set "firewall.$s.target=ACCEPT"
	fi
	uci commit firewall
	/etc/init.d/firewall reload >/dev/null 2>&1 || true
	say "firewall:     inbound TCP $PORT from WAN allowed (rule '$name')"
}

base_url() {
	if [ "$VERSION" = "latest" ]; then
		echo "https://github.com/${REPO}/releases/latest/download"
	else
		echo "https://github.com/${REPO}/releases/download/${VERSION}"
	fi
}

main() {
	[ "$(id -u)" = "0" ] || err "run as root (needed to install into $DIR and /usr/bin)"

	ASSET=$(detect_asset)
	KEY=$(asset_key "$ASSET")
	URL="$(base_url)"
	say "router arch:  $(uname -m)  ->  $ASSET"
	say "release repo: $REPO ($VERSION)"

	# A private download dir under /tmp (RAM on a router). We remove ONLY this
	# unique subdir on exit — never /tmp itself — to avoid leaving a ~32 MB copy
	# of the binary in RAM after we've installed it to $DIR.
	TMP=$(mktemp -d 2>/dev/null || echo "/tmp/decenzed.$$")
	mkdir -p "$TMP"
	cleanup() { [ -n "${TMP:-}" ] && [ -d "$TMP" ] && rm -rf "$TMP"; }
	trap cleanup EXIT INT TERM

	say "downloading binary..."
	fetch "$URL/$ASSET" "$TMP/decenzed-node" || err "download failed ($URL/$ASSET)"

	# Verify checksum against manifest.json when available (best-effort).
	if fetch "$URL/manifest.json" "$TMP/manifest.json" 2>/dev/null; then
		want=$(sed -n "s/.*\"$KEY\"[^}]*\"sha256\"[[:space:]]*:[[:space:]]*\"\([0-9a-fA-F]\{64\}\)\".*/\1/p" "$TMP/manifest.json" | head -n1)
		if [ -n "$want" ] && command -v sha256sum >/dev/null 2>&1; then
			got=$(sha256sum "$TMP/decenzed-node" | cut -d' ' -f1)
			[ "$got" = "$want" ] || err "checksum mismatch (got $got, want $want)"
			say "checksum ok:  $got"
		else
			say "checksum:     skipped (no entry/sha256sum)"
		fi
	fi

	# Warn if the install partition is tight (the binary is ~32 MB).
	avail_kb=$(df -k "$DIR" 2>/dev/null | awk 'NR==2{print $4}')
	if [ -n "${avail_kb:-}" ] && [ "$avail_kb" -lt 45000 ]; then
		say "! only $((avail_kb/1024)) MB free on $DIR — the binary is ~32 MB."
		say "  If it won't fit, set up extroot/USB and re-run with DIR=/mnt/usb."
	fi

	mkdir -p "$DIR"
	install -m 0755 "$TMP/decenzed-node" "$DIR/decenzed-node" 2>/dev/null \
		|| { cp "$TMP/decenzed-node" "$DIR/decenzed-node" && chmod 0755 "$DIR/decenzed-node"; }
	ln -sf "$DIR/decenzed-node" /usr/bin/decenzed-node

	open_firewall

	say ""
	say "installed: $DIR/decenzed-node  ($("$DIR/decenzed-node" version 2>/dev/null || echo '?'))"
	say "on PATH as: decenzed-node"
	say ""
	say "next steps:"
	say "  1. decenzed-node setup            # pick port 8443, scan REALITY domain, make keys"
	say "  2. decenzed-node service install  # autostart on boot (procd)"
	say "  3. decenzed-node check            # public IP, speed, port-forward help"
	say "  4. decenzed-node link             # print the share link for your phone/friends"
	say ""
	say "notes:"
	say "  - Port 443 is used by LuCI — keep the default 8443 in setup. If you choose a"
	say "    different port, re-run this installer with PORT=<port> to update the firewall"
	say "    (or edit the 'Allow-decenzed-node' rule in LuCI → Firewall → Traffic Rules)."
	say "  - The WAN firewall was opened for TCP $PORT on THIS router. If the node sits"
	say "    behind another router/ISP box, also port-forward TCP $PORT there to this router."
}

main "$@"
