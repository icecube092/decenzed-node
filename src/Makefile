# decenzed-node build/test. Requires a POSIX shell (Git Bash / WSL / macOS / Linux).
BINARY  := decenzed-node
PKG     := ./cmd/decenzed-node
DIST    := dist
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# GOOS/GOARCH targets to cross-compile for.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build build-win build-test build-test-win test vet fmt clean cross cross-openwrt publish-bin $(PLATFORMS)

## build: native build for the host platform (production Let's Encrypt CA)
build:
	go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(PKG)

## build-win: Windows amd64 PRODUCTION binary (trusted Let's Encrypt CA)
build-win:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY).exe $(PKG)

## build-test: native TEST build (Let's Encrypt STAGING CA via -tags staging)
build-test:
	go build -tags staging -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-staging $(PKG)

## build-test-win: Windows amd64 TEST binary (staging CA) — for local testing
build-test-win:
	GOOS=windows GOARCH=amd64 go build -tags staging -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-staging.exe $(PKG)

## test: run all unit tests
test:
	go test ./...

## vet: static checks
vet:
	go vet ./...

## fmt: format
fmt:
	go fmt ./...

## all: verify + cross-compile everything
all: vet test cross

## cross: build every platform in PLATFORMS into dist/
cross: $(PLATFORMS)

$(PLATFORMS):
	@os=$(word 1,$(subst /, ,$@)); arch=$(word 2,$(subst /, ,$@)); \
	ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	echo "==> $$os/$$arch"; \
	GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)-$$os-$$arch$$ext $(PKG)

## publish-bin: cross-compile client binaries into ../bin (win/mac/linux) for committing
publish-bin:
	@mkdir -p ../bin
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		echo "==> $(BINARY) $$os/$$arch -> ../bin"; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o ../bin/$(BINARY)-$$os-$$arch$$ext $(PKG); \
	done

# OpenWRT router build matrix, mirrors .github/workflows/release-node.yml.
# Each token is name:GOOS:GOARCH:EXTRA_ENV:MANIFEST_KEY (empty EXTRA = "::").
OPENWRT_TARGETS := \
	linux-amd64:linux:amd64::linux_amd64 \
	linux-arm64:linux:arm64::linux_arm64 \
	linux-armv7:linux:arm:GOARM=7:linux_armv7 \
	linux-armv6:linux:arm:GOARM=6:linux_armv6 \
	linux-armv5:linux:arm:GOARM=5:linux_armv5 \
	linux-mips-softfloat:linux:mips:GOMIPS=softfloat:linux_mips_softfloat \
	linux-mipsle-softfloat:linux:mipsle:GOMIPS=softfloat:linux_mipsle_softfloat \
	linux-mips64le:linux:mips64le::linux_mips64le \
	linux-mips64:linux:mips64::linux_mips64

## cross-openwrt: build OpenWRT router binaries (arm64/armv7/mipsel/…) into dist/
cross-openwrt:
	@set -e; mkdir -p $(DIST); \
	for t in $(OPENWRT_TARGETS); do \
		name=$${t%%:*}; rest=$${t#*:}; goos=$${rest%%:*}; rest=$${rest#*:}; \
		goarch=$${rest%%:*}; rest=$${rest#*:}; extra=$${rest%%:*}; key=$${rest##*:}; \
		echo "==> decenzed-node-$$name (key=$$key)"; \
		env $$extra GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 \
			go build -trimpath \
			-ldflags "$(LDFLAGS) -X decenzed/node_app/internal/selfupdate.VariantKey=$$key" \
			-o $(DIST)/decenzed-node-$$name ./cmd/decenzed-node; \
	done

## clean: remove build artifacts
clean:
	rm -rf $(DIST)
