# decenzed-node build/test. Requires a POSIX shell (Git Bash / WSL / macOS / Linux).
BINARY  := decenzed-node
PKG     := ./cmd/decenzed-node
DIST    := dist
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# GOOS/GOARCH targets to cross-compile for.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build test vet fmt clean cross publish-bin $(PLATFORMS)

## build: native build for the host platform
build:
	go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) $(PKG)

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

## clean: remove build artifacts
clean:
	rm -rf $(DIST)
