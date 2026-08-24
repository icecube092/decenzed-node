// Command decenzed-node is a STANDALONE VLESS + REALITY proxy server you run on
// your own machine. It scans for a camouflage domain, generates its own REALITY
// keys, runs an embedded xray-core, and prints share links you hand to friends.
// There is no coordination server — it is fully self-contained and open source.
//
// This is a thin entrypoint; all command logic lives in internal/commands.
package main

import (
	"os"

	"decenzed/node_app/internal/commands"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	commands.Version = version
	os.Exit(commands.Main())
}
