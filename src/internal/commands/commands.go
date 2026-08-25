// Package commands implements the decenzed-node CLI: the interactive shell, the
// command dispatch, and every `cmd*` handler (setup, check, link, service,
// start, stats, config, logs, update). The main package is a thin entrypoint
// that injects the build version and calls Main.
//
// decenzed-node is a STANDALONE VLESS + REALITY proxy you run on your own
// machine: it scans for a camouflage domain, generates its own REALITY keys,
// runs an embedded xray-core, and prints share links you hand to friends. There
// is no coordination server — it is fully self-contained and open source.
package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/kardianos/service"
)

// Version is the build version, set by the main package from -ldflags.
var Version = "dev"

// Main is the CLI entrypoint. It returns the process exit code.
func Main() int {
	// Daemon mode: launched by the OS service manager (non-interactive).
	if !service.Interactive() {
		if err := runAsService(); err != nil {
			fmt.Fprintln(os.Stderr, "service error:", err)
			return 1
		}
		return 0
	}

	stdin := bufio.NewReader(os.Stdin)
	if len(os.Args) < 2 {
		return repl(stdin)
	}
	if err := dispatch(stdin, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func dispatch(stdin *bufio.Reader, args []string) error {
	switch args[0] {
	case "version":
		fmt.Println("decenzed-node", Version)
	case "check":
		return cmdCheck(stdin)
	case "setup":
		return cmdSetup(stdin)
	case "link":
		return cmdLink(args[1:])
	case "start":
		return cmdStart()
	case "service":
		return cmdService(args[1:])
	case "stats":
		return cmdStats()
	case "logs":
		return cmdLogs()
	case "config":
		return cmdConfig(args[1:])
	case "update":
		return cmdUpdate()
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}

// repl is the interactive shell: prints help, then reads and runs commands.
func repl(stdin *bufio.Reader) int {
	fmt.Println("decenzed-node — self-hosted VLESS + REALITY proxy")
	usage()
	for {
		fmt.Print("\ndecenzed> ")
		line, err := stdin.ReadString('\n')
		if err != nil {
			return 0
		}
		args := strings.Fields(strings.TrimSpace(line))
		if len(args) == 0 {
			continue
		}
		switch args[0] {
		case "exit", "quit":
			return 0
		case "clear", "cls":
			fmt.Print("\033[H\033[2J")
			continue
		}
		if err := dispatch(stdin, args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
	}
}

func usage() {
	fmt.Print(`decenzed-node — run your own proxy, share links with friends

Run with no arguments for an interactive shell (type commands, 'exit' to quit).
Or run one command: decenzed-node <command>

Getting started:
  1. setup                  Wizard: port, policy, camouflage (REALITY or your
                            own TLS website + Let's Encrypt), keys.
  2. check                  Public IP, speed test, self-reachability, port help.
  3. service install        Run in the background on boot (needs admin/root).
  4. link                   Print your connection link to share.

Commands:
  link [list]               Print share links for all clients.
  link add [name]           Create a new client (for a friend) and print its link.
  link remove <name|uuid>   Revoke a client.
  start                     Run in the foreground (instead of the service).
  stats                     Traffic totals, load, and run status.
  config node|xray          Show the app-config / generated xray JSON.
  service install|uninstall|start|stop|restart|status
                            Manage the background service.
  logs                      Show the daemon log.
  update                    Download the latest version and restart the service.
  version · help · exit
`)
}
