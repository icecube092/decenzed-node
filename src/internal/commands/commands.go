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
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"

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

	in := newInput()
	if len(os.Args) < 2 {
		return repl(in)
	}
	return runOneShot(in, os.Args[1:])
}

// runOneShot runs a single command (non-REPL). A Ctrl+D at a prompt exits with
// code 130; Ctrl+C uses the default (process terminates).
func runOneShot(in *input, args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			if r == errEOF || r == errInterrupted {
				fmt.Fprintln(os.Stderr)
				code = 130
				return
			}
			panic(r)
		}
	}()
	if err := dispatch(in, args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func dispatch(in *input, args []string) error {
	switch args[0] {
	case "version":
		fmt.Println("decenzed-node", Version)
	case "check":
		return cmdCheck(in)
	case "setup":
		return cmdSetup(in)
	case "link":
		return cmdLink(args[1:])
	case "start":
		return cmdStart()
	case "service":
		return cmdService(args[1:])
	case "stats":
		return cmdStats()
	case "logs":
		return cmdLogs(args[1:])
	case "debug":
		return cmdDebug(in)
	case "config":
		return cmdConfig(args[1:])
	case "update":
		return cmdUpdate(in)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}

// interactiveCmds take over stdin; in the REPL, entering one prints a mode
// banner and Ctrl+C returns to the shell rather than quitting the CLI.
var interactiveCmds = map[string]bool{"setup": true, "check": true, "debug": true, "logs": true}

// repl is the interactive shell. Ctrl+C cancels the RUNNING command (or, at the
// prompt, is a no-op) instead of exiting; the CLI exits only via 'exit'/'quit'
// or Ctrl+D.
func repl(in *input) int {
	fmt.Println("decenzed-node — self-hosted VLESS proxy")
	usage()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	var mu sync.Mutex
	var cancel context.CancelFunc // non-nil only while a command runs
	go func() {
		for range sig {
			mu.Lock()
			if cancel != nil {
				cancel() // abort the running command
			} else {
				fmt.Print("\n(type 'exit' or press Ctrl-D to quit)\n")
			}
			mu.Unlock()
		}
	}()

	for {
		fmt.Print("\ndecenzed> ")
		line, eof := promptLine(in)
		if eof {
			fmt.Println()
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
		ctx, c := context.WithCancel(context.Background())
		mu.Lock()
		cancel = c
		mu.Unlock()
		in.setContext(ctx)

		runCommand(in, args)

		mu.Lock()
		cancel = nil
		mu.Unlock()
		in.setContext(context.Background())
		c()
	}
}

// promptLine reads a command line at the shell prompt. The prompt uses a
// background context so Ctrl+C never cancels it (the signal loop handles it);
// only Ctrl+D (EOF) ends the shell.
func promptLine(in *input) (line string, eof bool) {
	defer func() {
		if r := recover(); r != nil {
			if r == errEOF {
				eof = true
				return
			}
			panic(r)
		}
	}()
	return in.readLine(), false
}

// runCommand dispatches one command, recovering the Ctrl+C/Ctrl+D unwind so a
// cancelled interactive command drops back to the shell instead of crashing.
func runCommand(in *input, args []string) {
	if interactiveCmds[args[0]] {
		fmt.Printf("— %s (Ctrl+C to return to the shell) —\n", args[0])
	}
	defer func() {
		if r := recover(); r != nil {
			switch r {
			case errInterrupted:
				fmt.Println("\n^C — cancelled, back to the shell")
			case errEOF:
				fmt.Println()
			default:
				panic(r)
			}
		}
	}()
	if err := dispatch(in, args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
}

func usage() {
	fmt.Print(`decenzed-node — run your own proxy, share links with friends

Run with no arguments for an interactive shell. In the shell, Ctrl+C leaves the
current command (back to the prompt); quit with 'exit' or Ctrl+D.
Or run one command: decenzed-node <command>

Getting started:
  1. setup                  Wizard: port, policy, camouflage (REALITY or your
                            own TLS website + Let's Encrypt), keys.
  2. check                  Public IP, speed test, self-reachability, port help.
  3. service install        Run in the background on boot (needs admin/root).
  4. link                   Print your connection link to share.

Commands:
  link [-l|-s]              Show clients: subscription link; -l adds per-protocol
                            links, -s adds sing-box outbounds.
  link add [name]           Create a new client (for a friend) and print its link.
  link remove <name|uuid>   Revoke a client.
  start                     Run in the foreground (instead of the service).
  stats                     Protocols, per-client/per-inbound traffic, run status.
  debug                     Toggle verbose logging (all xray logs to the file).
  config node|xray          Show the app-config / generated xray JSON.
  service install|uninstall|start|stop|restart|status
                            Manage the background service.
  logs [app|xray] [-f]      Show the log; filter by source; -f to follow.
  update                    Check for a newer version; if found, ask to install
                            it, then restart the service and re-launch the CLI.
  version · help · exit
`)
}
