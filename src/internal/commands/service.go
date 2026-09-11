package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/kardianos/service"

	"decenzed/node_app/internal/config"
	"decenzed/node_app/internal/selfupdate"
)

type program struct{ cancel context.CancelFunc }

func (p *program) Start(_ service.Service) error {
	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())
	go func() {
		if err := runNode(ctx); err != nil {
			log.Println("agent exited:", err)
		}
	}()
	return nil
}
func (p *program) Stop(_ service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

func newService() (service.Service, error) {
	return service.New(&program{}, &service.Config{
		Name:        "decenzed-node",
		DisplayName: "decenzed node",
		Description: "decenzed self-hosted proxy (autostart).",
	})
}

func runAsService() error {
	svc, err := newService()
	if err != nil {
		return err
	}
	return svc.Run()
}

func cmdService(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: service install|uninstall|enable|disable|start|stop|restart|status")
	}
	// OpenWRT/procd systems are managed by a native init script, not kardianos.
	if procdAvailable() {
		return cmdServiceProcd(args)
	}
	svc, err := newService()
	if err != nil {
		return err
	}
	switch args[0] {
	case "install":
		c, cErr := loadConfig()
		if cErr != nil || !c.IsConfigured() {
			return fmt.Errorf("run 'setup' first")
		}
		if err := svc.Install(); err != nil {
			return fmt.Errorf("install service (needs admin/root): %w", err)
		}
		if err := svc.Start(); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		fmt.Println("installed and started — runs on boot. Share with: decenzed-node link")
		return nil
	case "uninstall":
		_ = svc.Stop()
		return svc.Uninstall()
	case "enable":
		if err := setBootStart(svc, true); err != nil {
			return err
		}
		fmt.Println("enabled — the service will start on boot.")
		return nil
	case "disable":
		if err := setBootStart(svc, false); err != nil {
			return err
		}
		fmt.Println("disabled — the service won't start on boot (still runs until stopped).")
		return nil
	case "start":
		return svc.Start()
	case "stop":
		return svc.Stop()
	case "restart":
		return svc.Restart()
	case "status":
		s, sErr := svc.Status()
		if sErr != nil {
			return sErr
		}
		fmt.Println("service status:", statusString(s))
		return nil
	default:
		return fmt.Errorf("service: unknown subcommand %q", args[0])
	}
}

// setBootStart enables (on=true) or disables (on=false) starting the installed
// service at boot, WITHOUT installing or removing it — the counterpart of
// systemd/procd "enable"/"disable". kardianos exposes no portable enable/disable,
// so we drive the underlying init system directly, keyed off svc.Platform().
// OpenWRT/procd is handled separately (cmdServiceProcd) and never reaches here.
func setBootStart(svc service.Service, on bool) error {
	const name = "decenzed-node"
	plat := svc.Platform()
	switch {
	case strings.Contains(plat, "systemd"):
		return runCtl("systemctl", boolPick(on, "enable", "disable"), name)
	case strings.Contains(plat, "windows"):
		// `sc config <svc> start= auto|demand`: the space after "start=" is part of
		// the syntax, so it is passed as its own argument.
		return runCtl("sc", "config", name, "start=", boolPick(on, "auto", "demand"))
	default:
		return fmt.Errorf("service %s: not supported on %q — enable/disable boot start with your init system directly",
			boolPick(on, "enable", "disable"), plat)
	}
}

// runCtl runs an init-system control command, streaming its output.
func runCtl(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// boolPick returns yes when b is true, else no — a tiny ternary for readability.
func boolPick(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// restartService best-effort restarts the background service so a config change
// takes effect immediately. Handles both procd (OpenWRT) and kardianos-managed
// services. Returns an error only if a restart was attempted and failed.
//
// When DECENZED_NO_ELEVATE is set the caller has opted out of admin rights, so a
// restart would only fail (or, on some Windows setups, prompt for elevation) —
// skip it and tell the operator to restart manually. Keeps the e2e suite prompt-
// and-noise-free.
func restartService() error {
	if os.Getenv("DECENZED_NO_ELEVATE") != "" {
		fmt.Println("  (skipping service restart — DECENZED_NO_ELEVATE set; apply with: decenzed-node service restart)")
		return nil
	}
	if procdAvailable() {
		return procdCtl("restart")
	}
	svc, err := newService()
	if err != nil {
		return err
	}
	return svc.Restart()
}

func statusString(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown (not installed?)"
	}
}

// cmdUpdate checks for a newer release and, only after the operator confirms,
// downloads + verifies it, replaces the running binary, restarts the background
// service, and re-launches the CLI so this session runs the new version too.
func cmdUpdate(in *input) error {
	// Update the geosite/geoip data first (only the files actually in use), then
	// the binary itself.
	updateGeodata(in)

	url := config.DefaultUpdateManifestURL()
	if url == "" {
		fmt.Println("binary self-update is not configured for this build.")
		return nil
	}
	fmt.Println("checking for updates...")
	available, ver, asset, err := selfupdate.Check(context.Background(), Version, url)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if !available {
		fmt.Printf("already up to date (%s)\n", Version)
		return nil
	}

	fmt.Printf("update available: %s -> %s\n", Version, ver)
	if !askYesNo(in, "Download and install it now?", true) {
		fmt.Println("skipped — nothing changed.")
		return nil
	}

	fmt.Println("downloading and installing...")
	if err := selfupdate.Apply(context.Background(), asset); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	fmt.Printf("installed %s — restarting the service...\n", ver)
	if rErr := restartService(); rErr != nil {
		fmt.Println("  ! could not restart the service automatically:", rErr)
		fmt.Println("    restart it yourself with: decenzed-node service restart")
	} else {
		fmt.Println("service restarted.")
	}

	// The running CLI still holds the OLD code in memory; re-launch it so this
	// session also runs the new version.
	fmt.Println("re-launching the CLI on the new version...")
	if err := execSelf(); err != nil {
		fmt.Println("  ! could not re-launch automatically:", err)
		fmt.Println("    restart decenzed-node yourself to use the new version.")
	}
	return nil
}
