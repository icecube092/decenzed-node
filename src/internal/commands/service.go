package commands

import (
	"context"
	"fmt"
	"log"

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
		return fmt.Errorf("usage: service install|uninstall|start|stop|status")
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

// restartService best-effort restarts the background service so a config change
// takes effect immediately. Handles both procd (OpenWRT) and kardianos-managed
// services. Returns an error only if a restart was attempted and failed.
func restartService() error {
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
	url := config.DefaultUpdateManifestURL()
	if url == "" {
		return fmt.Errorf("updates are not configured for this build")
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
