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
	svc, err := newService()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: service install|uninstall|start|stop|status")
	}
	switch args[0] {
	case "install":
		c, cErr := loadConfig()
		if cErr != nil || c.RealityPublicKey == "" {
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

// cmdUpdate downloads the latest release for this platform, replaces the running
// binary, and restarts the background service so the new version takes effect.
func cmdUpdate() error {
	url := config.DefaultUpdateManifestURL()
	if url == "" {
		return fmt.Errorf("updates are not configured for this build")
	}
	fmt.Println("checking for updates...")
	applied, ver, err := selfupdate.CheckAndApply(context.Background(), Version, url)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if !applied {
		fmt.Printf("already up to date (%s)\n", Version)
		return nil
	}
	fmt.Printf("installed %s — restarting the service...\n", ver)
	if svc, sErr := newService(); sErr == nil {
		if rErr := svc.Restart(); rErr != nil {
			fmt.Println("  ! could not restart the service automatically:", rErr)
			fmt.Println("    restart it yourself with: decenzed-node service restart")
			return nil
		}
		fmt.Println("service restarted — now running", ver)
	} else {
		fmt.Println("  ! the new binary is in place; restart the node to apply it.")
	}
	return nil
}
