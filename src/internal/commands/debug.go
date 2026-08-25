package commands

import (
	"fmt"

	"decenzed/node_app/internal/config"
)

// cmdDebug toggles debug logging. In debug mode every xray log line (including
// debug/info) is written to the log file; otherwise only warnings and errors
// are. The change is persisted and the service reloaded so it takes effect.
func cmdDebug(r *input) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	c, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("run 'setup' first")
	}

	fmt.Printf("debug mode is currently %s.\n", onOff(c.Debug))
	on := askYesNo(r, "Enable debug mode? (writes ALL xray logs — incl. debug — to the log)", c.Debug)
	if on == c.Debug {
		fmt.Println("no change.")
		return nil
	}

	c.Debug = on
	if err := saveAndReload(path, c); err != nil {
		return err
	}
	fmt.Printf("debug mode %s; service reloaded.\n", onOff(on))
	if on {
		fmt.Println("follow xray logs with:  decenzed-node logs xray -f")
	}
	return nil
}

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}
