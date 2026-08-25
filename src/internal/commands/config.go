package commands

import (
	"encoding/json"
	"fmt"

	"decenzed/node_app/internal/xraygen"
)

func cmdConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: config node|xray  (to change settings, re-run 'setup')")
	}
	c, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w — run 'setup' first", err)
	}
	switch args[0] {
	case "node":
		b, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(b))
	case "xray":
		b, gErr := xraygen.Generate(inputFromConfig(c)).JSON()
		if gErr != nil {
			return gErr
		}
		fmt.Println(string(b))
	default:
		return fmt.Errorf("unknown config subcommand %q (use: node | xray)", args[0])
	}
	return nil
}
