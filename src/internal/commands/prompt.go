package commands

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"decenzed/node_app/internal/bytesize"
)

func ask(r *bufio.Reader, q, def string) string {
	fmt.Printf("%s [%s]: ", q, def)
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if err != nil {
			fmt.Println(def)
		}
		return def
	}
	return line
}

var portChoices = []int{443, 8443}

func askPort(r *bufio.Reader, current int) int {
	def := current
	if def == 0 {
		def = portChoices[0]
	}
	fmt.Println("Node port (forward this TCP port on your router):")
	for i, p := range portChoices {
		mark := ""
		if p == def {
			mark = "  <- default"
		}
		fmt.Printf("  %d) %d%s\n", i+1, p, mark)
	}
	fmt.Printf("choose 1-%d, or type a port [%d]: ", len(portChoices), def)
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if err != nil {
			fmt.Println(def)
		}
		return def
	}
	if n, aerr := strconv.Atoi(line); aerr == nil {
		if n >= 1 && n <= len(portChoices) {
			return portChoices[n-1]
		}
		if n >= 1 && n <= 65535 {
			return n
		}
	}
	fmt.Println("  ! invalid — keeping", def)
	return def
}

func parseBandwidth(s string) (float64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "unlimited" || s == "0" {
		return 0, nil
	}
	switch {
	case strings.HasSuffix(s, "gbit"):
		return floatMul(strings.TrimSuffix(s, "gbit"), 1e9/8)
	case strings.HasSuffix(s, "mbit"):
		return floatMul(strings.TrimSuffix(s, "mbit"), 1e6/8)
	case strings.HasSuffix(s, "kbit"):
		return floatMul(strings.TrimSuffix(s, "kbit"), 1e3/8)
	default:
		b, err := bytesize.Parse(s)
		return float64(b), err
	}
}

func formatBandwidth(bps float64) string {
	if bps == 0 {
		return "unlimited"
	}
	return strconv.FormatFloat(bps*8/1e6, 'f', -1, 64) + "mbit"
}

func floatMul(s string, m float64) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return f * m, nil
}

// isNo reports whether the user typed a negative sentinel ("no"/"none"/"off"/
// "-") meaning "leave this empty / disabled".
func isNo(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "no", "none", "off", "-":
		return true
	}
	return false
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- small slice/string helpers ---

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
func firstOr(s []string) string { return first(s) }

func nonZeroF(v, def float64) float64 {
	if v == 0 {
		return def
	}
	return v
}

func orDefault(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}
