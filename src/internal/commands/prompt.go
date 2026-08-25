package commands

import (
	"fmt"
	"strconv"
	"strings"

	"decenzed/node_app/internal/bytesize"
)

func ask(r *input, q, def string) string {
	fmt.Printf("%s [%s]: ", q, def)
	line := strings.TrimSpace(r.readLine())
	if line == "" {
		return def
	}
	return line
}

// warnIfBusy prints a non-blocking notice if the port can't be bound right now
// (something else is using it), then returns the port unchanged.
func warnIfBusy(port int) int {
	if !portAvailable(port) {
		fmt.Printf("  ! heads up: TCP %d looks busy on this machine — free it or the node won't bind.\n", port)
	}
	return port
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

// askYesNo asks a yes/no question. Enter keeps the default; a leading 'y' (or
// "yes") is yes, "n"/negative sentinels are no.
func askYesNo(r *input, q string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	v := strings.ToLower(strings.TrimSpace(ask(r, q+" (y/n)", d)))
	if v == "" {
		return def
	}
	if isNo(v) {
		return false
	}
	return strings.HasPrefix(v, "y")
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
