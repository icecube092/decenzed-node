// Package bytesize parses and formats human data sizes used in the operator
// onboarding (monthly limit, bandwidth). Units are DECIMAL (GB = 1e9), matching
// how ISP data caps are advertised. "unlimited"/"" parse to 0, which everywhere
// in decenzed-node means "no limit".
package bytesize

import (
	"fmt"
	"strconv"
	"strings"
)

var units = []struct {
	suffix string
	mult   float64
}{
	{"tb", 1e12}, {"gb", 1e9}, {"mb", 1e6}, {"kb", 1e3}, {"b", 1},
}

// Parse turns "500GB", "2 TB", "1.5gb", "1500", "unlimited" into bytes.
func Parse(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "unlimited" || s == "0" {
		return 0, nil
	}
	// Longest suffix first so "tb" is matched before "b".
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			num := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("bytesize: bad number %q", num)
			}
			if f < 0 {
				return 0, fmt.Errorf("bytesize: negative size")
			}
			return uint64(f * u.mult), nil
		}
	}
	// No unit: treat as raw bytes.
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("bytesize: unrecognized size %q", s)
	}
	return uint64(f), nil
}

// Format renders bytes as a compact human string (0 -> "unlimited").
func Format(b uint64) string {
	if b == 0 {
		return "unlimited"
	}
	f := float64(b)
	for _, u := range units {
		if f >= u.mult {
			return strconv.FormatFloat(f/u.mult, 'f', -1, 64) + strings.ToUpper(u.suffix)
		}
	}
	return strconv.FormatUint(b, 10) + "B"
}
