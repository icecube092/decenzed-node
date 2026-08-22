package bytesize

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
		err  bool
	}{
		{"500GB", 500e9, false},
		{"2TB", 2e12, false},
		{"1.5gb", 1_500_000_000, false},
		{"1500", 1500, false},
		{"unlimited", 0, false},
		{"", 0, false},
		{"0", 0, false},
		{" 100 mb ", 100e6, false},
		{"-5gb", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.err {
			assert.Error(t, err, "Parse(%q)", c.in)
			continue
		}
		require.NoError(t, err, "Parse(%q)", c.in)
		assert.Equal(t, c.want, got, "Parse(%q)", c.in)
	}
}

func TestFormatRoundish(t *testing.T) {
	assert.Equal(t, "unlimited", Format(0))
	assert.Equal(t, "2TB", Format(2e12))
	assert.Equal(t, "500GB", Format(500e9))
}
