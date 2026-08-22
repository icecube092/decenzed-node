package throttle

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUnlimitedAlwaysAllows(t *testing.T) {
	assert.True(t, New(0, 0).AllowN(1e9), "rate 0 = unlimited")
}

func TestBurstThenRefillAndCap(t *testing.T) {
	now := time.Unix(0, 0)
	b := newWithClock(100 /* bytes/s */, 100 /* burst */, func() time.Time { return now })

	assert.True(t, b.AllowN(100), "full burst available")
	assert.False(t, b.AllowN(1), "empty after draining burst")

	now = now.Add(500 * time.Millisecond) // +50 tokens
	assert.True(t, b.AllowN(50))
	assert.False(t, b.AllowN(1))

	now = now.Add(10 * time.Second) // refill capped at burst (100), not 1000
	assert.True(t, b.AllowN(100))
	assert.False(t, b.AllowN(1), "must not accrue beyond burst")
}
