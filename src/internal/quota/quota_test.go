package quota

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 12, 0, 0, 0, time.UTC)
}

func TestAccumulateWithinPeriod(t *testing.T) {
	a := New(1000, 1)
	a.Add(date(2026, time.March, 5), 400)
	require.Equal(t, uint64(700), a.Add(date(2026, time.March, 10), 300))
	assert.False(t, a.Paused(date(2026, time.March, 10)))
}

func TestPauseAtLimit(t *testing.T) {
	a := New(1000, 1)
	a.Add(date(2026, time.March, 5), 1000)
	assert.True(t, a.Paused(date(2026, time.March, 6)))
}

func TestResetOnResetDay(t *testing.T) {
	a := New(1000, 15)
	a.Add(date(2026, time.March, 20), 900) // period started Mar 15
	require.Equal(t, uint64(900), a.Used())

	// Crossing into the next period (Apr 15) resets the counter.
	assert.False(t, a.Paused(date(2026, time.April, 16)), "new period must reset")
	assert.Equal(t, uint64(0), a.Used())
	require.Equal(t, uint64(100), a.Add(date(2026, time.April, 16), 100))
}

func TestUnlimitedNeverPauses(t *testing.T) {
	a := New(0, 1)
	a.Add(date(2026, time.March, 5), 1<<40)
	assert.False(t, a.Paused(date(2026, time.March, 5)))
}

func TestPeriodStartForBeforeResetDay(t *testing.T) {
	ps := periodStartFor(date(2026, time.March, 10), 15)
	assert.Equal(t, time.February, ps.Month())
	assert.Equal(t, 15, ps.Day())
}

func TestResetDayClamped(t *testing.T) {
	assert.Equal(t, 28, New(100, 31).resetDay)
}
