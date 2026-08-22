// Package quota implements the node operator's MONTHLY traffic limit
// (NODE-CLI §config quota). This is the operator capping how much of their home
// line to donate; it is SEPARATE from per-subscription client quotas, which the
// root server enforces via budgets pushed in heartbeats.
package quota

import "time"

// Accountant tracks cumulative traffic within the current billing period and
// reports whether the node should be PAUSED because the monthly limit is hit.
//
// The period resets on a configurable day-of-month. limitBytes == 0 means
// UNLIMITED.
type Accountant struct {
	limitBytes  uint64
	resetDay    int
	used        uint64
	periodStart time.Time
}

// New builds an accountant. resetDay is clamped to 1..28 so the boundary exists
// in every month (Feb has no 29–31).
func New(limitBytes uint64, resetDay int) *Accountant {
	if resetDay < 1 {
		resetDay = 1
	}
	if resetDay > 28 {
		resetDay = 28
	}
	return &Accountant{limitBytes: limitBytes, resetDay: resetDay}
}

// periodStartFor returns 00:00 of the most recent reset-day boundary at or
// before now. If today's day-of-month is >= resetDay, the boundary is THIS
// month's reset day; otherwise it's the PREVIOUS month's reset day.
func periodStartFor(now time.Time, resetDay int) time.Time {
	y, m, d := now.Date()
	loc := now.Location()
	if d >= resetDay {
		return time.Date(y, m, resetDay, 0, 0, 0, 0, loc)
	}
	// Step back one month. Anchor on day 1 first to avoid day-overflow
	// surprises (e.g. Mar 31 -> Feb), then place the reset day.
	prev := time.Date(y, m, 1, 0, 0, 0, 0, loc).AddDate(0, -1, 0)
	return time.Date(prev.Year(), prev.Month(), resetDay, 0, 0, 0, 0, loc)
}

// rollover resets the accumulator if a new period has begun since the last call.
func (a *Accountant) rollover(now time.Time) {
	ps := periodStartFor(now, a.resetDay)
	if a.periodStart.IsZero() {
		a.periodStart = ps
		return
	}
	if ps.After(a.periodStart) {
		a.periodStart = ps
		a.used = 0
	}
}

// Add records consumed bytes at time now (rolling the period over first) and
// returns the used total for the current period.
func (a *Accountant) Add(now time.Time, bytes uint64) uint64 {
	a.rollover(now)
	a.used += bytes
	return a.used
}

// Paused reports whether the monthly limit has been reached. Unlimited
// (limit == 0) never pauses. Rolls the period over first so a fresh period
// un-pauses the node automatically.
func (a *Accountant) Paused(now time.Time) bool {
	a.rollover(now)
	if a.limitBytes == 0 {
		return false
	}
	return a.used >= a.limitBytes
}

// Used returns the bytes consumed in the current period.
func (a *Accountant) Used() uint64 { return a.used }

// Limit returns the monthly limit in bytes (0 = unlimited).
func (a *Accountant) Limit() uint64 { return a.limitBytes }

// PeriodStart returns the start of the current billing period (zero until the
// first Add/Paused call establishes it).
func (a *Accountant) PeriodStart() time.Time { return a.periodStart }
