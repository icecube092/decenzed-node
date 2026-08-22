package traffic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeDeltasNormal(t *testing.T) {
	d := ComputeDeltas(Snapshot{"a": {Up: 100, Down: 200}}, Snapshot{"a": {Up: 150, Down: 260}})
	assert.Equal(t, Counter{Up: 50, Down: 60}, d["a"])
}

func TestComputeDeltasNewUUID(t *testing.T) {
	d := ComputeDeltas(Snapshot{}, Snapshot{"b": {Up: 10, Down: 20}})
	assert.Equal(t, Counter{Up: 10, Down: 20}, d["b"], "new uuid counts from zero")
}

// The critical case: xray restarted and its counter reset to a small value.
func TestComputeDeltasCounterReset(t *testing.T) {
	d := ComputeDeltas(Snapshot{"a": {Up: 1000, Down: 2000}}, Snapshot{"a": {Up: 30, Down: 0}})
	assert.Equal(t, uint64(30), d["a"].Up, "reset -> current is the delta, not an underflow")
	assert.Equal(t, uint64(0), d["a"].Down)
}

func TestComputeDeltasNoChange(t *testing.T) {
	d := ComputeDeltas(Snapshot{"a": {Up: 5, Down: 5}}, Snapshot{"a": {Up: 5, Down: 5}})
	assert.Zero(t, d["a"].Total())
}

func TestBuildReportOmitsZeroAndSorts(t *testing.T) {
	deltas := Snapshot{
		"c": {Up: 1, Down: 0},
		"a": {Up: 0, Down: 0}, // omitted
		"b": {Up: 2, Down: 3},
	}
	r := BuildReport("node1", 7, time.Unix(1000, 0), deltas)
	require.Len(t, r.Items, 2, "zero-delta item omitted")
	assert.Equal(t, "b", r.Items[0].UUID)
	assert.Equal(t, "c", r.Items[1].UUID)
	assert.Equal(t, uint64(7), r.EpochID)
	assert.Equal(t, int64(1000), r.TS)
	assert.Equal(t, "node1", r.NodeID)
}

func TestReportSigningBytesDeterministic(t *testing.T) {
	deltas := Snapshot{"a": {Up: 1, Down: 2}, "b": {Up: 3, Down: 4}}
	b1, _ := BuildReport("n", 1, time.Unix(5, 0), deltas).SigningBytes()
	b2, _ := BuildReport("n", 1, time.Unix(5, 0), deltas).SigningBytes()
	assert.Equal(t, b1, b2, "signing bytes must be deterministic")
}
