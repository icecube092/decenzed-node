package nodestats

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := Path(filepath.Join(dir, "config.json"))
	if p != filepath.Join(dir, "stats.json") {
		t.Fatalf("Path = %q", p)
	}

	in := Snapshot{
		UpdatedAt:         time.Now().Truncate(time.Second),
		Running:           true,
		ClientsConfigured: 2,
		ActiveClients:     3,
		TotalUp:           100, TotalDown: 250, PeriodUsed: 350,
		MonthlyLimit: 1000, Port: 8443,
	}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if out.ClientsConfigured != in.ClientsConfigured || out.TotalDown != in.TotalDown ||
		out.Running != in.Running || out.Port != in.Port {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}
}

func TestLoadMissingIsNotExist(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist, got %v", err)
	}
}
