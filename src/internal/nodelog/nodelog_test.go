package nodelog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritesTaggedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	l.WriteXray("warn", "handshake failed")
	l.base.Info("node started") // app stream
	l.Close()

	data, _ := os.ReadFile(path)
	s := string(data)
	if !strings.Contains(s, "\txray\t") || !strings.Contains(s, "handshake failed") {
		t.Errorf("missing tagged xray line:\n%s", s)
	}
	if !strings.Contains(s, "\tapp\t") || !strings.Contains(s, "node started") {
		t.Errorf("missing tagged app line:\n%s", s)
	}
}

func TestRotateKeepsRecentTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Write many lines; oldest carry "OLD", newest carry "NEW".
	for i := 0; i < 400; i++ {
		l.base.Info("OLD line padding padding padding padding padding")
	}
	for i := 0; i < 400; i++ {
		l.base.Info("NEW line padding padding padding padding padding")
	}

	fi, _ := os.Stat(path)
	cap := fi.Size() / 2 // force a rotation to ~half
	l.Rotate(cap)

	data, _ := os.ReadFile(path)
	s := string(data)
	if int64(len(s)) > fi.Size() {
		t.Errorf("file grew after rotate: %d > %d", len(s), fi.Size())
	}
	if !strings.Contains(s, "NEW line") {
		t.Error("recent lines were dropped by rotate")
	}
	// It should start on a clean line boundary (no leading partial line).
	if strings.HasPrefix(s, "line") {
		t.Error("rotate left a partial first line")
	}
}
