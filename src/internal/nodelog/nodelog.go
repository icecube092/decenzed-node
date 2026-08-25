// Package nodelog is the daemon's logging subsystem. It writes a single log file
// where every line is TAB-separated and tagged by source — "app" for the node's
// own logs and "xray" for the embedded xray-core — so `decenzed-node logs [app|
// xray]` can filter by source. It is built on zap.
//
// The file is size-capped: Rotate truncates it in place once it passes the cap
// (done periodically by the daemon, not on every write, to keep logging cheap).
//
// Layout of a line (ConsoleSeparator = TAB):
//
//	2006-01-02 15:04:05   info   app    node started; 2 client(s)
//	2006-01-02 15:04:05   warning xray  failed to handle mux client connection
package nodelog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Source tags used as the third field of every line.
const (
	SrcApp  = "app"
	SrcXray = "xray"
)

// Logger owns the log file and the app/xray zap loggers.
type Logger struct {
	base       *zap.Logger
	xray       *zap.Logger
	sink       *rotatingSyncer
	restoreStd func()
}

// New opens (creating/appending) the log file at path and wires zap. It also
// redirects the standard library logger into the "app" stream, so existing
// log.Print* calls in the daemon are captured and tagged without changes.
func New(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// O_RDWR (not just O_WRONLY) so Rotate can read the tail it keeps.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	sink := &rotatingSyncer{f: f}

	enc := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		TimeKey:          "T",
		LevelKey:         "L",
		NameKey:          "N",
		MessageKey:       "M",
		EncodeTime:       zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05"),
		EncodeLevel:      zapcore.LowercaseLevelEncoder,
		ConsoleSeparator: "\t",
	})
	// The core accepts every level; verbosity gating (debug on/off) is done by the
	// caller feeding this logger (see xrayrt: it drops xray info/debug when debug
	// mode is off), so nothing debug-related reaches here unless wanted.
	core := zapcore.NewCore(enc, sink, zapcore.DebugLevel)
	base := zap.New(core)

	l := &Logger{
		base: base.Named(SrcApp),
		xray: base.Named(SrcXray),
		sink: sink,
	}
	l.restoreStd = zap.RedirectStdLog(l.base)
	return l, nil
}

// WriteXray records one xray-core log line at the given level ("error"/"warn"/
// "info"/"debug"). Intended as the sink handed to xrayrt.SetLogSink.
func (l *Logger) WriteXray(level, text string) {
	l.xray.Log(parseLevel(level), text)
}

// Rotate trims the log file if it exceeds maxBytes, KEEPING the most recent
// ~half (dropping the oldest lines) so recent history survives. Safe to call
// concurrently with logging (the write path is serialized in the syncer).
func (l *Logger) Rotate(maxBytes int64) { l.sink.Rotate(maxBytes) }

// Close flushes and restores the standard logger.
func (l *Logger) Close() error {
	if l.restoreStd != nil {
		l.restoreStd()
	}
	_ = l.base.Sync()
	return l.sink.Close()
}

func parseLevel(s string) zapcore.Level {
	switch strings.ToLower(s) {
	case "error":
		return zapcore.ErrorLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "debug":
		return zapcore.DebugLevel
	default:
		return zapcore.InfoLevel
	}
}

// rotatingSyncer is a zapcore.WriteSyncer over an *os.File that can truncate the
// file in place. The file is opened O_APPEND, so after a Truncate(0) the next
// write lands at offset 0 — no seek needed. All access is mutex-guarded so a
// Rotate never races a Write.
type rotatingSyncer struct {
	mu sync.Mutex
	f  *os.File
}

func (r *rotatingSyncer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Write(p)
}

func (r *rotatingSyncer) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Sync()
}

// Rotate keeps the most recent ~half of the file when it grows past maxBytes,
// discarding the older prefix. The kept tail is trimmed to the next line
// boundary so no line is cut mid-way. The file is O_APPEND, so after Truncate(0)
// the rewritten tail lands at offset 0 and logging continues after it.
func (r *rotatingSyncer) Rotate(maxBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := r.f.Stat()
	if err != nil || fi.Size() <= maxBytes {
		return
	}
	keep := maxBytes / 2
	if keep <= 0 {
		keep = fi.Size() / 2
	}
	buf := make([]byte, keep)
	n, err := r.f.ReadAt(buf, fi.Size()-keep)
	if err != nil && n == 0 {
		return
	}
	buf = buf[:n]
	// Drop the partial first line so the file starts on a clean boundary.
	if i := bytes.IndexByte(buf, '\n'); i >= 0 && i+1 <= len(buf) {
		buf = buf[i+1:]
	}
	if err := r.f.Truncate(0); err != nil {
		return
	}
	_, _ = r.f.Write(buf)
}

func (r *rotatingSyncer) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
