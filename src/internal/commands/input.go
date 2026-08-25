package commands

import (
	"bufio"
	"context"
	"io"
	"os"
	"sync"
)

// Control-flow sentinels raised (via panic) from a blocked stdin read so a
// deeply-nested interactive flow (e.g. setup) can unwind back to the shell:
//   - errInterrupted: the running command was cancelled with Ctrl+C.
//   - errEOF:         stdin closed (Ctrl+D) — exit the CLI.
//
// They are recovered in the REPL / one-shot runner; nothing else should.
var (
	errInterrupted = &ctlErr{"interrupted"}
	errEOF         = &ctlErr{"eof"}
)

type ctlErr struct{ s string }

func (e *ctlErr) Error() string { return e.s }

// input is the process's single stdin line source. One goroutine reads lines, so
// a context-cancellable read never leaves a second reader competing for stdin
// (which would happen if each prompt started its own blocking Read).
type input struct {
	lines chan string
	eof   chan struct{}
	mu    sync.Mutex
	ctx   context.Context
}

// newInput reads from os.Stdin.
func newInput() *input { return newInputFrom(os.Stdin) }

// newInputFrom reads from r (used by tests).
func newInputFrom(r io.Reader) *input {
	in := &input{lines: make(chan string), eof: make(chan struct{})}
	go in.loop(bufio.NewReader(r))
	return in
}

func (in *input) loop(r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			in.lines <- line
		}
		if err != nil {
			close(in.eof)
			return
		}
	}
}

// setContext installs the context whose cancellation aborts the current read
// (set per command by the REPL; background at the shell prompt).
func (in *input) setContext(ctx context.Context) {
	in.mu.Lock()
	in.ctx = ctx
	in.mu.Unlock()
}

func (in *input) context() context.Context {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.ctx == nil {
		return context.Background()
	}
	return in.ctx
}

// readLine returns the next stdin line, or panics errInterrupted (Ctrl+C, i.e.
// the current context was cancelled) or errEOF (Ctrl+D).
func (in *input) readLine() string {
	select {
	case line := <-in.lines:
		return line
	case <-in.eof:
		panic(errEOF)
	case <-in.context().Done():
		panic(errInterrupted)
	}
}
