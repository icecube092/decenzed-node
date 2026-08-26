package commands

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// Control-flow sentinels raised (via panic) from a blocked stdin read so a
// deeply-nested interactive flow (e.g. setup) can unwind back to the shell:
//   - errQuit: the user typed 'q' at a prompt to leave the current command.
//   - errEOF:  stdin closed (Ctrl+D) — exit the CLI.
//
// They are recovered in the REPL / one-shot runner; nothing else should.
var (
	errQuit = &ctlErr{"quit"}
	errEOF  = &ctlErr{"eof"}
)

type ctlErr struct{ s string }

func (e *ctlErr) Error() string { return e.s }

// input is the process's single stdin line source. One goroutine reads lines so
// nothing else competes for stdin.
type input struct {
	lines chan string
	eof   chan struct{}
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
		if err == nil {
			in.lines <- line
			continue
		}
		// Only a real end-of-input (Ctrl+D / closed pipe) ends reading.
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				in.lines <- line // final line without a trailing newline
			}
			close(in.eof)
			return
		}
		// Other errors — notably on Windows, where Ctrl+C aborts the pending
		// console read — must NOT be treated as end-of-input (that would quit the
		// CLI). Discard any partial line and retry. A short sleep avoids a busy
		// loop if it ever persists.
		time.Sleep(50 * time.Millisecond)
	}
}

// readLine returns the next raw stdin line, or panics errEOF on Ctrl+D.
func (in *input) readLine() string {
	select {
	case line := <-in.lines:
		return line
	case <-in.eof:
		panic(errEOF)
	}
}

// answer reads a reply to an interactive prompt: the trimmed line. Typing 'q'
// leaves the current command (panics errQuit); Ctrl+D exits the CLI (errEOF).
func (in *input) answer() string {
	line := strings.TrimSpace(in.readLine())
	if strings.EqualFold(line, "q") {
		panic(errQuit)
	}
	return line
}
