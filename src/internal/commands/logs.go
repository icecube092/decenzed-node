package commands

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"
)

// cmdLogs prints the daemon log. Usage:
//
//	logs               all sources, last chunk
//	logs app | xray    only the app's or xray's lines
//	logs -f            follow (stream new lines until ctrl+c)
//
// Lines are TAB-separated "<time>\t<level>\t<src>\t<message>" (see nodelog); the
// src field drives the app|xray filter.
func cmdLogs(args []string) error {
	src, follow, err := parseLogsArgs(args)
	if err != nil {
		return err
	}
	path, perr := configPath()
	if perr != nil {
		return perr
	}
	logPath := logFilePath(path)

	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no logs yet — run 'service install' (or 'start') first")
		}
		return err
	}
	defer f.Close()

	// Print the existing tail (filtered), then remember where we stopped.
	data, _ := os.ReadFile(logPath)
	offset := int64(len(data))
	printTail(data, src, logsTail)

	if !follow {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Println("-- following log (ctrl+c to stop) --")

	var leftover []byte
	for {
		select {
		case <-ctx.Done():
			fmt.Println() // clean line after ^C
			return nil
		default:
		}
		fi, statErr := f.Stat()
		if statErr != nil {
			return statErr
		}
		if fi.Size() < offset { // file was rotated/truncated — restart from top
			offset, leftover = 0, nil
		}
		if fi.Size() > offset {
			chunk := make([]byte, fi.Size()-offset)
			n, _ := f.ReadAt(chunk, offset)
			offset += int64(n)
			leftover = printStream(append(leftover, chunk[:n]...), src)
		} else {
			time.Sleep(400 * time.Millisecond)
		}
	}
}

// logsTail is how many recent lines `logs` prints before following/returning.
const logsTail = 200

func parseLogsArgs(args []string) (src string, follow bool, err error) {
	for _, a := range args {
		switch a {
		case "-f", "--follow":
			follow = true
		case "app", "xray":
			src = a
		default:
			return "", false, fmt.Errorf("usage: logs [app|xray] [-f]")
		}
	}
	return src, follow, nil
}

// printTail prints the last `max` lines of data that match src.
func printTail(data []byte, src string, max int) {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var kept []string
	for _, ln := range lines {
		if lineMatches(ln, src) {
			kept = append(kept, ln)
		}
	}
	if len(kept) > max {
		kept = kept[len(kept)-max:]
	}
	if len(kept) > 0 {
		fmt.Println(strings.Join(kept, "\n"))
	}
}

// printStream prints complete matching lines from buf and returns any trailing
// partial line (bytes after the last newline) to be prepended next time.
func printStream(buf []byte, src string) []byte {
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			return buf
		}
		line := string(buf[:i])
		buf = buf[i+1:]
		if lineMatches(line, src) {
			fmt.Println(line)
		}
	}
}

// lineMatches reports whether a log line belongs to src (""=any). The src is the
// third TAB-separated field; untagged lines match only the "any" filter.
func lineMatches(line, src string) bool {
	if src == "" {
		return true
	}
	parts := strings.SplitN(line, "\t", 4)
	return len(parts) >= 3 && parts[2] == src
}
