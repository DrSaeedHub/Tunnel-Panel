package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Colour, but only when something is there to see it.
//
// NO_COLOR is honoured because it is the convention, and the check for a
// terminal matters more here than usual: this CLI's output is piped into logs
// and captured by the installer, and escape codes in a log file are noise
// somebody has to strip later.
var useColour = wantsColour()

func wantsColour() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTerminal(os.Stderr.Fd())
}

func paint(code, s string) string {
	if !useColour {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string   { return paint("1", s) }
func dim(s string) string    { return paint("2", s) }
func cyan(s string) string   { return paint("36", s) }
func green(s string) string  { return paint("32", s) }
func red(s string) string    { return paint("31", s) }
func yellow(s string) string { return paint("33", s) }

// boxWidth is the inside width of the menu frame. Wide enough for the longest
// label, narrow enough to sit inside an 80-column terminal without wrapping —
// a frame that wraps looks worse than no frame at all.
const boxWidth = 50

// visibleLen is the width of s on screen, ignoring colour escapes. Counting the
// escape bytes would push every framed line out of alignment the moment
// anything in it was coloured.
func visibleLen(s string) int {
	n, inEscape := 0, false
	for _, r := range s {
		switch {
		case inEscape:
			if r == 'm' {
				inEscape = false
			}
		case r == '\x1b':
			inEscape = true
		default:
			n++
		}
	}
	return n
}

type box struct{ w io.Writer }

func (b box) top()    { fmt.Fprintln(b.w, cyan("╔"+strings.Repeat("─", boxWidth)+"╗")) }
func (b box) bottom() { fmt.Fprintln(b.w, cyan("╚"+strings.Repeat("─", boxWidth)+"╝")) }
func (b box) rule()   { fmt.Fprintln(b.w, cyan("│"+strings.Repeat("─", boxWidth)+"│")) }

// line pads to the frame using the visible width, so colour never breaks it.
func (b box) line(s string) {
	pad := boxWidth - visibleLen(s) - 3
	if pad < 0 {
		pad = 0
	}
	fmt.Fprintf(b.w, "%s   %s%s%s\n", cyan("│"), s, strings.Repeat(" ", pad), cyan("│"))
}

// entry is a numbered option. The number is padded to two columns so the labels
// line up once the list runs past nine.
func (b box) entry(n int, label string) {
	b.line(fmt.Sprintf("%s. %s", bold(fmt.Sprintf("%2d", n)), label))
}
