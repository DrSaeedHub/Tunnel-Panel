// Package i18n says the panel's messages in the operator's language.
//
// Every sentence the panel shows an operator is written in English at the
// place it is produced, and that English is also its key: a message is passed
// through T (or one of its siblings) and comes back in the language of the
// request, or of the panel when there is no request behind it. Persian is the
// only other language, and its sentences live in the catalog files beside this
// one, keyed by the English they replace.
//
// Keying by the English keeps every call site readable -- the sentence is right
// there -- and the catalog test keeps the two in step: it reads every call in
// the source tree and fails for a sentence with no Persian, for a Persian
// sentence whose placeholders do not fit the English, and for Persian left
// behind after its English changed.
//
// Protocol terminology stays Latin in every language -- GRE, MTU, TTL, ICMP,
// interface names, sysctl keys -- because it is what the operator types into
// `ip` and reads in kernel messages. Only the sentence around it changes.
package i18n

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

// The languages the panel speaks.
const (
	English = "en"
	Farsi   = "fa"
)

// Header is the request header the interface sends its current language in.
// It decides the language of everything said in the answer, so an operator who
// switches language sees the change at once, and the sign-in page -- which has
// no session to read a setting through -- is answered in the language it is
// shown in.
const Header = "X-Panel-Language"

type contextKey struct{}

var panelLanguage atomic.Pointer[func() string]

// SetPanelLanguage names where the panel-wide language comes from: the
// display.language setting. It decides what is said with no request behind
// it -- a monitor's reason for a state change, a background apply's error --
// and what a request that names no language is answered in.
func SetPanelLanguage(source func() string) {
	panelLanguage.Store(&source)
}

// Normalize reduces a language tag to one the panel speaks, or "" when it
// speaks none of it: "fa-IR" is Farsi, "en-GB" is English, "de" is neither.
func Normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		tag = tag[:i]
	}
	switch tag {
	case English, Farsi:
		return tag
	}
	return ""
}

// WithLanguage returns a context whose messages are said in lang. An empty or
// unknown lang leaves the context as it was.
func WithLanguage(ctx context.Context, lang string) context.Context {
	if lang = Normalize(lang); lang == "" {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, lang)
}

// Language is the language messages produced under ctx are said in: the
// request's own, then the panel's, then English.
func Language(ctx context.Context) string {
	if ctx != nil {
		if lang, ok := ctx.Value(contextKey{}).(string); ok {
			return lang
		}
	}
	return Panel()
}

// Panel is the panel-wide language.
func Panel() string {
	if source := panelLanguage.Load(); source != nil {
		if lang := Normalize((*source)()); lang != "" {
			return lang
		}
	}
	return English
}

// T says format in the language ctx carries, with args substituted the way
// fmt.Sprintf would. With no args the text is returned as it is, so a sentence
// with no placeholders may contain a bare % ("80% full").
func T(ctx context.Context, format string, args ...any) string {
	return render(Language(ctx), format, args)
}

// P is T in the panel's own language, for what is said with no request behind
// it, or deep inside code that was never handed one.
func P(format string, args ...any) string {
	return render(Panel(), format, args)
}

// In is T for an explicit language.
func In(lang, format string, args ...any) string {
	return render(Normalize(lang), format, args)
}

// Errorf is fmt.Errorf with format said in the language ctx carries. A %w in
// the Persian keeps wrapping its error, so errors.Is and errors.As still work.
func Errorf(ctx context.Context, format string, args ...any) error {
	lang := Language(ctx)
	if lang == Farsi {
		if translated, ok := farsi[format]; ok {
			return fmt.Errorf(translated, isolate(args, true)...)
		}
	}
	if len(args) == 0 {
		return errors.New(format)
	}
	return fmt.Errorf(format, args...)
}

// N marks a sentence for translation where it is defined, without translating
// it. Text kept in a table and said later -- a setting's description, a
// sentinel error -- is defined with N and said with Tr, and N is what lets the
// catalog test find it.
func N(text string) string { return text }

// Tr says text that was marked with N, in the language ctx carries. Text that
// is not in the catalog -- a kernel's own error output, a value -- comes back
// unchanged, so Tr is safe to apply to anything about to be shown.
func Tr(ctx context.Context, text string) string {
	if Language(ctx) == Farsi {
		if translated, ok := farsi[text]; ok {
			return translated
		}
	}
	return text
}

func render(lang, format string, args []any) string {
	if lang == Farsi {
		if translated, ok := farsi[format]; ok {
			format = translated
			args = isolate(args, false)
		}
	}
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

// isolate wraps each textual value in Unicode isolates for a right-to-left
// sentence. An address, a port or an interface name dropped into Persian text
// otherwise takes the punctuation and numbers beside it along with it, and
// "1 rule" ends up at the far end of the line. The isolates are invisible.
//
// Errors kept for %w stay errors, so wrapping still works; their text is
// isolated where it is printed instead.
func isolate(args []any, keepErrors bool) []any {
	out := make([]any, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case error:
			if keepErrors {
				out[i] = v
			} else {
				out[i] = isolated{v.Error()}
			}
		case string, fmt.Stringer:
			out[i] = isolated{v}
		default:
			out[i] = arg
		}
	}
	return out
}

// isolated formats its value with whatever verb the sentence uses and puts the
// isolates around the result. Wrapping the text before formatting broke %q,
// which escaped the isolates into visible "⁨" text.
type isolated struct{ value any }

func (v isolated) Format(f fmt.State, verb rune) {
	text := fmt.Sprintf(fmt.FormatString(f, verb), v.value)
	if hasLatin(text) {
		text = "⁨" + text + "⁩"
	}
	_, _ = io.WriteString(f, text)
}

func hasLatin(text string) bool {
	for _, r := range text {
		if r < 0x0600 && (r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return true
		}
	}
	return false
}
