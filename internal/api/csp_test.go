package api

import (
	"strings"
	"testing"
)

// The regression this guards: moving the panel from the Settings page left the
// browser stranded. The page polls the new port to know when to send the
// operator there, a different port is a different origin, and connect-src
// 'self' blocked the fetch before it was ever sent:
//
//	Connecting to 'http://203.0.113.10:8444/…/api/v1/system/health' violates
//	the following Content Security Policy directive: "connect-src 'self'".
//
// The health endpoint's permissive CORS did nothing about it. CORS is the
// server saying who may read a response; CSP is the browser saying where this
// page may send a request. The request never left the browser.
func TestConnectSrcAllowsTheSameHostOnAnotherPort(t *testing.T) {
	got := connectSrc("203.0.113.10:8443")

	if !strings.Contains(got, "http://203.0.113.10:*") {
		t.Errorf("connect-src = %q, which does not admit the same host on another port; "+
			"the panel moving ports is exactly what the redirect has to poll for", got)
	}
	if !strings.Contains(got, "'self'") {
		t.Errorf("connect-src = %q, which dropped 'self'", got)
	}
}

// The widening must stay narrow. A bare "*" would have fixed the symptom and
// let the page talk to anywhere on the internet.
func TestConnectSrcAdmitsNoOtherHost(t *testing.T) {
	got := connectSrc("panel.example:8443")

	if strings.Contains(got, "*;") || strings.Contains(got, " * ") || strings.HasSuffix(got, " *") {
		t.Errorf("connect-src = %q contains a bare wildcard", got)
	}
	if strings.Contains(got, "evil.example") {
		t.Errorf("connect-src = %q names a host it was never given", got)
	}
	// Only the host it was given, and only with a port wildcard.
	for _, want := range []string{"http://panel.example:*", "https://panel.example:*"} {
		if !strings.Contains(got, want) {
			t.Errorf("connect-src = %q is missing %q", got, want)
		}
	}
}

// An IPv6 literal has to keep its brackets or the colon reads as a port
// separator and the whole source expression is discarded by the browser.
func TestConnectSrcBracketsAnIPv6Literal(t *testing.T) {
	got := connectSrc("[2001:db8::1]:8443")

	if !strings.Contains(got, "http://[2001:db8::1]:*") {
		t.Errorf("connect-src = %q, want a bracketed IPv6 host-source", got)
	}
}

// A request with no Host header must not produce a malformed directive; falling
// back to 'self' alone is correct, since there is no host to widen to.
func TestConnectSrcWithoutAHostIsJustSelf(t *testing.T) {
	if got := connectSrc(""); got != "connect-src 'self'" {
		t.Errorf("connect-src = %q, want exactly \"connect-src 'self'\"", got)
	}
}

// A bare host with no port is still a host.
func TestConnectSrcHandlesAHostWithNoPort(t *testing.T) {
	if got := connectSrc("panel.example"); !strings.Contains(got, "http://panel.example:*") {
		t.Errorf("connect-src = %q, want the host admitted even with no port in Host", got)
	}
}
