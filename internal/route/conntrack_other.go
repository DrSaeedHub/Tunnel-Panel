//go:build !linux

package route

// SelectConntrack returns the reader this platform can serve.
//
// Only Linux has the netfilter netlink interface, so everywhere else the panel
// falls back to the text listing — which, on a platform with no /proc/net
// either, reports itself as unavailable rather than reporting no connections.
func SelectConntrack() ConntrackReader { return NewProcConntrack() }
