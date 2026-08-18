package monitor

import (
	"time"

	"github.com/drs/gre-panel/internal/tunnel"
)

// Settings is the slice of the settings store this package reads.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
	Float(key string) float64
	FloatPtr(key string) *float64
	String(key string) string
}

// Config is the effective monitoring configuration for one tunnel: the global
// settings with the tunnel's own overrides applied.
type Config struct {
	TunnelID      int64
	InterfaceName string
	// Source is the tunnel's own address, which the probe socket binds to so
	// packets egress through the tunnel rather than the default route (§10.1).
	Source string
	// Target is what to probe: the peer address, or an explicit override.
	Target string

	Interval   time.Duration
	Timeout    time.Duration
	PacketSize int
	WindowSize int

	DegradedLossPercent float64
	DownLossPercent     float64
	DegradedRttMs       *float64
	StateChangeSamples  int

	Enabled bool
	// Reason explains why a tunnel is not monitored, when it is not.
	Reason string
}

// Equal reports whether two configurations would produce the same prober. The
// supervisor uses it to decide whether a settings change means restarting one.
func (c Config) Equal(other Config) bool {
	if c.TunnelID != other.TunnelID || c.Source != other.Source || c.Target != other.Target ||
		c.Interval != other.Interval || c.Timeout != other.Timeout ||
		c.PacketSize != other.PacketSize || c.WindowSize != other.WindowSize ||
		c.DegradedLossPercent != other.DegradedLossPercent ||
		c.DownLossPercent != other.DownLossPercent ||
		c.StateChangeSamples != other.StateChangeSamples ||
		c.Enabled != other.Enabled || c.InterfaceName != other.InterfaceName {
		return false
	}
	switch {
	case c.DegradedRttMs == nil && other.DegradedRttMs == nil:
		return true
	case c.DegradedRttMs == nil || other.DegradedRttMs == nil:
		return false
	default:
		return *c.DegradedRttMs == *other.DegradedRttMs
	}
}

// ConfigFor resolves one tunnel's monitoring configuration.
//
// Every threshold is a global setting that the tunnel may override with a
// nullable column, where NULL means inherit. That representation is what powers
// the inherit/override control in the interface, so it is resolved in exactly
// one place (§6, §10.2).
func ConfigFor(rec tunnel.Record, set Settings) Config {
	cfg := Config{
		TunnelID:      rec.TunnelID,
		InterfaceName: rec.InterfaceName,

		Interval:            seconds(orFloat(rec.MonitorIntervalSeconds, set.Float("monitor.interval_seconds"), 1)),
		Timeout:             seconds(orFloat(rec.MonitorTimeoutSeconds, set.Float("monitor.timeout_seconds"), 2)),
		PacketSize:          int(orInt(rec.MonitorPacketSize, set.Int("monitor.packet_size"), 56)),
		WindowSize:          int(orInt(rec.MonitorWindowSize, set.Int("monitor.window_size"), 60)),
		DegradedLossPercent: orFloat(rec.MonitorDegradedLossPercent, set.Float("monitor.degraded_loss_pct"), 20),
		DownLossPercent:     orFloat(rec.MonitorDownLossPercent, set.Float("monitor.down_loss_pct"), 100),
		StateChangeSamples:  int(orInt(rec.MonitorStateChangeSamples, set.Int("monitor.state_change_samples"), 3)),
	}

	// The latency threshold is nullable at both levels: null globally means the
	// criterion is off, and a tunnel may switch it on for itself or vice versa.
	cfg.DegradedRttMs = rec.MonitorDegradedRttMs
	if cfg.DegradedRttMs == nil {
		cfg.DegradedRttMs = set.FloatPtr("monitor.degraded_rtt_ms")
	}

	if cfg.PacketSize < MinPacketSize {
		cfg.PacketSize = MinPacketSize
	}
	if cfg.WindowSize < 1 {
		cfg.WindowSize = 1
	}
	if cfg.StateChangeSamples < 1 {
		cfg.StateChangeSamples = 1
	}

	cfg.Source, cfg.Target = probeEndpoints(rec)
	cfg.Enabled, cfg.Reason = shouldMonitor(rec, set, cfg)
	return cfg
}

// probeEndpoints picks what to probe from and to.
func probeEndpoints(rec tunnel.Record) (source, target string) {
	if len(rec.Addresses) == 0 {
		return "", ""
	}
	primary := rec.Addresses[0]
	for _, a := range rec.Addresses {
		if a.IsPrimary {
			primary = a
			break
		}
	}
	source = primary.Address
	if primary.PeerAddress != nil {
		target = *primary.PeerAddress
	}
	// An explicit target overrides the peer address, for a tunnel whose far end
	// answers on something else.
	if rec.MonitorTarget != nil && *rec.MonitorTarget != "" {
		target = *rec.MonitorTarget
	}
	return source, target
}

// shouldMonitor decides whether a tunnel is probed, and says why when it is
// not. A tunnel that cannot be monitored is Disabled with an explanation rather
// than silently absent from the display.
func shouldMonitor(rec tunnel.Record, set Settings, cfg Config) (bool, string) {
	enabled := set.Bool("monitor.enabled")
	if rec.IsMonitorEnabled != nil {
		enabled = *rec.IsMonitorEnabled
	}
	switch {
	case !enabled:
		return false, "monitoring is switched off for this tunnel"
	case !rec.IsEnabled:
		return false, "this tunnel is administratively down"
	case cfg.Source == "":
		return false, "this tunnel has no address to probe from"
	case cfg.Target == "":
		return false, "no peer address is recorded for this tunnel, so there is nothing to probe"
	}
	if err := sameFamily(cfg.Source, cfg.Target); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func orFloat(override *float64, global, fallback float64) float64 {
	if override != nil {
		return *override
	}
	if global > 0 {
		return global
	}
	return fallback
}

func orInt(override *int64, global, fallback int64) int64 {
	if override != nil {
		return *override
	}
	if global > 0 {
		return global
	}
	return fallback
}

func seconds(v float64) time.Duration {
	if v <= 0 {
		v = 1
	}
	return time.Duration(v * float64(time.Second))
}
