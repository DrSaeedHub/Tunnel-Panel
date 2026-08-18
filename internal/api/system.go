package api

import (
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
)

// systemInfoResponse is the body of GET /system/info.
type systemInfoResponse struct {
	Build     BuildInfo     `json:"build"`
	Runtime   runtimeInfo   `json:"runtime"`
	Paths     resolvedPaths `json:"paths"`
	Serving   servingInfo   `json:"serving"`
	Kernel    kernelInfo    `json:"kernel"`
	StartedAt string        `json:"started_at"`
}

type runtimeInfo struct {
	GoVersion     string `json:"go_version"`
	Os            string `json:"os"`
	Arch          string `json:"arch"`
	Hostname      string `json:"hostname"`
	Pid           int    `json:"pid"`
	Uid           int    `json:"uid"`
	IsRoot        bool   `json:"is_root"`
	DevMode       bool   `json:"dev_mode"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// resolvedPaths reports the binaries and directories actually in use. The
// legacy script hardcoded /sbin/ip; these are resolved at startup and reported
// so an operator can see exactly what will be executed (§5.1).
type resolvedPaths struct {
	DataDir      string `json:"data_dir"`
	DatabasePath string `json:"database_path"`
	SystemdDir   string `json:"systemd_dir"`
	NetworkdDir  string `json:"networkd_dir"`
	IpBin        string `json:"ip_bin"`
	SystemctlBin string `json:"systemctl_bin"`
}

type servingInfo struct {
	BindHost    string `json:"bind_host"`
	BindPort    int    `json:"bind_port"`
	WebPath     string `json:"web_path"`
	BasePath    string `json:"base_path"`
	ApiBasePath string `json:"api_base_path"`
}

type kernelInfo struct {
	Release       string          `json:"release"`
	LoadedModules map[string]bool `json:"loaded_modules"`
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	availability := link.Probe()

	writeJSON(w, http.StatusOK, systemInfoResponse{
		Build: s.build,
		Runtime: runtimeInfo{
			GoVersion:     runtime.Version(),
			Os:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			Hostname:      hostname,
			Pid:           os.Getpid(),
			Uid:           os.Geteuid(),
			IsRoot:        os.Geteuid() == 0,
			DevMode:       s.cfg.DevMode,
			UptimeSeconds: int64(time.Since(s.started).Seconds()),
		},
		Paths: resolvedPaths{
			DataDir:      s.cfg.DataDir,
			DatabasePath: s.cfg.DBPath,
			SystemdDir:   s.cfg.SystemdDir,
			NetworkdDir:  s.cfg.NetworkdDir,
			IpBin:        s.cfg.IPBin,
			SystemctlBin: s.cfg.SystemctlBin,
		},
		Serving: servingInfo{
			BindHost:    s.cfg.BindHost,
			BindPort:    s.cfg.BindPort,
			WebPath:     s.cfg.WebPath,
			BasePath:    s.cfg.BasePath(),
			ApiBasePath: s.cfg.APIBasePath(),
		},
		Kernel: kernelInfo{
			Release:       availability.KernelRelease,
			LoadedModules: availability.LoadedModules,
		},
		StartedAt: model.FormatTime(s.started),
	})
}

// tunnelTypeCapability reports what the panel can do with one tunnel type, so
// the frontend can disable options this kernel or this build cannot serve
// (§8.1).
type tunnelTypeCapability struct {
	TunnelTypeID int64  `json:"tunnel_type_id"`
	Title        string `json:"title"`
	Supported    bool   `json:"supported"`
	LinkManager  string `json:"link_manager"`
	Note         string `json:"note,omitempty"`
}

type persistenceCapability struct {
	PersistenceTypeID int64  `json:"persistence_type_id"`
	Title             string `json:"title"`
	Available         bool   `json:"available"`
	Note              string `json:"note,omitempty"`
}

type toolCapability struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	Available bool   `json:"available"`
}

// ruleBackendCapability reports which netfilter interface carries the panel's
// forwarding rules on this host, and why that one was chosen (§2.1 of the port
// forwarding specification). The frontend explains what is in use rather than
// leaving an operator to guess whether their rules landed in nftables or in
// iptables.
type ruleBackendCapability struct {
	Active string `json:"active"`
	// RuleBackendTypeID is the lookup identifier, or zero for the fake, which
	// is not a backend an installation can be running.
	RuleBackendTypeID int64             `json:"rule_backend_type_id,omitempty"`
	Available         bool              `json:"available"`
	Reason            string            `json:"reason,omitempty"`
	Detail            string            `json:"detail,omitempty"`
	Version           string            `json:"version,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	Features          map[string]bool   `json:"features,omitempty"`
	Binaries          map[string]string `json:"binaries,omitempty"`
	// NftVersion and IptablesVersion are what the tools reported at startup,
	// including the one that was not chosen, so the reason is checkable.
	NftVersion       string `json:"nft_version,omitempty"`
	IptablesVersion  string `json:"iptables_version,omitempty"`
	IptablesIsLegacy bool   `json:"iptables_is_legacy"`
}

type capabilitiesResponse struct {
	TunnelTypes  []tunnelTypeCapability  `json:"tunnel_types"`
	Persistence  []persistenceCapability `json:"persistence"`
	LinkManagers map[string]any          `json:"link_managers"`
	RuleBackend  ruleBackendCapability   `json:"rule_backend"`
	Tools        []toolCapability        `json:"tools"`
	Kernel       kernelInfo              `json:"kernel"`
	// Complete reports whether every field here reflects a live runtime probe.
	// It is false until the link manager and the persistence backends are
	// wired, so a caller never mistakes a structural default for a measurement.
	Complete bool `json:"complete"`
}

// handleCapabilities reports what this kernel, this build and this host can
// actually do, per tunnel type and per persistence backend, so the frontend
// disables what cannot be served rather than offering it and failing (§8.1).
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	availability := link.Probe()
	ctx := r.Context()

	types := make([]tunnelTypeCapability, 0, 4)
	if s.tunnels != nil {
		// The live answer: whichever manager would serve each type, and whether
		// it can.
		support := link.MergeCapabilities(s.tunnels.Links())
		for _, id := range []int64{
			model.TunnelTypeGRE, model.TunnelTypeGRETAP,
			model.TunnelTypeIP6GRE, model.TunnelTypeIP6GRETAP,
		} {
			kind := model.TunnelTypeKind(id)
			entry := support[kind]
			types = append(types, tunnelTypeCapability{
				TunnelTypeID: id, Title: strings.ToUpper(kind),
				Supported: entry.Supported, LinkManager: entry.Manager, Note: entry.Note,
			})
		}
	} else {
		for _, id := range []int64{
			model.TunnelTypeGRE, model.TunnelTypeGRETAP,
			model.TunnelTypeIP6GRE, model.TunnelTypeIP6GRETAP,
		} {
			types = append(types, tunnelTypeCapability{
				TunnelTypeID: id, Title: strings.ToUpper(model.TunnelTypeKind(id)),
				Supported: false, Note: "tunnel management is not available on this instance",
			})
		}
	}

	systemdAvailable := s.cfg.SystemctlBin != ""
	networkdAvailable := false
	if s.persist != nil {
		systemdAvailable = s.persist.SystemdAvailable()
		networkdAvailable = s.persist.NetworkdActive(ctx)
	}
	networkdNote := "systemd-networkd is running, so networkd persistence can be offered"
	if !networkdAvailable {
		networkdNote = "systemd-networkd is not active on this host, so networkd persistence is not offered"
	}

	persistence := []persistenceCapability{
		{model.PersistenceTypeSystemd, "Systemd", systemdAvailable,
			"renders a systemd unit; the tunnel returns after a reboot"},
		{model.PersistenceTypeNetworkd, "Networkd", networkdAvailable, networkdNote},
		{model.PersistenceTypeRuntime, "Runtime", true,
			"configures the running kernel only and does not survive a reboot"},
	}

	managers := map[string]any{
		"netlink": map[string]any{
			"available": availability.NetlinkAvailable,
			"error":     availability.NetlinkError,
		},
		"ip_command": map[string]any{
			"available": s.cfg.IPBin != "",
			"path":      s.cfg.IPBin,
		},
	}
	activeManager := ""
	if s.tunnels != nil {
		activeManager = s.tunnels.Links().Name()
		managers["active"] = activeManager
	}

	tools := []toolCapability{
		{Name: "ip", Path: s.cfg.IPBin, Available: s.cfg.IPBin != ""},
		{Name: "systemctl", Path: s.cfg.SystemctlBin, Available: s.cfg.SystemctlBin != ""},
	}
	ruleBackend := s.ruleBackendCapability()
	// Every netfilter tool that was resolved is reported, not only the chosen
	// backend's, so an operator can see what else this host has.
	for _, name := range []string{"nft", "iptables", "iptables-restore", "ip6tables", "ip6tables-restore"} {
		path := s.ruleBackend.Binaries[name]
		tools = append(tools, toolCapability{Name: name, Path: path, Available: path != ""})
	}

	writeJSON(w, http.StatusOK, capabilitiesResponse{
		TunnelTypes:  types,
		Persistence:  persistence,
		LinkManagers: managers,
		RuleBackend:  ruleBackend,
		Tools:        tools,
		Kernel: kernelInfo{
			Release:       availability.KernelRelease,
			LoadedModules: availability.LoadedModules,
		},
		// Everything above is now a live probe rather than a structural default.
		Complete: s.tunnels != nil,
	})
}

// ruleBackendCapability describes the netfilter backend this instance would
// apply forwarding rules through. A server built without one — which only
// happens in a test — reports an unavailable fake rather than pretending.
func (s *Server) ruleBackendCapability() ruleBackendCapability {
	detection := s.ruleBackend
	if detection.Backend == nil {
		return ruleBackendCapability{
			Active: "none", Available: false,
			Reason: "forwarding rules are not available on this instance",
		}
	}
	caps := detection.Backend.Capabilities()
	out := ruleBackendCapability{
		Active:           detection.Backend.Name(),
		Available:        caps.Available,
		Reason:           detection.Reason,
		Detail:           caps.Detail,
		Version:          caps.Version,
		Namespace:        caps.Namespace,
		Features:         caps.Features,
		Binaries:         caps.Binaries,
		NftVersion:       detection.NftVersion,
		IptablesVersion:  detection.IptablesVersion,
		IptablesIsLegacy: detection.IptablesIsLegacy,
	}
	if id, ok := model.RuleBackendTypeForName(out.Active); ok {
		out.RuleBackendTypeID = id
	}
	return out
}
