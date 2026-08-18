package route

import (
	"context"
	"os"
	"testing"
)

// TestConntrackIsReadableOnThisHost proves the reader works against the real
// kernel rather than against a recorded file.
//
// It only reads, so unlike the netfilter host tests it needs no isolation — but
// it does need root, because dumping the connection tracking table over netlink
// is privileged. Reading nothing is a pass: on a quiet host the table is empty,
// and what is being proved is that the dump succeeds and parses, not that this
// machine has connections.
func TestConntrackIsReadableOnThisHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("dumping the connection tracking table needs root")
	}

	reader := SelectConntrack()
	available, detail := reader.Available()
	if !available {
		t.Skipf("connection tracking is not readable here (%s): %s", reader.Name(), detail)
	}

	flows, err := reader.Flows(context.Background())
	if err != nil {
		t.Fatalf("dumping connection tracking over %s failed: %v", reader.Name(), err)
	}
	t.Logf("%s dumped %d flow(s)", reader.Name(), len(flows))

	for i, flow := range flows {
		if flow.Protocol != "tcp" && flow.Protocol != "udp" {
			t.Errorf("flow %d has protocol %q, which is neither transport the panel relays", i, flow.Protocol)
		}
		if flow.SourceAddress == "" || flow.BindAddress == "" {
			t.Errorf("flow %d was parsed with no addresses: %+v", i, flow)
		}
		if flow.BindPort == 0 {
			t.Errorf("flow %d was parsed with no destination port: %+v", i, flow)
		}
		// The key is what counts new connections between two readings, so it
		// has to distinguish flows.
		if flow.Key() == "" {
			t.Errorf("flow %d has no key: %+v", i, flow)
		}
		if i > 20 {
			break // a sample is enough to prove the parse
		}
	}
}
