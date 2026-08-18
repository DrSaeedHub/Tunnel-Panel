package link

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/drs/gre-panel/internal/audit"
)

// Fake is an in-memory LinkManager. It changes nothing on the host, which makes
// it the implementation behind the preview endpoint (§9.2) and behind every
// hermetic test.
//
// It models the two kernel behaviours that matter most for correctness: a
// freshly created tunnel is down, and once brought up it reports operational
// state UNKNOWN rather than UP, exactly as a real GRE device does (§2).
type Fake struct {
	mu    sync.Mutex
	links map[string]*Link
	route []Route
	calls []string
	// reads counts every observation of kernel state, so a test can assert that
	// validation rejected bad input before the kernel was consulted at all
	// (§7.2, the legacy "not-an-ip" bug).
	reads int

	// FailOn forces one operation to fail, keyed by the call signature that
	// Calls reports, e.g. "create gre-a-1" or "addaddress gre-a-1 172.17.1.1/30".
	// This is how a test makes an apply fail and asserts the rollback.
	FailOn map[string]error

	// UnsupportedKinds makes Create report ErrUnsupported for those kinds, which
	// is how the fallback path between managers is exercised.
	UnsupportedKinds map[string]bool

	subMu sync.Mutex
	subs  []chan Event
}

// NewFake returns an empty fake manager.
func NewFake() *Fake {
	return &Fake{
		links:            map[string]*Link{},
		FailOn:           map[string]error{},
		UnsupportedKinds: map[string]bool{},
	}
}

// NewFakeWithHost returns a fake pre-populated with a plausible host: a
// loopback interface and one physical NIC carrying the default route. Tests of
// the safety invariants need those to exist to prove the panel refuses them.
func NewFakeWithHost() *Fake {
	f := NewFake()
	f.AddLink(Link{
		Name: "lo", Index: 1, MTU: 65536, Kind: "loopback",
		OperState: "UNKNOWN", IsUp: true, IsLowerUp: true, IsRunning: true,
		Flags:     []string{"LOOPBACK", "UP", "LOWER_UP"},
		Addresses: []Address{{Address: "127.0.0.1", PrefixLength: 8, Family: FamilyIPv4}},
	})
	f.AddLink(Link{
		Name: "eth0", Index: 2, MTU: 1500, Kind: "device", HardwareAddr: "52:54:00:11:22:33",
		OperState: "UP", IsUp: true, IsLowerUp: true, IsRunning: true,
		Flags:     []string{"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
		Addresses: []Address{{Address: "203.0.113.10", PrefixLength: 24, Family: FamilyIPv4}},
	})
	f.SetRoutes([]Route{
		{Destination: "default", Gateway: "203.0.113.1", Device: "eth0", IsDefault: true, Protocol: "static"},
		{Destination: "203.0.113.0/24", Device: "eth0", Protocol: "kernel"},
	})
	return f
}

// Name identifies the implementation.
func (f *Fake) Name() string { return ManagerFake }

// Capabilities reports the fake as able to serve every tunnel type, since it
// models rather than performs them.
func (f *Fake) Capabilities() Capabilities {
	types := map[string]TypeSupport{}
	for _, kind := range TunnelKinds() {
		types[kind] = TypeSupport{
			Supported: !f.UnsupportedKinds[kind],
			Manager:   ManagerFake,
			Note:      "simulated: this manager changes nothing on the host",
		}
	}
	return Capabilities{
		Name:        ManagerFake,
		Available:   true,
		Detail:      "in-memory manager used for preview and tests; it never touches the kernel",
		TunnelTypes: types,
		Events:      true,
		Statistics:  true,
	}
}

// AddLink seeds an existing interface.
func (f *Fake) AddLink(l Link) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l.Index == 0 {
		l.Index = len(f.links) + 1
	}
	copied := l
	copied.Addresses = append([]Address(nil), l.Addresses...)
	f.links[l.Name] = &copied
}

// SetRoutes replaces the simulated routing table.
func (f *Fake) SetRoutes(routes []Route) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.route = append([]Route(nil), routes...)
}

// Calls returns the mutating operations performed, in order, in a compact form
// that reads well in a test assertion.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// ReadCalls reports how many times kernel state was observed. A validation
// failure that never consulted the kernel leaves this at zero.
func (f *Fake) ReadCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// Reset forgets recorded calls, keeping the simulated host intact.
func (f *Fake) Reset() {
	f.mu.Lock()
	f.calls = nil
	f.reads = 0
	f.mu.Unlock()
}

// LinkNames returns the names of every simulated interface, sorted.
func (f *Fake) LinkNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.links))
	for name := range f.links {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// record appends a call and returns any forced error for it. The caller holds
// the lock.
func (f *Fake) record(ctx context.Context, signature string) error {
	f.calls = append(f.calls, signature)
	audit.TraceFrom(ctx).Add(audit.Operation{Kind: audit.KindNetlink, Detail: signature})
	if err, ok := f.FailOn[signature]; ok && err != nil {
		return err
	}
	return nil
}

func (f *Fake) List(ctx context.Context) ([]Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	out := make([]Link, 0, len(f.links))
	for _, l := range f.links {
		copied := *l
		copied.Addresses = append([]Address(nil), l.Addresses...)
		out = append(out, copied)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func (f *Fake) Get(ctx context.Context, name string) (Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	l, ok := f.links[name]
	if !ok {
		return Link{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	copied := *l
	copied.Addresses = append([]Address(nil), l.Addresses...)
	return copied, nil
}

func (f *Fake) Routes(ctx context.Context) ([]Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return append([]Route(nil), f.route...), nil
}

func (f *Fake) Statistics(ctx context.Context, name string) (Statistics, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	l, ok := f.links[name]
	if !ok {
		return Statistics{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if l.Statistics == nil {
		return Statistics{}, nil
	}
	return *l.Statistics, nil
}

func (f *Fake) Create(ctx context.Context, spec TunnelSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, "create "+spec.Name); err != nil {
		return err
	}
	if f.UnsupportedKinds[spec.Kind] {
		return fmt.Errorf("%w: %s", ErrUnsupported, spec.Kind)
	}
	if _, exists := f.links[spec.Name]; exists {
		return fmt.Errorf("%w: %s", ErrExists, spec.Name)
	}

	mtu := spec.Mtu
	if mtu == 0 {
		mtu = 1476 // what the kernel picks for GRE over a 1500-byte underlay
	}
	txqlen := 1000
	if spec.TxQueueLength != nil {
		txqlen = *spec.TxQueueLength
	}
	// A newly created tunnel is administratively down and reports operational
	// state DOWN until it is brought up. Modelling that is what makes a test
	// that forgets the "up" step fail here rather than in production.
	l := &Link{
		Name: spec.Name, Index: len(f.links) + 1, MTU: mtu, Kind: spec.Kind,
		TxQueueLen: txqlen, OperState: "DOWN", Flags: []string{"POINTOPOINT", "NOARP"},
		Tunnel: &TunnelAttrs{
			Local: spec.Local, Remote: spec.Remote, Ttl: spec.Ttl, Tos: spec.Tos,
			IKey: spec.IKey, OKey: spec.OKey,
			HasInputChecksum: spec.HasInputChecksum, HasOutputChecksum: spec.HasOutputChecksum,
			HasInputSequence: spec.HasInputSequence, HasOutputSequence: spec.HasOutputSequence,
			IsPathMtuDiscovery: spec.IsPathMtuDiscovery, IsIgnoreDf: spec.IsIgnoreDf,
			BindDevice: spec.BindDevice, FwMark: spec.FwMark,
			HopLimit: spec.HopLimit, EncapLimit: spec.EncapLimit,
			TrafficClass: spec.TrafficClass, FlowLabel: spec.FlowLabel,
		},
	}
	f.links[spec.Name] = l
	f.publish(Event{Kind: EventAdded, Link: *l})
	return nil
}

func (f *Fake) Delete(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, "delete "+name); err != nil {
		return err
	}
	l, ok := f.links[name]
	if !ok {
		return nil // deleting what is already gone is a success, not an error
	}
	gone := *l
	delete(f.links, name)
	f.publish(Event{Kind: EventRemoved, Link: gone})
	return nil
}

func (f *Fake) SetMTU(ctx context.Context, name string, mtu int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, fmt.Sprintf("mtu %s %d", name, mtu)); err != nil {
		return err
	}
	l, ok := f.links[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	l.MTU = mtu
	f.publish(Event{Kind: EventChanged, Link: *l})
	return nil
}

func (f *Fake) SetTxQueueLength(ctx context.Context, name string, length int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, fmt.Sprintf("txqueuelen %s %d", name, length)); err != nil {
		return err
	}
	l, ok := f.links[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	l.TxQueueLen = length
	return nil
}

func (f *Fake) SetUp(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, "up "+name); err != nil {
		return err
	}
	l, ok := f.links[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	l.IsUp = true
	l.IsLowerUp = true
	l.IsRunning = true
	// The whole point: a healthy GRE tunnel reports UNKNOWN, never UP.
	if l.IsTunnel() {
		l.OperState = "UNKNOWN"
	} else {
		l.OperState = "UP"
	}
	l.Flags = mergeFlags(l.Flags, "UP", "LOWER_UP", "RUNNING")
	f.publish(Event{Kind: EventChanged, Link: *l})
	return nil
}

func (f *Fake) SetDown(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, "down "+name); err != nil {
		return err
	}
	l, ok := f.links[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	l.IsUp = false
	l.IsLowerUp = false
	l.IsRunning = false
	l.OperState = "DOWN"
	l.Flags = removeFlags(l.Flags, "UP", "LOWER_UP", "RUNNING")
	f.publish(Event{Kind: EventChanged, Link: *l})
	return nil
}

func (f *Fake) AddAddress(ctx context.Context, name string, addr Address) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, fmt.Sprintf("addaddress %s %s", name, addr)); err != nil {
		return err
	}
	l, ok := f.links[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	for _, existing := range l.Addresses {
		if existing.Equal(addr) {
			return fmt.Errorf("%w: %s already has %s", ErrExists, name, addr)
		}
	}
	l.Addresses = append(l.Addresses, addr)
	return nil
}

func (f *Fake) RemoveAddress(ctx context.Context, name string, addr Address) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.record(ctx, fmt.Sprintf("deladdress %s %s", name, addr)); err != nil {
		return err
	}
	l, ok := f.links[name]
	if !ok {
		return nil // the interface is gone, so the address is too
	}
	kept := l.Addresses[:0]
	for _, existing := range l.Addresses {
		if !existing.Equal(addr) {
			kept = append(kept, existing)
		}
	}
	l.Addresses = append([]Address(nil), kept...)
	return nil
}

func (f *Fake) Subscribe(ctx context.Context) (<-chan Event, error) {
	ch := make(chan Event, 32)
	f.subMu.Lock()
	f.subs = append(f.subs, ch)
	f.subMu.Unlock()

	go func() {
		<-ctx.Done()
		f.subMu.Lock()
		for i, existing := range f.subs {
			if existing == ch {
				f.subs = append(f.subs[:i], f.subs[i+1:]...)
				break
			}
		}
		f.subMu.Unlock()
		close(ch)
	}()
	return ch, nil
}

// publish delivers an event to every subscriber, dropping it for a subscriber
// that is not keeping up rather than blocking the caller. The caller holds the
// link lock, so this must not take it again.
// Publish emits an event to every subscriber, the way the kernel's netlink
// notifications would. Simulating one is the point of the fake: the panel reacts
// to interfaces appearing and vanishing, and that reaction needs testing without
// a kernel to arrange it.
func (f *Fake) Publish(ev Event) { f.publish(ev) }

func (f *Fake) publish(ev Event) {
	f.subMu.Lock()
	defer f.subMu.Unlock()
	for _, ch := range f.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func mergeFlags(flags []string, add ...string) []string {
	for _, name := range add {
		if !hasFlag(flags, name) {
			flags = append(flags, name)
		}
	}
	return flags
}

func removeFlags(flags []string, drop ...string) []string {
	out := flags[:0]
	for _, f := range flags {
		remove := false
		for _, d := range drop {
			if strings.EqualFold(f, d) {
				remove = true
				break
			}
		}
		if !remove {
			out = append(out, f)
		}
	}
	return append([]string(nil), out...)
}
