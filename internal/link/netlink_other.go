//go:build !linux

package link

import (
	"context"
	"fmt"
)

// Netlink is unavailable off Linux. The panel manages Linux kernel tunnels and
// is only ever deployed there; this file exists so the tree still builds, vets
// and tests on a developer's machine.
type Netlink struct{}

// NewNetlink returns a manager that reports itself unavailable.
func NewNetlink() *Netlink { return &Netlink{} }

func (n *Netlink) Name() string { return ManagerNetlink }

func (n *Netlink) Capabilities() Capabilities {
	types := map[string]TypeSupport{}
	for _, kind := range TunnelKinds() {
		types[kind] = TypeSupport{Supported: false, Manager: ManagerNetlink, Note: "netlink is only available on Linux"}
	}
	return Capabilities{
		Name: ManagerNetlink, Available: false,
		Detail: "netlink is only available on Linux", TunnelTypes: types,
	}
}

func off() error { return fmt.Errorf("%w: netlink is only available on Linux", ErrUnsupported) }

func (n *Netlink) List(context.Context) ([]Link, error)      { return nil, off() }
func (n *Netlink) Get(context.Context, string) (Link, error) { return Link{}, off() }
func (n *Netlink) Routes(context.Context) ([]Route, error)   { return nil, off() }
func (n *Netlink) Statistics(context.Context, string) (Statistics, error) {
	return Statistics{}, off()
}
func (n *Netlink) Create(context.Context, TunnelSpec) error            { return off() }
func (n *Netlink) Delete(context.Context, string) error                { return off() }
func (n *Netlink) SetMTU(context.Context, string, int) error           { return off() }
func (n *Netlink) SetTxQueueLength(context.Context, string, int) error { return off() }
func (n *Netlink) SetUp(context.Context, string) error                 { return off() }
func (n *Netlink) SetDown(context.Context, string) error               { return off() }
func (n *Netlink) AddAddress(context.Context, string, Address) error   { return off() }
func (n *Netlink) RemoveAddress(context.Context, string, Address) error {
	return off()
}
func (n *Netlink) Subscribe(context.Context) (<-chan Event, error) { return nil, off() }
