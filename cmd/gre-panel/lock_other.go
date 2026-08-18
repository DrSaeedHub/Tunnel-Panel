//go:build !unix

package main

// dataDirLock is a no-op away from Unix. The panel manages Linux kernel
// tunnels and only runs there; this file exists so the tree builds and vets on
// a developer's machine.
type dataDirLock struct{}

func acquireDataDirLock(string) (*dataDirLock, error) { return &dataDirLock{}, nil }

func (l *dataDirLock) Held() bool { return false }

func (l *dataDirLock) Release() {}
