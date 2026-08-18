package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

// Ctrl+C used to do nothing at the menu. main installs a signal.NotifyContext
// for SIGINT, which stops Go terminating the process and cancels that context
// instead — so a prompt that read the terminal without watching the context left
// the operator pressing a key that had been taken away from them and given to
// nobody.
//
// The reader here never produces a line, which is what a terminal nobody is
// typing at looks like.
func TestPromptGivesUpWhenTheContextIsCancelled(t *testing.T) {
	a := &app{in: neverReads{}, out: &bytes.Buffer{}, err: &bytes.Buffer{}}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() {
		_, err := a.prompt(ctx, "Choose", "0")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("prompt returned no error on a cancelled context; Ctrl+C has to end the wait")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prompt ignored the cancelled context and kept waiting, which is what made Ctrl+C do nothing")
	}
}

// A confirmation is the last moment before something irreversible, so it is
// exactly where somebody reaches for Ctrl+C. Cancelling must answer "no".
func TestConfirmRefusesWhenTheContextIsCancelled(t *testing.T) {
	a := &app{in: neverReads{}, out: &bytes.Buffer{}, err: &bytes.Buffer{}}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	type result struct {
		ok  bool
		err error
	}
	done := make(chan result, 1)
	go func() {
		ok, err := a.confirm(ctx, "Remove everything?")
		done <- result{ok, err}
	}()

	select {
	case got := <-done:
		if got.err == nil {
			t.Fatal("confirm returned no error on a cancelled context")
		}
		if got.ok {
			t.Fatal("confirm answered yes on a cancelled context; an interrupted confirmation must never proceed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("confirm ignored the cancelled context and kept waiting")
	}
}

// --yes still short-circuits before any reading, so automation is unaffected by
// the context watching.
func TestConfirmWithAssumeYesNeedsNoTerminal(t *testing.T) {
	a := &app{in: neverReads{}, out: &bytes.Buffer{}, err: &bytes.Buffer{}, assumeYes: true}
	ok, err := a.confirm(context.Background(), "proceed?")
	if err != nil || !ok {
		t.Fatalf("confirm with --yes = (%v, %v), want (true, nil)", ok, err)
	}
}

// neverReads is a reader that blocks forever, standing in for a terminal with
// nobody typing at it.
type neverReads struct{}

func (neverReads) Read([]byte) (int, error) {
	select {} //nolint:staticcheck // blocking forever is the point
}

var _ io.Reader = neverReads{}
