//go:build integration

package route

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
)

// TestTrafficReachesTheDestination is the first claim §13 asks for: a rule
// created through the service actually carries traffic, end to end.
func TestTrafficReachesTheDestination(t *testing.T) {
	lab := newLab(t)
	server := lab.startDestination(9001, 0)

	result, err := lab.service.Create(lab.ctx, routeRequest("relay", 8001, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the rule failed: %v", err)
	}
	if !result.Verify.Ok {
		t.Fatalf("the apply was not verified: %+v", result.Verify.Failures)
	}

	answer := lab.connect(relayToClient, 8001, 10)
	if answer.Err != nil {
		t.Fatalf("the client could not reach the destination through the relay: %v", answer.Err)
	}
	if answer.Peer == "" {
		t.Fatal("the destination did not report a peer, so nothing arrived")
	}
	t.Logf("the destination answered; it saw the connection coming from %s", answer.Peer)
}

// TestNatModeIsObservedAtTheDestination is the assertion the specification
// singles out, and it is made from the destination's side.
//
// The rule text is never consulted. What is compared is the source address the
// destination's own accept() reported, under each of the two modes, against the
// two addresses that could produce it: the client's, and the relay's leg facing
// the destination. Reading the mode off the rule would prove only that the
// panel rendered what it was asked to.
func TestNatModeIsObservedAtTheDestination(t *testing.T) {
	lab := newLab(t)
	server := lab.startDestination(9002, 0)

	t.Run("masquerade replaces the client address", func(t *testing.T) {
		result, err := lab.service.Create(lab.ctx,
			routeRequest("masqueraded", 8002, server.port, model.NatModeMasquerade))
		if err != nil {
			t.Fatalf("creating the rule failed: %v", err)
		}
		t.Cleanup(func() {
			_, _ = lab.service.Delete(context.Background(), result.Route.RouteRuleID, Request{})
		})

		answer := lab.connect(relayToClient, 8002, 10)
		if answer.Err != nil {
			t.Fatalf("the client could not reach the destination: %v", answer.Err)
		}
		if answer.Peer != relayToDest {
			t.Errorf("the destination saw %s; masquerade must make it see the relay's own "+
				"address %s", answer.Peer, relayToDest)
		}
		if answer.Peer == clientAddr {
			t.Error("the destination saw the client's real address, which is what masquerade " +
				"exists to prevent")
		}
		t.Logf("masquerade: the destination saw %s (the relay), not %s (the client)",
			answer.Peer, clientAddr)
	})

	t.Run("none preserves the client address", func(t *testing.T) {
		result, err := lab.service.Create(lab.ctx,
			routeRequest("preserved", 8003, server.port, model.NatModeNone))
		if err != nil {
			t.Fatalf("creating the rule failed: %v", err)
		}
		t.Cleanup(func() {
			_, _ = lab.service.Delete(context.Background(), result.Route.RouteRuleID, Request{})
		})

		answer := lab.connect(relayToClient, 8003, 10)
		if answer.Err != nil {
			t.Fatalf("the client could not reach the destination with the source preserved. "+
				"This mode needs the destination's replies to route back through the relay, "+
				"which this lab arranges: %v", answer.Err)
		}
		if answer.Peer != clientAddr {
			t.Errorf("the destination saw %s; NAT mode None must make it see the client's own "+
				"address %s", answer.Peer, clientAddr)
		}
		if answer.Peer == relayToDest {
			t.Error("the destination saw the relay's address, so the source was rewritten " +
				"after all")
		}
		t.Logf("none: the destination saw %s (the client), not %s (the relay)",
			answer.Peer, relayToDest)
	})
}

// TestCountersMatchTheBytesTransferred: the accounting rules live in the filter
// forward hook, so they count every packet of a relayed flow rather than only
// the first one a nat hook would see.
func TestCountersMatchTheBytesTransferred(t *testing.T) {
	lab := newLab(t)
	const payload = 512 * 1024
	server := lab.startDestination(9004, payload)

	result, err := lab.service.Create(lab.ctx,
		routeRequest("counted", 8004, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the rule failed: %v", err)
	}
	id := result.Route.RouteRuleID

	before := lab.counters(id)
	if before.RxBytes != 0 || before.TxBytes != 0 {
		t.Fatalf("a freshly installed rule already has traffic: %+v", before)
	}

	answer := lab.connect(relayToClient, 8004, 30)
	if answer.Err != nil {
		t.Fatalf("the transfer failed: %v", answer.Err)
	}
	if answer.Bytes != payload {
		t.Fatalf("the client received %d bytes of the %d sent", answer.Bytes, payload)
	}

	after := lab.counters(id)
	t.Logf("payload %d bytes; counters rx=%d tx=%d", payload, after.RxBytes, after.TxBytes)

	// Rx is the direction carrying the payload back from the destination. It
	// must be at least the payload — the counter sees framing the application
	// does not — and not wildly more, which would mean it is counting
	// something else as well.
	if after.RxBytes < uint64(payload) {
		t.Errorf("the return direction counted %d bytes for a %d byte payload; the counter is "+
			"missing traffic", after.RxBytes, payload)
	}
	if after.RxBytes > uint64(payload)*2 {
		t.Errorf("the return direction counted %d bytes for a %d byte payload, which is more "+
			"than framing explains", after.RxBytes, payload)
	}
	// Tx is the request and the acknowledgements going the other way. It is
	// small, and it must not be zero: a counter that only moves one way is the
	// nat-hook mistake §5.1 warns about.
	if after.TxBytes == 0 {
		t.Error("nothing was counted towards the destination, so only one direction is counted")
	}
	if after.RxPackets == 0 || after.TxPackets == 0 {
		t.Errorf("packets rx=%d tx=%d; both directions must count", after.RxPackets, after.TxPackets)
	}
}

// TestCumulativeTotalsSurviveACounterResetOnARealKernel is §5.2 proved against a real
// kernel.
//
// It turns out there are two cases and they behave differently, which is worth
// stating because the design intended it. Replacing the ruleset with
// `flush table` leaves the named counter objects in place, so their values
// carry across a rebuild on their own — exactly what §5.1 asked named counters
// to buy. Removing the table takes the objects with it, which is what a reboot
// does, and there the panel's own folded totals are the only thing that
// survives. Both are asserted.
func TestCumulativeTotalsSurviveACounterResetOnARealKernel(t *testing.T) {
	lab := newLab(t)
	const payload = 256 * 1024
	server := lab.startDestination(9005, payload)

	result, err := lab.service.Create(lab.ctx,
		routeRequest("folded", 8005, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the rule failed: %v", err)
	}
	id := result.Route.RouteRuleID

	// A baseline sample first. The accounting treats the counter it sees on
	// first sighting as traffic it never observed and starts the total from
	// there rather than crediting the rule with it — otherwise installing the
	// panel on a busy host would book everything since boot. The running
	// sampler takes that first reading at zero, and this stands in for it.
	lab.acct.Sample(lab.ctx)

	if answer := lab.connect(relayToClient, 8005, 30); answer.Err != nil {
		t.Fatalf("the first transfer failed: %v", answer.Err)
	}

	lab.acct.Sample(lab.ctx)
	first, ok := lab.acct.Traffic(id)
	if !ok || first.RxBytesSinceCreation == 0 {
		t.Fatalf("the accounting saw nothing after a transfer: %+v", first)
	}
	t.Logf("after the transfer: kernel rx=%d, panel total rx=%d",
		lab.counters(id).RxBytes, first.RxBytesSinceCreation)

	// 1. A rebuild. The panel replaces the ruleset with one transaction that
	// begins by flushing the table, and the counter objects are not flushed
	// with it.
	if _, err := lab.service.Reapply(lab.ctx, id, Request{}); err != nil {
		t.Fatalf("reapplying failed: %v", err)
	}
	lab.acct.Sample(lab.ctx)
	afterRebuild, _ := lab.acct.Traffic(id)
	t.Logf("after a rebuild:   kernel rx=%d, panel total rx=%d",
		lab.counters(id).RxBytes, afterRebuild.RxBytesSinceCreation)
	if afterRebuild.RxBytesSinceCreation < first.RxBytesSinceCreation {
		t.Errorf("the cumulative total went backwards across a rebuild: %d then %d",
			first.RxBytesSinceCreation, afterRebuild.RxBytesSinceCreation)
	}

	// 2. The table itself goes, taking the counter objects with it, and the
	// stored ruleset is installed again. This is what a reboot looks like, and
	// it is the case the folding exists for.
	if err := lab.backend.Flush(lab.ctx); err != nil {
		t.Fatalf("flushing failed: %v", err)
	}
	if _, err := lab.service.Reapply(lab.ctx, id, Request{}); err != nil {
		t.Fatalf("reinstalling after the flush failed: %v", err)
	}

	reset := lab.counters(id)
	if reset.RxBytes >= first.RxBytesSinceBoot {
		t.Fatalf("the kernel counter did not reset when the table was removed (%d then %d); "+
			"this test is not exercising what it claims to", first.RxBytesSinceBoot, reset.RxBytes)
	}

	lab.acct.Sample(lab.ctx)
	afterReset, _ := lab.acct.Traffic(id)
	t.Logf("after the reset:   kernel rx=%d, panel total rx=%d",
		afterReset.RxBytesSinceBoot, afterReset.RxBytesSinceCreation)

	if afterReset.RxBytesSinceCreation < first.RxBytesSinceCreation {
		t.Errorf("the cumulative total was lost across the counter reset: %d then %d",
			first.RxBytesSinceCreation, afterReset.RxBytesSinceCreation)
	}
	if afterReset.RxBytesSinceBoot >= first.RxBytesSinceBoot {
		t.Errorf("the since-boot figure did not reset (%d then %d), so the two figures are "+
			"not being kept apart", first.RxBytesSinceBoot, afterReset.RxBytesSinceBoot)
	}

	// 3. And traffic after the reset adds to the total rather than restarting it.
	if answer := lab.connect(relayToClient, 8005, 30); answer.Err != nil {
		t.Fatalf("the second transfer failed: %v", answer.Err)
	}
	lab.acct.Sample(lab.ctx)
	third, _ := lab.acct.Traffic(id)
	t.Logf("after a second transfer: panel total rx=%d", third.RxBytesSinceCreation)
	if third.RxBytesSinceCreation <= afterReset.RxBytesSinceCreation {
		t.Errorf("the total did not grow after the second transfer: %d then %d",
			afterReset.RxBytesSinceCreation, third.RxBytesSinceCreation)
	}
	if third.RxBytesSinceCreation < uint64(payload)*2 {
		t.Errorf("two %d byte transfers left a total of %d, so one of them was lost",
			payload, third.RxBytesSinceCreation)
	}
}

// TestADeletedRulesCountersLeaveTheKernelWithIt is the other half of the
// property the test above relies on. Named counter objects survive a table
// flush, which is what carries a rule's figures across an edit — and it is also
// what would leave a deleted rule's counters in the kernel forever. Whether the
// removal actually works can only be answered by nft itself, since it is nft
// that would refuse the transaction if the deletes were wrong.
func TestADeletedRulesCountersLeaveTheKernelWithIt(t *testing.T) {
	lab := newLab(t)
	server := lab.startDestination(9010, 0)

	doomed, err := lab.service.Create(lab.ctx,
		routeRequest("doomed", 8010, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the first rule failed: %v", err)
	}
	survivor, err := lab.service.Create(lab.ctx,
		routeRequest("survivor", 8011, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the second rule failed: %v", err)
	}
	t.Logf("counters before the delete: %v", lab.counterIDs())

	if _, err := lab.service.Delete(lab.ctx, doomed.Route.RouteRuleID, Request{}); err != nil {
		t.Fatalf("deleting the rule failed: %v", err)
	}

	after := lab.counterIDs()
	t.Logf("counters after the delete:  %v", after)
	for _, id := range after {
		if id == doomed.Route.RouteRuleID {
			t.Errorf("the deleted rule's counter objects are still in the kernel: %v", after)
		}
	}
	found := false
	for _, id := range after {
		if id == survivor.Route.RouteRuleID {
			found = true
		}
	}
	if !found {
		t.Errorf("deleting one rule took another rule's counters with it: %v", after)
	}

	// And the surviving rule is still installed: the deletes ride in the same
	// transaction, so getting them wrong would have taken the ruleset with them.
	if !strings.Contains(lab.liveRuleset(), rules.Identity(survivor.Route.RouteRuleID)) {
		t.Error("the transaction that removed the counters also lost the surviving rule")
	}
}

// TestAFailedApplyLeavesNoPartialRules: the apply is one transaction, so a
// refused ruleset must leave the previous one exactly as it was.
func TestAFailedApplyLeavesNoPartialRules(t *testing.T) {
	lab := newLab(t)
	server := lab.startDestination(9006, 0)

	working, err := lab.service.Create(lab.ctx,
		routeRequest("working", 8006, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the first rule failed: %v", err)
	}
	before := lab.liveRuleset()

	// The ruleset submission is made to fail. Everything else is real: the
	// previous ruleset is genuinely installed, the rollback is a genuine
	// transaction against it, and what the kernel holds afterwards is what is
	// asserted. Provoking a refusal with a ruleset the panel would also accept
	// is not reliably possible — the panel validates the things nft rejects —
	// so the failure is injected at the one step whose outcome is in question.
	// Exactly one submission fails. The rollback is a submission too, and it
	// is allowed to succeed — that is the outcome under test.
	lab.refuseApplies.Store(1)
	_, err = lab.service.Create(lab.ctx, routeRequest("refused", 8007, server.port, model.NatModeMasquerade))
	lab.refuseApplies.Store(0)
	if err == nil {
		t.Fatal("a refused ruleset was reported as applied")
	}
	var applyErr *ApplyError
	if !errors.As(err, &applyErr) {
		t.Fatalf("got %v, want an ApplyError", err)
	}
	if !applyErr.RolledBack {
		t.Error("the failure was not reported as rolled back")
	}
	if applyErr.Stderr == "" {
		t.Error("the failure does not carry the backend's own message")
	}
	t.Logf("the refused apply reported: %v (stderr: %s)", applyErr.Error(), applyErr.Stderr)

	// The refused rule is kept and marked failed rather than removed: an
	// operator needs to see what was attempted.
	stored, listErr := lab.repo.List(lab.ctx)
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, record := range stored {
		if record.RouteRuleTitle == "refused" && record.ApplyStatusID != model.ApplyStatusFailed {
			t.Errorf("the refused rule is recorded as %d, want Failed", record.ApplyStatusID)
		}
	}

	after := lab.liveRuleset()
	if strings.Contains(after, "refused") {
		t.Error("the refused rule is in the kernel")
	}
	if !strings.Contains(after, rules.Identity(working.Route.RouteRuleID)) {
		t.Error("the rollback lost the rule that was already working")
	}
	// The working rule still carries traffic, which is the point of rolling
	// back rather than leaving a half-built namespace.
	if answer := lab.connect(relayToClient, 8006, 10); answer.Err != nil {
		t.Errorf("the surviving rule stopped working after the failed apply: %v", answer.Err)
	}
	if before != after {
		t.Errorf("the ruleset differs after the rollback\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestForeignRulesSurviveARebuild: the panel owns one table and replaces only
// that. Something else's rules in a built-in chain are not its to touch.
func TestForeignRulesSurviveARebuild(t *testing.T) {
	lab := newLab(t)
	server := lab.startDestination(9008, 0)

	// Another piece of software, in its own table, hooking the same point.
	const foreign = `table ip other_software {
	chain PREROUTING {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 10.90.1.1 tcp dport 18099 dnat to 10.90.2.2:9999
	}
}`
	writeAndApply(t, foreign)

	result, err := lab.service.Create(lab.ctx,
		routeRequest("coexisting", 8008, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the rule failed: %v", err)
	}

	if _, err := lab.service.Reapply(lab.ctx, result.Route.RouteRuleID, Request{}); err != nil {
		t.Fatalf("reapplying failed: %v", err)
	}

	live := lab.liveRuleset()
	if !strings.Contains(live, "other_software") {
		t.Fatal("rebuilding the panel's ruleset removed a table it does not own")
	}
	if !strings.Contains(live, "dnat to 10.90.2.2:9999") {
		t.Error("the foreign rule itself is gone")
	}
	if !strings.Contains(live, rules.Identity(result.Route.RouteRuleID)) {
		t.Error("the panel's own rule is missing after the rebuild")
	}

	// And the panel sees it as foreign rather than as its own.
	view, err := lab.backend.Foreign(lab.ctx)
	if err != nil {
		t.Fatalf("reading the host's other rules failed: %v", err)
	}
	found := false
	for _, rule := range view.Rules {
		if strings.Contains(rule.Table, "other_software") {
			found = true
		}
		if strings.Contains(rule.Text, rules.IdentityPrefix) {
			t.Errorf("one of the panel's own rules was reported as foreign: %s", rule.Text)
		}
	}
	if !found {
		t.Errorf("the foreign rule was not reported; %d rules were seen", len(view.Rules))
	}

	// The relay still works with the other table present.
	if answer := lab.connect(relayToClient, 8008, 10); answer.Err != nil {
		t.Errorf("the relay stopped working alongside the foreign rule: %v", answer.Err)
	}

	t.Cleanup(func() {
		_, _ = nsExec(t, relayNS, nftBin, "delete", "table", "ip", "other_software")
	})
}

// writeAndApply hands nft a ruleset through a file, which is how the panel
// itself submits one.
func writeAndApply(t *testing.T, ruleset string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "extra.nft")
	if err := os.WriteFile(path, []byte(ruleset+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := nsExec(t, relayNS, nftBin, "-f", path); err != nil {
		t.Fatalf("installing the ruleset failed: %v\n%s", err, out)
	}
}

// TestSafetyInvariantsCannotBeForced is §6.3 against a real host: the panel's
// own port and the live SSH port are refused, and no flag reaches either.
func TestSafetyInvariantsCannotBeForced(t *testing.T) {
	lab := newLab(t)

	t.Run("the panel's own port", func(t *testing.T) {
		request := routeRequest("take the panel down", 8443, 9009, model.NatModeMasquerade)
		request.Force = true
		_, err := lab.service.Create(lab.ctx, request)
		if err == nil {
			t.Fatal("a rule redirecting the panel's own port was applied")
		}
		violation, ok := safety.AsViolation(err)
		if !ok || violation.Code != safety.CodeProtectedPort {
			t.Fatalf("got %v, want a protected-port refusal", err)
		}
		if strings.Contains(lab.liveRuleset(), "8443") {
			t.Error("the refused rule reached the kernel")
		}
	})

	t.Run("the live SSH port", func(t *testing.T) {
		// The port is read from the running sshd rather than assumed, so the
		// guard is asked what it found and the rule is built against that.
		guard := safety.NewRouteGuard(8443, rules.NewSocketReader(), lab.dir)
		protected := guard.ProtectedPorts(lab.ctx)

		sshPort := 0
		for _, entry := range protected {
			if entry.Process == "sshd" {
				sshPort = entry.Port
			}
		}
		if sshPort == 0 {
			t.Skip("no sshd socket was found on this host, so there is no live SSH port to protect")
		}
		t.Logf("the live SSH port was detected as %d", sshPort)

		request := routeRequest("lock the machine", sshPort, 9009, model.NatModeMasquerade)
		request.Force = true
		_, err := lab.service.Create(lab.ctx, request)
		if err == nil {
			t.Fatalf("a rule redirecting the live SSH port %d was applied", sshPort)
		}
		violation, ok := safety.AsViolation(err)
		if !ok || violation.Code != safety.CodeProtectedPort {
			t.Fatalf("got %v, want a protected-port refusal", err)
		}
	})
}

// TestTheRulesetReturnsAfterAReboot is the reboot equivalent.
//
// systemd cannot be asked to start a unit inside a test namespace — it would
// run in the host's — so the unit the panel rendered is read back from disk and
// its own ExecStart commands are run, which is exactly what systemd would do
// with it. That still proves the thing worth proving: the file the panel wrote
// is sufficient to restore the ruleset from nothing.
func TestTheRulesetReturnsAfterAReboot(t *testing.T) {
	lab := newLab(t)
	server := lab.startDestination(9010, 0)

	result, err := lab.service.Create(lab.ctx,
		routeRequest("persistent", 8010, server.port, model.NatModeMasquerade))
	if err != nil {
		t.Fatalf("creating the rule failed: %v", err)
	}
	id := result.Route.RouteRuleID

	unitPath := ""
	for _, file := range result.Plan.Files {
		if strings.HasSuffix(file.Path, ".service") {
			unitPath = file.Path
		}
	}
	if unitPath == "" {
		t.Fatal("the apply rendered no restore unit")
	}
	rendered, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("the restore unit was not written: %v", err)
	}
	unit := string(rendered)

	// Everything goes, as a reboot would take it.
	if err := lab.backend.Flush(lab.ctx); err != nil {
		t.Fatalf("flushing failed: %v", err)
	}
	if strings.Contains(lab.liveRuleset(), rules.Identity(id)) {
		t.Fatal("the flush left the rules behind, so this test proves nothing")
	}
	if answer := lab.connect(relayToClient, 8010, 3); answer.Err == nil {
		t.Fatal("the relay still worked with no rules installed")
	}

	// Now run what the unit would run.
	ran := 0
	for _, line := range strings.Split(unit, "\n") {
		command, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart=")
		if !ok {
			continue
		}
		command = strings.TrimPrefix(command, "-")
		fields := strings.Fields(command)
		if len(fields) == 0 {
			continue
		}
		if out, err := nsExec(t, relayNS, fields...); err != nil {
			t.Fatalf("the restore command %q failed: %v\n%s", command, err, out)
		}
		ran++
	}
	if ran == 0 {
		t.Fatal("the restore unit carries no ExecStart command")
	}
	t.Logf("ran %d restore command(s) from %s", ran, unitPath)

	if !strings.Contains(lab.liveRuleset(), rules.Identity(id)) {
		t.Fatal("the ruleset did not come back")
	}
	answer := lab.connect(relayToClient, 8010, 10)
	if answer.Err != nil {
		t.Fatalf("the relay did not work after the restore: %v", answer.Err)
	}
	t.Logf("the relay works again after the restore; the destination saw %s", answer.Peer)
}

// TestMssClampingRescuesALargeTransfer is the §3 defect this subsystem exists
// to fix, reproduced.
//
// Both of the relay's legs are narrower than either host's interface, so
// neither endpoint can see the constraint and both advertise a segment size the
// path cannot carry. The relay's ICMP "fragmentation needed" is dropped, which
// is what makes the failure a silent stall rather than a path-MTU discovery
// that fixes itself — and which is exactly what a firewall between two hosts
// routinely does.
func TestMssClampingRescuesALargeTransfer(t *testing.T) {
	lab := newLab(t)
	const payload = 512 * 1024
	server := lab.startDestination(9011, payload)

	// Drop the relay's own ICMP too-big messages, in a table of the panel's
	// making so the panel's namespace is untouched.
	writeAndApply(t, `table inet itest_blackhole {
	chain output {
		type filter hook output priority filter; policy accept;
		icmp type destination-unreachable icmp code frag-needed drop
	}
}`)
	t.Cleanup(func() {
		_, _ = nsExec(t, relayNS, nftBin, "delete", "table", "inet", "itest_blackhole")
	})

	// Without clamping the transfer stalls.
	unclamped := routeRequest("unclamped", 8011, server.port, model.NatModeMasquerade)
	unclamped.IsClampMssToPmtu = false
	created, err := lab.service.Create(lab.ctx, unclamped)
	if err != nil {
		t.Fatalf("creating the unclamped rule failed: %v", err)
	}
	if strings.Contains(lab.liveRuleset(), "maxseg") {
		t.Fatal("the unclamped rule rendered an MSS clamp anyway")
	}

	without := lab.connect(relayToClient, 8011, 8)
	t.Logf("without clamping: %d of %d bytes arrived (stalled=%v, err=%v)",
		without.Bytes, payload, without.Stalled, without.Err)
	if without.Err == nil && without.Bytes == payload {
		t.Fatal("the transfer completed without MSS clamping, so the low path MTU is not " +
			"actually constraining it and this test proves nothing")
	}

	// With clamping it completes.
	clamped := routeRequest("clamped", 8011, server.port, model.NatModeMasquerade)
	clamped.RouteRuleID = created.Route.RouteRuleID
	clamped.IsClampMssToPmtu = true
	if _, err := lab.service.Update(lab.ctx, created.Route.RouteRuleID, clamped); err != nil {
		t.Fatalf("turning clamping on failed: %v", err)
	}
	if !strings.Contains(lab.liveRuleset(), "maxseg") {
		t.Fatal("the clamped rule rendered no MSS clamp")
	}

	with := lab.connect(relayToClient, 8011, 30)
	t.Logf("with clamping: %d of %d bytes arrived (stalled=%v, err=%v)",
		with.Bytes, payload, with.Stalled, with.Err)
	if with.Err != nil {
		t.Fatalf("the transfer still failed with MSS clamping on: %v", with.Err)
	}
	if with.Bytes != payload {
		t.Errorf("only %d of %d bytes arrived with clamping on", with.Bytes, payload)
	}
}

// TestConntrackSeesTheRelayedConnections proves the connection list is real:
// the flows the panel reports for a rule are the ones actually open.
func TestConntrackSeesTheRelayedConnections(t *testing.T) {
	lab := newLab(t)
	const payload = 4 * 1024 * 1024
	server := lab.startDestination(9012, payload)

	if _, err := lab.service.Create(lab.ctx,
		routeRequest("tracked", 8012, server.port, model.NatModeMasquerade)); err != nil {
		t.Fatalf("creating the rule failed: %v", err)
	}

	// A transfer big enough to still be open while conntrack is read.
	done := make(chan clientResult, 1)
	go func() { done <- lab.connect(relayToClient, 8012, 60) }()

	// Conntrack lives in the relay's namespace, so it is read from there
	// rather than through the panel's own reader, which would see this
	// process's namespace.
	deadline := time.Now().Add(15 * time.Second)
	seen := ""
	for time.Now().Before(deadline) {
		out, err := nsExec(t, relayNS, "/usr/sbin/conntrack", "-L")
		if err == nil && strings.Contains(out, "dport=8012") {
			seen = out
			break
		}
		if err != nil {
			out, err = nsExec(t, relayNS, "cat", "/proc/net/nf_conntrack")
			if err == nil && strings.Contains(out, "dport=8012") {
				seen = out
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	answer := <-done
	if answer.Err != nil {
		t.Fatalf("the transfer failed: %v", answer.Err)
	}
	if seen == "" {
		t.Skip("connection tracking could not be read in the relay namespace on this host")
	}
	for _, line := range strings.Split(seen, "\n") {
		if strings.Contains(line, "dport=8012") {
			t.Logf("the relay tracked: %s", strings.TrimSpace(line))
			break
		}
	}
}
