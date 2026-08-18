package route

import (
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/rules"
)

// The interface renders a failing verification check by its Detail, and falls
// back to the check's Name when Detail is empty — see routeVerificationFailures
// in web/_app/src/hooks/useRouteActions.ts and its twin in useTunnelActions.ts.
// A check that fails without a Detail therefore shows an operator the bare
// string `no_stale_chains` or `ip_forwarding`, untranslated in every language,
// which is the same defect as the `oper_state` and `flags` field labels.
//
// None of the check names has a locale entry, and none should need one: the
// name is a stable identifier for machines and the detail is the sentence for
// people. So the guarantee has to be that the sentence is always there.

func TestAFailingCheckAlwaysCarriesASentence(t *testing.T) {
	var report VerifyReport
	report.add(VerifyCheck{Name: CheckNoStaleChains, Fatal: true})
	report.add(VerifyCheck{Name: CheckForwarding, Fatal: true, Expected: "1", Actual: "0"})
	report.add(VerifyCheck{Name: CheckRulesPresent, Ok: true})
	report.add(VerifyCheck{Name: CheckPersistence, Skipped: true})

	for _, check := range report.Checks {
		if check.Ok || check.Skipped {
			continue
		}
		if strings.TrimSpace(check.Detail) == "" {
			t.Errorf("the %q check failed with no detail, so the interface would show its raw name",
				check.Name)
		}
		if strings.TrimSpace(check.Detail) == check.Name {
			t.Errorf("the %q check's detail is just its name", check.Name)
		}
	}

	// Every fatal failure reaches the operator through Failures too, and it must
	// be the same sentence rather than an identifier.
	for _, failure := range report.Failures {
		if !strings.Contains(failure, " ") {
			t.Errorf("a failure reads as an identifier rather than a sentence: %q", failure)
		}
	}
}

// TestTheStaleChainCheckNamesTheChainsItFound covers the check added for the
// chain-inventory defect specifically: it fires on a host still carrying the
// chains an older build left behind, and the first thing it ever did on a real
// server was report the three that server A was holding. What it reports has to
// be readable, and has to name them.
func TestTheStaleChainCheckNamesTheChainsItFound(t *testing.T) {
	service := &Service{backend: rules.NewFake()}

	live := rules.Live{
		Backend: rules.BackendFake,
		// The real inventory read off server A before the fix.
		Chains: []string{"prerouting", "output", "postrouting", "forward", "accounting",
			"mss", "marking"},
	}
	check := service.staleChainCheck(rules.Ruleset{}, live)

	if check.Ok {
		t.Fatal("a kernel holding seven chains for a ruleset that declares none is not in sync")
	}
	if check.Skipped {
		t.Fatal("the inventory was readable, so the check must not be skipped")
	}
	for _, name := range []string{"marking", "output"} {
		if !strings.Contains(check.Detail, name) {
			t.Errorf("the detail does not name the stale chain %q: %q", name, check.Detail)
		}
	}
	if strings.TrimSpace(check.Detail) == "" || !strings.Contains(check.Detail, " ") {
		t.Errorf("the detail is not a sentence: %q", check.Detail)
	}

	// And it passes once the kernel holds only what the ruleset declares.
	clean := service.staleChainCheck(rules.Ruleset{}, rules.Live{
		Backend: rules.BackendFake, Chains: []string{},
	})
	if !clean.Skipped && !clean.Ok {
		t.Errorf("an empty inventory reported a failure: %+v", clean)
	}
}
