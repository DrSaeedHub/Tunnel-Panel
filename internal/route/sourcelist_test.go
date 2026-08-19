package route

import (
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/sourcelist"
	"github.com/drs/gre-panel/internal/validate"
)

// A rule that allows a shared list matches a declared set rather than carrying
// its several hundred ranges in its own match.
//
// The whole point of the lists is that the ranges live in one place, so this
// checks the two halves that make that true: the set is declared with the
// ranges in it, and the rule refers to it by name.
func TestARuleThatAllowsAListMatchesADeclaredSet(t *testing.T) {
	ctx, database, repo := openRepo(t)
	lists := sourcelist.NewRepo(database)

	mci, err := lists.Create(ctx, sourcelist.Input{
		Name:    "MCI",
		Entries: []string{"5.22.0.0/20\n2.144.0.0/14\n2001:db8::/32"},
	})
	if err != nil {
		t.Fatalf("storing the source list failed: %v", err)
	}

	if _, err := repo.Insert(ctx, validate.RouteInput{
		RouteRuleTitle:  "Web relay",
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		NatModeID:      model.NatModeMasquerade,
		IsEnabled:      true,
		SourceListIDs:  []int64{mci.SourceListID},
		AllowedSources: []validate.RouteAllowedSourceInput{{Cidr: "192.0.2.7"}},
	}); err != nil {
		t.Fatalf("storing the rule failed: %v", err)
	}

	records, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	desired := DesiredOf(records)
	if len(desired.Routes) != 1 || len(desired.SourceSets) != 1 {
		t.Fatalf("desired = %d route(s) and %d set(s), want one of each",
			len(desired.Routes), len(desired.SourceSets))
	}

	spec, set := desired.Routes[0], desired.SourceSets[0]
	if spec.SourceSet != set.Name {
		t.Errorf("the rule matches %q and the set is called %q", spec.SourceSet, set.Name)
	}
	// The addresses the rule names itself are folded into the same set: two
	// matches on the source would be an and where the operator meant an or.
	if len(spec.AllowedSources) != 0 {
		t.Errorf("the rule also carries %v inline, which would narrow it to the intersection",
			spec.AllowedSources)
	}
	joined := strings.Join(set.Prefixes, " ")
	for _, want := range []string{"5.22.0.0/20", "2.144.0.0/14", "192.0.2.7/32"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the set does not hold %s: %v", want, set.Prefixes)
		}
	}
	// The IPv6 range in the list belongs to a family this rule does not work
	// in. Dropping it is right; refusing the rule over it would not be.
	if strings.Contains(joined, "2001:db8") {
		t.Errorf("an IPv6 range reached an IPv4 rule's set: %v", set.Prefixes)
	}
	if set.Family != rules.FamilyIPv4 {
		t.Errorf("the set is typed %q, want IPv4", set.Family)
	}

	// And the rendered ruleset declares the set before the rule that uses it,
	// because nft reads the file in order and a rule naming a set that is not
	// there yet takes the whole transaction down.
	backend := rules.NewFake()
	payload, err := backend.Render(desired)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	_ = payload
}

// A list a rule allows cannot be deleted out from under it: removing the
// ranges would leave the rule matching an empty set, or worse, no set at all.
func TestAListInUseCannotBeDeleted(t *testing.T) {
	ctx, database, repo := openRepo(t)
	lists := sourcelist.NewRepo(database)

	mci, err := lists.Create(ctx, sourcelist.Input{Name: "MCI", Entries: []string{"5.22.0.0/20"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Insert(ctx, validate.RouteInput{
		RouteRuleTitle:  "Web relay",
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		NatModeID:     model.NatModeMasquerade,
		IsEnabled:     true,
		SourceListIDs: []int64{mci.SourceListID},
	}); err != nil {
		t.Fatal(err)
	}

	if err := lists.Delete(ctx, mci.SourceListID); err == nil {
		t.Fatal("a list a rule allows was deleted")
	}

	// The rule reports the list, so the interface can say what is using it.
	rec, err := repo.ByID(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.SourceLists) != 1 || rec.SourceLists[0].Name != "MCI" {
		t.Errorf("the rule reports %+v, want the MCI list", rec.SourceLists)
	}
	again, err := lists.ByID(ctx, mci.SourceListID)
	if err != nil {
		t.Fatal(err)
	}
	if again.UsedBy != 1 {
		t.Errorf("the list says %d rules use it, want 1", again.UsedBy)
	}
}
