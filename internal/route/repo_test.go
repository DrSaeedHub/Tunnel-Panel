package route

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// openRepo returns a repository over a fresh database.
func openRepo(t *testing.T) (context.Context, *db.DB, *Repo) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("opening the database failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the database failed: %v", err)
	}
	// A tunnel for the rules to point at. The foreign key is real, so a rule
	// naming a tunnel that does not exist is refused by the database — which is
	// why validation checks it first and answers on the field instead.
	now := model.NowUTC()
	if _, err := database.Write.ExecContext(ctx, `
		INSERT INTO Tunnel (TunnelID, TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName,
			LocalEndpoint, RemoteEndpoint, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (3, ?, ?, ?, 'gre-a-1', '203.0.113.10', '198.51.100.20', ?, ?, 0)`,
		model.TunnelTypeGRE, model.TunnelSideA, model.PersistenceTypeSystemd, now, now); err != nil {
		t.Fatalf("seeding a tunnel failed: %v", err)
	}
	return ctx, database, NewRepo(database)
}

// sampleInput is a complete rule: two destinations, an allowlist, and every
// option that has to survive a round trip through the database.
func sampleInput() validate.RouteInput {
	fwmark := int64(100)
	maxConns := int64(25)
	rate := int64(120)
	tunnelID := int64(3)
	return validate.RouteInput{
		RouteRuleTitle:  "Web relay",
		Description:     "Relays the public web port to the far end of the tunnel",
		RouteProtocolID: model.RouteProtocolBoth,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 20000, BindPortRangeEnd: 20100,
		BindInterface:      "eth0",
		DestinationAddress: "172.31.7.2", DestinationPort: 30000, DestinationPortRangeEnd: 30100,
		NatModeID: model.NatModeSnat, SnatAddress: "203.0.113.10",
		LoadBalanceModeID: model.LoadBalanceModeWeighted,
		TunnelID:          &tunnelID,
		Destinations: []validate.RouteDestinationInput{
			{Address: "172.31.7.2", Port: 30000, PortRangeEnd: 30100, Weight: 3, IsEnabled: true},
			{Address: "172.31.7.6", Port: 30000, PortRangeEnd: 30100, Weight: 1, IsEnabled: true},
		},
		AllowedSources: []validate.RouteAllowedSourceInput{
			{Cidr: "10.0.0.0/8", Description: "the office"},
		},
		IsClampMssToPmtu:         true,
		IsIncludeLocalOriginated: true,
		IsLoggingEnabled:         true,
		FwMark:                   &fwmark,
		MaxConnectionsPerSource:  &maxConns,
		ConnectionRateLimit:      &rate,
		IsEnabled:                true,
	}
}

func TestInsertAndReadBackEveryField(t *testing.T) {
	ctx, _, repo := openRepo(t)

	id, err := repo.Insert(ctx, sampleInput())
	if err != nil {
		t.Fatalf("Insert returned an unexpected error: %v", err)
	}
	rec, err := repo.ByID(ctx, id)
	if err != nil {
		t.Fatalf("ByID returned an unexpected error: %v", err)
	}

	if rec.RouteRuleTitle != "Web relay" || rec.Description == "" {
		t.Errorf("the name or description did not survive: %+v", rec.RouteRule)
	}
	if rec.RouteProtocolID != model.RouteProtocolBoth || rec.NatModeID != model.NatModeSnat {
		t.Errorf("the lookups did not survive: %+v", rec.RouteRule)
	}
	if rec.BindPortRangeEnd == nil || *rec.BindPortRangeEnd != 20100 {
		t.Errorf("the bind range did not survive: %+v", rec.BindPortRangeEnd)
	}
	if rec.BindInterface == nil || *rec.BindInterface != "eth0" {
		t.Errorf("the bind interface did not survive: %+v", rec.BindInterface)
	}
	if rec.SnatAddress == nil || *rec.SnatAddress != "203.0.113.10" {
		t.Errorf("the SNAT address did not survive: %+v", rec.SnatAddress)
	}
	if rec.TunnelID == nil || *rec.TunnelID != 3 {
		t.Errorf("the tunnel binding did not survive: %+v", rec.TunnelID)
	}
	if rec.FwMark == nil || *rec.FwMark != 100 {
		t.Errorf("the firewall mark did not survive: %+v", rec.FwMark)
	}
	if rec.MaxConnectionsPerSource == nil || rec.ConnectionRateLimit == nil {
		t.Errorf("the limits did not survive: %+v", rec.RouteRule)
	}
	if !rec.IsClampMssToPmtu || !rec.IsIncludeLocalOriginated || !rec.IsLoggingEnabled {
		t.Errorf("the boolean options did not survive: %+v", rec.RouteRule)
	}
	if rec.ApplyStatusID != model.ApplyStatusPending {
		t.Errorf("a new rule starts at %d, want Pending", rec.ApplyStatusID)
	}

	// The children come back with the rule, because a rule without them is not
	// a usable description of anything.
	if len(rec.Destinations) != 2 {
		t.Fatalf("got %d destinations, want 2: %+v", len(rec.Destinations), rec.Destinations)
	}
	if rec.Destinations[0].Weight != 3 || rec.Destinations[1].Weight != 1 {
		t.Errorf("the weights did not survive: %+v", rec.Destinations)
	}
	if len(rec.AllowedSources) != 1 || rec.AllowedSources[0].Cidr != "10.0.0.0/8" {
		t.Errorf("the allowlist did not survive: %+v", rec.AllowedSources)
	}

	// And what comes back has to render, or the round trip lost something the
	// rule layer needs.
	spec := rec.Spec()
	if err := (rules.Ruleset{Routes: []rules.RouteSpec{spec}}).Check(); err != nil {
		t.Errorf("the stored rule cannot be rendered: %v", err)
	}
	if len(spec.Destinations) != 2 || spec.LoadBalance != rules.LoadBalanceWeighted {
		t.Errorf("the rendering input is wrong: %+v", spec)
	}
}

// TestASingleDestinationRuleHasExactlyOneRow is §4: the schema does not
// special-case a rule with one destination, so nothing below it has to either.
func TestASingleDestinationRuleHasExactlyOneRow(t *testing.T) {
	ctx, _, repo := openRepo(t)

	in := validate.RouteInput{
		RouteRuleTitle: "Simple", RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		NatModeID: model.NatModeMasquerade, IsEnabled: true,
	}
	id, err := repo.Insert(ctx, in)
	if err != nil {
		t.Fatalf("Insert returned an unexpected error: %v", err)
	}
	rec, err := repo.ByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Destinations) != 1 {
		t.Fatalf("got %d destination rows, want exactly 1", len(rec.Destinations))
	}
	if rec.Destinations[0].Address != "198.51.100.20" || rec.Destinations[0].Weight != 1 {
		t.Errorf("the single destination is wrong: %+v", rec.Destinations[0])
	}
}

func TestUpdateReplacesTheChildren(t *testing.T) {
	ctx, _, repo := openRepo(t)
	id, err := repo.Insert(ctx, sampleInput())
	if err != nil {
		t.Fatal(err)
	}

	in := sampleInput()
	in.RouteRuleID = id
	in.Destinations = []validate.RouteDestinationInput{
		{Address: "172.31.7.2", Port: 30000, PortRangeEnd: 30100, Weight: 1, IsEnabled: true},
	}
	in.AllowedSources = nil
	if err := repo.Update(ctx, id, in); err != nil {
		t.Fatalf("Update returned an unexpected error: %v", err)
	}

	rec, err := repo.ByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Destinations) != 1 {
		t.Errorf("got %d destinations after the update, want 1: %+v", len(rec.Destinations), rec.Destinations)
	}
	if len(rec.AllowedSources) != 0 {
		t.Errorf("the allowlist was not cleared: %+v", rec.AllowedSources)
	}
}

func TestSoftDeleteHidesTheRuleAndItsChildren(t *testing.T) {
	ctx, database, repo := openRepo(t)
	id, err := repo.Insert(ctx, sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SoftDelete(ctx, id); err != nil {
		t.Fatalf("SoftDelete returned an unexpected error: %v", err)
	}

	if _, err := repo.ByID(ctx, id); err == nil {
		t.Error("a deleted rule was still returned")
	}
	// Soft, not hard: the row is still there for the audit trail.
	var count int
	if err := database.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM RouteRule WHERE RouteRuleID = ?`, id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("the row was hard-deleted; business rows are never removed")
	}
	var liveChildren int
	if err := database.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM RouteDestination WHERE RouteRuleID = ? AND IsDeleted = 0`,
		id).Scan(&liveChildren); err != nil {
		t.Fatal(err)
	}
	if liveChildren != 0 {
		t.Errorf("%d destinations outlived their rule", liveChildren)
	}
}

// TestDesiredRulesetContainsOnlyEnabledRules: disabling a rule is what makes it
// stop forwarding, so it must contribute nothing to what is applied.
func TestDesiredRulesetContainsOnlyEnabledRules(t *testing.T) {
	ctx, _, repo := openRepo(t)

	first := sampleInput()
	if _, err := repo.Insert(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := sampleInput()
	second.RouteRuleTitle = "Disabled relay"
	second.BindPort, second.BindPortRangeEnd = 40000, 40100
	second.IsEnabled = false
	if _, err := repo.Insert(ctx, second); err != nil {
		t.Fatal(err)
	}

	desired, err := repo.Desired(ctx)
	if err != nil {
		t.Fatalf("Desired returned an unexpected error: %v", err)
	}
	if len(desired.Routes) != 1 {
		t.Fatalf("the desired ruleset has %d rules, want only the enabled one", len(desired.Routes))
	}
	if desired.Routes[0].Title != "Web relay" {
		t.Errorf("the wrong rule is in the desired ruleset: %+v", desired.Routes[0])
	}
}

// TestReorderWritesTheEmissionOrder covers behaviour an operator can see:
// overlapping matches resolve first-match-wins, so the order is a setting.
func TestReorderWritesTheEmissionOrder(t *testing.T) {
	ctx, _, repo := openRepo(t)

	var ids []int64
	for _, title := range []string{"first", "second", "third"} {
		in := sampleInput()
		in.RouteRuleTitle = title
		in.BindPort, in.BindPortRangeEnd = 20000+len(ids)*1000, 20100+len(ids)*1000
		in.DestinationPort, in.DestinationPortRangeEnd = 30000+len(ids)*1000, 30100+len(ids)*1000
		in.Destinations = []validate.RouteDestinationInput{{
			Address: "172.31.7.2", Port: 30000 + len(ids)*1000, PortRangeEnd: 30100 + len(ids)*1000,
			Weight: 1, IsEnabled: true,
		}}
		id, err := repo.Insert(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	// A new rule goes to the end rather than shuffling the others.
	records, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, rec := range records {
		if rec.RouteRuleID != ids[i] {
			t.Fatalf("rules are listed in the wrong order: %+v", records)
		}
	}

	reversed := []int64{ids[2], ids[1], ids[0]}
	if err := repo.Reorder(ctx, reversed); err != nil {
		t.Fatalf("Reorder returned an unexpected error: %v", err)
	}
	records, err = repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, rec := range records {
		if rec.RouteRuleID != reversed[i] {
			t.Fatalf("the new order was not applied: %+v", records)
		}
	}

	// And an identifier that is not there is refused rather than silently
	// reordering the rest.
	if err := repo.Reorder(ctx, []int64{9999}); err == nil {
		t.Error("reordering a rule that does not exist was accepted")
	}
}

func TestApplyStatusIsRecorded(t *testing.T) {
	ctx, _, repo := openRepo(t)
	id, err := repo.Insert(ctx, sampleInput())
	if err != nil {
		t.Fatal(err)
	}

	if err := repo.SetApplyStatus(ctx, id, model.ApplyStatusApplied, nil); err != nil {
		t.Fatal(err)
	}
	rec, err := repo.ByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ApplyStatusID != model.ApplyStatusApplied || rec.LastAppliedDate == nil {
		t.Errorf("a successful apply was not recorded: %+v", rec.RouteRule)
	}
	if rec.LastApplyError != nil {
		t.Errorf("a successful apply left an error behind: %v", *rec.LastApplyError)
	}

	if err := repo.SetApplyStatus(ctx, id, model.ApplyStatusFailed, context.DeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	rec, err = repo.ByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ApplyStatusID != model.ApplyStatusFailed || rec.LastApplyError == nil {
		t.Errorf("a failed apply was not recorded: %+v", rec.RouteRule)
	}
	// The date of the last successful apply survives a later failure, because
	// "when did this last work" is the question it answers.
	if rec.LastAppliedDate == nil {
		t.Error("the last successful apply date was cleared by a failure")
	}
}

func TestExistingRoutesFeedValidation(t *testing.T) {
	ctx, _, repo := openRepo(t)
	if _, err := repo.Insert(ctx, sampleInput()); err != nil {
		t.Fatal(err)
	}

	existing, err := repo.ForValidation().ExistingRoutes(ctx)
	if err != nil {
		t.Fatalf("ExistingRoutes returned an unexpected error: %v", err)
	}
	if len(existing) != 1 {
		t.Fatalf("got %d rules, want 1", len(existing))
	}
	if existing[0].BindPort != 20000 || existing[0].BindPortRangeEnd != 20100 {
		t.Errorf("the listener range did not reach validation: %+v", existing[0])
	}
}

func TestInputRoundTripsThroughTheRecord(t *testing.T) {
	ctx, _, repo := openRepo(t)
	id, err := repo.Insert(ctx, sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := repo.ByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	// An update that mentions one field starts from what the rule already is,
	// so the request shape has to carry everything back.
	in := Input(rec)
	in.Description = "changed"
	if err := repo.Update(ctx, id, in); err != nil {
		t.Fatalf("Update from a round-tripped input failed: %v", err)
	}
	after, err := repo.ByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Description != "changed" {
		t.Errorf("the change was not stored: %q", after.Description)
	}
	if after.BindPort != rec.BindPort || len(after.Destinations) != len(rec.Destinations) ||
		len(after.AllowedSources) != len(rec.AllowedSources) {
		t.Errorf("a field-level change lost something else:\nbefore %+v\nafter  %+v", rec, after)
	}
}

// A rule with no allowed sources and no extra destinations still has to answer
// with two arrays, because a nil slice marshals to JSON null and null is not a
// list. The edit dialog seeds itself with route.allowed_sources.map(...) and
// route.destinations.slice(1), both of which throw on null — so every rule
// created without an allowed-source list, which is nearly all of them, could
// not be opened for editing at all. The page went to the error boundary.
func TestAStoredRuleAlwaysAnswersWithListsNotNull(t *testing.T) {
	ctx, _, repo := openRepo(t)

	id, err := repo.Insert(ctx, validate.RouteInput{
		RouteRuleTitle:  "no children",
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 9400,
		DestinationAddress: "198.51.100.20", DestinationPort: 9400,
		NatModeID: model.NatModeMasquerade, IsEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	byID, err := repo.ByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	assertListsNotNull(t, "ByID", byID)

	all, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected one rule, got %d", len(all))
	}
	assertListsNotNull(t, "List", all[0])
}

func assertListsNotNull(t *testing.T, from string, rec Record) {
	t.Helper()

	if rec.AllowedSources == nil {
		t.Errorf("%s returned a nil AllowedSources, which becomes null on the wire", from)
	}
	if rec.Destinations == nil {
		t.Errorf("%s returned a nil Destinations, which becomes null on the wire", from)
	}

	// The wire format is what the dialog actually reads, so assert on that
	// rather than on the Go value alone.
	encoded, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling the %s record: %v", from, err)
	}
	for _, field := range []string{`"allowed_sources":null`, `"destinations":null`} {
		if strings.Contains(string(encoded), field) {
			t.Errorf("%s serialises %s; the frontend calls .map() on it and the page dies", from, field)
		}
	}
}
