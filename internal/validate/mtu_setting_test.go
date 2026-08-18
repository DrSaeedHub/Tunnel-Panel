package validate

import (
	"context"
	"testing"
)

// TestTheUnderlayIsOnlyMeasuredWhenTheSettingSaysSo is the regression for a
// setting with no consumer.
//
// tunnel.auto_mtu_from_underlay is described on the Settings page as deciding
// whether the suggested MTU is computed from the underlay interface, and
// nothing anywhere read it. The advisory measured the egress interface and
// warned about a mismatch whatever the operator had asked for, so turning the
// setting off changed nothing at all.
//
// The overhead itself is still reported with the setting off: that is the
// arithmetic of the encapsulation and does not depend on any interface. What
// goes away is the recommendation and the mismatch warning, because both are
// statements about an underlay the panel has been told not to look at.
func TestTheUnderlayIsOnlyMeasuredWhenTheSettingSaysSo(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name            string
		auto            bool
		wantRecommended int
		wantUnderlay    int
		wantWarning     bool
	}{
		{
			name: "on, the default: the underlay is measured and a mismatch is reported",
			auto: true,
			// The fixture host's egress interface is 1500, and this request's
			// overhead is 28, so the advice is the documented 1472.
			wantRecommended: 1472, wantUnderlay: 1500, wantWarning: true,
		},
		{
			name: "off: no recommendation, no warning, nothing measured",
			auto: false,
			wantRecommended: 0, wantUnderlay: 0, wantWarning: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := newValidator(t, nil, fakeSettings{
				"tunnel.auto_mtu_from_underlay": tc.auto,
			})

			in := validInput()
			// Deliberately not the recommended value, so the advisory has
			// something to object to when it is allowed to.
			in.Mtu = 1400

			result, err := v.Validate(ctx, in)
			if err != nil {
				t.Fatalf("validation failed: %v", err)
			}

			if result.Mtu.Overhead != 28 {
				t.Errorf("overhead = %d, want 28 whatever the setting says: it is the size of the "+
					"headers, not a property of any interface", result.Mtu.Overhead)
			}
			if result.Mtu.Recommended != tc.wantRecommended {
				t.Errorf("recommended = %d, want %d", result.Mtu.Recommended, tc.wantRecommended)
			}
			if result.Mtu.UnderlayMtu != tc.wantUnderlay {
				t.Errorf("underlay MTU = %d, want %d", result.Mtu.UnderlayMtu, tc.wantUnderlay)
			}

			_, warned := result.Mtu.Warning()
			if warned != tc.wantWarning {
				t.Errorf("a mismatch warning was raised = %v, want %v", warned, tc.wantWarning)
			}
		})
	}
}
