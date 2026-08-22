package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/pairing"
	"github.com/drs/gre-panel/internal/rules"
)

// session sets the panel up and signs in, returning a client that carries the
// cookies and the CSRF token the way the frontend does.
func session(t *testing.T, h *harness) (*client, string) {
	t.Helper()
	c := newClient(t, h)
	api := h.cfg.APIBasePath()

	resp, body := c.request(http.MethodPost, api+"/auth/setup",
		map[string]string{"username": testUser, "password": testPassword})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d\nbody: %s", resp.StatusCode, body)
	}
	return c, api
}

// createTunnel asks the API for a tunnel. Runtime persistence keeps the whole
// apply inside the fake link manager, which is what makes the test hermetic.
func createTunnel(t *testing.T, c *client, api string, extra map[string]any) map[string]any {
	t.Helper()
	payload := map[string]any{
		"local_endpoint":      "203.0.113.10",
		"remote_endpoint":     "198.51.100.20",
		"persistence_type_id": model.PersistenceTypeRuntime,
		"is_enabled":          true,
	}
	for k, v := range extra {
		payload[k] = v
	}

	resp, body := c.request(http.MethodPost, api+"/tunnels", payload)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /tunnels = %d, want 201\nbody: %s", resp.StatusCode, body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decoding the response failed: %v\nbody: %s", err, body)
	}
	return decoded
}

func tunnelID(t *testing.T, created map[string]any) string {
	t.Helper()
	tunnel, ok := created["tunnel"].(map[string]any)
	if !ok {
		t.Fatalf("the response carries no tunnel: %+v", created)
	}
	id, ok := tunnel["tunnel_id"].(float64)
	if !ok {
		t.Fatalf("the tunnel carries no identifier: %+v", tunnel)
	}
	return jsonNumber(id)
}

// jsonNumber renders an identifier decoded from JSON, which arrives as a
// float64, back into the path segment form.
func jsonNumber(v float64) string { return strconv.FormatInt(int64(v), 10) }

// ---------------------------------------------------------------- lifecycle

func TestCreateListGetAndDeleteATunnel(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	created := createTunnel(t, c, api, nil)
	id := tunnelID(t, created)

	// The response carries the plan and the verification report, not just "ok".
	if _, ok := created["plan"]; !ok {
		t.Fatal("the create response must carry the plan that was carried out")
	}
	verification, ok := created["verification"].(map[string]any)
	if !ok || verification["ok"] != true {
		t.Fatalf("the create response must carry a passing verification: %+v", created["verification"])
	}

	resp, body := c.request(http.MethodGet, api+"/tunnels", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /tunnels = %d\nbody: %s", resp.StatusCode, body)
	}
	var list struct {
		Tunnels []map[string]any `json:"tunnels"`
		Total   int              `json:"total"`
		Limit   int              `json:"limit"`
		Offset  int              `json:"offset"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || len(list.Tunnels) != 1 {
		t.Fatalf("the list reports %d tunnels: %s", list.Total, body)
	}
	// The list separates what the panel wants from what the kernel has.
	observed, ok := list.Tunnels[0]["observed"].(map[string]any)
	if !ok || observed["exists"] != true {
		t.Fatalf("the list must report the live state separately: %+v", list.Tunnels[0])
	}
	if observed["oper_state"] != "UNKNOWN" {
		t.Fatalf("operational state = %v; a healthy GRE tunnel reports UNKNOWN", observed["oper_state"])
	}

	resp, body = c.request(http.MethodGet, api+"/tunnels/"+id, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /tunnels/%s = %d\nbody: %s", id, resp.StatusCode, body)
	}

	resp, body = c.request(http.MethodDelete, api+"/tunnels/"+id, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /tunnels/%s = %d\nbody: %s", id, resp.StatusCode, body)
	}
	var report struct {
		InterfaceFound bool `json:"interface_found"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if !report.InterfaceFound {
		t.Fatal("delete must report exactly what it found")
	}

	resp, _ = c.request(http.MethodGet, api+"/tunnels/"+id, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET a deleted tunnel = %d, want 404", resp.StatusCode)
	}
}

// The legacy bug, at the API boundary: an unparseable endpoint is a 422 with a
// field-level error, not a 500 and certainly not a 201.
func TestCreateRejectsAnUnparseableEndpoint(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/tunnels", map[string]any{
		"local_endpoint":  "not-an-ip",
		"remote_endpoint": "198.51.100.20",
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("POST /tunnels with a bad endpoint = %d, want 422\nbody: %s", resp.StatusCode, body)
	}

	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != CodeValidationFailed {
		t.Fatalf("error code = %q", env.Error.Code)
	}
	if env.Error.Field != "local_endpoint" {
		t.Fatalf("the error must name the field, got %q", env.Error.Field)
	}
	if _, ok := env.Error.Details["local_endpoint"]; !ok {
		t.Fatalf("the details must carry a message per field: %+v", env.Error.Details)
	}
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("the kernel was changed by a rejected request: %v", calls)
	}
}

func TestPreviewChangesNothing(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	h.links.Reset()

	resp, body := c.request(http.MethodPost, api+"/tunnels/preview", map[string]any{
		"local_endpoint":  "203.0.113.10",
		"remote_endpoint": "198.51.100.20",
		"is_enabled":      true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /tunnels/preview = %d\nbody: %s", resp.StatusCode, body)
	}

	var preview struct {
		Plan struct {
			Steps []map[string]any `json:"steps"`
			Files []struct {
				Kind    string `json:"kind"`
				Path    string `json:"path"`
				Content string `json:"content"`
			} `json:"files"`
			Verification []string `json:"verification"`
		} `json:"plan"`
		Mtu struct {
			Recommended int `json:"recommended"`
			Overhead    int `json:"overhead"`
		} `json:"mtu"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}

	if len(preview.Plan.Steps) == 0 {
		t.Fatal("the preview returned no steps")
	}
	if len(preview.Plan.Files) != 1 || preview.Plan.Files[0].Kind != "systemd_unit" {
		t.Fatalf("the preview must return the unit body: %+v", preview.Plan.Files)
	}
	if !strings.Contains(preview.Plan.Files[0].Content, "ExecStart=/sbin/ip link add name gre-a-1 type gre") {
		t.Fatalf("the unit body is not the real one:\n%s", preview.Plan.Files[0].Content)
	}
	if preview.Mtu.Overhead != 28 || preview.Mtu.Recommended != 1472 {
		t.Fatalf("the MTU advisory is wrong: %+v", preview.Mtu)
	}
	if len(preview.Plan.Verification) == 0 {
		t.Fatal("the preview must state what will be verified")
	}

	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("preview changed the kernel: %v", calls)
	}
	if len(h.runner.Calls()) != 0 {
		t.Fatalf("preview ran commands: %v", h.runner.CommandLines())
	}
}

func TestUpAndDownAndReapply(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	for _, action := range []string{"down", "up", "reapply", "restart"} {
		resp, body := c.request(http.MethodPost, api+"/tunnels/"+id+"/"+action, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /tunnels/%s/%s = %d\nbody: %s", id, action, resp.StatusCode, body)
		}
		var out struct {
			Action       string `json:"action"`
			Verification struct {
				Ok bool `json:"ok"`
			} `json:"verification"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if !out.Verification.Ok {
			t.Fatalf("%s did not verify: %s", action, body)
		}
	}
}

func TestUpdateRequiresConfirmationForARebuild(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	created := createTunnel(t, c, api, nil)
	id := tunnelID(t, created)

	change := map[string]any{
		"local_endpoint":      "203.0.113.10",
		"remote_endpoint":     "198.51.100.99",
		"persistence_type_id": model.PersistenceTypeRuntime,
		"is_enabled":          true,
	}
	resp, body := c.request(http.MethodPatch, api+"/tunnels/"+id, change)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("PATCH without confirmation = %d, want 409\nbody: %s", resp.StatusCode, body)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != CodeRecreateRequired {
		t.Fatalf("error code = %q", env.Error.Code)
	}
	if env.Error.Field != "confirm_recreate" {
		t.Fatalf("the error must name the field that unblocks it, got %q", env.Error.Field)
	}

	change["confirm_recreate"] = true
	resp, body = c.request(http.MethodPatch, api+"/tunnels/"+id, change)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH with confirmation = %d\nbody: %s", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------- addresses

func TestAddressEndpoints(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	resp, body := c.request(http.MethodGet, api+"/tunnels/"+id+"/addresses", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET addresses = %d\nbody: %s", resp.StatusCode, body)
	}
	var listed addressesResponse
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Addresses) != 1 || len(listed.Observed) != 1 {
		t.Fatalf("addresses = %+v, observed = %v", listed.Addresses, listed.Observed)
	}

	resp, body = c.request(http.MethodPost, api+"/tunnels/"+id+"/addresses", map[string]any{
		"address": "10.10.5.1", "prefix_length": 30,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST an address = %d\nbody: %s", resp.StatusCode, body)
	}
	observed, err := h.links.Get(context.Background(), "gre-a-1")
	if err != nil {
		t.Fatal(err)
	}
	if !observed.HasAddress(link.Address{Address: "10.10.5.1", PrefixLength: 30}) {
		t.Fatalf("the address was not applied to the kernel: %+v", observed.Addresses)
	}

	resp, body = c.request(http.MethodDelete, api+"/tunnels/"+id+"/addresses", map[string]any{
		"address": "10.10.5.1", "prefix_length": 30,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE an address = %d\nbody: %s", resp.StatusCode, body)
	}
	observed, _ = h.links.Get(context.Background(), "gre-a-1")
	if observed.HasAddress(link.Address{Address: "10.10.5.1", PrefixLength: 30}) {
		t.Fatal("the address was not removed from the kernel")
	}
}

// ---------------------------------------------------------------- pairing

func TestPairingCodeRoundTripThroughTheApi(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	resp, body := c.request(http.MethodGet, api+"/tunnels/"+id+"/pairing-code", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET the pairing code = %d\nbody: %s", resp.StatusCode, body)
	}
	var produced struct {
		PairingCode string `json:"pairing_code"`
		Summary     struct {
			FromSide string `json:"from_side"`
			ToSide   string `json:"to_side"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(body, &produced); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(produced.PairingCode, "v1.") {
		t.Fatalf("the code is not versioned: %q", produced.PairingCode)
	}
	if produced.Summary.FromSide != "A" || produced.Summary.ToSide != "B" {
		t.Fatalf("summary = %+v", produced.Summary)
	}

	resp, body = c.request(http.MethodPost, api+"/tunnels/from-pairing-code",
		map[string]any{"pairing_code": produced.PairingCode})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST from-pairing-code = %d\nbody: %s", resp.StatusCode, body)
	}
	var decoded struct {
		Tunnel struct {
			TunnelSideID   int64  `json:"tunnel_side_id"`
			InterfaceName  string `json:"interface_name"`
			LocalEndpoint  string `json:"local_endpoint"`
			RemoteEndpoint string `json:"remote_endpoint"`
			Addresses      []struct {
				Address     string `json:"address"`
				PeerAddress string `json:"peer_address"`
			} `json:"addresses"`
		} `json:"tunnel"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Tunnel.TunnelSideID != model.TunnelSideB {
		t.Fatalf("the side was not flipped: %d", decoded.Tunnel.TunnelSideID)
	}
	if decoded.Tunnel.LocalEndpoint != "198.51.100.20" || decoded.Tunnel.RemoteEndpoint != "203.0.113.10" {
		t.Fatalf("the endpoints were not mirrored: %+v", decoded.Tunnel)
	}
	if decoded.Tunnel.Addresses[0].Address != "172.17.1.2" ||
		decoded.Tunnel.Addresses[0].PeerAddress != "172.17.1.1" {
		t.Fatalf("the addresses were not mirrored: %+v", decoded.Tunnel.Addresses)
	}
	// The far end renders its own name from its own template.
	if decoded.Tunnel.InterfaceName != "gre-b-1" {
		t.Fatalf("the suggested name is %q, want one rendered from this server's template",
			decoded.Tunnel.InterfaceName)
	}

	// Nothing was created by decoding.
	resp, body = c.request(http.MethodGet, api+"/tunnels", nil)
	var list struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(body, &list)
	if resp.StatusCode != http.StatusOK || list.Total != 1 {
		t.Fatalf("decoding a pairing code created something: total = %d", list.Total)
	}
}

func TestCorruptPairingCodeIsRejected(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/tunnels/from-pairing-code",
		map[string]any{"pairing_code": "v1.notarealcode"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a corrupt code = %d, want 422\nbody: %s", resp.StatusCode, body)
	}
	var env ErrorEnvelope
	_ = json.Unmarshal(body, &env)
	if env.Error.Field != "pairing_code" {
		t.Fatalf("the error must name the field: %+v", env.Error)
	}
}

/*
The address pool a pairing code names.

A pool id is a row in one server's database. The code used to carry the id and
the far end used to take it at face value, so importing a code from a server
whose pool happened to be number 41 filled the form in with "address pool 41",
which on this host was nothing at all -- and the create failed on a value the
operator never chose and could not correct from the form.

The code now carries the pool's range. A pool here with the same range is used;
otherwise the tunnel keeps the addresses the code carried, which the far end has
already committed to, and the response says what the missing pool would be so
the panel can offer to create it.
*/

func TestAPairingCodePoolIsMatchedByRangeNotById(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	_, body := c.request(http.MethodGet, api+"/tunnels/"+id+"/pairing-code", nil)
	var produced struct {
		PairingCode string `json:"pairing_code"`
	}
	_ = json.Unmarshal(body, &produced)

	payload, err := pairing.Decode(produced.PairingCode)
	if err != nil {
		t.Fatal(err)
	}
	if payload.AddressPoolCidr != "172.17.0.0/16" {
		t.Fatalf("the code carries pool cidr %q, want the range the tunnel was allocated from",
			payload.AddressPoolCidr)
	}

	decoded := decodePairingCode(t, c, api, produced.PairingCode)
	if decoded.Pool == nil || decoded.Pool.Status != "matched" {
		t.Fatalf("pool hint = %+v, want the local pool with the same range", decoded.Pool)
	}
	if decoded.Tunnel.AddressPoolID == nil || *decoded.Tunnel.AddressPoolID != *decoded.Pool.AddressPoolID {
		t.Fatalf("the tunnel was not put on this server's matching pool: %+v", decoded.Tunnel)
	}
}

func TestAPairingCodePoolThisServerDoesNotHaveIsReportedNotImposed(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	// A code from a server whose pool is its row 41 and whose range this host
	// has never heard of.
	poolID := int64(41)
	code, err := pairing.Encode(pairing.Payload{
		TunnelTypeID:            model.TunnelTypeGRE,
		TunnelSideID:            model.TunnelSideA,
		LocalEndpoint:           "203.0.113.10",
		RemoteEndpoint:          "198.51.100.20",
		Ttl:                     255,
		Mtu:                     1472,
		AddressPoolID:           &poolID,
		AddressPoolCidr:         "10.250.250.0/25",
		AddressPoolTitle:        "Free private range",
		AddressPoolPrefixLength: 30,
		Addresses: []pairing.PairAddress{
			{AddressA: "10.250.250.1", AddressB: "10.250.250.2", PrefixLength: 30, IsPrimary: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	decoded := decodePairingCode(t, c, api, code)
	// The far end's id is not imposed on this server: the form opens on the
	// addresses the code carried instead of on a pool that does not exist.
	if decoded.Tunnel.AddressPoolID != nil {
		t.Fatalf("address_pool_id = %d, want none: this server has no such pool",
			*decoded.Tunnel.AddressPoolID)
	}
	if len(decoded.Tunnel.Addresses) != 1 || decoded.Tunnel.Addresses[0].Address != "10.250.250.2" {
		t.Fatalf("the carried addresses were lost: %+v", decoded.Tunnel.Addresses)
	}
	// And the panel is told what to offer to create.
	if decoded.Pool == nil || decoded.Pool.Status != "missing" {
		t.Fatalf("pool hint = %+v, want the missing range described", decoded.Pool)
	}
	if decoded.Pool.Cidr != "10.250.250.0/25" || decoded.Pool.PrefixLength != 30 {
		t.Fatalf("pool hint = %+v, want the range and subnet size to create", decoded.Pool)
	}
}

func TestAPairingCodePoolThatIsDisabledHereIsNotSelected(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/pools", map[string]any{
		"address_pool_title": "Free private range", "cidr": "10.250.250.0/25",
		"prefix_length": 30, "is_enabled": false,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /pools = %d\nbody: %s", resp.StatusCode, body)
	}

	code, err := pairing.Encode(pairing.Payload{
		TunnelTypeID: model.TunnelTypeGRE, TunnelSideID: model.TunnelSideA,
		LocalEndpoint: "203.0.113.10", RemoteEndpoint: "198.51.100.20",
		Ttl: 255, Mtu: 1472,
		AddressPoolCidr: "10.250.250.0/25", AddressPoolPrefixLength: 30,
		Addresses: []pairing.PairAddress{
			{AddressA: "10.250.250.1", AddressB: "10.250.250.2", PrefixLength: 30, IsPrimary: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	decoded := decodePairingCode(t, c, api, code)
	// A disabled pool allocates nothing, so it is reported rather than chosen.
	if decoded.Tunnel.AddressPoolID != nil {
		t.Fatalf("address_pool_id = %d, want none: the matching pool is disabled",
			*decoded.Tunnel.AddressPoolID)
	}
	if decoded.Pool == nil || decoded.Pool.Status != "disabled" || decoded.Pool.AddressPoolID == nil {
		t.Fatalf("pool hint = %+v, want the disabled local pool named", decoded.Pool)
	}
}

type decodedPairingCode struct {
	Tunnel struct {
		AddressPoolID *int64 `json:"address_pool_id"`
		Addresses     []struct {
			Address     string `json:"address"`
			PeerAddress string `json:"peer_address"`
		} `json:"addresses"`
	} `json:"tunnel"`
	Pool *pairedPoolHint `json:"address_pool"`
}

func decodePairingCode(t *testing.T, c *client, api, code string) decodedPairingCode {
	t.Helper()
	resp, body := c.request(http.MethodPost, api+"/tunnels/from-pairing-code",
		map[string]any{"pairing_code": code})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST from-pairing-code = %d\nbody: %s", resp.StatusCode, body)
	}
	var decoded decodedPairingCode
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

// ---------------------------------------------------------------- side info

func TestSideInfoServesTheCanonicalText(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodGet, api+"/tunnels/side-info", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET side-info = %d\nbody: %s", resp.StatusCode, body)
	}
	var info struct {
		Summary string `json:"summary"`
		Sides   []struct {
			Slot            string `json:"slot"`
			Label           string `json:"label"`
			AddressInSubnet string `json:"address_in_subnet"`
		} `json:"sides"`
		IdenticalOnBothEnds []string `json:"identical_on_both_ends"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}

	// The specification's own sentences, verbatim.
	for _, phrase := range []string{
		"A and B are simply the two ends of one tunnel",
		"The choice is arbitrary and neither end has a special role",
		"Use A on the first server you set up and B on the second",
		"the tunnel will appear up while carrying no traffic",
	} {
		if !strings.Contains(info.Summary, phrase) {
			t.Fatalf("the canonical text is missing %q:\n%s", phrase, info.Summary)
		}
	}
	// It must not reference any country, region or deployment scenario.
	for _, forbidden := range []string{"region", "country", "abroad", "overseas"} {
		if strings.Contains(strings.ToLower(info.Summary), forbidden) {
			t.Fatalf("the text references %q, which it must not", forbidden)
		}
	}

	if len(info.Sides) != 2 || info.Sides[0].Slot != "a" || info.Sides[1].Slot != "b" {
		t.Fatalf("sides = %+v", info.Sides)
	}
	if !strings.Contains(info.Sides[0].AddressInSubnet, "first") ||
		!strings.Contains(info.Sides[1].AddressInSubnet, "second") {
		t.Fatalf("the table must state which address each slot takes: %+v", info.Sides)
	}
	if len(info.IdenticalOnBothEnds) == 0 {
		t.Fatal("the response must list what has to match on both ends")
	}
}

// ---------------------------------------------------------------- pools

func TestPoolCrudAndNextFree(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodGet, api+"/pools", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /pools = %d\nbody: %s", resp.StatusCode, body)
	}
	var listed struct {
		Pools []struct {
			AddressPoolID int64  `json:"address_pool_id"`
			Cidr          string `json:"cidr"`
			IsPublicRange bool   `json:"is_public_range"`
			IsEnabled     bool   `json:"is_enabled"`
			Capacity      struct {
				Scheme    string `json:"scheme"`
				Capacity  int64  `json:"capacity"`
				MaxNumber int64  `json:"max_tunnel_number"`
			} `json:"capacity"`
		} `json:"pools"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Total != 4 {
		t.Fatalf("the four seeded pools should be listed, got %d", listed.Total)
	}
	// The capacity is derived rather than assumed: a /16 of /30s holds 256.
	if listed.Pools[0].Capacity.Capacity != 256 || listed.Pools[0].Capacity.MaxNumber != 255 {
		t.Fatalf("capacity = %+v", listed.Pools[0].Capacity)
	}
	// The two legacy compatibility pools ship disabled and flagged.
	for _, pool := range listed.Pools {
		if strings.HasPrefix(pool.Cidr, "109.194.") || strings.HasPrefix(pool.Cidr, "87.107.") {
			if !pool.IsPublicRange || pool.IsEnabled {
				t.Fatalf("%s must be flagged public and ship disabled: %+v", pool.Cidr, pool)
			}
		}
	}

	resp, body = c.request(http.MethodGet, api+"/pools/10/next-free", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET next-free = %d\nbody: %s", resp.StatusCode, body)
	}
	var next struct {
		Allocation struct {
			Subnet       string `json:"subnet"`
			TunnelNumber int64  `json:"tunnel_number"`
			AddressA     string `json:"address_a"`
			AddressB     string `json:"address_b"`
		} `json:"allocation"`
	}
	if err := json.Unmarshal(body, &next); err != nil {
		t.Fatal(err)
	}
	if next.Allocation.Subnet != "172.17.1.0/30" || next.Allocation.TunnelNumber != 1 {
		t.Fatalf("allocation = %+v", next.Allocation)
	}
	if next.Allocation.AddressA != "172.17.1.1" || next.Allocation.AddressB != "172.17.1.2" {
		t.Fatalf("the two ends' addresses are wrong: %+v", next.Allocation)
	}

	// Create, update and delete a pool of our own.
	resp, body = c.request(http.MethodPost, api+"/pools", map[string]any{
		"address_pool_title": "Test range",
		"cidr":               "192.168.50.0/24",
		"prefix_length":      30,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /pools = %d\nbody: %s", resp.StatusCode, body)
	}
	var created struct {
		AddressPoolID int64 `json:"address_pool_id"`
		Capacity      struct {
			Scheme   string `json:"scheme"`
			Capacity int64  `json:"capacity"`
		} `json:"capacity"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	// A /24 is too small for the third-octet scheme, so it packs densely.
	if created.Capacity.Scheme != "dense" || created.Capacity.Capacity != 64 {
		t.Fatalf("capacity = %+v", created.Capacity)
	}

	id := jsonNumber(float64(created.AddressPoolID))
	resp, body = c.request(http.MethodPut, api+"/pools/"+id, map[string]any{
		"address_pool_title": "Renamed range",
		"cidr":               "192.168.50.0/24",
		"prefix_length":      31,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /pools/%s = %d\nbody: %s", id, resp.StatusCode, body)
	}

	resp, body = c.request(http.MethodDelete, api+"/pools/"+id, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /pools/%s = %d\nbody: %s", id, resp.StatusCode, body)
	}
}

func TestPoolWithAPublicRangeIsFlaggedFromTheRangeItself(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/pools", map[string]any{
		"address_pool_title": "Someone else's addresses",
		"cidr":               "203.0.113.0/24",
		"prefix_length":      30,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /pools = %d\nbody: %s", resp.StatusCode, body)
	}
	var created struct {
		IsPublicRange bool `json:"is_public_range"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !created.IsPublicRange {
		t.Fatal("a globally routable range must be flagged by measuring it, not by trusting the request")
	}
}

func TestPoolInUseCannotBeDeleted(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	createTunnel(t, c, api, map[string]any{"address_pool_id": 10})

	resp, body := c.request(http.MethodDelete, api+"/pools/10", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("deleting a pool in use = %d, want 409\nbody: %s", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------- reconcile

func TestReconcileAndAdoptThroughTheApi(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	// A tunnel the old install script left behind.
	key := uint32(2749365187)
	h.links.AddLink(link.Link{
		Name: "gre-ir-7", Index: 9, MTU: 1472, Kind: link.KindGRE,
		OperState: "UNKNOWN", IsUp: true, IsLowerUp: true,
		Flags: []string{"POINTOPOINT", "NOARP", "UP", "LOWER_UP"},
		Tunnel: &link.TunnelAttrs{
			Local: "203.0.113.10", Remote: "198.51.100.20", Ttl: 255, IKey: &key, OKey: &key,
		},
		Addresses: []link.Address{
			{Address: "172.17.7.1", PrefixLength: 30, Family: link.FamilyIPv4, Scope: "global"},
		},
	})

	resp, body := c.request(http.MethodGet, api+"/reconcile", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /reconcile = %d\nbody: %s", resp.StatusCode, body)
	}
	var report struct {
		Items []struct {
			InterfaceName string   `json:"interface_name"`
			Status        string   `json:"status"`
			Actions       []string `json:"actions"`
			Legacy        *struct {
				TunnelNumber int64 `json:"tunnel_number"`
			} `json:"legacy"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Items) != 1 || report.Items[0].Status != "Unmanaged" {
		t.Fatalf("report = %+v", report.Items)
	}
	if report.Items[0].Legacy == nil || report.Items[0].Legacy.TunnelNumber != 7 {
		t.Fatalf("the legacy tunnel was not recognised: %+v", report.Items[0])
	}

	h.links.Reset()
	resp, body = c.request(http.MethodPost, api+"/reconcile/adopt",
		map[string]any{"interface_name": "gre-ir-7"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /reconcile/adopt = %d\nbody: %s", resp.StatusCode, body)
	}
	var adopted struct {
		Tunnel struct {
			TunnelID        int64  `json:"tunnel_id"`
			InterfaceName   string `json:"interface_name"`
			TunnelSideID    int64  `json:"tunnel_side_id"`
			IsNameTemplated bool   `json:"is_name_templated"`
		} `json:"tunnel"`
		InterfaceBounced bool `json:"interface_bounced"`
	}
	if err := json.Unmarshal(body, &adopted); err != nil {
		t.Fatal(err)
	}
	if adopted.Tunnel.InterfaceName != "gre-ir-7" {
		t.Fatalf("the interface was renamed to %q", adopted.Tunnel.InterfaceName)
	}
	if adopted.Tunnel.TunnelSideID != model.TunnelSideA {
		t.Fatalf("side = %d", adopted.Tunnel.TunnelSideID)
	}
	if adopted.Tunnel.IsNameTemplated {
		t.Fatal("an adopted name must not be marked templated")
	}
	if adopted.InterfaceBounced {
		t.Fatal("adoption must not bounce the interface")
	}
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("adoption changed the interface: %v", calls)
	}

	// It now reads as in sync.
	resp, body = c.request(http.MethodGet, api+"/reconcile", nil)
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || report.Items[0].Status != "InSync" {
		t.Fatalf("after adoption the report says %+v", report.Items)
	}

	// Forget drops the record and leaves the interface alone.
	id := jsonNumber(float64(adopted.Tunnel.TunnelID))
	resp, body = c.request(http.MethodPost, api+"/reconcile/"+id+"/forget", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST forget = %d\nbody: %s", resp.StatusCode, body)
	}
	if _, err := h.links.Get(context.Background(), "gre-ir-7"); err != nil {
		t.Fatal("forget removed the interface; it must only drop the record")
	}
}

func TestIgnoreAnUnmanagedInterface(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	h.links.AddLink(link.Link{Name: "gre-other", Index: 9, Kind: link.KindGRE,
		Tunnel: &link.TunnelAttrs{Local: "203.0.113.10", Remote: "198.51.100.30"}})

	resp, body := c.request(http.MethodPost, api+"/reconcile/ignore",
		map[string]any{"interface_name": "gre-other"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST ignore = %d\nbody: %s", resp.StatusCode, body)
	}
	var out struct {
		IgnoredInterfaces []string `json:"ignored_interfaces"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.IgnoredInterfaces) != 1 || out.IgnoredInterfaces[0] != "gre-other" {
		t.Fatalf("ignored = %v", out.IgnoredInterfaces)
	}
}

// ---------------------------------------------------------------- invariants

// §17.4 at the API boundary: a request arriving through the tunnel it is about
// to delete is refused until the operator says they accept losing access.
func TestDeleteRefusesToCutTheCallersOwnConnection(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	// The request source address is taken from the connection, never from a
	// header, so this is exercised through the harness's direct dispatch.
	rec := h.do(t, http.MethodDelete, api+"/tunnels/"+id, map[string]any{},
		func(r *http.Request) { r.RemoteAddr = "172.17.1.2:54321" })
	if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusForbidden &&
		rec.Code != http.StatusConflict {
		t.Fatalf("DELETE from inside the tunnel = %d\nbody: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------- capabilities

func TestCapabilitiesReportTheLiveLinkManager(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodGet, api+"/system/capabilities", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/capabilities = %d\nbody: %s", resp.StatusCode, body)
	}
	var caps struct {
		TunnelTypes []struct {
			TunnelTypeID int64  `json:"tunnel_type_id"`
			Supported    bool   `json:"supported"`
			LinkManager  string `json:"link_manager"`
		} `json:"tunnel_types"`
		Persistence []struct {
			PersistenceTypeID int64 `json:"persistence_type_id"`
			Available         bool  `json:"available"`
		} `json:"persistence"`
		Complete bool `json:"complete"`
	}
	if err := json.Unmarshal(body, &caps); err != nil {
		t.Fatal(err)
	}
	if !caps.Complete {
		t.Fatal("with the link manager wired the capabilities must be a live probe")
	}
	if len(caps.TunnelTypes) != 4 {
		t.Fatalf("tunnel types = %+v", caps.TunnelTypes)
	}
	for _, tt := range caps.TunnelTypes {
		if !tt.Supported || tt.LinkManager == "" {
			t.Fatalf("every type must be attributed to a manager: %+v", tt)
		}
	}
	// Runtime persistence is always available; it configures the kernel only.
	for _, p := range caps.Persistence {
		if p.PersistenceTypeID == model.PersistenceTypeRuntime && !p.Available {
			t.Fatal("runtime persistence must always be available")
		}
	}
}

// TestCapabilitiesReportTheNetfilterBackend covers §2.1 of the port forwarding
// specification: the panel detects which netfilter interface it will use and
// says so, rather than leaving an operator to guess whether their forwarding
// rules landed in nftables or in iptables.
func TestCapabilitiesReportTheNetfilterBackend(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodGet, api+"/system/capabilities", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/capabilities = %d\nbody: %s", resp.StatusCode, body)
	}
	var caps struct {
		RuleBackend struct {
			Active            string            `json:"active"`
			RuleBackendTypeID int64             `json:"rule_backend_type_id"`
			Available         bool              `json:"available"`
			Reason            string            `json:"reason"`
			Namespace         string            `json:"namespace"`
			Features          map[string]bool   `json:"features"`
			Binaries          map[string]string `json:"binaries"`
		} `json:"rule_backend"`
		Tools []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &caps); err != nil {
		t.Fatal(err)
	}

	if caps.RuleBackend.Active != rules.BackendNftables {
		t.Errorf("the active backend is %q, want nftables where nft is available", caps.RuleBackend.Active)
	}
	if caps.RuleBackend.RuleBackendTypeID != model.RuleBackendTypeNftables {
		t.Errorf("the backend is reported as type %d, want the RuleBackendType row %d",
			caps.RuleBackend.RuleBackendTypeID, model.RuleBackendTypeNftables)
	}
	if !caps.RuleBackend.Available || caps.RuleBackend.Reason == "" {
		t.Errorf("the backend is reported without an explanation: %+v", caps.RuleBackend)
	}
	if caps.RuleBackend.Namespace != "table inet gre_panel" {
		t.Errorf("the namespace the panel owns is reported as %q", caps.RuleBackend.Namespace)
	}
	// The frontend disables what a backend cannot serve, so the feature map has
	// to arrive with it.
	for _, feature := range []string{rules.FeatureIPv6, rules.FeatureMssClamp, rules.FeatureNamedCounters} {
		if !caps.RuleBackend.Features[feature] {
			t.Errorf("nftables should report %s as supported: %+v", feature, caps.RuleBackend.Features)
		}
	}

	names := map[string]bool{}
	for _, tool := range caps.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"nft", "iptables", "iptables-restore"} {
		if !names[want] {
			t.Errorf("the tools list does not mention %s: %+v", want, caps.Tools)
		}
	}
}

// A PATCH mentioning only one field changes only that field. In particular it
// must not regenerate the interface name from the naming template: that would
// rename the interface, which tears the tunnel down.
func TestPartialUpdateChangesOnlyWhatItMentions(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	created := createTunnel(t, c, api, nil)
	id := tunnelID(t, created)

	resp, body := c.request(http.MethodPatch, api+"/tunnels/"+id, map[string]any{"mtu": 1400})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH {\"mtu\":1400} = %d\nbody: %s", resp.StatusCode, body)
	}

	var out struct {
		Tunnel struct {
			InterfaceName string `json:"interface_name"`
			Mtu           int64  `json:"mtu"`
			Ttl           int64  `json:"ttl"`
			IKey          *int64 `json:"ikey"`
			TunnelNumber  *int64 `json:"tunnel_number"`
			Addresses     []struct {
				Address string `json:"address"`
			} `json:"addresses"`
		} `json:"tunnel"`
		Plan struct {
			RequiresRecreate bool `json:"requires_recreate"`
		} `json:"plan"`
		Verification struct {
			Ok bool `json:"ok"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}

	if out.Tunnel.InterfaceName != "gre-a-1" {
		t.Fatalf("the interface was renamed to %q by a request that never mentioned the name",
			out.Tunnel.InterfaceName)
	}
	if out.Plan.RequiresRecreate {
		t.Fatal("changing only the MTU must be applied in place")
	}
	if out.Tunnel.Mtu != 1400 {
		t.Fatalf("mtu = %d, want 1400", out.Tunnel.Mtu)
	}
	if out.Tunnel.Ttl != 255 || out.Tunnel.IKey == nil || *out.Tunnel.IKey != 2749365187 {
		t.Fatalf("an unmentioned field changed: ttl %d, ikey %v", out.Tunnel.Ttl, out.Tunnel.IKey)
	}
	if out.Tunnel.TunnelNumber == nil || *out.Tunnel.TunnelNumber != 1 {
		t.Fatalf("the tunnel number was lost: %v", out.Tunnel.TunnelNumber)
	}
	if len(out.Tunnel.Addresses) != 1 || out.Tunnel.Addresses[0].Address != "172.17.1.1" {
		t.Fatalf("the addresses changed: %+v", out.Tunnel.Addresses)
	}
	if !out.Verification.Ok {
		t.Fatal("the change did not verify")
	}
}

// A GRE key of null means "no key", which is a different instruction from not
// mentioning the key at all.
func TestPatchTellsAbsentFromNull(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	resp, body := c.request(http.MethodPatch, api+"/tunnels/"+id,
		map[string]any{"ikey": nil, "okey": nil, "confirm_recreate": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH clearing the keys = %d\nbody: %s", resp.StatusCode, body)
	}
	var out struct {
		Tunnel struct {
			IKey *int64 `json:"ikey"`
			OKey *int64 `json:"okey"`
		} `json:"tunnel"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Tunnel.IKey != nil || out.Tunnel.OKey != nil {
		t.Fatalf("the keys were not cleared: %v, %v", out.Tunnel.IKey, out.Tunnel.OKey)
	}

	observed, err := h.links.Get(context.Background(), "gre-a-1")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Tunnel.IKey != nil {
		t.Fatalf("the kernel still has a key: %v", observed.Tunnel.IKey)
	}
}
