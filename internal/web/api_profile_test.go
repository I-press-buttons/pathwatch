package web

import (
	"encoding/json"
	"testing"
)

func TestOverviewLayoutProfile(t *testing.T) {
	f := newFixture(t, fixtureOpts{auth: true})

	var p map[string]any
	if resp := f.getJSON("/api/profile", &p); resp.StatusCode != 200 {
		t.Fatalf("GET profile: %d", resp.StatusCode)
	}
	if p["user"] != "admin" || p["overview"] != nil {
		t.Fatalf("fresh profile: %v", p)
	}

	// save: sections missing from the layout are appended, group_by defaults to server
	resp, b := f.do("PUT", "/api/profile/overview", "application/json",
		`{"sections":[{"id":"dns"},{"id":"targets","hidden":true}],"target_order":[3,1,2],"dns":{"group_order":{"server":["pi-hole","router"]}}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT layout: %d %s", resp.StatusCode, b)
	}
	var got profileJSON
	f.getJSON("/api/profile", &got)
	l := got.Overview
	if l == nil || len(l.Sections) != 4 || l.Sections[0].ID != "dns" || l.Sections[1].ID != "targets" || !l.Sections[1].Hidden ||
		l.Sections[2].ID != "network" || l.Sections[3].ID != "status" {
		t.Fatalf("sections: %+v", l)
	}
	if l.DNS.GroupBy != "server" || len(l.TargetOrder) != 3 || l.TargetOrder[0] != 3 || l.DNS.GroupOrder["server"][1] != "router" {
		t.Fatalf("layout: %+v", l)
	}
	// stored on the server, under the user
	raw, ok, err := f.st.Setting("profile:admin")
	if err != nil || !ok {
		t.Fatalf("stored: %v %v", ok, err)
	}
	var sp storedProfile
	if json.Unmarshal([]byte(raw), &sp) != nil || sp.Overview == nil {
		t.Fatalf("stored value: %s", raw)
	}

	for _, bad := range []string{
		`{"sections":[{"id":"nope"}]}`,
		`{"sections":[{"id":"dns"},{"id":"dns"}]}`,
		`{"sections":[],"dns":{"group_by":"color"}}`,
		`{"sections":[],"dns":{"group_order":{"none":["x"]}}}`,
		`{"sections":[],"extra":1}`,
	} {
		if resp, b := f.do("PUT", "/api/profile/overview", "application/json", bad); resp.StatusCode != 400 {
			t.Errorf("PUT %s: %d %s", bad, resp.StatusCode, b)
		}
	}
	if resp, _ := f.do("PUT", "/api/profile/overview", "text/plain", `{}`); resp.StatusCode != 415 {
		t.Errorf("non-JSON PUT: %d", resp.StatusCode)
	}

	// reset to the default layout
	if resp, b := f.do("DELETE", "/api/profile/overview", "", nil); resp.StatusCode != 200 {
		t.Fatalf("DELETE: %d %s", resp.StatusCode, b)
	}
	p = nil
	f.getJSON("/api/profile", &p)
	if p["overview"] != nil {
		t.Fatalf("after reset: %v", p)
	}
	if _, ok, _ := f.st.Setting("profile:admin"); ok {
		t.Error("profile row left behind")
	}
}

func TestOverviewLayoutProfileWithoutAuth(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	if resp, b := f.do("PUT", "/api/profile/overview", "application/json", `{"sections":[{"id":"status"}]}`); resp.StatusCode != 200 {
		t.Fatalf("PUT: %d %s", resp.StatusCode, b)
	}
	var got profileJSON
	f.getJSON("/api/profile", &got)
	if got.User != "default" || got.Overview == nil || got.Overview.Sections[0].ID != "status" {
		t.Fatalf("profile: %+v", got)
	}
}
