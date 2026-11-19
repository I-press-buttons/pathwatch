package publicip

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// scripted answers IPv4 lookups from a list (the last one repeats) and fails IPv6.
type scripted struct{ v4 []string }

func (s *scripted) lookup(_ context.Context, family string) (netip.Addr, error) {
	if family == IPv6 {
		return netip.Addr{}, errors.New("no IPv6 connectivity")
	}
	a := s.v4[0]
	if len(s.v4) > 1 {
		s.v4 = s.v4[1:]
	}
	return netip.MustParseAddr(a), nil
}

func TestMonitorRecordsConfirmedChanges(t *testing.T) {
	st := openStore(t)
	sc := &scripted{v4: []string{"203.0.113.1", "203.0.113.9", "203.0.113.1", "203.0.113.9", "203.0.113.9"}}
	changes := 0
	m := New(Options{Store: st, Lookup: sc.lookup, OnChange: func() { changes++ },
		Enrich: func(a netip.Addr) Info { return Info{ASN: 64500, ASName: "Example"} }})
	m.Configure(config.PublicIPConfig{Enabled: true, Interval: config.Duration(time.Minute)})
	ctx := context.Background()

	if m.Check(ctx) {
		t.Fatal("first sighting needs no confirmation")
	}
	if got := m.States()[0]; got.Addr != "203.0.113.1" || got.EventID == 0 {
		t.Fatalf("first address not recorded: %+v", got)
	}
	if got := m.States()[1]; got.Addr != "" || got.LastErr != "no IPv6 connectivity" {
		t.Fatalf("ipv6 state: %+v", got)
	}
	// a single different answer is only pending; the old address coming back clears it
	if !m.Check(ctx) || m.States()[0].Pending != "203.0.113.9" {
		t.Fatalf("different address should be pending: %+v", m.States()[0])
	}
	if m.Check(ctx) || m.States()[0].Pending != "" || m.States()[0].Addr != "203.0.113.1" {
		t.Fatalf("flap must not count: %+v", m.States()[0])
	}
	// seen twice in a row: recorded
	m.Check(ctx)
	m.Check(ctx)
	if got := m.States()[0]; got.Addr != "203.0.113.9" {
		t.Fatalf("confirmed change not recorded: %+v", got)
	}
	if changes != 2 {
		t.Fatalf("OnChange calls = %d, want 2", changes)
	}
	if err := st.Sync(); err != nil {
		t.Fatal(err)
	}

	open, err := st.OpenEvents(EventKind)
	if err != nil || len(open) != 1 {
		t.Fatalf("want one open event, got %d (%v)", len(open), err)
	}
	d, ok := ParseDetails(open[0].Details)
	if !ok || d.Previous != "203.0.113.1" || d.Addr != "203.0.113.9" || d.ASN != 64500 {
		t.Fatalf("details: %+v", d)
	}

	// a restart picks the current address up again
	m2 := New(Options{Store: st, Lookup: sc.lookup})
	if got := m2.States()[0]; got.Addr != "203.0.113.9" || got.EventID != open[0].ID {
		t.Fatalf("restore: %+v", got)
	}
}
