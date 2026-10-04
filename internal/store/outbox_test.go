package store

import (
	"strings"
	"testing"
	"time"
)

// The sender polls DueOutbox and NextOutboxDue every few seconds; neither may scan the outbox
// table, which keeps its delivered rows as the alerts feed history.
func TestOutboxPollingUsesStatusIndex(t *testing.T) {
	s := openTest(t, nil)
	if v, err := s.SchemaVersion(); err != nil || v < 3 {
		t.Fatalf("schema version %d (%v), want at least 3", v, err)
	}
	for name, q := range map[string]struct {
		sql  string
		args []any
	}{
		"DueOutbox":     {dueOutboxSQL, []any{1, 100}},
		"NextOutboxDue": {nextOutboxDueSQL, nil},
	} {
		plan := planLines(t, s, q.sql, q.args...)
		viaStatus := false
		for _, line := range plan {
			if strings.HasPrefix(line, "SCAN") {
				t.Errorf("%s scans: %q", name, plan)
			}
			if strings.Contains(line, "USING INDEX outbox_status") {
				viaStatus = true
			}
		}
		if !viaStatus {
			t.Errorf("%s does not use outbox_status: %q", name, plan)
		}
	}
}

func TestOutboxDueAndNext(t *testing.T) {
	s := openTest(t, nil)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	enqueue := func(alert int64, channel string, at time.Time) int64 {
		id, err := s.EnqueueOutbox(alert, channel, "{}", at)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := enqueue(1, "webhook", t0)                    // due
	b := enqueue(2, "webhook", t0.Add(time.Second))   // delivered below
	c := enqueue(3, "email", t0.Add(2*time.Second))   // retrying, not due yet
	d := enqueue(1, "webhook", t0.Add(3*time.Second)) // held back behind a (same alert and channel)
	if err := s.UpdateOutbox(b, OutboxDelivered, 1, time.Time{}, "", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	retryAt := t0.Add(10 * time.Minute)
	if err := s.UpdateOutbox(c, OutboxRetrying, 1, retryAt, "boom", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	due, err := s.DueOutbox(t0.Add(10*time.Minute), 100) // a and c are due, d waits for a
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, r := range due {
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 || ids[0] != a || ids[1] != c {
		t.Errorf("due = %v, want [%d %d] (delivered %d and the held-back %d excluded)", ids, a, c, b, d)
	}
	next, ok := s.NextOutboxDue()
	if !ok || !next.Equal(t0) {
		t.Errorf("next due = %v %v, want %v", next, ok, t0)
	}
	// once nothing is pending there is no next attempt
	for _, id := range []int64{a, c, d} {
		if err := s.UpdateOutbox(id, OutboxDelivered, 1, time.Time{}, "", t0.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if next, ok := s.NextOutboxDue(); ok {
		t.Errorf("next due = %v with nothing pending", next)
	}
	if due, _ := s.DueOutbox(t0.Add(24*time.Hour), 100); len(due) != 0 {
		t.Errorf("%d rows due with nothing pending", len(due))
	}
}
