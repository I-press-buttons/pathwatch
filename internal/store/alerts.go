package store

import (
	"database/sql"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// alert engine reads

// ActiveAlerts returns the alerts that have not ended yet: firing ones and those recorded as
// suppressed while their condition still holds. The alert engine restores its state from them.
func (s *Store) ActiveAlerts() ([]Alert, error) {
	return s.queryAlerts(`SELECT ` + alertCols + ` FROM alerts WHERE state IN ('firing','suppressed') AND ended_at IS NULL ORDER BY id`)
}

// AlertsEndedSince returns alerts that were firing and resolved at or after since (cooldown restore).
func (s *Store) AlertsEndedSince(since time.Time) ([]Alert, error) {
	return s.queryAlerts(`SELECT `+alertCols+` FROM alerts WHERE state='resolved' AND ended_at IS NOT NULL AND ended_at >= ? ORDER BY id`, us(since))
}

// AlertsOfType returns the newest alerts of a rule type (any state), newest first.
func (s *Store) AlertsOfType(ruleType string, limit int) ([]Alert, error) {
	return s.queryAlerts(`SELECT `+alertCols+` FROM alerts WHERE rule_type=? ORDER BY id DESC LIMIT ?`, ruleType, limit)
}

// AlertsOverlappingTypes returns alerts of the given rule types (any state) that overlap [from, ∞):
// they started before the end of time and ended at or after from (or have not ended).
func (s *Store) AlertsOverlappingTypes(from time.Time, ruleTypes ...string) ([]Alert, error) {
	if len(ruleTypes) == 0 {
		return nil, nil
	}
	args := []any{us(from)}
	for _, t := range ruleTypes {
		args = append(args, t)
	}
	in := strings.TrimSuffix(strings.Repeat("?,", len(ruleTypes)), ",")
	return s.queryAlerts(`SELECT `+alertCols+` FROM alerts WHERE (ended_at IS NULL OR ended_at >= ?) AND rule_type IN (`+in+`) ORDER BY started_at`, args...)
}

func (s *Store) queryAlerts(q string, args ...any) ([]Alert, error) {
	rows, err := s.rdb.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ProbeAvg is one rollup bucket of a probe: sample counts and mean latencies in milliseconds
// over the successful samples (zero when there were none).
type ProbeAvg struct {
	Bucket  time.Time
	N       int64
	Errors  int64
	TotalMS float64
	TTFBMS  float64
}

// HaveAvg reports whether the bucket has at least one successful sample.
func (p ProbeAvg) HaveAvg() bool { return p.N-p.Errors > 0 }

// ProbeAverages returns a probe's per-bucket averages in [from, to) from the 1-minute rollups
// (or the 1-hour rollups when tier is Tier1h), oldest first. The alert engine derives latency
// baselines from it.
func (s *Store) ProbeAverages(probeID int64, from, to time.Time, tier Tier) ([]ProbeAvg, error) {
	table := "probe_rollup_1m"
	if tier == Tier1h {
		table = "probe_rollup_1h"
	}
	rows, err := s.rdb.Query(`SELECT bucket, n, errors, total_avg, ttfb_avg FROM `+table+` WHERE probe_id=? AND bucket>=? AND bucket<? ORDER BY bucket`, probeID, us(from), us(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeAvg
	for rows.Next() {
		var p ProbeAvg
		var b int64
		var total, ttfb sql.NullFloat64
		if err := rows.Scan(&b, &p.N, &p.Errors, &total, &ttfb); err != nil {
			return nil, err
		}
		p.Bucket = fromUs(b)
		p.TotalMS, p.TTFBMS = total.Float64, ttfb.Float64
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// outbox

// Outbox statuses.
const (
	OutboxQueued    = "queued"
	OutboxRetrying  = "retrying"
	OutboxDelivered = "delivered"
	OutboxFailed    = "failed"
	OutboxExpired   = "expired"
)

// OutboxRow is one notification waiting for (or finished with) delivery.
type OutboxRow struct {
	ID            int64
	AlertID       int64
	Channel       string
	Payload       string
	Status        string
	CreatedAt     time.Time
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
}

// EnqueueOutbox writes a notification to the outbox, due immediately, and returns its id.
func (s *Store) EnqueueOutbox(alertID int64, channel, payload string, now time.Time) (int64, error) {
	var id int64
	err := s.exec(func(tx *sql.Tx) error {
		res, err := tx.Exec(`INSERT INTO outbox(alert_id, channel, payload, status, created_at, attempts, next_attempt_at) VALUES (?,?,?,?,?,0,?)`,
			alertID, channel, payload, OutboxQueued, us(now), us(now))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// The sender polls the outbox every few seconds; both queries select on status IN
// ('queued','retrying') so that the outbox_status index (migration 3) limits them to the pending
// rows instead of the whole table, which keeps delivered rows as the alerts feed history.
const (
	dueOutboxSQL = `SELECT o.id, o.alert_id, o.channel, o.payload, o.status, o.created_at, o.attempts, COALESCE(o.next_attempt_at, o.created_at), COALESCE(o.last_error,'')
		FROM outbox o
		WHERE o.status IN ('queued','retrying') AND COALESCE(o.next_attempt_at, o.created_at) <= ?
		AND NOT EXISTS (SELECT 1 FROM outbox p WHERE p.alert_id=o.alert_id AND p.channel=o.channel AND p.id<o.id AND p.status IN ('queued','retrying'))
		ORDER BY o.id LIMIT ?`
	nextOutboxDueSQL = `SELECT MIN(COALESCE(next_attempt_at, created_at)) FROM outbox WHERE status IN ('queued','retrying')`
)

// DueOutbox returns up to limit undelivered rows whose next attempt is due, oldest first. A row
// is held back while an earlier notification of the same alert and channel is still pending, so
// "resolved" never overtakes "firing".
func (s *Store) DueOutbox(now time.Time, limit int) ([]OutboxRow, error) {
	rows, err := s.rdb.Query(dueOutboxSQL, us(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		var c, n int64
		if err := rows.Scan(&r.ID, &r.AlertID, &r.Channel, &r.Payload, &r.Status, &c, &r.Attempts, &n, &r.LastError); err != nil {
			return nil, err
		}
		r.CreatedAt, r.NextAttemptAt = fromUs(c), fromUs(n)
		out = append(out, r)
	}
	return out, rows.Err()
}

// NextOutboxDue returns the earliest next-attempt time among pending rows.
func (s *Store) NextOutboxDue() (time.Time, bool) {
	var v sql.NullInt64
	_ = s.rdb.QueryRow(nextOutboxDueSQL).Scan(&v)
	if !v.Valid {
		return time.Time{}, false
	}
	return fromUs(v.Int64), true
}

// OutboxRowByID returns one outbox row.
func (s *Store) OutboxRowByID(id int64) (OutboxRow, error) {
	var r OutboxRow
	var c int64
	var n sql.NullInt64
	err := s.rdb.QueryRow(`SELECT id, alert_id, channel, payload, status, created_at, attempts, next_attempt_at, COALESCE(last_error,'') FROM outbox WHERE id=?`, id).
		Scan(&r.ID, &r.AlertID, &r.Channel, &r.Payload, &r.Status, &c, &r.Attempts, &n, &r.LastError)
	if err == sql.ErrNoRows {
		return r, ErrNotFound
	}
	r.CreatedAt = fromUs(c)
	if n.Valid {
		r.NextAttemptAt = fromUs(n.Int64)
	}
	return r, err
}

// UpdateOutbox records the outcome of a delivery attempt. delivered sets delivered_at to now;
// a zero next clears next_attempt_at.
func (s *Store) UpdateOutbox(id int64, status string, attempts int, next time.Time, lastErr string, now time.Time) error {
	return s.exec(func(tx *sql.Tx) error {
		var nx, del any
		if !next.IsZero() {
			nx = us(next)
		}
		if status == OutboxDelivered {
			del = us(now)
		}
		_, err := tx.Exec(`UPDATE outbox SET status=?, attempts=?, next_attempt_at=?, delivered_at=?, last_error=? WHERE id=?`,
			status, attempts, nx, del, nullStr(lastErr), id)
		return err
	})
}

// OutboxPending returns the number of notifications still waiting for delivery (queued or
// retrying). It uses the outbox_status index.
func (s *Store) OutboxPending() (int, error) {
	var n int
	err := s.rdb.QueryRow(`SELECT COUNT(*) FROM outbox WHERE status IN ('queued','retrying')`).Scan(&n)
	return n, err
}
