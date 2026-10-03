package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Targets returns stored targets. Removed (inactive) targets are included only on request.
func (s *Store) Targets(includeInactive bool) ([]TargetRow, error) {
	q := `SELECT ` + targetCols + ` FROM targets`
	if !includeInactive {
		q += ` WHERE active=1`
	}
	q += ` ORDER BY id`
	rows, err := s.rdb.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetRow
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Target returns one target by id (ErrNotFound if missing).
func (s *Store) Target(id int64) (TargetRow, error) {
	t, err := scanTarget(s.rdb.QueryRow(`SELECT `+targetCols+` FROM targets WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// ProbeRow is a stored probe.
type ProbeRow struct {
	ID       int64
	TargetID int64
	Type     string
	Key      string
	Label    string
}

// Probes returns the probes of a target (0 = unbound DNS probes).
func (s *Store) Probes(targetID int64) ([]ProbeRow, error) {
	rows, err := s.rdb.Query(`SELECT id, target_id, type, key, label FROM probes WHERE target_id=? ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeRow
	for rows.Next() {
		var p ProbeRow
		if err := rows.Scan(&p.ID, &p.TargetID, &p.Type, &p.Key, &p.Label); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PathRow is a path version.
type PathRow struct {
	ID         int64
	TargetID   int64
	ResolvedIP string
	DestTTL    int
	StartedAt  time.Time
	EndedAt    *time.Time
}

// PathHopRow is one responder of a path at a TTL.
type PathHopRow struct {
	PathID  int64
	TTL     int
	Idx     int
	Address string
	Share   float64
}

func scanPath(sc interface{ Scan(...any) error }) (PathRow, error) {
	var p PathRow
	var st int64
	var en sql.NullInt64
	if err := sc.Scan(&p.ID, &p.TargetID, &p.ResolvedIP, &p.DestTTL, &st, &en); err != nil {
		return p, err
	}
	p.StartedAt = fromUs(st)
	if en.Valid {
		t := fromUs(en.Int64)
		p.EndedAt = &t
	}
	return p, nil
}

const pathCols = `id, target_id, resolved_ip, dest_ttl, started_at, ended_at`

// Path returns one path version.
func (s *Store) Path(id int64) (PathRow, error) {
	p, err := scanPath(s.rdb.QueryRow(`SELECT `+pathCols+` FROM paths WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// PathAt returns the path version of the target that was current at t (the latest one that
// started at or before t, or the first one when t precedes them all).
func (s *Store) PathAt(targetID int64, t time.Time) (PathRow, error) {
	p, err := scanPath(s.rdb.QueryRow(`SELECT `+pathCols+` FROM paths WHERE target_id=? AND started_at<=? ORDER BY started_at DESC LIMIT 1`, targetID, us(t)))
	if errors.Is(err, sql.ErrNoRows) {
		p, err = scanPath(s.rdb.QueryRow(`SELECT `+pathCols+` FROM paths WHERE target_id=? ORDER BY started_at ASC LIMIT 1`, targetID))
		if errors.Is(err, sql.ErrNoRows) {
			return p, ErrNotFound
		}
	}
	return p, err
}

// PathsOf returns path versions by id.
func (s *Store) PathsOf(ids []int64) (map[int64]PathRow, error) {
	out := map[int64]PathRow{}
	if len(ids) == 0 {
		return out, nil
	}
	in, args := inClause(ids)
	rows, err := s.rdb.Query(`SELECT `+pathCols+` FROM paths WHERE id IN `+in, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		p, err := scanPath(rows)
		if err != nil {
			return nil, err
		}
		out[p.ID] = p
	}
	return out, rows.Err()
}

// PathHops returns the responder sets of the given paths.
func (s *Store) PathHops(pathIDs []int64) (map[int64][]PathHopRow, error) {
	out := map[int64][]PathHopRow{}
	if len(pathIDs) == 0 {
		return out, nil
	}
	in, args := inClause(pathIDs)
	rows, err := s.rdb.Query(`SELECT path_id, ttl, idx, address, share FROM path_hops WHERE path_id IN `+in+` ORDER BY path_id, ttl, idx`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h PathHopRow
		if err := rows.Scan(&h.PathID, &h.TTL, &h.Idx, &h.Address, &h.Share); err != nil {
			return nil, err
		}
		out[h.PathID] = append(out[h.PathID], h)
	}
	return out, rows.Err()
}

// LatestPath returns the most recent path version of a target.
func (s *Store) LatestPath(targetID int64) (PathRow, error) {
	p, err := scanPath(s.rdb.QueryRow(`SELECT `+pathCols+` FROM paths WHERE target_id=? ORDER BY started_at DESC LIMIT 1`, targetID))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// LastRoundTime returns the timestamp of the newest stored round of a target.
func (s *Store) LastRoundTime(targetID int64) (time.Time, bool) {
	var v sql.NullInt64
	if err := s.rdb.QueryRow(`SELECT MAX(ts) FROM icmp_rounds WHERE target_id=?`, targetID).Scan(&v); err != nil || !v.Valid {
		return time.Time{}, false
	}
	return fromUs(v.Int64), true
}

// FirstDataTime returns when a target's data starts (earliest round or probe rollup bucket).
func (s *Store) FirstDataTime(targetID int64) (time.Time, bool) {
	var v sql.NullInt64
	_ = s.rdb.QueryRow(`SELECT MIN(bucket) FROM icmp_rollup_1m WHERE target_id=?`, targetID).Scan(&v)
	if !v.Valid {
		_ = s.rdb.QueryRow(`SELECT MIN(ts) FROM icmp_rounds WHERE target_id=?`, targetID).Scan(&v)
	}
	if !v.Valid {
		return time.Time{}, false
	}
	return fromUs(v.Int64), true
}

// Gap is a monitor gap.
type Gap struct{ From, To time.Time }

// Gaps returns the target's gaps overlapping [from, to].
func (s *Store) Gaps(targetID int64, from, to time.Time) ([]Gap, error) {
	rows, err := s.rdb.Query(`SELECT started_at, ended_at FROM gaps WHERE target_id=? AND ended_at>=? AND started_at<=? ORDER BY started_at`, targetID, us(from), us(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Gap
	for rows.Next() {
		var a, b int64
		if err := rows.Scan(&a, &b); err != nil {
			return nil, err
		}
		out = append(out, Gap{fromUs(a), fromUs(b)})
	}
	return out, rows.Err()
}

func scanEvent(sc interface{ Scan(...any) error }) (Event, error) {
	var e Event
	var tid, ttl, end sql.NullInt64
	var st int64
	var det sql.NullString
	if err := sc.Scan(&e.ID, &tid, &e.Kind, &ttl, &st, &end, &det); err != nil {
		return e, err
	}
	if tid.Valid {
		v := tid.Int64
		e.TargetID = &v
	}
	if ttl.Valid {
		v := int(ttl.Int64)
		e.TTL = &v
	}
	e.From = fromUs(st)
	if end.Valid {
		t := fromUs(end.Int64)
		e.To = &t
	}
	if det.Valid && det.String != "" {
		e.Details = json.RawMessage(det.String)
	}
	return e, nil
}

const eventCols = `id, target_id, kind, ttl, started_at, ended_at, details`

// EventQuery filters Events.
type EventQuery struct {
	TargetID     *int64 // nil = all targets; otherwise events of that target plus global ones
	From, To     time.Time
	Kinds        []string // empty = all kinds
	ExcludeKinds []string
}

// Events returns events overlapping the query range, oldest first. An event overlaps when it
// started before To and ended (or is open / instant) after From.
func (s *Store) Events(q EventQuery) ([]Event, error) {
	var sb strings.Builder
	sb.WriteString(`SELECT ` + eventCols + ` FROM events WHERE started_at <= ? AND COALESCE(ended_at, started_at) >= ?`)
	args := []any{us(q.To), us(q.From)}
	if q.TargetID != nil {
		sb.WriteString(` AND (target_id = ? OR target_id IS NULL)`)
		args = append(args, *q.TargetID)
	}
	addKinds := func(list []string, not string) {
		if len(list) == 0 {
			return
		}
		sb.WriteString(` AND kind ` + not + ` IN (` + strings.TrimSuffix(strings.Repeat("?,", len(list)), ",") + `)`)
		for _, k := range list {
			args = append(args, k)
		}
	}
	addKinds(q.Kinds, "")
	addKinds(q.ExcludeKinds, "NOT")
	sb.WriteString(` ORDER BY started_at, id`)
	rows, err := s.rdb.Query(sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// OpenEvents returns events of the given kinds that have no end time yet.
func (s *Store) OpenEvents(kinds ...string) ([]Event, error) {
	q := `SELECT ` + eventCols + ` FROM events WHERE ended_at IS NULL`
	var args []any
	if len(kinds) > 0 {
		q += ` AND kind IN (` + strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",") + `)`
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	rows, err := s.rdb.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const alertCols = `id, target_id, rule, rule_type, state, COALESCE(suppressed_reason,''), started_at, ended_at, value, peak_value, baseline, COALESCE(message,''), COALESCE(details_json,'')`

func scanAlert(sc interface{ Scan(...any) error }) (Alert, error) {
	var a Alert
	var tid, end sql.NullInt64
	var st int64
	var val, peak, base sql.NullFloat64
	if err := sc.Scan(&a.ID, &tid, &a.Rule, &a.RuleType, &a.State, &a.SuppressedReason, &st, &end, &val, &peak, &base, &a.Message, &a.DetailsJSON); err != nil {
		return a, err
	}
	if tid.Valid {
		v := tid.Int64
		a.TargetID = &v
	}
	a.StartedAt = fromUs(st)
	if end.Valid {
		t := fromUs(end.Int64)
		a.EndedAt = &t
	}
	if val.Valid {
		a.Value = &val.Float64
	}
	if peak.Valid {
		a.PeakValue = &peak.Float64
	}
	if base.Valid {
		a.Baseline = &base.Float64
	}
	return a, nil
}

// ListAlerts returns the newest alerts first.
func (s *Store) ListAlerts(limit int, targetID *int64) ([]Alert, error) {
	q := `SELECT ` + alertCols + ` FROM alerts`
	var args []any
	if targetID != nil {
		q += ` WHERE target_id = ?`
		args = append(args, *targetID)
	}
	q += ` ORDER BY started_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
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

// ActiveAlertCounts returns the number of firing alerts per target id (0 = global) and the total.
func (s *Store) ActiveAlertCounts() (map[int64]int, int, error) {
	rows, err := s.rdb.Query(`SELECT COALESCE(target_id,0), COUNT(*) FROM alerts WHERE state='firing' GROUP BY 1`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[int64]int{}
	total := 0
	for rows.Next() {
		var t int64
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, 0, err
		}
		out[t] = n
		total += n
	}
	return out, total, rows.Err()
}

// Delivery is the delivery status of one alert notification.
type Delivery struct {
	AlertID   int64
	Channel   string
	Status    string // queued | delivered | retrying | failed | expired
	Attempts  int
	LastError *string
}

// Deliveries returns outbox rows grouped by alert id.
func (s *Store) Deliveries(alertIDs []int64) (map[int64][]Delivery, error) {
	out := map[int64][]Delivery{}
	if len(alertIDs) == 0 {
		return out, nil
	}
	in, args := inClause(alertIDs)
	rows, err := s.rdb.Query(`SELECT alert_id, channel, status, attempts, last_error FROM outbox WHERE alert_id IN `+in+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Delivery
		var le sql.NullString
		if err := rows.Scan(&d.AlertID, &d.Channel, &d.Status, &d.Attempts, &le); err != nil {
			return nil, err
		}
		if le.Valid {
			d.LastError = &le.String
		}
		out[d.AlertID] = append(out[d.AlertID], d)
	}
	return out, rows.Err()
}

// Silence is a UI-created silence.
type Silence struct {
	ID        int64
	TargetID  *int64
	Rule      *string
	StartsAt  time.Time
	EndsAt    time.Time
	Reason    string
	CreatedBy string
}

// Silences returns silences that have not ended before now (active and upcoming).
func (s *Store) Silences(now time.Time) ([]Silence, error) {
	rows, err := s.rdb.Query(`SELECT id, target_id, rule, starts_at, ends_at, COALESCE(reason,''), COALESCE(created_by,'') FROM silences WHERE ends_at > ? ORDER BY starts_at, id`, us(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Silence
	for rows.Next() {
		var x Silence
		var tid sql.NullInt64
		var rule sql.NullString
		var a, b int64
		if err := rows.Scan(&x.ID, &tid, &rule, &a, &b, &x.Reason, &x.CreatedBy); err != nil {
			return nil, err
		}
		if tid.Valid {
			v := tid.Int64
			x.TargetID = &v
		}
		if rule.Valid {
			v := rule.String
			x.Rule = &v
		}
		x.StartsAt, x.EndsAt = fromUs(a), fromUs(b)
		out = append(out, x)
	}
	return out, rows.Err()
}

// GetAlert returns one alert by id.
func (s *Store) GetAlert(id int64) (Alert, error) {
	a, err := scanAlert(s.rdb.QueryRow(`SELECT `+alertCols+` FROM alerts WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// AlertsOverlapping returns a target's alerts that overlap [from, to] (for timeline markers).
func (s *Store) AlertsOverlapping(targetID int64, from, to time.Time) ([]Alert, error) {
	rows, err := s.rdb.Query(`SELECT `+alertCols+` FROM alerts WHERE target_id=? AND started_at<=? AND COALESCE(ended_at, ?)>=? AND state<>'suppressed' ORDER BY started_at`,
		targetID, us(to), us(to), us(from))
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
