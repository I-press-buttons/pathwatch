package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrDuplicate is returned when a target name already exists.
var ErrDuplicate = errors.New("duplicate name")

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return us(t)
}

// ---------------------------------------------------------------------------
// raw samples

// RecordRound stores one round (one packed row) and folds it into the 1-minute aggregates.
func (s *Store) RecordRound(r Round) {
	if len(r.Hops) == 0 {
		return
	}
	s.agg.AddRound(r)
	blob := EncodeHops(r.Hops)
	n := len(r.Hops)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO icmp_rounds(target_id, ts, path_id, hop_count, results) VALUES (?,?,?,?,?)`,
			r.TargetID, us(r.TS), r.PathID, n, blob)
		return err
	})
}

// RecordHTTP stores one HTTP sample.
func (s *Store) RecordHTTP(h HTTPSample) {
	s.agg.AddHTTP(h)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO http_samples(probe_id, ts, resolved_ip, status, dns_us, connect_us, tls_us, ttfb_us, transfer_us, total_us, redirects, cert_not_after, error)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			h.ProbeID, us(h.TS), nullStr(h.ResolvedIP), h.Status, h.DNS.Microseconds(), h.Connect.Microseconds(), h.TLS.Microseconds(),
			h.TTFB.Microseconds(), h.Transfer.Microseconds(), h.Total.Microseconds(), h.Redirects, nullTime(h.CertNotAfter), nullStr(h.Error))
		return err
	})
}

// RecordTCP stores one TCP connect sample.
func (s *Store) RecordTCP(t TCPSample) {
	s.agg.AddTCP(t)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO tcp_samples(probe_id, ts, resolved_ip, connect_us, error) VALUES (?,?,?,?,?)`,
			t.ProbeID, us(t.TS), nullStr(t.ResolvedIP), t.Connect.Microseconds(), nullStr(t.Error))
		return err
	})
}

// RecordDNS stores one DNS probe sample.
func (s *Store) RecordDNS(d DNSSample) {
	s.agg.AddDNS(d)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO dns_samples(probe_id, ts, rcode, rtt_us, error) VALUES (?,?,?,?,?)`,
			d.ProbeID, us(d.TS), d.RCode, d.RTT.Microseconds(), nullStr(d.Error))
		return err
	})
}

// RecordGap stores a monitor gap ("no data") plus a matching event, and resets jitter state.
func (s *Store) RecordGap(targetID int64, from, to time.Time, reason string) {
	s.agg.ResetJitter(targetID)
	details, _ := json.Marshal(map[string]string{"reason": reason})
	s.enqueue(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO gaps(target_id, started_at, ended_at, reason) VALUES (?,?,?,?)`, targetID, us(from), us(to), reason); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO events(target_id, kind, ttl, started_at, ended_at, details) VALUES (?,?,?,?,?,?)`,
			targetID, "gap", nil, us(from), us(to), string(details))
		return err
	})
}

// ---------------------------------------------------------------------------
// rollups

func insertICMPRollRow(tx *sql.Tx, table string, target int64, bucket int64, ttl int, path int64, r *Roll) error {
	avg, _ := r.Avg()
	jit, _ := r.Jitter()
	var min, max any
	if r.Replies() > 0 {
		min, max = r.Min, r.Max
	}
	var avgv any
	if r.Replies() > 0 {
		avgv = avg
	}
	var jitv any
	if r.JitN > 0 {
		jitv = jit
	}
	_, err := tx.Exec(`INSERT OR REPLACE INTO `+table+`(target_id, bucket, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		target, bucket, ttl, path, r.N, r.Lost, min, avgv, max, jitv, r.Hist.Encode())
	return err
}

func insertProbeRollRow(tx *sql.Tx, table string, probe int64, bucket int64, p *ProbeRoll) error {
	var dns, conn, tls, ttfb, tr, tmin, tavg, tmax any
	if p.OK() > 0 {
		dns, _ = p.AvgDNS()
		conn, _ = p.AvgConnect()
		tls, _ = p.AvgTLS()
		ttfb, _ = p.AvgTTFB()
		tr, _ = p.AvgTransfer()
		tavg, _ = p.AvgTotal()
		tmin, tmax = p.TotalMin, p.TotalMax
	}
	_, err := tx.Exec(`INSERT OR REPLACE INTO `+table+`(probe_id, bucket, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		probe, bucket, p.N, p.Errors, dns, conn, tls, ttfb, tr, tmin, tavg, tmax, p.Hist.Encode(), nullInt(p.CertNotAfter))
	return err
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// persistMinute writes a completed minute as 1m rollups and rebuilds the affected 1h rollups.
func (s *Store) persistMinute(mb MinuteBatch) { s.persistMinutes([]MinuteBatch{mb}) }

// persistMinutes writes several minutes in one writer operation and rebuilds each affected
// hour once, from the 1m rows, inside the writer so reads see consistent data.
func (s *Store) persistMinutes(mbs []MinuteBatch) {
	type hourSet struct {
		targets, probes map[int64]bool
	}
	hours := map[int64]*hourSet{}
	n := 0
	for _, mb := range mbs {
		if len(mb.ICMP) == 0 && len(mb.Probes) == 0 {
			continue
		}
		n++
		h := mb.Bucket.Truncate(time.Hour).UnixMicro()
		hs := hours[h]
		if hs == nil {
			hs = &hourSet{targets: map[int64]bool{}, probes: map[int64]bool{}}
			hours[h] = hs
		}
		for _, r := range mb.ICMP {
			hs.targets[r.TargetID] = true
		}
		for _, p := range mb.Probes {
			hs.probes[p.ProbeID] = true
		}
	}
	if n == 0 {
		return
	}
	s.enqueue(func(tx *sql.Tx) error {
		for _, mb := range mbs {
			for _, r := range mb.ICMP {
				if err := insertICMPRollRow(tx, "icmp_rollup_1m", r.TargetID, r.Bucket, r.TTL, r.PathID, r.Roll); err != nil {
					return err
				}
			}
			for _, p := range mb.Probes {
				if err := insertProbeRollRow(tx, "probe_rollup_1m", p.ProbeID, p.Bucket, p.Roll); err != nil {
					return err
				}
			}
		}
		for h, hs := range hours {
			if err := rebuildHour(tx, h, keys(hs.targets), keys(hs.probes)); err != nil {
				return err
			}
		}
		return nil
	})
}

func keys(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func inClause(ids []int64) (string, []any) {
	if len(ids) == 0 {
		return "(NULL)", nil
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	return "(" + strings.Join(ph, ",") + ")", args
}

// rebuildHour recomputes the 1h rollups of the given targets/probes for the hour starting at
// hourUs from their 1m rows.
func rebuildHour(tx *sql.Tx, hourUs int64, targets, probes []int64) error {
	end := hourUs + int64(time.Hour/time.Microsecond)
	if len(targets) > 0 {
		in, args := inClause(targets)
		rows, err := tx.Query(`SELECT target_id, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist FROM icmp_rollup_1m
			WHERE bucket >= ? AND bucket < ? AND target_id IN `+in, append([]any{hourUs, end}, args...)...)
		if err != nil {
			return err
		}
		type k struct {
			t, p int64
			ttl  int
		}
		merged := map[k]*Roll{}
		for rows.Next() {
			var t, p, n, lost int64
			var ttl int
			var mn, av, mx, jt sql.NullFloat64
			var hist []byte
			if err := rows.Scan(&t, &ttl, &p, &n, &lost, &mn, &av, &mx, &jt, &hist); err != nil {
				rows.Close()
				return err
			}
			r := rollFromRow(n, lost, mn.Float64, av.Float64, mx.Float64, jt.Float64, hist)
			key := k{t, p, ttl}
			m := merged[key]
			if m == nil {
				m = &Roll{}
				merged[key] = m
			}
			m.Merge(r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for key, r := range merged {
			if err := insertICMPRollRow(tx, "icmp_rollup_1h", key.t, hourUs, key.ttl, key.p, r); err != nil {
				return err
			}
		}
	}
	if len(probes) > 0 {
		in, args := inClause(probes)
		rows, err := tx.Query(`SELECT probe_id, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after FROM probe_rollup_1m
			WHERE bucket >= ? AND bucket < ? AND probe_id IN `+in+` ORDER BY bucket`, append([]any{hourUs, end}, args...)...)
		if err != nil {
			return err
		}
		merged := map[int64]*ProbeRoll{}
		for rows.Next() {
			var id, n, e int64
			var dns, conn, tls, ttfb, tr, tmin, tavg, tmax sql.NullFloat64
			var hist []byte
			var cert sql.NullInt64
			if err := rows.Scan(&id, &n, &e, &dns, &conn, &tls, &ttfb, &tr, &tmin, &tavg, &tmax, &hist, &cert); err != nil {
				rows.Close()
				return err
			}
			r := probeRollFromRow(n, e, dns.Float64, conn.Float64, tls.Float64, ttfb.Float64, tr.Float64, tmin.Float64, tavg.Float64, tmax.Float64, hist, cert.Int64)
			m := merged[id]
			if m == nil {
				m = &ProbeRoll{}
				merged[id] = m
			}
			m.Merge(r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for id, p := range merged {
			if err := insertProbeRollRow(tx, "probe_rollup_1h", id, hourUs, p); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// targets and probes

// TargetRow is a stored target.
type TargetRow struct {
	ID        int64
	Name      string
	Host      string
	Active    bool // false = removed from config
	Paused    bool
	Source    string // config | ui
	Spec      string // JSON (ui targets)
	CreatedAt time.Time
	UpdatedAt time.Time
}

const targetCols = `id, name, host, active, source, paused, COALESCE(spec,''), created_at, updated_at`

func scanTarget(sc interface{ Scan(...any) error }) (TargetRow, error) {
	var t TargetRow
	var active, paused int
	var c, u int64
	if err := sc.Scan(&t.ID, &t.Name, &t.Host, &active, &t.Source, &paused, &t.Spec, &c, &u); err != nil {
		return t, err
	}
	t.Active, t.Paused = active != 0, paused != 0
	t.CreatedAt, t.UpdatedAt = fromUs(c), fromUs(u)
	return t, nil
}

// SyncConfigTarget upserts a config-file target by name. A UI target with the same name is
// taken over (the config wins). The paused flag is preserved.
func (s *Store) SyncConfigTarget(name, host string) (TargetRow, error) {
	var out TargetRow
	err := s.exec(func(tx *sql.Tx) error {
		now := us(s.now())
		res, err := tx.Exec(`UPDATE targets SET host=?, active=1, source='config', spec=NULL, updated_at=? WHERE name=?`, host, now, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, err := tx.Exec(`INSERT INTO targets(name, host, active, source, paused, created_at, updated_at) VALUES (?,?,1,'config',0,?,?)`, name, host, now, now); err != nil {
				return err
			}
		}
		out, err = scanTarget(tx.QueryRow(`SELECT `+targetCols+` FROM targets WHERE name=?`, name))
		return err
	})
	return out, err
}

// DeactivateConfigTargetsExcept marks config targets that are not in names as removed.
func (s *Store) DeactivateConfigTargetsExcept(names []string) error {
	return s.exec(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id, name FROM targets WHERE source='config' AND active=1`)
		if err != nil {
			return err
		}
		keep := map[string]bool{}
		for _, n := range names {
			keep[strings.ToLower(n)] = true
		}
		var drop []int64
		for rows.Next() {
			var id int64
			var n string
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return err
			}
			if !keep[strings.ToLower(n)] {
				drop = append(drop, id)
			}
		}
		rows.Close()
		for _, id := range drop {
			if _, err := tx.Exec(`UPDATE targets SET active=0, updated_at=? WHERE id=?`, us(s.now()), id); err != nil {
				return err
			}
		}
		return nil
	})
}

// CreateUITarget inserts a UI-managed target. It returns ErrDuplicate if the name exists.
func (s *Store) CreateUITarget(name, host, spec string) (TargetRow, error) {
	var out TargetRow
	err := s.exec(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM targets WHERE name=?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrDuplicate
		}
		now := us(s.now())
		res, err := tx.Exec(`INSERT INTO targets(name, host, active, source, paused, spec, created_at, updated_at) VALUES (?,?,1,'ui',0,?,?,?)`, name, host, spec, now, now)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		out, err = scanTarget(tx.QueryRow(`SELECT `+targetCols+` FROM targets WHERE id=?`, id))
		return err
	})
	return out, err
}

// SetTargetPaused changes the paused flag of a target.
func (s *Store) SetTargetPaused(id int64, paused bool) error {
	return s.exec(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE targets SET paused=?, updated_at=? WHERE id=?`, boolInt(paused), us(s.now()), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DeleteTarget removes a target and all of its data.
func (s *Store) DeleteTarget(id int64) error {
	return s.exec(func(tx *sql.Tx) error {
		var probeIDs []int64
		rows, err := tx.Query(`SELECT id FROM probes WHERE target_id=?`, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p int64
			if err := rows.Scan(&p); err != nil {
				rows.Close()
				return err
			}
			probeIDs = append(probeIDs, p)
		}
		rows.Close()
		for _, p := range probeIDs {
			for _, t := range []string{"http_samples", "tcp_samples", "dns_samples", "probe_rollup_1m", "probe_rollup_1h"} {
				if _, err := tx.Exec(`DELETE FROM `+t+` WHERE probe_id=?`, p); err != nil {
					return err
				}
			}
		}
		stmts := []string{
			`DELETE FROM probes WHERE target_id=?1`,
			`DELETE FROM path_hops WHERE path_id IN (SELECT id FROM paths WHERE target_id=?1)`,
			`DELETE FROM paths WHERE target_id=?1`,
			`DELETE FROM icmp_rounds WHERE target_id=?1`,
			`DELETE FROM icmp_rollup_1m WHERE target_id=?1`,
			`DELETE FROM icmp_rollup_1h WHERE target_id=?1`,
			`DELETE FROM gaps WHERE target_id=?1`,
			`DELETE FROM events WHERE target_id=?1`,
			`DELETE FROM outbox WHERE alert_id IN (SELECT id FROM alerts WHERE target_id=?1)`,
			`DELETE FROM alerts WHERE target_id=?1`,
			`DELETE FROM silences WHERE target_id=?1`,
			`DELETE FROM targets WHERE id=?1`,
		}
		for _, q := range stmts {
			if _, err := tx.Exec(q, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnsureProbe returns the id of the probe with (targetID, key), creating it if needed and
// refreshing its label. targetID 0 means "not bound to a target" (DNS probes).
func (s *Store) EnsureProbe(targetID int64, typ, key, label string) (int64, error) {
	var id int64
	err := s.exec(func(tx *sql.Tx) error {
		err := tx.QueryRow(`SELECT id FROM probes WHERE target_id=? AND key=?`, targetID, key).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			res, err := tx.Exec(`INSERT INTO probes(target_id, type, key, label) VALUES (?,?,?,?)`, targetID, typ, key, label)
			if err != nil {
				return err
			}
			id, _ = res.LastInsertId()
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE probes SET label=?, type=? WHERE id=?`, label, typ, id)
		return err
	})
	return id, err
}

// ---------------------------------------------------------------------------
// paths

// NewPath ends the target's current path version (if any) and starts a new one.
func (s *Store) NewPath(targetID int64, ip string, destTTL int, ts time.Time) (int64, error) {
	var id int64
	err := s.exec(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE paths SET ended_at=? WHERE target_id=? AND ended_at IS NULL`, us(ts), targetID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO paths(target_id, resolved_ip, dest_ttl, started_at) VALUES (?,?,?,?)`, targetID, ip, destTTL, us(ts))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// SetPathDestTTL records the destination TTL once it is known.
func (s *Store) SetPathDestTTL(pathID int64, ttl int) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE paths SET dest_ttl=? WHERE id=?`, ttl, pathID)
		return err
	})
}

// AddPathHop records a responder for (path, ttl) at a stable idx (0-based, first-seen order).
func (s *Store) AddPathHop(pathID int64, ttl, idx int, addr string) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO path_hops(path_id, ttl, idx, address, share) VALUES (?,?,?,?,COALESCE((SELECT share FROM path_hops WHERE path_id=? AND ttl=? AND idx=?),1))`,
			pathID, ttl, idx, addr, pathID, ttl, idx)
		return err
	})
}

// ShareUpdate is one responder share.
type ShareUpdate struct {
	TTL   int
	Idx   int
	Share float64
}

// UpdatePathShares stores the fraction of replies per responder.
func (s *Store) UpdatePathShares(pathID int64, shares []ShareUpdate) {
	if len(shares) == 0 {
		return
	}
	s.enqueue(func(tx *sql.Tx) error {
		for _, sh := range shares {
			if _, err := tx.Exec(`UPDATE path_hops SET share=? WHERE path_id=? AND ttl=? AND idx=?`, sh.Share, pathID, sh.TTL, sh.Idx); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// events

// Event is an annotation (state transition).
type Event struct {
	ID       int64
	TargetID *int64
	Kind     string
	TTL      *int
	From     time.Time
	To       *time.Time // nil = instant or still open
	Details  json.RawMessage
}

// Event kinds.
const (
	EventRouteChange      = "route_change"
	EventRateLimited      = "rate_limited"
	EventDegraded         = "degraded"
	EventICMPUnresponsive = "icmp_unresponsive"
	EventGap              = "gap"
	EventLocalOutage      = "local_outage"
)

// InsertEvent stores an event synchronously and returns its id.
func (s *Store) InsertEvent(e Event) (int64, error) {
	var id int64
	err := s.exec(func(tx *sql.Tx) error {
		var tid, ttl, to any
		if e.TargetID != nil {
			tid = *e.TargetID
		}
		if e.TTL != nil {
			ttl = *e.TTL
		}
		if e.To != nil {
			to = us(*e.To)
		}
		var det any
		if len(e.Details) > 0 {
			det = string(e.Details)
		}
		res, err := tx.Exec(`INSERT INTO events(target_id, kind, ttl, started_at, ended_at, details) VALUES (?,?,?,?,?,?)`, tid, e.Kind, ttl, us(e.From), to, det)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// CloseEvent sets the end time of an open event.
func (s *Store) CloseEvent(id int64, end time.Time) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE events SET ended_at=? WHERE id=? AND ended_at IS NULL`, us(end), id)
		return err
	})
}

// ---------------------------------------------------------------------------
// ip_info

// IPInfo is cached enrichment for one address.
type IPInfo struct {
	Address   string
	Hostname  string
	ASN       int
	ASName    string
	UpdatedAt time.Time
}

// PutIPInfo upserts enrichment for an address.
func (s *Store) PutIPInfo(i IPInfo) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO ip_info(address, hostname, asn, as_name, updated_at) VALUES (?,?,?,?,?)`,
			i.Address, nullStr(i.Hostname), nullInt(int64(i.ASN)), nullStr(i.ASName), us(i.UpdatedAt))
		return err
	})
}

// LoadIPInfo returns all cached enrichment rows.
func (s *Store) LoadIPInfo() ([]IPInfo, error) {
	rows, err := s.rdb.Query(`SELECT address, COALESCE(hostname,''), COALESCE(asn,0), COALESCE(as_name,''), updated_at FROM ip_info`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPInfo
	for rows.Next() {
		var i IPInfo
		var u int64
		if err := rows.Scan(&i.Address, &i.Hostname, &i.ASN, &i.ASName, &u); err != nil {
			return nil, err
		}
		i.UpdatedAt = fromUs(u)
		out = append(out, i)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// alerts, outbox, silences (the engine itself is a later phase)

// Alert is one row of the alerts table.
type Alert struct {
	ID               int64
	TargetID         *int64
	Rule             string
	RuleType         string
	State            string // firing | resolved | suppressed
	SuppressedReason string // silence | maintenance | local_outage | cooldown
	StartedAt        time.Time
	EndedAt          *time.Time
	Value            *float64
	PeakValue        *float64
	Baseline         *float64
	Message          string
	DetailsJSON      string
}

// SaveAlert inserts the alert (ID == 0, ID is set) or updates it.
func (s *Store) SaveAlert(a *Alert) error {
	return s.exec(func(tx *sql.Tx) error {
		var tid, end, val, peak, base any
		if a.TargetID != nil {
			tid = *a.TargetID
		}
		if a.EndedAt != nil {
			end = us(*a.EndedAt)
		}
		if a.Value != nil {
			val = *a.Value
		}
		if a.PeakValue != nil {
			peak = *a.PeakValue
		}
		if a.Baseline != nil {
			base = *a.Baseline
		}
		if a.ID == 0 {
			res, err := tx.Exec(`INSERT INTO alerts(target_id, rule, rule_type, state, suppressed_reason, started_at, ended_at, value, peak_value, baseline, message, details_json)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, tid, a.Rule, a.RuleType, a.State, nullStr(a.SuppressedReason), us(a.StartedAt), end, val, peak, base, a.Message, nullStr(a.DetailsJSON))
			if err != nil {
				return err
			}
			a.ID, err = res.LastInsertId()
			return err
		}
		_, err := tx.Exec(`UPDATE alerts SET state=?, suppressed_reason=?, ended_at=?, value=?, peak_value=?, baseline=?, message=?, details_json=? WHERE id=?`,
			a.State, nullStr(a.SuppressedReason), end, val, peak, base, a.Message, nullStr(a.DetailsJSON), a.ID)
		return err
	})
}

// CreateSilence inserts a UI silence.
func (s *Store) CreateSilence(x Silence) (Silence, error) {
	err := s.exec(func(tx *sql.Tx) error {
		var tid, rule any
		if x.TargetID != nil {
			tid = *x.TargetID
		}
		if x.Rule != nil {
			rule = *x.Rule
		}
		res, err := tx.Exec(`INSERT INTO silences(target_id, rule, starts_at, ends_at, reason, created_by) VALUES (?,?,?,?,?,?)`,
			tid, rule, us(x.StartsAt), us(x.EndsAt), x.Reason, x.CreatedBy)
		if err != nil {
			return err
		}
		x.ID, err = res.LastInsertId()
		return err
	})
	return x, err
}

// DeleteSilence ends (deletes) a UI silence. It returns ErrNotFound for unknown ids.
func (s *Store) DeleteSilence(id int64) error {
	return s.exec(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM silences WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}
