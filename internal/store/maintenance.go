package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"
)

// retainChunk is the most rows one retention delete removes, so the writer is never held for
// long and normal writes interleave with a big expiry run.
const retainChunk = 5000

// retainJob is one table to expire: rows with col < cutoff go. col is the second primary-key
// column (after key) of every table below, so expiry works key by key with a primary-key range
// instead of scanning the table from its start.
type retainJob struct {
	table, key, pk, col string
	cutoff              time.Time
}

// nextKeySQL finds the smallest key above ? with one index seek.
func (j retainJob) nextKeySQL() string {
	return fmt.Sprintf(`SELECT MIN(%[2]s) FROM %[1]s WHERE %[2]s > ?`, j.table, j.key)
}

// deleteSQL removes up to retainChunk expired rows of one key (args: key, cutoff).
func (j retainJob) deleteSQL() string {
	return fmt.Sprintf(`DELETE FROM %[1]s WHERE (%[3]s) IN (SELECT %[3]s FROM %[1]s WHERE %[2]s=? AND %[4]s<? LIMIT %[5]d)`, j.table, j.key, j.pk, j.col, retainChunk)
}

// retainJobs lists the tables to expire for the configured retention periods.
func (s *Store) retainJobs(now time.Time) []retainJob {
	var jobs []retainJob
	if d := s.opts.RawRetention; d > 0 {
		c := now.Add(-d)
		jobs = append(jobs,
			retainJob{"icmp_rounds", "target_id", "target_id, ts", "ts", c},
			retainJob{"http_samples", "probe_id", "probe_id, ts", "ts", c},
			retainJob{"tcp_samples", "probe_id", "probe_id, ts", "ts", c},
			retainJob{"dns_samples", "probe_id", "probe_id, ts", "ts", c})
	}
	if d := s.opts.Rollup1mRetention; d > 0 {
		c := now.Add(-d)
		jobs = append(jobs,
			retainJob{"icmp_rollup_1m", "target_id", "target_id, bucket, ttl, path_id", "bucket", c},
			retainJob{"probe_rollup_1m", "probe_id", "probe_id, bucket", "bucket", c})
	}
	if d := s.opts.Rollup1hRetention; d > 0 {
		c := now.Add(-d)
		jobs = append(jobs,
			retainJob{"icmp_rollup_1h", "target_id", "target_id, bucket, ttl, path_id", "bucket", c},
			retainJob{"probe_rollup_1h", "probe_id", "probe_id, bucket", "bucket", c})
	}
	return jobs
}

// Retain deletes expired raw and rollup data (in chunks, interleaved with normal writes) and
// then returns freed pages to the filesystem with an incremental vacuum. It stops between
// chunks once ctx is cancelled.
func (s *Store) Retain(ctx context.Context) error {
	now := s.now()
	if d := s.opts.Rollup1mRetention; d > 0 {
		// annotations follow the 1m retention
		c := now.Add(-d)
		if _, err := s.deleteWhere(ctx, `DELETE FROM events WHERE COALESCE(ended_at, started_at) < ? AND (ended_at IS NOT NULL OR kind = 'route_change')`, us(c)); err != nil {
			return err
		}
		if _, err := s.deleteWhere(ctx, `DELETE FROM gaps WHERE ended_at < ?`, us(c)); err != nil {
			return err
		}
	}
	var total int64
	for _, j := range s.retainJobs(now) {
		n, err := s.expire(ctx, j)
		total += n
		if err != nil {
			return err
		}
	}
	if total > 0 {
		s.log.Info("retention removed expired rows", "rows", total)
		if _, err := s.wdb.ExecContext(ctx, `PRAGMA incremental_vacuum(5000)`); err != nil {
			return err
		}
	}
	return nil
}

// expire deletes j's expired rows and returns how many it removed. It walks the keys actually
// present in the table (not the targets/probes tables) so rows orphaned by a deleted target
// are cleaned up too; each step is an index seek, and so is each chunk's primary-key range.
func (s *Store) expire(ctx context.Context, j retainJob) (int64, error) {
	var total int64
	after := int64(math.MinInt64)
	for {
		var k sql.NullInt64
		if err := s.rdb.QueryRowContext(ctx, j.nextKeySQL(), after).Scan(&k); err != nil {
			return total, err
		}
		if !k.Valid {
			return total, nil
		}
		for {
			if err := ctx.Err(); err != nil {
				return total, err
			}
			n, err := s.deleteWhere(ctx, j.deleteSQL(), k.Int64, us(j.cutoff))
			total += n
			if err != nil {
				return total, err
			}
			if n < retainChunk {
				break
			}
		}
		after = k.Int64
	}
}

func (s *Store) deleteWhere(ctx context.Context, q string, args ...any) (int64, error) {
	var n int64
	err := s.exec(func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// Backfill recomputes 1m rollups (and the affected 1h rollups) from raw data for every bucket
// missed while the process was down, and seeds the live aggregator with the rounds and samples
// of the still-open minute. Call once at startup before probing begins.
func (s *Store) Backfill(ctx context.Context) error {
	cur := s.now().Truncate(MinuteStep)
	tmp := NewAggregator()
	var batches []MinuteBatch
	flush := func(force bool) {
		if len(batches) >= 60 || (force && len(batches) > 0) {
			s.persistMinutes(batches)
			batches = nil
		}
	}
	collect := func(mbs []MinuteBatch) {
		batches = append(batches, mbs...)
		flush(false)
	}

	targets, err := s.Targets(true)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		var last sql.NullInt64
		_ = s.rdb.QueryRow(`SELECT MAX(bucket) FROM icmp_rollup_1m WHERE target_id=?`, t.ID).Scan(&last)
		from := int64(0)
		if last.Valid {
			from = last.Int64
		}
		rows, err := s.rdb.QueryContext(ctx, `SELECT ts, path_id, hop_count, results FROM icmp_rounds WHERE target_id=? AND ts>=? ORDER BY ts`, t.ID, from)
		if err != nil {
			return err
		}
		n := 0
		for rows.Next() {
			var ts, path int64
			var hc int
			var blob []byte
			if err := rows.Scan(&ts, &path, &hc, &blob); err != nil {
				rows.Close()
				return err
			}
			hops, err := DecodeHops(blob, hc)
			if err != nil {
				continue
			}
			r := Round{TargetID: t.ID, TS: fromUs(ts), PathID: path, Hops: hops}
			if r.TS.Truncate(MinuteStep).Compare(cur) >= 0 {
				s.agg.AddRound(r)
				continue
			}
			tmp.AddRound(r)
			if n++; n%2000 == 0 {
				collect(tmp.Flush(r.TS.Truncate(MinuteStep)))
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		collect(tmp.Flush(cur))
		tmp.ResetJitter(t.ID)
	}

	// probes
	type pr struct {
		id  int64
		typ string
	}
	var probes []pr
	prows, err := s.rdb.Query(`SELECT id, type FROM probes`)
	if err != nil {
		return err
	}
	for prows.Next() {
		var p pr
		if err := prows.Scan(&p.id, &p.typ); err != nil {
			prows.Close()
			return err
		}
		probes = append(probes, p)
	}
	prows.Close()
	for _, p := range probes {
		if err := ctx.Err(); err != nil {
			return err
		}
		var last sql.NullInt64
		_ = s.rdb.QueryRow(`SELECT MAX(bucket) FROM probe_rollup_1m WHERE probe_id=?`, p.id).Scan(&last)
		from := int64(0)
		if last.Valid {
			from = last.Int64
		}
		var rows *sql.Rows
		switch p.typ {
		case "http":
			rows, err = s.rdb.QueryContext(ctx, `SELECT ts, COALESCE(status,0), COALESCE(dns_us,0), COALESCE(connect_us,0), COALESCE(tls_us,0), COALESCE(ttfb_us,0), COALESCE(transfer_us,0), COALESCE(total_us,0), cert_not_after, COALESCE(error,'') FROM http_samples WHERE probe_id=? AND ts>=? ORDER BY ts`, p.id, from)
		case "tcp":
			rows, err = s.rdb.QueryContext(ctx, `SELECT ts, COALESCE(connect_us,0), COALESCE(error,'') FROM tcp_samples WHERE probe_id=? AND ts>=? ORDER BY ts`, p.id, from)
		case "dns":
			rows, err = s.rdb.QueryContext(ctx, `SELECT ts, COALESCE(rtt_us,0), COALESCE(error,'') FROM dns_samples WHERE probe_id=? AND ts>=? ORDER BY ts`, p.id, from)
		default:
			continue
		}
		if err != nil {
			return err
		}
		n := 0
		for rows.Next() {
			var ts int64
			var tsT time.Time
			switch p.typ {
			case "http":
				var h HTTPSample
				var cert sql.NullInt64
				var dns, conn, tls, ttfb, tr, tot int64
				if err := rows.Scan(&ts, &h.Status, &dns, &conn, &tls, &ttfb, &tr, &tot, &cert, &h.Error); err != nil {
					rows.Close()
					return err
				}
				h.ProbeID, h.TS = p.id, fromUs(ts)
				h.DNS, h.Connect, h.TLS = time.Duration(dns)*time.Microsecond, time.Duration(conn)*time.Microsecond, time.Duration(tls)*time.Microsecond
				h.TTFB, h.Transfer, h.Total = time.Duration(ttfb)*time.Microsecond, time.Duration(tr)*time.Microsecond, time.Duration(tot)*time.Microsecond
				if cert.Valid {
					h.CertNotAfter = fromUs(cert.Int64)
				}
				tsT = h.TS
				if tsT.Truncate(MinuteStep).Compare(cur) >= 0 {
					s.agg.AddHTTP(h)
				} else {
					tmp.AddHTTP(h)
				}
			case "tcp":
				var c TCPSample
				var cu int64
				if err := rows.Scan(&ts, &cu, &c.Error); err != nil {
					rows.Close()
					return err
				}
				c.ProbeID, c.TS, c.Connect = p.id, fromUs(ts), time.Duration(cu)*time.Microsecond
				tsT = c.TS
				if tsT.Truncate(MinuteStep).Compare(cur) >= 0 {
					s.agg.AddTCP(c)
				} else {
					tmp.AddTCP(c)
				}
			case "dns":
				var d DNSSample
				var ru int64
				if err := rows.Scan(&ts, &ru, &d.Error); err != nil {
					rows.Close()
					return err
				}
				d.ProbeID, d.TS, d.RTT = p.id, fromUs(ts), time.Duration(ru)*time.Microsecond
				tsT = d.TS
				if tsT.Truncate(MinuteStep).Compare(cur) >= 0 {
					s.agg.AddDNS(d)
				} else {
					tmp.AddDNS(d)
				}
			}
			if n++; n%2000 == 0 {
				collect(tmp.Flush(tsT.Truncate(MinuteStep)))
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		collect(tmp.Flush(cur))
	}
	flush(true)
	return nil
}
