package store

import (
	"database/sql"
	"time"
)

// certEntry is the newest certificate expiry known for one probe. notAfter 0 caches "no
// certificate seen": a plain http:// probe never has one, and finding that out from the
// database means walking all of the probe's samples.
type certEntry struct {
	seen     int64 // time of the sample (or rollup bucket) the expiry came from, unix micros
	notAfter int64 // unix micros; 0 = none
}

// noteCert is called for every recorded HTTP sample. It keeps the cache current without a
// query; samples without a certificate (plain http, failed handshakes) change nothing, like
// the lookup in loadCert, which skips them.
func (s *Store) noteCert(h HTTPSample) {
	if h.CertNotAfter.IsZero() {
		return
	}
	s.certMu.Lock()
	s.putCert(h.ProbeID, certEntry{seen: us(h.TS), notAfter: us(h.CertNotAfter)})
	s.certMu.Unlock()
}

// forgetCerts drops the cached entries of probes that were deleted or (re)created, since their
// ids can be reused.
func (s *Store) forgetCerts(probeIDs ...int64) {
	s.certMu.Lock()
	for _, id := range probeIDs {
		delete(s.certs, id)
	}
	s.certGen++
	s.certMu.Unlock()
}

// putCert stores e unless the cache already holds a certificate seen at or after it.
// The caller holds certMu.
func (s *Store) putCert(probeID int64, e certEntry) {
	if cur, ok := s.certs[probeID]; ok && cur.notAfter != 0 && (e.notAfter == 0 || cur.seen >= e.seen) {
		return
	}
	s.certs[probeID] = e
}

// latestCert answers from the cache; the first lookup of a probe reads the database and
// caches the answer, including "none".
func (s *Store) latestCert(probeID int64) (time.Time, bool) {
	s.certMu.Lock()
	e, ok := s.certs[probeID]
	gen := s.certGen
	s.certMu.Unlock()
	if !ok {
		e = s.loadCert(probeID)
		s.certMu.Lock()
		// Cache the result unless entries were forgotten while the query ran (it may have read
		// rows of a deleted probe whose id is now reused); a sample recorded meanwhile wins.
		if s.certGen == gen {
			s.putCert(probeID, e)
			e = s.certs[probeID]
		}
		s.certMu.Unlock()
	}
	if e.notAfter == 0 {
		return time.Time{}, false
	}
	return fromUs(e.notAfter), true
}

// loadCert reads the newest certificate of a probe from its raw samples, then from the
// 1-minute rollups once the raw samples have been expired.
func (s *Store) loadCert(probeID int64) certEntry {
	var seen, v sql.NullInt64
	_ = s.rdb.QueryRow(`SELECT ts, cert_not_after FROM http_samples WHERE probe_id=? AND cert_not_after IS NOT NULL ORDER BY ts DESC LIMIT 1`, probeID).Scan(&seen, &v)
	if !v.Valid {
		_ = s.rdb.QueryRow(`SELECT bucket, cert_not_after FROM probe_rollup_1m WHERE probe_id=? AND cert_not_after IS NOT NULL ORDER BY bucket DESC LIMIT 1`, probeID).Scan(&seen, &v)
	}
	if !v.Valid {
		return certEntry{}
	}
	return certEntry{seen: seen.Int64, notAfter: v.Int64}
}
