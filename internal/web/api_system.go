package web

import (
	"net/http"

	"github.com/i-press-buttons/pathwatch/internal/selfmon"
)

// systemSummary is the monitor health part of /api/status.
func (s *Server) systemSummary() map[string]any {
	if s.d.System == nil {
		return nil
	}
	snap := s.d.System.Snapshot()
	iss := snap.Issues
	if iss == nil {
		iss = []selfmon.Issue{}
	}
	return map[string]any{"state": snap.State, "issues": iss}
}

// handleSystem describes pathwatch's own health: disk, database, probing and clock.
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if s.d.System == nil {
		writeError(w, http.StatusServiceUnavailable, "monitor health is not available")
		return
	}
	snap := s.d.System.Snapshot()
	iss := snap.Issues
	if iss == nil {
		iss = []selfmon.Issue{}
	}
	disk := map[string]any{"known": snap.DiskKnown, "dir": snap.DataDir}
	if snap.DiskKnown {
		disk["free_bytes"], disk["total_bytes"], disk["free_pct"] = snap.DiskFreeBytes, snap.DiskTotalBytes, snap.DiskFreePct
	}
	clock := map[string]any{"server": nil}
	if c := snap.Clock; c.Server != "" {
		clock["server"] = c.Server
		clock["checked"] = optMS(c.Checked)
		clock["error"] = optStr(c.Err)
		if c.Measured {
			clock["offset_ms"] = float64(c.Offset.Microseconds()) / 1000
			clock["rtt_ms"] = float64(c.RTT.Microseconds()) / 1000
		}
	}
	rw, rt := snap.RoundsWindow, snap.Rounds
	writeJSON(w, http.StatusOK, map[string]any{
		"at":     snap.At.UnixMilli(),
		"state":  snap.State,
		"issues": iss,
		"disk":   disk,
		"database": map[string]any{
			"size_bytes": snap.DBBytes, "wal_bytes": snap.WALBytes, "writer_alive": snap.WriterAlive,
			"dropped_writes": snap.DroppedWrites, "write_errors": snap.WriteErrors,
			"last_commit_ms": float64(snap.CommitTime.Microseconds()) / 1000,
		},
		"probing": map[string]any{
			"healthy": snap.SchedulerOK, "reason": optStr(snap.SchedulerReason),
			"rounds_10m": rw.Rounds, "late_10m": rw.Late, "discarded_10m": rw.Discarded, "send_errors_10m": rw.SendErrors,
			"rounds_total": rt.Rounds, "late_total": rt.Late, "discarded_total": rt.Discarded, "send_errors_total": rt.SendErrors,
		},
		"clock": clock,
		"process": map[string]any{
			"uptime_s": int64(snap.Uptime.Seconds()), "goroutines": snap.Goroutines, "heap_bytes": snap.HeapBytes, "version": s.d.Version,
		},
	})
}
