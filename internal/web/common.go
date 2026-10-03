package web

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

const maxRange = 400 * 24 * time.Hour

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// fp returns a rounded pointer for JSON (nil -> null).
func fp(v float64, ok bool) *float64 {
	if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	r := round3(v)
	return &r
}

func msPtr(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	v := t.UnixMilli()
	return &v
}

// parseRange implements the range parameters of docs/API.md: from/to in Unix ms, or range=…
// (ignored when from is given); default to=now, from=to-1h.
func (s *Server) parseRange(r *http.Request) (from, to time.Time, err error) {
	q := r.URL.Query()
	now := s.now()
	to = now
	if v := q.Get("to"); v != "" {
		n, perr := strconv.ParseInt(v, 10, 64)
		if perr != nil {
			return from, to, fmt.Errorf("invalid to: expected Unix milliseconds")
		}
		to = time.UnixMilli(n).UTC()
	}
	if to.After(now) {
		to = now
	}
	switch {
	case q.Get("from") != "":
		n, perr := strconv.ParseInt(q.Get("from"), 10, 64)
		if perr != nil {
			return from, to, fmt.Errorf("invalid from: expected Unix milliseconds")
		}
		from = time.UnixMilli(n).UTC()
	case q.Get("range") != "":
		d, perr := config.ParseDuration(q.Get("range"))
		if perr != nil || d <= 0 {
			return from, to, fmt.Errorf("invalid range %q (use 1h, 6h, 24h, 7d, 30d, 90d)", q.Get("range"))
		}
		from = to.Add(-d)
	default:
		from = to.Add(-time.Hour)
	}
	if !to.After(from) {
		return from, to, fmt.Errorf("to must be after from")
	}
	if to.Sub(from) > maxRange {
		return from, to, fmt.Errorf("range too large (max %d days)", int(maxRange/(24*time.Hour)))
	}
	return from.UTC(), to.UTC(), nil
}

func intParam(r *http.Request, name string, def, min, max int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("invalid %s: expected an integer between %d and %d", name, min, max)
	}
	return n, nil
}

// targetFromPath loads the target of /api/targets/{id}/….
func (s *Server) targetFromPath(w http.ResponseWriter, r *http.Request) (store.TargetRow, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target id")
		return store.TargetRow{}, false
	}
	row, err := s.d.Store.Target(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "target not found")
		} else {
			s.internal(w, r, err)
		}
		return row, false
	}
	return row, true
}
