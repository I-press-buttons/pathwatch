package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/publicip"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// digestStateKey is the settings-table key holding when the last scheduled digest was sent, so a
// restart neither repeats nor skips one.
const digestStateKey = "state.digest_last_sent"

// maxDigestTargets bounds the per-target lines (chat channels limit message sizes).
const maxDigestTargets = 25

// Outbox queues notifications for delivery (the rule engine's sender implements it).
type Outbox interface {
	Channels() []string
	Enqueue(n alert.Notification, channels []string)
}

// digestTarget is one target's line of the digest.
type digestTarget struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	AvailabilityPct *float64 `json:"availability_pct"`
	AvgMS           *float64 `json:"avg_ms"`
	P95MS           *float64 `json:"p95_ms"`
	HTTPSuccessPct  *float64 `json:"http_success_pct"`
	Alerts          int      `json:"alerts"`
	LongestMS       int64    `json:"longest_ms"`
	LongestRule     string   `json:"longest_rule,omitempty"`
}

// Digest is the summary of one period.
type Digest struct {
	Name      string         `json:"name"` // "daily summary"
	From      time.Time      `json:"-"`
	To        time.Time      `json:"-"`
	Targets   []digestTarget `json:"targets"`
	Alerts    int            `json:"alerts"`
	Ongoing   int            `json:"ongoing"`
	Other     []string       `json:"other"` // alerts without a target ("DNS failure: home 2×")
	IPChanges []string       `json:"ip_changes"`
	Health    []string       `json:"health"`
	Text      string         `json:"text"`
	Truncated bool           `json:"truncated"`
}

func digestName(schedule string) string {
	if schedule == config.DigestWeekly {
		return "weekly summary"
	}
	return "daily summary"
}

func digestPeriod(schedule string) time.Duration {
	if schedule == config.DigestWeekly {
		return 7 * 24 * time.Hour
	}
	return 24 * time.Hour
}

// counted reports whether an alert counts in the digest: suppressed ones were never sent.
func counted(a store.Alert) bool {
	return a.State == alert.StateFiring || a.State == alert.StateResolved
}

func alertSpan(a store.Alert, to time.Time) time.Duration {
	end := to
	if a.EndedAt != nil && a.EndedAt.Before(to) {
		end = *a.EndedAt
	}
	if d := end.Sub(a.StartedAt); d > 0 {
		return d
	}
	return 0
}

// BuildDigest summarizes [from, to): availability and latency per target, alerts, public IP
// changes and the monitor's current health.
func (s *Server) BuildDigest(ctx context.Context, name string, from, to time.Time) (*Digest, error) {
	d := &Digest{Name: name, From: from, To: to, Targets: []digestTarget{}, Other: []string{}, IPChanges: []string{}, Health: []string{}}
	rows, err := s.d.Store.Targets(false)
	if err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
	plan := windowPlan(from, to, store.TierFor(from, to))
	for _, row := range rows {
		if row.Paused {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v := s.viewOf(row)
		t := digestTarget{ID: row.ID, Name: row.Name}
		e, err := s.e2e(ctx, v, plan, false)
		if err != nil {
			return nil, err
		}
		if len(e.points) > 0 && e.points[0].n > 0 {
			p := e.points[0]
			if p.haveLoss {
				t.AvailabilityPct = fp(100-p.loss, true)
			}
			t.AvgMS = fp(p.avg, p.haveAvg)
			t.P95MS = fp(p.p95, p.haveAvg && p.p95 > 0)
		}
		if ps, err := s.probeStats(ctx, v, from, to); err == nil {
			var n, errs int64
			for _, p := range ps {
				if p.Type == config.ProbeHTTP {
					n, errs = n+p.Samples, errs+p.Errors
				}
			}
			if n > 0 {
				t.HTTPSuccessPct = fp(float64(n-errs)/float64(n)*100, true)
			}
		}
		als, err := s.d.Store.AlertsOverlapping(row.ID, from, to)
		if err != nil {
			return nil, err
		}
		for _, a := range als {
			if !counted(a) || a.RuleType == "route_change" {
				continue
			}
			t.Alerts++
			d.Alerts++
			if a.EndedAt == nil {
				d.Ongoing++
			}
			if sp := alertSpan(a, to); sp.Milliseconds() > t.LongestMS {
				t.LongestMS, t.LongestRule = sp.Milliseconds(), a.Rule
			}
		}
		d.Targets = append(d.Targets, t)
	}

	// alerts without a target: local connectivity, DNS probes, monitor health
	glob, err := s.d.Store.AlertsOverlappingTypes(from, alert.RuleLocalConnectivity, "dns_failure", "dns_latency", alert.RuleMonitorHealth)
	if err != nil {
		return nil, err
	}
	type agg struct {
		n       int
		longest time.Duration
	}
	others := map[string]*agg{}
	var order []string
	for _, a := range glob {
		if !counted(a) || a.TargetID != nil || !a.StartedAt.Before(to) {
			continue
		}
		d.Alerts++
		if a.EndedAt == nil {
			d.Ongoing++
		}
		k := a.Rule
		if a.RuleType == alert.RuleLocalConnectivity {
			k = "local connection down"
		}
		if others[k] == nil {
			others[k] = &agg{}
			order = append(order, k)
		}
		others[k].n++
		if sp := alertSpan(a, to); sp > others[k].longest {
			others[k].longest = sp
		}
	}
	for _, k := range order {
		o := others[k]
		d.Other = append(d.Other, fmt.Sprintf("%s: %d× (longest %s)", k, o.n, alert.FormatDuration(o.longest)))
	}

	evs, err := s.d.Store.Events(store.EventQuery{From: from, To: to, Kinds: []string{publicip.EventKind}})
	if err != nil {
		return nil, err
	}
	for _, ev := range evs {
		pd, ok := publicip.ParseDetails(ev.Details)
		if !ok || pd.Previous == "" || ev.From.Before(from) || !ev.From.Before(to) {
			continue
		}
		fam := "IPv4"
		if pd.Family == publicip.IPv6 {
			fam = "IPv6"
		}
		line := fmt.Sprintf("%s %s → %s (%s)", fam, pd.Previous, pd.Addr, s.digestTime(ev.From))
		if pd.ASN != 0 && pd.PrevASN != 0 && pd.ASN != pd.PrevASN {
			line += fmt.Sprintf(", now AS%d %s", pd.ASN, pd.ASName)
		}
		d.IPChanges = append(d.IPChanges, line)
	}
	if s.d.System != nil {
		for _, i := range s.d.System.Snapshot().Issues {
			d.Health = append(d.Health, i.Message)
		}
	}
	d.Text = d.render(s.digestTime)
	return d, nil
}

// digestTime formats a time in the digest's time zone.
func (s *Server) digestTime(t time.Time) string {
	return t.In(digestLocation(s.cfg().Digest)).Format("Jan 2 15:04")
}

func digestLocation(c config.DigestConfig) *time.Location {
	if c.Timezone != "" {
		if loc, err := time.LoadLocation(c.Timezone); err == nil {
			return loc
		}
	}
	return time.Local
}

func digestPct(p *float64) string {
	if p == nil {
		return "–"
	}
	v := *p
	switch {
	case v >= 100:
		return "100%"
	case v >= 99.995 && v < 100:
		return "99.99%"
	case v >= 99.9:
		return fmt.Sprintf("%.2f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}

func digestMS(p *float64) string {
	if p == nil {
		return "–"
	}
	if *p < 10 {
		return fmt.Sprintf("%.1f ms", *p)
	}
	return fmt.Sprintf("%.0f ms", *p)
}

func (d *Digest) render(at func(time.Time) string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s to %s\n", at(d.From), at(d.To))
	switch {
	case d.Alerts == 0:
		b.WriteString("No alerts.\n")
	case d.Ongoing > 0:
		fmt.Fprintf(&b, "%d %s, %d still firing.\n", d.Alerts, pluralWord(d.Alerts, "alert", "alerts"), d.Ongoing)
	default:
		fmt.Fprintf(&b, "%d %s, all resolved.\n", d.Alerts, pluralWord(d.Alerts, "alert", "alerts"))
	}
	if len(d.Targets) > 0 {
		b.WriteString("\nTargets (availability · average · p95):\n")
		for i, t := range d.Targets {
			if i == maxDigestTargets {
				fmt.Fprintf(&b, "  … and %d more\n", len(d.Targets)-maxDigestTargets)
				d.Truncated = true
				break
			}
			fmt.Fprintf(&b, "• %s: %s · %s · %s", t.Name, digestPct(t.AvailabilityPct), digestMS(t.AvgMS), digestMS(t.P95MS))
			if t.HTTPSuccessPct != nil {
				fmt.Fprintf(&b, " · HTTP ok %s", digestPct(t.HTTPSuccessPct))
			}
			if t.Alerts > 0 {
				fmt.Fprintf(&b, " · %d %s (longest %s, %s)", t.Alerts, pluralWord(t.Alerts, "alert", "alerts"), alert.FormatDuration(time.Duration(t.LongestMS)*time.Millisecond), t.LongestRule)
			}
			b.WriteString("\n")
		}
	}
	if len(d.Other) > 0 {
		b.WriteString("\nOther alerts:\n")
		for _, o := range d.Other {
			b.WriteString("• " + o + "\n")
		}
	}
	if len(d.IPChanges) > 0 {
		b.WriteString("\nPublic IP changes:\n")
		for _, c := range d.IPChanges {
			b.WriteString("• " + c + "\n")
		}
	}
	if len(d.Health) > 0 {
		b.WriteString("\nMonitor health:\n")
		for _, h := range d.Health {
			b.WriteString("• " + h + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// notification wraps the digest for the outbox.
func (s *Server) digestNotification(d *Digest) alert.Notification {
	from, to := d.From.UTC(), d.To.UTC()
	n := alert.Notification{
		Target: "pathwatch", Rule: d.Name, RuleType: alert.RuleTypeDigest, State: alert.StateEvent,
		Message: d.Text, StartedAt: from, EndedAt: &to,
	}
	if base := strings.TrimRight(s.cfg().PublicURL, "/"); base != "" {
		n.Link = base + "/"
	}
	return n
}

// digestChannels are the configured channels the digest goes to.
func digestChannels(avail []string, want []string) []string {
	if len(want) == 0 {
		return avail
	}
	var out []string
	for _, w := range want {
		for _, a := range avail {
			if w == a {
				out = append(out, w)
			}
		}
	}
	return out
}

// lastDigestSlot is the most recent scheduled send time at or before now (zero when off).
func lastDigestSlot(c config.DigestConfig, now time.Time) time.Time {
	if c.Schedule != config.DigestDaily && c.Schedule != config.DigestWeekly {
		return time.Time{}
	}
	mins, ok := config.ParseClock(c.Time)
	if !ok {
		return time.Time{}
	}
	loc := digestLocation(c)
	n := now.In(loc)
	slot := time.Date(n.Year(), n.Month(), n.Day(), mins/60, mins%60, 0, 0, loc)
	if c.Schedule == config.DigestDaily {
		if slot.After(n) {
			slot = slot.AddDate(0, 0, -1)
		}
		return slot
	}
	wd, _ := config.ParseWeekday(c.Weekday)
	back := (int(n.Weekday()) - int(wd) + 7) % 7
	slot = slot.AddDate(0, 0, -back)
	if slot.After(n) {
		slot = slot.AddDate(0, 0, -7)
	}
	return slot
}

// digester sends the scheduled digest.
type digester struct {
	s    *Server
	out  Outbox
	log  *slog.Logger
	mu   sync.Mutex
	last time.Time // last slot handled
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// StartDigest launches the scheduled digest (it needs an outbox). Stop it with the returned func.
func (s *Server) StartDigest(out Outbox) (stop func()) {
	dg := &digester{s: s, out: out, log: s.log, stop: make(chan struct{}), done: make(chan struct{})}
	if v, err := s.d.Store.Settings(); err == nil {
		if t, err := time.Parse(time.RFC3339, v[digestStateKey]); err == nil {
			dg.last = t
		}
	}
	s.digest = dg
	go dg.loop()
	return func() {
		dg.once.Do(func() { close(dg.stop) })
		select {
		case <-dg.done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (dg *digester) loop() {
	defer close(dg.done)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	dg.tick()
	for {
		select {
		case <-dg.stop:
			return
		case <-t.C:
			dg.tick()
		}
	}
}

// tick sends the digest when a slot passed that was not handled yet. A slot that passed while
// the digest was turned off, or before the first run, is only marked as handled.
func (dg *digester) tick() {
	c := dg.s.cfg().Digest
	now := dg.s.now()
	slot := lastDigestSlot(c, now)
	dg.mu.Lock()
	last := dg.last
	dg.mu.Unlock()
	if slot.IsZero() {
		return
	}
	if !slot.After(last) {
		return
	}
	dg.mark(slot)
	if last.IsZero() || now.Sub(slot) > time.Hour {
		return // first run, or long after the slot (pathwatch was down): wait for the next one
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := dg.s.sendDigest(ctx, dg.out, c, slot); err != nil {
		dg.log.Warn("digest not sent", "err", err)
	}
}

func (dg *digester) mark(slot time.Time) {
	dg.mu.Lock()
	dg.last = slot
	dg.mu.Unlock()
	if err := dg.s.d.Store.SetSetting(digestStateKey, slot.UTC().Format(time.RFC3339)); err != nil {
		dg.log.Warn("saving the digest state failed", "err", err)
	}
}

// sendDigest builds the digest for the period ending at `to` and queues it on the channels.
func (s *Server) sendDigest(ctx context.Context, out Outbox, c config.DigestConfig, to time.Time) (*Digest, error) {
	schedule := c.Schedule
	if schedule == config.DigestOff {
		schedule = config.DigestDaily
	}
	d, err := s.BuildDigest(ctx, digestName(schedule), to.Add(-digestPeriod(schedule)), to)
	if err != nil {
		return nil, err
	}
	chs := digestChannels(out.Channels(), c.Notify)
	if len(chs) == 0 {
		return d, errNoChannel
	}
	out.Enqueue(s.digestNotification(d), chs)
	s.log.Info("digest queued", "name", d.Name, "channels", strings.Join(chs, ","))
	return d, nil
}

var errNoChannel = errors.New("no notification channel is configured")

// digestSendGap is the minimum time between two manual sends.
const digestSendGap = 30 * time.Second

func (s *Server) digestConfig() config.DigestConfig { return s.cfg().Digest }

// handleDigestPreview returns the digest for the period ending now, as it would be sent.
func (s *Server) handleDigestPreview(w http.ResponseWriter, r *http.Request) {
	c := s.digestConfig()
	schedule := c.Schedule
	if schedule == config.DigestOff {
		schedule = config.DigestDaily
	}
	now := s.now()
	d, err := s.BuildDigest(r.Context(), digestName(schedule), now.Add(-digestPeriod(schedule)), now)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	var chs []string
	if s.d.Outbox != nil {
		chs = digestChannels(s.d.Outbox.Channels(), c.Notify)
	}
	if chs == nil {
		chs = []string{}
	}
	out := map[string]any{
		"name": d.Name, "title": "pathwatch " + d.Name, "from": d.From.UnixMilli(), "to": d.To.UnixMilli(), "text": d.Text,
		"targets": d.Targets, "alerts": d.Alerts, "channels": chs, "schedule": c.Schedule,
	}
	if slot := lastDigestSlot(c, now); !slot.IsZero() {
		days := 1
		if c.Schedule == config.DigestWeekly {
			days = 7
		}
		out["next"] = slot.AddDate(0, 0, days).UnixMilli() // calendar days, so DST shifts keep the clock time
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDigestSend queues the digest for the period ending now on the digest's channels.
func (s *Server) handleDigestSend(w http.ResponseWriter, r *http.Request) {
	if s.d.Outbox == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications are not available")
		return
	}
	s.digestMu.Lock()
	if wait := digestSendGap - s.now().Sub(s.digestSent); wait > 0 {
		s.digestMu.Unlock()
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "a digest was just sent; try again in a few seconds")
		return
	}
	s.digestSent = s.now()
	s.digestMu.Unlock()
	d, err := s.sendDigest(r.Context(), s.d.Outbox, s.digestConfig(), s.now())
	if errors.Is(err, errNoChannel) {
		writeError(w, http.StatusConflict, "no notification channel is configured for the digest (Settings → Notifications)")
		return
	}
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"queued": true, "name": d.Name, "channels": digestChannels(s.d.Outbox.Channels(), s.digestConfig().Notify)})
}
