// Package alert is the alert rule engine and the notification senders.
//
// RuleEngine (ruleengine.go) implements Engine. cmd/pathwatch passes it to analyze.New, which
// calls it from the aggregation goroutine:
//
//   - HandleMinute is called once per completed 1-minute bucket with per-target aggregates
//     (end-to-end stats, per-hop stats with their rate-limited or degraded classification,
//     HTTP/TCP probe stats), the DNS probe stats and the local-connectivity state. Gaps never
//     produce a Minute for the affected period, so rules never trigger or resolve on "no data".
//   - HandleProbe is called for every individual HTTP/TCP/DNS probe result, for the rules that
//     count consecutive failures (http_failure, tcp_failure, dns_failure) and cert_expiry.
//
// Files: rules.go (rule resolution, thresholds), state.go (the pending -> firing -> resolved state
// machine, suppression, persistence), baseline.go (cached median/MAD baselines),
// ruleengine.go (evaluation of every rule type), outbox.go (persistent outbox, retry with
// backoff), webhook.go and email.go (the channels), heartbeat.go (dead-man's switch).
//
// Every alert change is stored with store.SaveAlert and announced to the AlertSink (web.Hub
// implements it) so the UI receives an SSE "alert" event. Notifications are written to the
// outbox table first and delivered by the Sender goroutine.
package alert

import "time"

// Engine consumes the analyzer's output. All methods must be safe for concurrent use and must
// not block for long.
type Engine interface {
	// HandleMinute is called once for every completed 1-minute bucket.
	HandleMinute(m Minute)
	// HandleProbe is called for every individual probe result.
	HandleProbe(s ProbeSample)
	// Close releases resources (flush state, stop sender goroutines).
	Close()
}

// AlertSink receives alert state changes for live delivery to the UI (SSE "alert" event).
type AlertSink interface {
	AlertChanged(alertID int64)
}

// Nop is an engine that ignores everything (tests and tools that do not need alerting).
type Nop struct{}

// HandleMinute implements Engine.
func (Nop) HandleMinute(Minute) {}

// HandleProbe implements Engine.
func (Nop) HandleProbe(ProbeSample) {}

// Close implements Engine.
func (Nop) Close() {}

// Minute is the analyzer's output for one completed 1-minute bucket.
type Minute struct {
	Bucket  time.Time // start of the minute (UTC)
	Targets []TargetMinute
	DNS     []ProbeMinute // DNS resolver probes (not bound to a target)
	Local   LocalState
}

// LocalState is the local-connectivity verdict.
type LocalState struct {
	Down   bool
	Since  time.Time // when the outage began (valid when Down)
	Reason string    // "gateway" | "all_targets"
}

// TargetMinute is one target's aggregates for the minute.
type TargetMinute struct {
	TargetID         int64
	Name             string
	ICMPUnresponsive bool   // destination never answers Echo; E2E then comes from TCP or the last hop
	E2E              *Stat  // end-to-end loss/latency (destination ICMP, else TCP probe, else last hop); nil = no data
	E2ESource        string // "icmp" | "tcp" | "last_hop"
	Hops             []HopMinute
	HTTP             []ProbeMinute
	TCP              []ProbeMinute
	// Degradation is non-nil when the hop classifier found a real degradation (a hop and every
	// downstream signal degraded). Rate-limited hops never appear here.
	Degradation *Degradation
}

// Stat is loss and latency over the minute. Latencies in milliseconds.
type Stat struct {
	Sent, Lost int
	LossPct    float64
	AvgMS      float64 // 0 when no replies
	P95MS      float64
	JitterMS   float64
	HaveAvg    bool
}

// HopMinute is one hop's stats and classification.
type HopMinute struct {
	TTL   int
	Stat  Stat
	Class string // ok | rate_limited | degraded | no_reply
}

// Degradation describes a real path degradation.
type Degradation struct {
	StartTTL int // earliest degraded hop: "problem begins at hop k"
}

// ProbeMinute is a probe's aggregate for the minute. Latencies in milliseconds.
type ProbeMinute struct {
	ProbeID      int64
	Type         string // http | tcp | dns
	Label        string
	N, Errors    int
	AvgTotalMS   float64
	AvgTTFBMS    float64
	P95TotalMS   float64
	HaveAvg      bool
	CertNotAfter time.Time // zero if none
}

// ProbeSample is one probe result.
type ProbeSample struct {
	TargetID     int64 // 0 for DNS probes
	ProbeID      int64
	Type         string // http | tcp | dns
	TS           time.Time
	OK           bool
	Error        string
	Status       int // HTTP status
	TotalMS      float64
	TTFBMS       float64
	CertNotAfter time.Time
}
