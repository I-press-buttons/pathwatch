package alert

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Notification states.
const (
	StateFiring   = "firing"
	StateResolved = "resolved"
	// StateEvent is the single notification of a one-shot alert (route_change): the alert
	// resolves immediately, so there is no separate "firing" and "resolved" pair.
	StateEvent = "event"
)

// Channel names.
const (
	ChannelWebhook = "webhook"
	ChannelEmail   = "email"
)

// Notification is the payload stored in the outbox. It is self-contained, so a notification
// delivered hours later (after the connection came back) still carries the real start and end
// times, and so it can be rendered by whichever channel configuration is current at send time.
type Notification struct {
	AlertID   int64           `json:"alert_id"`
	TargetID  *int64          `json:"target_id"`
	Target    string          `json:"target"`
	Rule      string          `json:"rule"`
	RuleType  string          `json:"rule_type"`
	State     string          `json:"state"` // firing | resolved | event
	Value     *float64        `json:"value"`
	PeakValue *float64        `json:"peak_value"`
	Baseline  *float64        `json:"baseline"`
	Unit      string          `json:"unit"`
	Message   string          `json:"message"`
	StartedAt time.Time       `json:"started_at"`
	EndedAt   *time.Time      `json:"ended_at"`
	CreatedAt time.Time       `json:"created_at"` // when the notification was queued
	Link      string          `json:"link"`
	Details   json.RawMessage `json:"details,omitempty"`
}

// Title is a short one-line summary, for example "FIRING cloudflare: http-slow".
func (n Notification) Title() string {
	return strings.ToUpper(n.State) + " " + n.Target + ": " + n.Rule
}

// Duration is how long the alert lasted (resolved) or has lasted so far (firing).
func (n Notification) Duration() time.Duration {
	end := n.CreatedAt
	if n.EndedAt != nil {
		end = *n.EndedAt
	}
	if end.Before(n.StartedAt) {
		return 0
	}
	return end.Sub(n.StartedAt)
}

// FormatValue renders a value with the notification's unit ("412 ms", "12.5 %", "3 failures").
func FormatValue(v float64, unit string) string {
	s := strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
	switch unit {
	case "":
		return s
	case "%":
		return s + "%"
	default:
		return s + " " + unit
	}
}

// ValueText and BaselineText are the formatted value and baseline ("" when absent).
func (n Notification) ValueText() string {
	if n.Value == nil {
		return ""
	}
	return FormatValue(*n.Value, n.Unit)
}

// BaselineText is the formatted baseline ("" when absent).
func (n Notification) BaselineText() string {
	if n.Baseline == nil {
		return ""
	}
	return FormatValue(*n.Baseline, n.Unit)
}

// FormatDuration renders a duration compactly ("45s", "5m3s", "2h10m").
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return "0s"
	}
	d = d.Round(time.Second)
	h, m, s := int(d/time.Hour), int(d%time.Hour/time.Minute), int(d%time.Minute/time.Second)
	switch {
	case h > 0 && m == 0:
		return fmt.Sprintf("%dh", h)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0 && s == 0:
		return fmt.Sprintf("%dm", m)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// deepLink builds the UI link for an alert: public_url + #/target/{id}?from=…&to=… (ms), with
// some context before the start and after the end. Alerts without a target link to the alerts
// page. It returns "" when public_url is empty.
func deepLink(publicURL string, targetID *int64, start time.Time, end *time.Time, now time.Time) string {
	base := strings.TrimRight(publicURL, "/")
	if base == "" {
		return ""
	}
	if targetID == nil {
		return base + "/#/alerts"
	}
	const pad = 10 * time.Minute
	from := start.Add(-pad)
	to := now
	if end != nil {
		to = end.Add(pad)
	}
	if !to.After(from) {
		to = from.Add(pad)
	}
	q := url.Values{}
	q.Set("from", strconv.FormatInt(from.UnixMilli(), 10))
	q.Set("to", strconv.FormatInt(to.UnixMilli(), 10))
	return fmt.Sprintf("%s/#/target/%d?%s", base, *targetID, q.Encode())
}
