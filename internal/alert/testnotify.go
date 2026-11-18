package alert

import (
	"context"
	"errors"
	"strings"
	"time"
)

// RuleTypeTest is the rule type of a test notification. Test notifications use state "event"
// (like route_change), so presets and body templates render them without a special case.
const RuleTypeTest = "test"

// ErrChannelNotConfigured is returned by SendTest for a channel that has no configuration.
var ErrChannelNotConfigured = errors.New("channel is not configured")

// TestNotification is what SendTest delivers: a one-shot event with alert id 0 and no target.
// Its link points at the alerts page when public_url is set, so the test also shows whether
// deep links reach the UI.
func TestNotification(channel, publicURL string, now time.Time) Notification {
	now = now.UTC()
	n := Notification{
		Target:    "pathwatch",
		Rule:      "test-notification",
		RuleType:  RuleTypeTest,
		State:     StateEvent,
		Message:   "Test notification from pathwatch. If you can read this, the " + channel + " channel works.",
		StartedAt: now,
		EndedAt:   &now,
		CreatedAt: now,
	}
	if base := strings.TrimRight(publicURL, "/"); base != "" {
		n.Link = base + "/#/alerts"
	}
	return n
}

// SendTest delivers a test notification over one channel right away. It bypasses the outbox:
// nothing is stored or retried, so the caller sees the channel's own error (HTTP status, SMTP
// reply, template error). Errors never contain the webhook URL or credentials.
func (s *Sender) SendTest(ctx context.Context, channel string) error {
	s.mu.RLock()
	sender := s.channels[channel]
	publicURL := s.publicURL
	s.mu.RUnlock()
	if sender == nil {
		return ErrChannelNotConfigured
	}
	return sender.Send(ctx, TestNotification(channel, publicURL, s.now()))
}
