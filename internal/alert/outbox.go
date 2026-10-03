package alert

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Backoff schedule of the outbox: 30s, 1m, 2m, 4m, 8m, then 15m between attempts.
const (
	backoffBase = 30 * time.Second
	backoffMax  = 15 * time.Minute
)

// Backoff returns the delay before the next attempt after `attempts` failed attempts.
func Backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := backoffBase
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= backoffMax {
			return backoffMax
		}
	}
	return d
}

// channelSender delivers one notification over one channel.
type channelSender interface {
	Send(ctx context.Context, n Notification) error
}

// Sender writes notifications to the outbox table and delivers them from a goroutine with
// exponential backoff until they are delivered or older than outbox.max_age. Rows survive
// restarts, so notifications about an outage of the local connection go out once it is back, with
// the outage's real start and end times (they are part of the stored payload).
type Sender struct {
	st   *store.Store
	log  *slog.Logger
	now  func() time.Time
	sink AlertSink

	mu       sync.RWMutex
	channels map[string]channelSender
	maxAge   time.Duration

	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
	started atomic.Bool
}

// NewSender creates a sender. sink may be nil; now may be nil.
func NewSender(st *store.Store, sink AlertSink, log *slog.Logger, now func() time.Time) *Sender {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &Sender{
		st: st, sink: sink, log: log, now: now, channels: map[string]channelSender{}, maxAge: 24 * time.Hour,
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
}

// Configure (re)builds the channel senders from the configuration. A broken channel
// configuration is logged and leaves that channel unconfigured.
func (s *Sender) Configure(cfg *config.Config) {
	ch := map[string]channelSender{}
	if w := cfg.Alerts.Notify.Webhook; w != nil {
		if ws, err := NewWebhookSender(*w, nil, nil); err != nil {
			s.log.Error("webhook channel disabled", "err", err)
		} else {
			ch[ChannelWebhook] = ws
		}
	}
	if e := cfg.Alerts.Notify.Email; e != nil {
		ch[ChannelEmail] = NewEmailSender(*e, nil, s.now)
	}
	s.setChannels(ch, cfg.Alerts.Outbox.MaxAge.D())
}

func (s *Sender) setChannels(ch map[string]channelSender, maxAge time.Duration) {
	s.mu.Lock()
	s.channels = ch
	if maxAge > 0 {
		s.maxAge = maxAge
	}
	s.mu.Unlock()
}

// Channels returns the configured channel names (webhook, email).
func (s *Sender) Channels() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, c := range []string{ChannelWebhook, ChannelEmail} {
		if _, ok := s.channels[c]; ok {
			out = append(out, c)
		}
	}
	return out
}

// Enqueue writes the notification to the outbox for each channel and wakes the sender.
func (s *Sender) Enqueue(n Notification, channels []string) {
	if len(channels) == 0 {
		return
	}
	n.CreatedAt = s.now().UTC()
	payload, err := json.Marshal(n)
	if err != nil {
		s.log.Error("cannot encode notification", "err", err)
		return
	}
	for _, c := range channels {
		if _, err := s.st.EnqueueOutbox(n.AlertID, c, string(payload), n.CreatedAt); err != nil {
			s.log.Error("cannot queue notification", "channel", c, "err", err)
		}
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Start launches the delivery goroutine.
func (s *Sender) Start() {
	if s.started.Swap(true) {
		return
	}
	go s.loop()
}

// Close stops the delivery goroutine.
func (s *Sender) Close() {
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	if s.started.Load() {
		<-s.done
	}
}

func (s *Sender) loop() {
	defer close(s.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-s.stop
		cancel()
	}()
	for {
		s.ProcessDue(ctx)
		wait := 5 * time.Second
		if next, ok := s.st.NextOutboxDue(); ok {
			if d := next.Sub(s.now()); d < wait {
				wait = d
			}
		}
		if wait < time.Second {
			wait = time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-s.stop:
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// ProcessDue attempts every notification that is due and returns how many attempts were made.
// Channels are served concurrently so a slow webhook never delays email.
func (s *Sender) ProcessDue(ctx context.Context) int {
	total := 0
	// a delivered notification may release a held-back one (resolved after firing): go again
	for i := 0; i < 8; i++ {
		n := s.processOnce(ctx)
		total += n
		if n == 0 {
			break
		}
	}
	return total
}

func (s *Sender) processOnce(ctx context.Context) int {
	now := s.now()
	rows, err := s.st.DueOutbox(now, 100)
	if err != nil {
		s.log.Warn("outbox read failed", "err", err)
		return 0
	}
	by := map[string][]store.OutboxRow{}
	for _, r := range rows {
		by[r.Channel] = append(by[r.Channel], r)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for _, list := range by {
		wg.Add(1)
		go func(list []store.OutboxRow) {
			defer wg.Done()
			for _, r := range list {
				if ctx.Err() != nil {
					return
				}
				if s.deliver(ctx, r) {
					mu.Lock()
					n++
					mu.Unlock()
				}
			}
		}(list)
	}
	wg.Wait()
	return n
}

// deliver handles one row; it reports whether an attempt was made.
func (s *Sender) deliver(ctx context.Context, r store.OutboxRow) bool {
	now := s.now()
	s.mu.RLock()
	sender := s.channels[r.Channel]
	maxAge := s.maxAge
	s.mu.RUnlock()

	finish := func(status string, attempts int, next time.Time, lastErr string) {
		if err := s.st.UpdateOutbox(r.ID, status, attempts, next, lastErr, now); err != nil {
			s.log.Warn("outbox update failed", "err", err)
			return
		}
		if s.sink != nil {
			s.sink.AlertChanged(r.AlertID)
		}
	}
	if now.Sub(r.CreatedAt) >= maxAge {
		msg := r.LastError
		if msg == "" {
			msg = "not delivered before outbox.max_age elapsed"
		}
		s.log.Warn("notification expired undelivered", "alert", r.AlertID, "channel", r.Channel, "attempts", r.Attempts)
		finish(store.OutboxExpired, r.Attempts, time.Time{}, msg)
		return false
	}
	var n Notification
	if err := json.Unmarshal([]byte(r.Payload), &n); err != nil {
		finish(store.OutboxFailed, r.Attempts, time.Time{}, "unreadable notification payload")
		return false
	}
	var err error
	if sender == nil {
		err = errors.New("channel " + r.Channel + " is not configured")
	} else {
		err = sender.Send(ctx, n)
	}
	attempts := r.Attempts + 1
	switch {
	case err == nil:
		finish(store.OutboxDelivered, attempts, time.Time{}, "")
	case IsPermanent(err):
		s.log.Warn("notification cannot be delivered", "alert", r.AlertID, "channel", r.Channel, "err", err)
		finish(store.OutboxFailed, attempts, time.Time{}, err.Error())
	default:
		next := now.Add(Backoff(attempts))
		if limit := r.CreatedAt.Add(maxAge); next.After(limit) {
			next = limit
		}
		s.log.Warn("notification delivery failed; will retry", "alert", r.AlertID, "channel", r.Channel, "attempts", attempts, "retry_in", next.Sub(now).Round(time.Second), "err", err)
		finish(store.OutboxRetrying, attempts, next, err.Error())
	}
	return true
}
