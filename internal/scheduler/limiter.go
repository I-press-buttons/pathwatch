package scheduler

// Limiter decides how many TTLs to probe each round (mtr-style).
//
//   - Initially, and for one round at every rediscovery, up to MaxHops TTLs are probed.
//   - Once the destination answers at TTL d, probing stops there: exactly d TTLs per round.
//   - If the destination stays silent for MissStreakExpand rounds the limit grows by TrimSlack
//     so a longer path is noticed.
//   - For a destination that never answers, the limit is the highest TTL that responded in the
//     last Window rounds plus TrimSlack: trailing "* * *" rows are trimmed instead of probing all
//     the way to MaxHops forever.
type Limiter struct {
	MaxHops          int
	TrimSlack        int // default 3
	Window           int // default 10
	MissStreakExpand int // default 5

	known      int   // destination TTL, 0 = unknown
	missStreak int   // consecutive rounds without a destination reply while known > 0
	recent     []int // highest responding TTL of the last rounds (destination unknown)
	rediscover bool
}

// NewLimiter returns a limiter for a path of at most maxHops.
func NewLimiter(maxHops int) *Limiter {
	return &Limiter{MaxHops: maxHops, TrimSlack: 3, Window: 10, MissStreakExpand: 5, rediscover: true}
}

// Rediscover makes the next round probe up to MaxHops again.
func (l *Limiter) Rediscover() { l.rediscover = true }

// Known returns the destination TTL (0 if unknown).
func (l *Limiter) Known() int { return l.known }

// Next returns the number of TTLs (1..n) to probe in the coming round.
func (l *Limiter) Next() int {
	if l.rediscover || l.MaxHops <= 0 {
		return l.MaxHops
	}
	var n int
	switch {
	case l.known > 0 && l.missStreak < l.MissStreakExpand:
		n = l.known
	case l.known > 0:
		n = l.known + l.TrimSlack
	default:
		top := 0
		for _, v := range l.recent {
			if v > top {
				top = v
			}
		}
		n = top + l.TrimSlack
		if len(l.recent) == 0 {
			n = l.MaxHops
		}
	}
	if n < 1 {
		n = 1
	}
	if n > l.MaxHops {
		n = l.MaxHops
	}
	return n
}

// Record feeds the outcome of a round: destTTL is the TTL of the destination's Echo Reply (0 if
// none) and maxResp the highest TTL that got any reply.
func (l *Limiter) Record(destTTL, maxResp int) {
	l.rediscover = false
	if destTTL > 0 {
		l.known, l.missStreak = destTTL, 0
		l.recent = l.recent[:0]
		return
	}
	if l.known > 0 {
		l.missStreak++
		return
	}
	l.recent = append(l.recent, maxResp)
	if w := l.Window; w > 0 && len(l.recent) > w {
		l.recent = l.recent[len(l.recent)-w:]
	}
}
