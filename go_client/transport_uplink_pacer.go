package main

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"sync"
	"sync/atomic"
	"time"
)

// Limit aggregate bursts before they enter independent TURN queues. TCP ACKs
// and handshakes bypass pacing; bulk delivery reports adjust the shared budget.
// This is confined to the opt-in uplink transport, never a subscription limit.
type uplinkPacer struct {
	limiter            *rate.Limiter
	probes             *rate.Limiter
	mu                 sync.Mutex
	expected, received uint64
	mbps               float64
	offeredBytes       atomic.Int64
	lastAdjust         time.Time
	idleTicks          int
	previousUsageMbps  float64
	paths              map[*uplinkQuality]uplinkPathFeedback
	sharedSince        time.Time
	sharedUntil        time.Time
	lastSharedAdjust   time.Time
	congestionEpoch    atomic.Uint64
}

type uplinkPathFeedback struct {
	start, latest      time.Time
	expected, received uint64
}

func (p *uplinkPacer) registerPath(q *uplinkQuality) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.paths == nil {
		p.paths = make(map[*uplinkQuality]uplinkPathFeedback)
	}
	p.paths[q] = uplinkPathFeedback{}
}

func (p *uplinkPacer) unregisterPath(q *uplinkQuality) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.paths, q)
}

// Several paths share one device uplink. Widespread loss first needs a common
// budget reduction, rather than quarantining every path and losing feedback.
// A minority still follows normal isolation; persistent failure can defer it
// for at most two seconds. State is bounded by registered live paths.
func (p *uplinkPacer) notePath(q *uplinkQuality, expected, received uint64, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	sample, exists := p.paths[q]
	if !exists || q.muted.Load() {
		return false
	}
	if sample.start.IsZero() || now.Sub(sample.start) >= time.Second {
		sample = uplinkPathFeedback{start: now}
	}
	sample.latest = now
	sample.expected += expected
	sample.received += received
	p.paths[q] = sample
	active, participating, bad := 0, 0, 0
	var totalExpected, totalReceived uint64
	for path, feedback := range p.paths {
		if path.muted.Load() {
			continue
		}
		active++
		if feedback.expected < 32 || feedback.latest.IsZero() || now.Sub(feedback.latest) >= time.Second {
			continue
		}
		participating++
		totalExpected += feedback.expected
		totalReceived += feedback.received
		if feedback.received < feedback.expected && feedback.expected-feedback.received > feedback.expected/50 {
			bad++
		}
	}
	if participating >= max(2, (active+1)/2) && bad >= 2 && bad*2 > participating && totalExpected >= 128 {
		if p.sharedSince.IsZero() {
			p.sharedSince = now
		}
		if now.Sub(p.sharedSince) < 2*time.Second {
			p.sharedUntil = now.Add(500 * time.Millisecond)
			deadline := p.sharedSince.Add(2 * time.Second)
			if p.sharedUntil.After(deadline) {
				p.sharedUntil = deadline
			}
			if now.Sub(p.sharedSince) >= 100*time.Millisecond && (p.lastSharedAdjust.IsZero() || now.Sub(p.lastSharedAdjust) >= 250*time.Millisecond) {
				previousBudget := p.mbps
				p.mbps = max(8, p.mbps*.8)
				if p.mbps < previousBudget {
					p.congestionEpoch.Add(1)
				}
				p.limiter.SetLimitAt(now, rate.Limit(p.mbps*1e6/8))
				p.lastSharedAdjust = now
				if transportMetricsEnabled {
					b, _ := json.Marshal(map[string]any{"side": "uplink_shared_congestion", "at": now.UTC().Format(time.RFC3339Nano), "mbps": p.mbps, "active": active, "participating": participating, "bad": bad, "expected": totalExpected, "received": totalReceived})
					fmt.Printf("TRANSPORT_METRIC|%s\n", b)
				}
			}
		}
	} else if !now.Before(p.sharedUntil) {
		// A recovered majority ends the episode. Continuing widespread failure
		// never renews the bounded grace period.
		p.sharedSince = time.Time{}
	}
	return now.Before(p.sharedUntil)
}

func newUplinkPacer() *uplinkPacer {
	return &uplinkPacer{limiter: rate.NewLimiter(rate.Limit(64e6/8), 8*1500), probes: rate.NewLimiter(256, 4), mbps: 64}
}
func (p *uplinkPacer) wait(ctx context.Context, n int) error {
	if n <= 160 {
		return nil
	}
	// Include framing, DTLS, wrapping, TURN and the outer IP/UDP header.
	if err := p.limiter.WaitN(ctx, n+128); err != nil {
		return err
	}
	p.offeredBytes.Add(int64(n + 128))
	return nil
}
func (p *uplinkPacer) observe(expected, received uint64, eligible bool) {
	if !eligible {
		return
	}
	p.mu.Lock()
	p.expected += expected
	p.received += received
	p.mu.Unlock()
}
func (p *uplinkPacer) adjust(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	seconds := 1.0
	if !p.lastAdjust.IsZero() {
		seconds = max(.1, now.Sub(p.lastAdjust).Seconds())
	}
	p.lastAdjust = now
	offered := p.offeredBytes.Swap(0)
	expected, received := p.expected, p.received
	p.expected = 0
	p.received = 0
	if offered == 0 {
		p.idleTicks++
	} else {
		p.idleTicks = 0
	}
	if p.idleTicks >= 5 {
		p.mbps = min(64, p.mbps)
		p.limiter.SetLimitAt(now, rate.Limit(p.mbps*1e6/8))
	}
	usageMbps := float64(offered) * 8 / 1e6 / seconds
	recentUsageMbps := max(usageMbps, p.previousUsageMbps)
	p.previousUsageMbps = usageMbps
	if expected < 128 {
		return
	}
	missing := uint64(0)
	if expected > received {
		missing = expected - received
	}
	loss := float64(missing) / float64(expected)
	sharedAdjustment := !p.lastSharedAdjust.IsZero() && now.Sub(p.lastSharedAdjust) < time.Second
	if sharedAdjustment {
		// The fast common response already reduced this budget. Do not apply
		// another reduction using receipts from before that adjustment.
	} else if loss > .02 {
		// Back off relative to traffic actually carried, not a stale ceiling
		// learned when application demand was much lower than that ceiling.
		previousBudget := p.mbps
		p.mbps = max(8, min(p.mbps*.8, recentUsageMbps*.85))
		if p.mbps < previousBudget {
			p.congestionEpoch.Add(1)
		}
	} else if loss < .005 && usageMbps >= p.mbps*.7 {
		p.mbps = min(512, p.mbps*1.15)
	}
	p.limiter.SetLimitAt(now, rate.Limit(p.mbps*1e6/8))
	if transportMetricsEnabled {
		b, _ := json.Marshal(map[string]any{"side": "uplink_pacing", "mode": "uplink", "id": 0, "at": now.UTC().Format(time.RFC3339Nano), "mbps": p.mbps, "offered_mbps": usageMbps, "expected": expected, "received": received})
		fmt.Printf("TRANSPORT_METRIC|%s\n", b)
	}
}
func (p *uplinkPacer) run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.adjust(now)
		}
	}
}
