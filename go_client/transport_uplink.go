package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"wdtt.local/pathprobe"
)

// Uplink selection uses delivery evidence, not RTT rankings. A path with poor
// upload remains registered for download. After cooldown, full-size probes
// verify recovery without sacrificing user packets to a known failing path.
type uplinkQuality struct {
	replace                    func() bool
	probeWait                  func(context.Context) error
	sleeping                   func() bool
	failedProbes               int
	pacer                      *uplinkPacer
	mu                         sync.Mutex
	muted                      atomic.Bool
	probation                  atomic.Bool
	id                         int
	next, expected, received   uint64
	baseExpected, baseReceived uint64
	badSince                   time.Time
	checkAt                    time.Time
	probeEnd, probeReceived    uint64
	probeDeadline              time.Time
	pendingSince               time.Time
	silenceProbes              int
	silenceProbeAt             time.Time
	loss                       uint64
	pacingEpoch                uint64
}

func (q *uplinkQuality) frame(dst, payload []byte, kind byte) []byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	if kind == pathprobe.Data && len(payload) <= 160 {
		return pathprobe.Frame(dst, payload, pathprobe.Bypass, 0)
	}
	p := pathprobe.Frame(dst, payload, kind, q.next)
	if p != nil {
		if q.next == q.expected {
			q.pendingSince = time.Now()
		}
		q.next++
	}
	return p
}
func (q *uplinkQuality) ack(p []byte, now time.Time) bool {
	expected, received, ok := pathprobe.ParseAck(p)
	if !ok {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	// Stale/forged counters must not alter scheduling or overflow subtraction.
	if expected > q.next || expected < q.expected || received < q.received {
		return true
	}
	deltaExpected, deltaReceived := expected-q.expected, received-q.received
	sharedCongestion := false
	if q.pacer != nil {
		sharedCongestion = q.pacer.notePath(q, deltaExpected, deltaReceived, now)
		// A persistently defective path is isolated locally. Its losses must
		// not repeatedly throttle every other path while quarantine converges.
		defer func() { q.pacer.observe(deltaExpected, deltaReceived, !q.muted.Load() && q.badSince.IsZero()) }()
	}
	if expected > q.expected {
		q.silenceProbes = 0
		q.silenceProbeAt = time.Time{}
		if expected == q.next {
			q.pendingSince = time.Time{}
		} else {
			q.pendingSince = now
		}
	}
	q.expected = expected
	q.received = received
	if q.muted.Load() {
		return true
	}
	if q.pacer != nil {
		epoch := q.pacer.congestionEpoch.Load()
		if epoch != q.pacingEpoch {
			// Loss observed before a common backoff describes the old load.
			// Re-test this path at the reduced budget before isolating it.
			q.pacingEpoch = epoch
			q.badSince = time.Time{}
			q.baseExpected = expected
			q.baseReceived = received
			return true
		}
	}
	if sharedCongestion {
		q.badSince = time.Time{}
		q.baseExpected = expected
		q.baseReceived = received
		return true
	}
	if expected < q.baseExpected || received < q.baseReceived {
		return true
	}
	total := expected - q.baseExpected
	got := received - q.baseReceived
	if total < 64 || got > total {
		return true
	}
	missing := total - got
	q.loss = missing * 1000 / total
	if missing*8 > total {
		if q.badSince.IsZero() {
			q.badSince = now
			return true
		}
		if now.Sub(q.badSince) < 100*time.Millisecond {
			return true
		}
		q.muted.Store(true)
		q.reportLocked("loss")
		q.checkAt = now.Add(10 * time.Second)
		q.badSince = time.Time{}
		if transportMetricsEnabled {
			log.Printf("[ОТДАЧА] Канал #%d временно исключён из отправки: подтверждено %d/%d пакетов; приём сохранён", q.id, got, total)
		}
	} else {
		q.badSince = time.Time{}
		if total >= 128 {
			q.baseExpected = expected
			q.baseReceived = received
		}
	}
	return true
}
func (q *uplinkQuality) forceOpen() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.muted.Store(false)
	q.pendingSince = time.Now()
	q.silenceProbes = 0
	q.silenceProbeAt = time.Time{}
	q.reportLocked("fallback")
	q.probeEnd = 0
	q.baseExpected = q.expected
	q.baseReceived = q.received
	q.badSince = time.Time{}
	return q.loss
}
func (q *uplinkQuality) lossScore() uint64 { q.mu.Lock(); defer q.mu.Unlock(); return q.loss }

// run owns probe scheduling. write must serialize with ordinary DTLS writes;
// no sleeps or remote waits occur under the dispatcher's lock.
func (q *uplinkQuality) run(ctx context.Context, write func([]byte) error, cancel context.CancelFunc) {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	payload := make([]byte, 1312)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			q.mu.Lock()
			if q.sleeping != nil && q.sleeping() {
				// Doze is not evidence of a broken path. Keep recovery silent and
				// restart its evidence window after wake instead of spending the
				// phone's idle network/battery budget on full-size probes.
				if !q.pendingSince.IsZero() {
					q.pendingSince = now
				}
				q.silenceProbes = 0
				q.silenceProbeAt = time.Time{}
				q.probeEnd = 0
				q.checkAt = now.Add(time.Second)
				q.badSince = time.Time{}
				q.mu.Unlock()
				continue
			}
			if !q.muted.Load() {
				if q.next-q.expected >= 1 && !q.pendingSince.IsZero() && now.Sub(q.pendingSince) >= 2*time.Second {
					// A single missing tail packet during an otherwise idle phase
					// is not a dead channel. Request delivery evidence twice before
					// quarantine, without sacrificing ordinary user traffic.
					if now.Before(q.silenceProbeAt) {
						q.mu.Unlock()
						continue
					}
					if q.silenceProbes < 2 {
						q.silenceProbes++
						q.silenceProbeAt = now.Add(2 * time.Second)
						p := pathprobe.Frame(nil, payload, pathprobe.Probe, q.next)
						q.next++
						q.mu.Unlock()
						if q.probeWait != nil && q.probeWait(ctx) != nil {
							return
						}
						if write(p) != nil {
							cancel()
							return
						}
						continue
					}
					q.muted.Store(true)
					q.loss = 1000
					q.checkAt = now.Add(10 * time.Second)
					q.reportLocked("no_progress")
					if transportMetricsEnabled {
						log.Printf("[ОТДАЧА] Канал #%d временно исключён из отправки: нет подтверждения доставки; приём сохранён", q.id)
					}
				}
				q.mu.Unlock()
				continue
			}
			if q.probeEnd != 0 {
				if now.Before(q.probeDeadline) {
					q.mu.Unlock()
					continue
				}
				good := q.expected >= q.probeEnd && q.received >= q.probeReceived && q.received-q.probeReceived >= 32
				q.probeEnd = 0
				q.checkAt = now.Add(10 * time.Second)
				if good {
					q.failedProbes = 0
					q.probation.Store(false)
					q.muted.Store(false)
					q.pendingSince = time.Time{}
					q.reportLocked("recovered")
					q.baseExpected = q.expected
					q.baseReceived = q.received
					q.badSince = time.Time{}
					if transportMetricsEnabled {
						log.Printf("[ОТДАЧА] Канал #%d снова участвует в отправке после проверки доставки", q.id)
					}
				} else {
					q.failedProbes++
				}
				shouldReplace := !good && q.failedProbes >= 2 && q.replace != nil
				q.mu.Unlock()
				if shouldReplace && q.replace() {
					q.mu.Lock()
					q.reportLocked("replace")
					q.mu.Unlock()
					if transportMetricsEnabled {
						log.Printf("[ОТДАЧА] Канал #%d не восстановил доставку после проверок; заменяем только этот канал", q.id)
					}
					cancel()
					return
				}
				continue
			}
			if now.Before(q.checkAt) {
				q.mu.Unlock()
				continue
			}
			q.probeReceived = q.received
			// Reserve the entire probe sequence under one lock. Ordinary traffic has
			// drained during cooldown; an emergency fallback cancels this probation.
			frames := make([][]byte, 32)
			for i := range frames {
				frames[i] = pathprobe.Frame(nil, payload, pathprobe.Probe, q.next)
				q.next++
			}
			q.probeEnd = q.next
			q.probeDeadline = now.Add(time.Second)
			q.mu.Unlock()
			for _, p := range frames {
				if ctx.Err() != nil {
					return
				}
				if q.probeWait != nil && q.probeWait(ctx) != nil {
					return
				}
				if write(p) != nil {
					cancel()
					return
				}
			}
			q.mu.Lock()
			q.probeDeadline = time.Now().Add(time.Second)
			q.mu.Unlock()
		}
	}
}

// Called under q.mu; diagnostic output contains only local IDs and counters.
func (q *uplinkQuality) reportLocked(event string) {
	if !transportMetricsEnabled {
		return
	}
	b, _ := json.Marshal(map[string]any{"side": "uplink_delivery", "mode": "uplink", "id": q.id, "at": time.Now().UTC().Format(time.RFC3339Nano), "event": event, "sent": q.next, "expected": q.expected, "received": q.received, "muted": q.muted.Load()})
	fmt.Printf("TRANSPORT_METRIC|%s\n", b)
}

func ensureUplinkServiceFloor(ws []*WorkerSlot, wakeGeneration uint64, deviceSleeping bool) {
	// Keep a last-resort path only when none is usable. Reopening a fixed
	// fraction of the requested workers reintroduced proven losses whenever
	// a small hash set supplied many defective paths. Healthy paths determine
	// usable capacity; the slider must not force known failures back into it.
	healthy := 0
	for _, w := range ws {
		if !workerEligibleForWakeGeneration(w, wakeGeneration, deviceSleeping) || (w.uplink != nil && w.uplink.probation.Load()) {
			continue
		}
		if w.uplink == nil || !w.uplink.muted.Load() {
			healthy++
		}
	}
	floor := 1
	for healthy < floor {
		var best *WorkerSlot
		for _, w := range ws {
			if !workerEligibleForWakeGeneration(w, wakeGeneration, deviceSleeping) || w.uplink == nil || w.uplink.probation.Load() || !w.uplink.muted.Load() {
				continue
			}
			if best == nil || w.uplink.lossScore() < best.uplink.lossScore() {
				best = w
			}
		}
		if best == nil {
			break
		}
		best.uplink.forceOpen()
		healthy++
	}
}
