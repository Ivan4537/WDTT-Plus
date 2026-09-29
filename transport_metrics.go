package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// No addresses, payloads, keys or credentials enter these opt-in measurements.
// Histograms and counters are cumulative for one process-local path ID.
var transportMetricsEnabled = os.Getenv("WDTT_TRANSPORT_METRICS") == "1"
var transportMetricIDs atomic.Uint64

func (a *deviceWGAttachment) isRetired() bool {
	lease := a.lease.Load()
	return lease != nil && lease.retired.Load()
}

func (a *deviceWGAttachment) offerData(p []byte) bool {
	if a.isRetired() {
		return false
	}
	if a.queue != nil {
		return a.queue.offer(p)
	}
	select {
	case a.downstream <- p:
		return true
	default:
		return false
	}
}
func (a *deviceWGAttachment) takeData(ctx context.Context) ([]byte, bool) {
	if a.queue == nil {
		select {
		case p := <-a.downstream:
			return p, true
		case <-ctx.Done():
			return nil, false
		}
	}
	p, ok := a.queue.take(ctx)
	if ok {
		a.queue.noteDequeue(p)
	}
	return p.data, ok
}
func (a *deviceWGAttachment) drainMeasured() {
	if a.queue == nil {
		return
	}
	for {
		select {
		case <-a.queue.items:
		default:
			return
		}
	}
}

type timedDatagram struct {
	data   []byte
	queued time.Time
}
type transportHistogram struct{ buckets [8]atomic.Uint64 }

func (h *transportHistogram) observe(d time.Duration) {
	limits := [...]time.Duration{time.Millisecond, 3 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond, time.Second}
	i := 0
	for i < len(limits) && d > limits[i] {
		i++
	}
	h.buckets[i].Add(1)
}
func (h *transportHistogram) snapshot() [8]uint64 {
	var v [8]uint64
	for i := range v {
		v[i] = h.buckets[i].Load()
	}
	return v
}

type transportQueue struct {
	items                                                 chan timedDatagram
	id                                                    uint64
	enqueued, bytes, full, written, received, writeErrors atomic.Uint64
	wait, write                                           transportHistogram
}

func newTransportQueue(capacity int) *transportQueue {
	return &transportQueue{items: make(chan timedDatagram, capacity), id: transportMetricIDs.Add(1)}
}
func (q *transportQueue) offer(p []byte) bool {
	select {
	case q.items <- timedDatagram{p, time.Now()}:
		q.enqueued.Add(1)
		q.bytes.Add(uint64(len(p)))
		return true
	default:
		q.full.Add(1)
		return false
	}
}
func (q *transportQueue) take(ctx context.Context) (timedDatagram, bool) {
	if ctx.Err() != nil {
		return timedDatagram{}, false
	}
	select {
	case p := <-q.items:
		return p, true
	case <-ctx.Done():
		return timedDatagram{}, false
	}
}
func (q *transportQueue) noteDequeue(p timedDatagram) { q.wait.observe(time.Since(p.queued)) }
func (q *transportQueue) noteWrite(start time.Time, n int, err error) {
	q.write.observe(time.Since(start))
	if err != nil {
		q.writeErrors.Add(1)
	} else {
		q.written.Add(uint64(n))
	}
}
func (q *transportQueue) report(side, mode string, final bool) {
	if !transportMetricsEnabled {
		return
	}
	v := map[string]any{"side": side, "mode": mode, "id": q.id, "at": time.Now().UTC().Format(time.RFC3339Nano), "final": final,
		"depth": len(q.items), "capacity": cap(q.items), "enqueued": q.enqueued.Load(), "bytes": q.bytes.Load(), "full": q.full.Load(), "written_bytes": q.written.Load(), "received_bytes": q.received.Load(), "write_errors": q.writeErrors.Load(), "wait_bins": q.wait.snapshot(), "write_bins": q.write.snapshot()}
	b, _ := json.Marshal(v)
	fmt.Printf("TRANSPORT_METRIC|%s\n", b)
}
func (q *transportQueue) run(ctx context.Context, side, mode string) {
	if !transportMetricsEnabled {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			q.report(side, mode, true)
			return
		case <-t.C:
			q.report(side, mode, false)
		}
	}
}

// Observe only visible WireGuard transport headers. A lower counter proves
// reordering/duplication, not packet loss. Key rotation uses a bounded map.
type transportOrder struct {
	mu                       sync.Mutex
	highest                  map[uint32]uint64
	packets, late, maxBehind uint64
}

func (o *transportOrder) observe(p []byte) {
	if !transportMetricsEnabled || len(p) < 32 || binary.LittleEndian.Uint32(p[:4]) != 4 {
		return
	}
	key := binary.LittleEndian.Uint32(p[4:8])
	seq := binary.LittleEndian.Uint64(p[8:16])
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.highest == nil {
		o.highest = make(map[uint32]uint64)
	}
	high, ok := o.highest[key]
	o.packets++
	if ok && seq < high {
		o.late++
		if high-seq > o.maxBehind {
			o.maxBehind = high - seq
		}
	}
	if !ok || seq > high {
		if !ok && len(o.highest) >= 8 {
			clear(o.highest)
		}
		o.highest[key] = seq
	}
}
func (o *transportOrder) report(side string) {
	if !transportMetricsEnabled {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"side": side, "packets": o.packets, "late_or_duplicate": o.late, "max_behind": o.maxBehind, "at": time.Now().UTC().Format(time.RFC3339Nano)})
	fmt.Printf("TRANSPORT_ORDER|%s\n", b)
}
