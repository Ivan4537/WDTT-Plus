package main

import (
	"context"
	"sync"
	"time"
	"wdtt.local/pathprobe"
)

type uplinkReceipt struct {
	mu         sync.Mutex
	receipt    pathprobe.Receipt
	dirty      bool
	lastData   time.Time
	lastReport time.Time
}

// Receipt is telemetry, not a second replay filter. A datagram may arrive
// outside its small observation window and still be valid to WireGuard.
// Only WireGuard decides whether user data is a replay; probes never enter it.
func (r *uplinkReceipt) forward(kind byte, seq uint64) bool {
	if kind != pathprobe.Bypass {
		r.observe(seq)
	}
	return kind != pathprobe.Probe
}

func (r *uplinkReceipt) observe(seq uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ok := r.receipt.Observe(seq)
	r.dirty = r.dirty || ok
	if ok {
		r.lastData = time.Now()
	}
	return ok
}
func (r *uplinkReceipt) run(ctx context.Context, write func([]byte) error, cancel context.CancelFunc) {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.mu.Lock()
		var ack []byte
		if r.dirty || (!r.lastData.IsZero() && time.Since(r.lastData) < 2*time.Second && time.Since(r.lastReport) >= 250*time.Millisecond) {
			ack = pathprobe.Ack(r.receipt.Expected, r.receipt.Received)
			r.dirty = false
			r.lastReport = time.Now()
		}
		r.mu.Unlock()
		if ack != nil && write(ack) != nil {
			cancel()
			return
		}
	}
}
