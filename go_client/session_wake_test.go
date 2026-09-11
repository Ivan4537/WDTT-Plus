package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func newWakeProbeTestSlot() *WorkerSlot {
	return &WorkerSlot{
		WakeCh:    make(chan uint64, 1),
		SleepCh:   make(chan struct{}, 1),
		WakeAckCh: make(chan uint64, 1),
	}
}

func TestWorkerWakeProbePreservesAResponsiveChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slot := newWakeProbeTestSlot()
	writes := make(chan struct{}, 8)
	expired := make(chan uint64, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		runWorkerWakeProbeLoop(
			ctx,
			slot,
			func(time.Time) bool {
				writes <- struct{}{}
				return true
			},
			80*time.Millisecond,
			15*time.Millisecond,
			func(generation uint64) { expired <- generation },
		)
	}()

	slot.WakeCh <- 7
	select {
	case <-writes:
	case <-time.After(time.Second):
		t.Fatal("wake did not send an immediate worker probe")
	}
	slot.WakeAckCh <- 7
	time.Sleep(120 * time.Millisecond)
	select {
	case generation := <-expired:
		t.Fatalf("responsive worker expired for generation %d", generation)
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wake probe loop did not stop with its session")
	}
}

func TestWorkerWakeProbeExpiresOnlyTheUnresponsiveChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slot := newWakeProbeTestSlot()
	var writes atomic.Int32
	expired := make(chan uint64, 1)

	go runWorkerWakeProbeLoop(
		ctx,
		slot,
		func(time.Time) bool {
			writes.Add(1)
			return true
		},
		80*time.Millisecond,
		15*time.Millisecond,
		func(generation uint64) { expired <- generation },
	)

	slot.WakeCh <- 11
	select {
	case generation := <-expired:
		if generation != 11 {
			t.Fatalf("expired generation = %d, want 11", generation)
		}
	case <-time.After(time.Second):
		t.Fatal("unresponsive worker wake probe did not expire")
	}
	if got := writes.Load(); got < 2 {
		t.Fatalf("worker received only %d probe(s), want an immediate probe and retries", got)
	}
}

func TestWorkerWakeProbeIsCancelledByAnotherSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slot := newWakeProbeTestSlot()
	writes := make(chan struct{}, 8)
	expired := make(chan uint64, 1)

	go runWorkerWakeProbeLoop(
		ctx,
		slot,
		func(time.Time) bool {
			writes <- struct{}{}
			return true
		},
		80*time.Millisecond,
		15*time.Millisecond,
		func(generation uint64) { expired <- generation },
	)

	slot.WakeCh <- 3
	select {
	case <-writes:
	case <-time.After(time.Second):
		t.Fatal("wake did not start a probe")
	}
	slot.SleepCh <- struct{}{}
	time.Sleep(120 * time.Millisecond)
	select {
	case generation := <-expired:
		t.Fatalf("intentional sleep expired wake generation %d", generation)
	default:
	}
}
