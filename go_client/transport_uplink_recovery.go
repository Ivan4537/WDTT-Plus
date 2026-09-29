package main

import (
	"errors"
	"sync"
	"time"
)

var errUplinkPathReplacement = errors.New("uplink delivery path replacement")

// One dispatcher owns the budget, so separate credential groups cannot each
// start their own replacement storm. Credentials are reused by WorkerGroup.
type uplinkRecovery struct {
	mu            sync.Mutex
	active        map[int]bool
	pending       map[int]bool
	next          map[int]time.Time
	attempts      map[int]int
	nextGlobal    time.Time
	capacityUntil time.Time
}

func (r *uplinkRecovery) acquire(id int, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.active) >= 2 || r.active[id] || now.Before(r.nextGlobal) || now.Before(r.next[id]) || now.Before(r.capacityUntil) {
		return false
	}
	if r.active == nil {
		r.active = make(map[int]bool)
		r.pending = make(map[int]bool)
		r.next = make(map[int]time.Time)
		r.attempts = make(map[int]int)
	}
	r.active[id] = true
	r.pending[id] = true
	r.attempts[id] = min(4, r.attempts[id]+1)
	r.next[id] = now.Add(30 * time.Second * time.Duration(1<<(r.attempts[id]-1)))
	r.nextGlobal = now.Add(5 * time.Second)
	return true
}

func (r *uplinkRecovery) capacityLimited(now time.Time) {
	r.mu.Lock()
	r.capacityUntil = now.Add(30 * time.Second)
	r.mu.Unlock()
}

// Capture the previous attempt's permit before entering RunSession. A permit
// acquired later by this session must survive its teardown until the following
// handshake finishes or fails. The returned release is idempotent.
func (r *uplinkRecovery) completion(id int) (bool, func()) {
	r.mu.Lock()
	held := r.active[id]
	needsProbe := r.pending[id]
	r.mu.Unlock()
	var once sync.Once
	return needsProbe, func() {
		if held {
			once.Do(func() { r.mu.Lock(); delete(r.active, id); r.mu.Unlock() })
		}
	}
}

// A failed handshake releases the concurrency permit, but must not turn the
// following retry into an unverified ordinary path. Clear probation only once
// a registered successor owns its own full-size delivery check.
func (r *uplinkRecovery) registered(id int) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
}

func (d *Dispatcher) canReplaceUplink(id int) bool {
	if d.ctx.Err() != nil || d.deviceSleeping.Load() {
		return false
	}
	ws := d.workers.Load()
	if ws == nil {
		return false
	}
	healthy := 0
	for _, w := range *ws {
		if w.ID != id && workerEligibleForWakeGeneration(w, d.wakeGeneration.Load(), false) &&
			(w.uplink == nil || !w.uplink.muted.Load()) {
			healthy++
		}
	}
	// Never tear down the remaining usable service to improve a sick path.
	return healthy >= 1 && d.uplinkRecovery.acquire(id, time.Now())
}
