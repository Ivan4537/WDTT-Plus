package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Connection selection is independent of the server's packet framing. A
// candidate is accepted only after authenticated GETCONF and a relay reply.
// There is one discovery attempt for the entire client, not one per worker.
const connectionAttemptBudget = 12
const connectionVerifiedStartLimit = 3

type connectionPath struct {
	endpoint turnEndpoint
	masque   warpMasqueProtocol
	front    string
}

func (p connectionPath) kind() string {
	if p.masque == warpMasqueHTTP2 {
		return "h2"
	}
	if p.masque == warpMasqueHTTP3 {
		return "h3"
	}
	if p.front != "" {
		return "tls-front"
	}
	return string(p.endpoint.Transport)
}
func (p connectionPath) key() string { return p.endpoint.key() + "|" + p.kind() }

type connectionPolicy struct {
	mu                        sync.Mutex
	preferred                 string
	noUDP                     bool
	active, pending, failures int
	blocked, sleeping, paused bool
	epoch                     uint64
	next                      time.Time
	udpRetryAfter             time.Time
	excluded                  map[string]time.Time
	changed                   chan struct{}
	probes                    map[*connectionLease]struct{}
	readyPaths                map[string]int
	readyKinds                map[string]int
}

func newConnectionPolicy(preferred string, noUDP bool) *connectionPolicy {
	return &connectionPolicy{preferred: preferred, noUDP: noUDP, excluded: make(map[string]time.Time), changed: make(chan struct{}), probes: make(map[*connectionLease]struct{}), readyPaths: make(map[string]int), readyKinds: make(map[string]int)}
}

func (a *connectionPolicy) configure(preferred string, noUDP bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Android may report a handover while flags/startup secrets are loading.
	// The command-line hint belongs exclusively to the original network.
	if a.epoch == 0 {
		a.preferred = preferred
	}
	a.noUDP = noUDP
}
func (a *connectionPolicy) deferUDP(delay time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if delay > 0 {
		a.udpRetryAfter = time.Now().Add(delay)
	}
}

func (a *connectionPolicy) pathAllowed(p connectionPath, now time.Time) bool {
	datagram := p.kind() == "udp" || p.kind() == "h3"
	return !datagram || (!a.noUDP && !now.Before(a.udpRetryAfter))
}

func (a *connectionPolicy) notifyLocked() { close(a.changed); a.changed = make(chan struct{}) }

func (a *connectionPolicy) waitAvailable(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.mu.Lock()
		available, changed := !a.blocked && !a.sleeping && !a.paused, a.changed
		a.mu.Unlock()
		if available {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
func (a *connectionPolicy) command(command string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch command {
	case "CONNECTION_NETWORK":
		a.epoch++
		a.failures = 0
		a.paused = false
		a.preferred = ""
		a.excluded = make(map[string]time.Time)
		a.readyPaths = make(map[string]int)
		a.readyKinds = make(map[string]int)
	case "CONNECTION_OFFLINE":
		a.blocked = true
	case "CONNECTION_ONLINE":
		a.blocked = false
	case "DEVICE_SLEEP", "PAUSE":
		a.sleeping = true
	case "DEVICE_WAKE", "RESUME":
		a.sleeping = false
	default:
		return
	}
	if a.sleeping || a.blocked || command == "CONNECTION_NETWORK" {
		for lease := range a.probes {
			lease.interrupted = true
			if lease.cancel != nil {
				lease.cancel()
			}
		}
	}
	a.notifyLocked()
}

func connectionPaths(endpoints []turnEndpoint, tp *TurnParams, noUDP bool) []connectionPath {
	paths := make([]connectionPath, 0, len(endpoints)*3)
	for _, e := range endpoints {
		if e.Transport == turnTransportUDP {
			continue
		}
		paths = append(paths, connectionPath{endpoint: e})
		if e.Transport == turnTransportTLS && tp.TLSFrontSNI != "" {
			paths = append(paths, connectionPath{endpoint: e, front: tp.TLSFrontSNI})
		}
	}
	if tp.Masque != nil {
		for _, protocol := range []warpMasqueProtocol{warpMasqueHTTP2, warpMasqueHTTP3} {
			if noUDP && protocol == warpMasqueHTTP3 {
				continue
			}
			for _, e := range endpoints {
				if e.Transport != turnTransportUDP {
					paths = append(paths, connectionPath{endpoint: e, masque: protocol})
				}
			}
		}
	}
	if !noUDP {
		for _, e := range endpoints {
			if e.Transport == turnTransportUDP {
				paths = append(paths, connectionPath{endpoint: e})
			}
		}
	}
	// Interleave transport classes, so many dead addresses of one class do
	// not consume the complete budget before another transport gets a chance.
	var result []connectionPath
	for round := 0; ; round++ {
		added := false
		for _, kind := range []string{"udp", "tls", "tls-front", "tcp", "h2", "h3"} {
			n := 0
			for _, p := range paths {
				if p.kind() != kind {
					continue
				}
				if n == round {
					result = append(result, p)
					added = true
					break
				}
				n++
			}
		}
		if !added {
			return result
		}
	}
}

type connectionLease struct {
	a           *connectionPolicy
	path        connectionPath
	epoch       uint64
	ready       bool
	cancel      context.CancelFunc
	interrupted bool
	finished    bool
	stage       string
	started     time.Time
}

func (l *connectionLease) bind(cancel context.CancelFunc) {
	l.a.mu.Lock()
	defer l.a.mu.Unlock()
	l.cancel = cancel
	if l.interrupted {
		cancel()
	}
}

func (l *connectionLease) setStage(stage string) {
	l.a.mu.Lock()
	defer l.a.mu.Unlock()
	l.stage = stage
}

func (a *connectionPolicy) acquire(ctx context.Context, paths []connectionPath) (*connectionLease, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("нет разрешённых путей подключения")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a.mu.Lock()
		now := time.Now()
		index := -1
		for i, p := range paths {
			if !a.pathAllowed(p, now) || now.Before(a.excluded[p.key()]) {
				continue
			}
			if index < 0 {
				index = i
			}
			if p.kind() == a.preferred {
				index = i
				break
			}
		}
		// A new transport still has one discovery probe. Once a worker on
		// this network has confirmed it, match the existing DTLS limit of 3.
		limit := 1
		if index >= 0 && a.readyKinds[paths[index].kind()] > 0 {
			limit = connectionVerifiedStartLimit
		}
		if a.failures >= connectionAttemptBudget && a.active == 0 && !a.paused {
			a.paused = true
			log.Print("[CONNECTION] PAUSED Лимит попыток исчерпан. Смените сеть или подключитесь заново.")
		}
		if !a.blocked && !a.sleeping && !a.paused && a.pending < limit && !now.Before(a.next) {
			if index >= 0 {
				a.pending++
				a.next = now.Add(250 * time.Millisecond)
				lease := &connectionLease{a: a, path: paths[index], epoch: a.epoch, stage: "turn", started: now}
				a.probes[lease] = struct{}{}
				a.mu.Unlock()
				log.Printf("[CONNECTION] TRY %s", lease.path.kind())
				return lease, nil
			}
		}
		// Paused workers sleep on a notification, not repeating timers.
		var wakeAt time.Time
		if !a.blocked && !a.sleeping && !a.paused && a.pending < limit {
			if now.Before(a.next) {
				wakeAt = a.next
			} else {
				for _, path := range paths {
					if a.noUDP && (path.kind() == "udp" || path.kind() == "h3") {
						continue
					}
					expiry := a.excluded[path.key()]
					if (path.kind() == "udp" || path.kind() == "h3") && a.udpRetryAfter.After(expiry) {
						expiry = a.udpRetryAfter
					}
					if wakeAt.IsZero() || expiry.Before(wakeAt) {
						wakeAt = expiry
					}
				}
			}
		}
		changed := a.changed
		a.mu.Unlock()
		var timer *time.Timer
		var tick <-chan time.Time
		if !wakeAt.IsZero() {
			timer = time.NewTimer(time.Until(wakeAt))
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil, ctx.Err()
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-tick:
		}
	}
}

func (l *connectionLease) accept() bool {
	a := l.a
	a.mu.Lock()
	defer a.mu.Unlock()
	if l.interrupted || l.ready || l.finished || l.epoch != a.epoch {
		return false
	}
	delete(a.probes, l)
	l.ready = true
	a.pending--
	a.active++
	if l.epoch == a.epoch {
		a.readyPaths[l.path.key()]++
		a.readyKinds[l.path.kind()]++
		// A reserve worker does not disprove already working UDP workers.
		if a.readyKinds["udp"] > 0 {
			a.preferred = "udp"
		} else {
			a.preferred = l.path.kind()
		}
		if l.path.kind() == "udp" {
			a.udpRetryAfter = time.Time{}
		}
		l.stage = "active"
		a.failures = 0
		a.paused = false
		delete(a.excluded, l.path.key())
		log.Printf("[CONNECTION] READY %d %s", a.epoch, l.path.kind())
	}
	a.notifyLocked()
	return true
}

func connectionPathFailure(err error) bool {
	if errors.Is(err, errUplinkPathReplacement) {
		return false
	}
	if _, limited := workerPolicyLimit(err); limited {
		return false
	}
	if isCredentialTURNError(err) || isTURNCapacityError(err) {
		return false
	}
	if err != nil {
		s := strings.ToUpper(err.Error())
		for _, marker := range []string{"FATAL_AUTH", "FATAL_TRANSPORT", "CAPTCHA", "FLOOD", "CALL_FULL", "INVALID_JOIN_LINK"} {
			if strings.Contains(s, marker) {
				return false
			}
		}
	}
	return true
}

func (l *connectionLease) finish(err error, cancelled bool) {
	a := l.a
	a.mu.Lock()
	defer a.mu.Unlock()
	if l.finished {
		return
	}
	l.finished = true
	delete(a.probes, l)
	if l.ready {
		a.active--
		if l.epoch == a.epoch {
			a.readyPaths[l.path.key()]--
			a.readyKinds[l.path.kind()]--
			if a.readyKinds[a.preferred] == 0 {
				for _, kind := range []string{"udp", "tls", "tls-front", "tcp", "h2", "h3"} {
					if a.readyKinds[kind] > 0 {
						a.preferred = kind
						break
					}
				}
			}
		}
	} else {
		a.pending--
	}
	if l.epoch == a.epoch && !cancelled && !l.interrupted && !a.sleeping && !a.blocked {
		if errors.Is(err, errUplinkPathReplacement) {
			a.notifyLocked()
			return
		}
		log.Printf("[CONNECTION] FAILED %d %s %s %s %d", a.epoch, l.path.kind(), l.stage, connectionFailureReason(err), time.Since(l.started).Milliseconds())
		if connectionPathFailure(err) {
			if l.path.kind() == "udp" || l.path.kind() == "h3" {
				if a.readyKinds["udp"]+a.readyKinds["h3"] == 0 {
					if !time.Now().Before(a.udpRetryAfter) {
						a.udpRetryAfter = time.Now().Add(5 * time.Minute)
						log.Printf("[CONNECTION] UDP_BACKOFF %d", a.epoch)
					}
				} else {
					log.Printf("[CONNECTION] UDP_PARTIAL %d", a.epoch)
				}
			}
			a.failures++
			if a.readyPaths[l.path.key()] == 0 {
				a.excluded[l.path.key()] = time.Now().Add(90 * time.Second)
			}
			if a.failures >= connectionAttemptBudget {
				a.next = time.Now().Add(90 * time.Second)
			}
		} else {
			a.failures++
			// Authentication and admission control are not network evidence.
			a.next = time.Now().Add(20 * time.Second)
		}
	}
	a.notifyLocked()
}

func connectionFailureReason(err error) string {
	if !connectionPathFailure(err) {
		if _, limited := workerPolicyLimit(err); limited {
			return "limit"
		}
		if isTURNCapacityError(err) {
			return "capacity"
		}
		if err != nil && strings.Contains(err.Error(), "FATAL_TRANSPORT") {
			return "protocol"
		}
		return "auth"
	}
	if err == nil {
		return "closed"
	}
	lower := strings.ToLower(err.Error())
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline") {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "interrupted"
	}
	return "network"
}

// The established relay must carry traffic in both directions. This also
// works with old servers: keepalive is part of the original DTLS protocol.
func confirmConnectionPath(ctx context.Context, conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte{keepaliveByte}); err != nil {
		return err
	}
	buf := make([]byte, readBufSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("проверка рабочего пути: %w", err)
		}
		if n == 1 && buf[0] == keepaliveByte {
			return nil
		}
		// Data from already active workers may arrive before our ping reply.
	}
}
