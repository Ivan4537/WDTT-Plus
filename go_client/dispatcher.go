package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	wireGuardTransportDataType = 4
	wireGuardEmptyDataSize     = 32
)

func isWireGuardUserDataPacket(packet []byte) bool {
	return len(packet) > wireGuardEmptyDataSize &&
		binary.LittleEndian.Uint32(packet[:4]) == wireGuardTransportDataType
}

var pktPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

func getPktBuf(size int) []byte {
	b := pktPool.Get().([]byte)
	if cap(b) < size {
		b = make([]byte, size)
	}
	return b[:size]
}

func putPktBuf(b []byte) {
	if cap(b) < 2048 {
		return
	}
	pktPool.Put(b[:cap(b)])
}

const (
	returnChBuf           = 384
	deviceWakeHealthGrace = 60 * time.Second

	// chunkSize — количество последовательных пакетов, отправляемых в один worker
	// перед переключением на следующий.
	//
	// Зачем: при round-robin (chunk=1) каждый пакет летит через разный TURN relay
	// с разным latency, что приводит к reorder на сервере. TCP внутри WireGuard
	// интерпретирует reorder как потери → cwnd collapse → скорость single-flow
	// падает до ~8 KB/s.
	//
	// С chunk=16 пакеты реже перескакивают между путями с разной задержкой. Это
	// уменьшает reorder на активной многоканальной сессии, сохраняя равномерную
	// загрузку всех workers.
	// Reorder возможен только между chunk-границами, что покрывается WG replay
	// window (2048 пакетов).
	//
	// Все workers по-прежнему получают одинаковую долю трафика за полный цикл;
	// фактический выигрыш зависит от различия задержек между TURN-путями.
	chunkSize = 16
)

type WorkerSlot struct {
	ID        int
	SendCh    chan []byte
	WakeCh    chan uint64
	SleepCh   chan struct{}
	WakeAckCh chan uint64
	// A worker may stay registered while its UDP/DTLS socket is stale after
	// Android Doze. User packets must not use it until the current wake probe
	// receives a response from the server.
	WakeVerifiedGeneration atomic.Uint64
}

type Dispatcher struct {
	localConn             net.PacketConn
	clientAddr            atomic.Pointer[net.Addr]
	workers               atomic.Pointer[[]*WorkerSlot]
	mu                    sync.Mutex // Используется только для записи
	rrIndex               int
	rrCount               int
	ReturnCh              chan []byte
	ctx                   context.Context
	cancel                context.CancelFunc
	wg                    sync.WaitGroup
	stats                 *Stats
	updateMetadataMu      sync.Mutex
	updateMetadataWaiters map[string]*updateMetadataAssembly
	updateRelayNext       atomic.Uint64
	// firstUnansweredUserTxAt is global for the dispatcher because a reply may
	// return through a different worker than the one that sent the request.
	// Keeping the first (rather than latest) unanswered send also prevents a
	// continuous stream of retries from postponing stall detection forever.
	firstUnansweredUserTxAt atomic.Int64
	stalledUserTraffic      atomic.Bool
	// SOCKS5 forwards independent opt-in flows. A single silent destination is
	// not evidence that the shared transport failed, so that mode relies on the
	// keepalive watchdog instead of the VPN-wide unanswered-traffic watchdog.
	unansweredUserTrafficHealthDisabled atomic.Bool
	deviceSleeping                      atomic.Bool
	wakeGeneration                      atomic.Uint64
	wakeHealthGraceUntil                atomic.Int64
}

func NewDispatcher(ctx context.Context, localConn net.PacketConn, stats *Stats) *Dispatcher {
	dctx, dcancel := context.WithCancel(ctx)
	d := &Dispatcher{
		localConn:             localConn,
		ReturnCh:              make(chan []byte, returnChBuf),
		ctx:                   dctx,
		cancel:                dcancel,
		stats:                 stats,
		updateMetadataWaiters: make(map[string]*updateMetadataAssembly),
	}

	empty := make([]*WorkerSlot, 0)
	d.workers.Store(&empty)

	d.wg.Add(2)
	go d.readLoop()
	go d.writeLoop()
	return d
}

func (d *Dispatcher) Shutdown() {
	d.cancel()
	d.wg.Wait()
}

func (d *Dispatcher) Register(w *WorkerSlot) {
	d.mu.Lock()
	oldWorkers := d.workers.Load()
	newWorkers := make([]*WorkerSlot, len(*oldWorkers)+1)
	copy(newWorkers, *oldWorkers)
	newWorkers[len(*oldWorkers)] = w
	d.workers.Store(&newWorkers)
	d.mu.Unlock()
	log.Printf("[ДИСП] Воркер #%d зарегистрирован (всего: %d)", w.ID, len(newWorkers))

	// A replacement worker created during wake recovery must prove its new
	// socket before the dispatcher starts sending user traffic through it.
	generation := d.wakeGeneration.Load()
	if generation > 0 && !d.deviceSleeping.Load() && w.WakeCh != nil {
		offerLatestGeneration(w.WakeCh, generation)
		d.logWakeStatus(generation)
	}
}

func (d *Dispatcher) Unregister(slot *WorkerSlot) {
	d.mu.Lock()
	oldWorkers := d.workers.Load()
	newWorkers := make([]*WorkerSlot, 0, len(*oldWorkers))
	for _, w := range *oldWorkers {
		if w != slot {
			newWorkers = append(newWorkers, w)
		}
	}
	d.workers.Store(&newWorkers)
	d.mu.Unlock()
	log.Printf("[ДИСП] Воркер #%d отключён (осталось: %d)", slot.ID, len(newWorkers))
	if generation := d.wakeGeneration.Load(); generation > 0 && !d.deviceSleeping.Load() {
		d.logWakeStatus(generation)
	}
}

func (d *Dispatcher) noteUserTrafficSent(now time.Time) {
	if d.unansweredUserTrafficHealthDisabled.Load() {
		return
	}
	d.firstUnansweredUserTxAt.CompareAndSwap(0, now.UnixNano())
}

func (d *Dispatcher) noteUserTrafficResponse() bool {
	if d.unansweredUserTrafficHealthDisabled.Load() {
		d.resetUserTrafficHealth()
		return false
	}
	d.firstUnansweredUserTxAt.Store(0)
	return d.stalledUserTraffic.Swap(false)
}

func (d *Dispatcher) setUnansweredUserTrafficHealthEnabled(enabled bool) {
	d.unansweredUserTrafficHealthDisabled.Store(!enabled)
	d.resetUserTrafficHealth()
}

func (d *Dispatcher) resetUserTrafficHealth() {
	d.firstUnansweredUserTxAt.Store(0)
	d.stalledUserTraffic.Store(false)
}

func (d *Dispatcher) noteDeviceSleep() {
	d.deviceSleeping.Store(true)
	d.wakeHealthGraceUntil.Store(0)
	d.resetUserTrafficHealth()

	workers := d.workers.Load()
	if workers == nil {
		return
	}
	for _, worker := range *workers {
		if worker.SleepCh == nil {
			continue
		}
		select {
		case worker.SleepCh <- struct{}{}:
		default:
		}
	}
}

func (d *Dispatcher) noteDeviceWake(now time.Time) uint64 {
	d.resetUserTrafficHealth()
	d.wakeHealthGraceUntil.Store(now.Add(deviceWakeHealthGrace).UnixNano())
	generation := d.wakeGeneration.Add(1)
	d.deviceSleeping.Store(false)

	workers := d.workers.Load()
	if workers == nil {
		d.logWakeStatus(generation)
		return generation
	}
	d.logWakeStatus(generation)
	for _, worker := range *workers {
		if worker.WakeCh == nil {
			continue
		}
		offerLatestGeneration(worker.WakeCh, generation)
	}
	return generation
}

func workerEligibleForWakeGeneration(worker *WorkerSlot, generation uint64, deviceSleeping bool) bool {
	if worker == nil {
		return false
	}
	return generation == 0 || deviceSleeping || worker.WakeVerifiedGeneration.Load() >= generation
}

func (d *Dispatcher) wakeStatus(generation uint64) (ready int, total int) {
	workers := d.workers.Load()
	if workers == nil {
		return 0, 0
	}
	for _, worker := range *workers {
		if worker == nil {
			continue
		}
		total++
		if worker.WakeVerifiedGeneration.Load() >= generation {
			ready++
		}
	}
	return ready, total
}

func (d *Dispatcher) logWakeStatus(generation uint64) {
	if generation == 0 || generation != d.wakeGeneration.Load() || d.deviceSleeping.Load() {
		return
	}
	ready, total := d.wakeStatus(generation)
	log.Printf("[WAKE_STATUS] generation=%d ready=%d total=%d", generation, ready, total)
}

func (d *Dispatcher) acknowledgeWorkerWake(worker *WorkerSlot, generation uint64) {
	if worker == nil || generation == 0 || generation != d.wakeGeneration.Load() || d.deviceSleeping.Load() {
		return
	}
	previous := worker.WakeVerifiedGeneration.Swap(generation)
	offerLatestGeneration(worker.WakeAckCh, generation)
	if previous < generation {
		d.logWakeStatus(generation)
	}
}

func offerLatestGeneration(ch chan uint64, generation uint64) {
	if ch == nil {
		return
	}
	select {
	case ch <- generation:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- generation:
	default:
	}
}

func (d *Dispatcher) shouldSuppressTransportHealth(now time.Time) bool {
	if d.deviceSleeping.Load() {
		return true
	}
	graceUntil := d.wakeHealthGraceUntil.Load()
	return graceUntil > 0 && now.UnixNano() < graceUntil
}

func (d *Dispatcher) claimStalledUserTraffic(now time.Time, timeout time.Duration) (time.Duration, bool) {
	if d.unansweredUserTrafficHealthDisabled.Load() {
		return 0, false
	}
	startedAt := d.firstUnansweredUserTxAt.Load()
	if startedAt == 0 {
		return 0, false
	}
	stalledFor := now.Sub(time.Unix(0, startedAt))
	if stalledFor <= timeout || !d.firstUnansweredUserTxAt.CompareAndSwap(startedAt, 0) {
		return 0, false
	}
	d.stalledUserTraffic.Store(true)
	return stalledFor, true
}

// readLoop читает WireGuard-пакеты и распределяет по workers chunk'ами.
//
// Логика: отправляем chunkSize подряд пакетов в один worker, потом переходим
// к следующему. Если текущий worker перегружен (канал полный) — немедленно
// ищем свободный worker и начинаем новый chunk на нём. Это гарантирует:
//   - В рамках chunk пакеты идут через один TURN relay → in-order delivery
//   - Между chunks — разные relay → максимальная агрегатная скорость
//   - Нет блокировки, нет буферизации, нет дополнительного latency
func (d *Dispatcher) readLoop() {
	defer d.wg.Done()

	for {
		if err := d.ctx.Err(); err != nil {
			return
		}

		pkt := getPktBuf(2048)

		n, addr, err := d.localConn.ReadFrom(pkt)
		if err != nil {
			putPktBuf(pkt)
			if d.ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		pkt = pkt[:n]

		d.clientAddr.Store(&addr)
		d.stats.TotalBytesUp.Add(int64(n))

		workersPtr := d.workers.Load()
		if workersPtr == nil || len(*workersPtr) == 0 {
			putPktBuf(pkt)
			continue
		}

		ws := *workersPtr
		nw := len(ws)
		wakeGeneration := d.wakeGeneration.Load()
		deviceSleeping := d.deviceSleeping.Load()

		sent := false
		idx := d.rrIndex % nw

		// After wake, a registered worker is only a candidate after its own
		// current-generation keepalive has returned. This keeps stale sockets
		// out of the user-data round robin while healthy workers keep carrying
		// traffic and the remaining sessions reconnect independently.
		for offset := 0; offset < nw; offset++ {
			candidateIdx := (idx + offset) % nw
			candidate := ws[candidateIdx]
			if !workerEligibleForWakeGeneration(candidate, wakeGeneration, deviceSleeping) {
				continue
			}
			select {
			case candidate.SendCh <- pkt:
				sent = true
				if offset == 0 {
					d.rrCount++
				} else {
					d.rrIndex = candidateIdx
					d.rrCount = 1
				}
				if d.rrCount >= chunkSize {
					d.rrIndex = (candidateIdx + 1) % nw
					d.rrCount = 0
				}
			default:
			}
			if sent {
				break
			}
		}

		if !sent {
			// Все workers перегружены — сдвигаем указатель, пакет дропается
			d.rrIndex = (idx + 1) % nw
			d.rrCount = 0
			putPktBuf(pkt)
		}
	}
}

func (d *Dispatcher) writeLoop() {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		case pkt := <-d.ReturnCh:
			addrPtr := d.clientAddr.Load()
			if addrPtr == nil {
				putPktBuf(pkt)
				continue
			}
			addr := *addrPtr
			if _, err := d.localConn.WriteTo(pkt, addr); err != nil {
				if d.ctx.Err() != nil {
					putPktBuf(pkt)
					return
				}
			}
			d.stats.TotalBytesDown.Add(int64(len(pkt)))
			putPktBuf(pkt)
		}
	}
}
