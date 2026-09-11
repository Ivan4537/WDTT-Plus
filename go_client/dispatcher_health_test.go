package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func wireGuardTestPacket(messageType uint32, size int) []byte {
	packet := make([]byte, size)
	binary.LittleEndian.PutUint32(packet, messageType)
	return packet
}

func TestWireGuardUserTrafficExcludesControlAndEmptyKeepalivePackets(t *testing.T) {
	if isWireGuardUserDataPacket(wireGuardTestPacket(1, 148)) {
		t.Fatal("a WireGuard handshake is not user traffic")
	}
	if isWireGuardUserDataPacket(wireGuardTestPacket(4, 32)) {
		t.Fatal("an empty WireGuard transport keepalive is not user traffic")
	}
	if !isWireGuardUserDataPacket(wireGuardTestPacket(4, 52)) {
		t.Fatal("a non-empty WireGuard transport packet must be tracked as user traffic")
	}
}

func TestUnansweredTrafficUsesFirstSendDespiteContinuousRetries(t *testing.T) {
	d := &Dispatcher{}
	startedAt := time.Unix(100, 0)

	d.noteUserTrafficSent(startedAt)
	d.noteUserTrafficSent(startedAt.Add(40 * time.Second))

	if stalledFor, stalled := d.claimStalledUserTraffic(startedAt.Add(46*time.Second), 45*time.Second); !stalled || stalledFor != 46*time.Second {
		t.Fatal("continuous outgoing traffic must not postpone stall detection")
	}
	if _, stalled := d.claimStalledUserTraffic(startedAt.Add(47*time.Second), 45*time.Second); stalled {
		t.Fatal("a reported stall must be claimed only once")
	}
}

func TestUserResponseClearsUnansweredTraffic(t *testing.T) {
	d := &Dispatcher{}
	startedAt := time.Unix(100, 0)

	d.noteUserTrafficSent(startedAt)
	if d.noteUserTrafficResponse() {
		t.Fatal("an ordinary response must not report recovery without a prior stall")
	}

	if _, stalled := d.claimStalledUserTraffic(startedAt.Add(time.Minute), 45*time.Second); stalled {
		t.Fatal("a real user response must clear the unanswered traffic timer")
	}
}

func TestFirstResponseAfterReportedStallReportsRecoveryOnce(t *testing.T) {
	d := &Dispatcher{}
	startedAt := time.Unix(100, 0)
	d.noteUserTrafficSent(startedAt)
	if _, stalled := d.claimStalledUserTraffic(startedAt.Add(time.Minute), 45*time.Second); !stalled {
		t.Fatal("expected a reported stall")
	}
	if !d.noteUserTrafficResponse() {
		t.Fatal("the first response after a stall must report recovery")
	}
	if d.noteUserTrafficResponse() {
		t.Fatal("recovery must be reported only once")
	}
}

func TestDeviceStateChangeClearsPendingAndReportedTrafficStall(t *testing.T) {
	d := &Dispatcher{}
	startedAt := time.Unix(100, 0)
	d.noteUserTrafficSent(startedAt)
	if _, stalled := d.claimStalledUserTraffic(startedAt.Add(time.Minute), 45*time.Second); !stalled {
		t.Fatal("expected a reported stall before the device state change")
	}

	d.resetUserTrafficHealth()

	if _, stalled := d.claimStalledUserTraffic(startedAt.Add(2*time.Minute), 45*time.Second); stalled {
		t.Fatal("sleep or wake must clear the old unanswered traffic timer")
	}
	if d.noteUserTrafficResponse() {
		t.Fatal("a response after reset must not report recovery from an obsolete stall")
	}
}

func TestSocksModeDoesNotTreatOneSilentFlowAsGlobalTransportFailure(t *testing.T) {
	d := &Dispatcher{}
	startedAt := time.Unix(100, 0)

	d.setUnansweredUserTrafficHealthEnabled(false)
	d.noteUserTrafficSent(startedAt)

	if _, stalled := d.claimStalledUserTraffic(startedAt.Add(10*time.Minute), 45*time.Second); stalled {
		t.Fatal("a silent SOCKS flow must not fail the shared transport")
	}
	if d.noteUserTrafficResponse() {
		t.Fatal("SOCKS traffic must not report recovery from a disabled watchdog")
	}
}

func TestVpnModeCanReenableUnansweredTrafficHealth(t *testing.T) {
	d := &Dispatcher{}
	startedAt := time.Unix(100, 0)

	d.setUnansweredUserTrafficHealthEnabled(false)
	d.setUnansweredUserTrafficHealthEnabled(true)
	d.noteUserTrafficSent(startedAt)

	if _, stalled := d.claimStalledUserTraffic(startedAt.Add(time.Minute), 45*time.Second); !stalled {
		t.Fatal("VPN mode must retain unanswered user traffic detection")
	}
}

func TestDeviceSleepSuppressesHealthAndWakeNotifiesWorkers(t *testing.T) {
	d := &Dispatcher{}
	wakeCh := make(chan uint64, 1)
	sleepCh := make(chan struct{}, 1)
	workers := []*WorkerSlot{{ID: 1, WakeCh: wakeCh, SleepCh: sleepCh}}
	d.workers.Store(&workers)
	wakeAt := time.Unix(500, 0)

	d.noteDeviceSleep()
	select {
	case <-sleepCh:
	default:
		t.Fatal("sleep must cancel an outstanding worker wake probe")
	}
	if !d.shouldSuppressTransportHealth(wakeAt.Add(24 * time.Hour)) {
		t.Fatal("transport timeouts must stay suppressed while the device sleeps")
	}

	if generation := d.noteDeviceWake(wakeAt); generation != 1 {
		t.Fatalf("first wake generation = %d, want 1", generation)
	}
	select {
	case generation := <-wakeCh:
		if generation != 1 {
			t.Fatalf("worker wake generation = %d, want 1", generation)
		}
	default:
		t.Fatal("wake must request an immediate keepalive from every worker")
	}
	if !d.shouldSuppressTransportHealth(wakeAt.Add(deviceWakeHealthGrace - time.Nanosecond)) {
		t.Fatal("transport timeouts must stay suppressed during wake grace")
	}
	if d.shouldSuppressTransportHealth(wakeAt.Add(deviceWakeHealthGrace)) {
		t.Fatal("transport health checks must resume after wake grace")
	}
}

func TestLatestWakeGenerationReplacesAnUndeliveredOlderProbe(t *testing.T) {
	ch := make(chan uint64, 1)
	offerLatestGeneration(ch, 1)
	offerLatestGeneration(ch, 2)

	if generation := <-ch; generation != 2 {
		t.Fatalf("queued generation = %d, want latest generation 2", generation)
	}
}

func TestWakeGenerationRoutesOnlyThroughIndividuallyVerifiedWorkers(t *testing.T) {
	d := &Dispatcher{}
	workers := []*WorkerSlot{
		{ID: 1, WakeCh: make(chan uint64, 1), WakeAckCh: make(chan uint64, 1)},
		{ID: 2, WakeCh: make(chan uint64, 1), WakeAckCh: make(chan uint64, 1)},
	}
	d.workers.Store(&workers)

	generation := d.noteDeviceWake(time.Unix(700, 0))
	if workerEligibleForWakeGeneration(workers[0], generation, false) ||
		workerEligibleForWakeGeneration(workers[1], generation, false) {
		t.Fatal("registered workers must stay out of user routing until their own wake response")
	}

	d.acknowledgeWorkerWake(workers[0], generation)
	if !workerEligibleForWakeGeneration(workers[0], generation, false) {
		t.Fatal("the worker that answered the current wake probe must become routable")
	}
	if workerEligibleForWakeGeneration(workers[1], generation, false) {
		t.Fatal("one worker response must not validate another worker")
	}

	ready, total := d.wakeStatus(generation)
	if ready != 1 || total != 2 {
		t.Fatalf("wake status = %d/%d, want 1/2", ready, total)
	}
}

func TestSleepingDoesNotApplyWakeRoutingGate(t *testing.T) {
	worker := &WorkerSlot{ID: 1}
	if !workerEligibleForWakeGeneration(worker, 3, true) {
		t.Fatal("screen-off traffic must not be blocked by a previous wake generation")
	}
}

func TestReplacementWorkerReceivesCurrentWakeGeneration(t *testing.T) {
	d := &Dispatcher{}
	empty := make([]*WorkerSlot, 0)
	d.workers.Store(&empty)
	d.wakeGeneration.Store(4)
	worker := &WorkerSlot{ID: 7, WakeCh: make(chan uint64, 1)}

	d.Register(worker)

	select {
	case generation := <-worker.WakeCh:
		if generation != 4 {
			t.Fatalf("replacement worker generation = %d, want 4", generation)
		}
	default:
		t.Fatal("a replacement worker must be probed before receiving user traffic")
	}
}

func TestSleepAndWakeReachEverySupportedWorkerCount(t *testing.T) {
	for workerCount := workersPerGroup; workerCount <= 108; workerCount += workersPerGroup {
		d := &Dispatcher{}
		workers := make([]*WorkerSlot, 0, workerCount)
		for id := 1; id <= workerCount; id++ {
			workers = append(workers, &WorkerSlot{
				ID:      id,
				WakeCh:  make(chan uint64, 1),
				SleepCh: make(chan struct{}, 1),
			})
		}
		d.workers.Store(&workers)

		d.noteDeviceSleep()
		if generation := d.noteDeviceWake(time.Unix(int64(workerCount), 0)); generation != 1 {
			t.Fatalf("%d workers: wake generation = %d, want 1", workerCount, generation)
		}
		for _, worker := range workers {
			select {
			case <-worker.SleepCh:
			default:
				t.Fatalf("%d workers: worker %d missed sleep notification", workerCount, worker.ID)
			}
			select {
			case generation := <-worker.WakeCh:
				if generation != 1 {
					t.Fatalf("%d workers: worker %d generation = %d, want 1", workerCount, worker.ID, generation)
				}
			default:
				t.Fatalf("%d workers: worker %d missed wake notification", workerCount, worker.ID)
			}
		}
	}
}
