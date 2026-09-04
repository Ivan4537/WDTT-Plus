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

func TestDeviceSleepSuppressesHealthAndWakeNotifiesWorkers(t *testing.T) {
	d := &Dispatcher{}
	wakeCh := make(chan struct{}, 1)
	workers := []*WorkerSlot{{ID: 1, WakeCh: wakeCh}}
	d.workers.Store(&workers)
	wakeAt := time.Unix(500, 0)

	d.noteDeviceSleep()
	if !d.shouldSuppressTransportHealth(wakeAt.Add(24 * time.Hour)) {
		t.Fatal("transport timeouts must stay suppressed while the device sleeps")
	}

	if generation := d.noteDeviceWake(wakeAt); generation != 1 {
		t.Fatalf("first wake generation = %d, want 1", generation)
	}
	select {
	case <-wakeCh:
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
