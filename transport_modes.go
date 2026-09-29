package main

const adaptiveTransportHello = "WDTT_UPLINK2"
const transportAck = "WDTT_TRANSPORT_OK1"

func transportCapabilities() string { return "# WDTT_TRANSPORTS=uplink2\n" }

func (relay *deviceWGRelay) dispatchPacket(packet []byte) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	chosen := relay.nextAttachmentLocked()
	if chosen != nil {
		chosen.offerData(append([]byte(nil), packet...))
	}
}
