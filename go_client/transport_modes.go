package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const experimentAuto = "auto"
const experimentStandard = "standard"
const experimentUplink = "uplink"

func validateTransportExperiment(value string) error {
	switch value {
	case experimentAuto, experimentStandard, experimentUplink:
		return nil
	}
	return errors.New("unknown transport mode")
}

func negotiateTransportExperiment(ctx context.Context, connection net.Conn, config, mode string) error {
	capability, marker := "", multipathRelayHello
	switch mode {
	case experimentUplink:
		capability, marker = "uplink2", "WDTT_UPLINK2"
	}
	if capability != "" {
		supported := supportsAdaptiveTransport(config)
		if !supported {
			return errors.New("FATAL_TRANSPORT: сервер изменил возможности транспорта; переподключите туннель")
		}
	}
	if _, err := connection.Write([]byte(marker)); err != nil {
		return err
	}
	if capability == "" {
		return nil
	}
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	stop := context.AfterFunc(ctx, func() { _ = connection.SetReadDeadline(time.Now()) })
	defer stop()
	defer connection.SetReadDeadline(time.Time{})
	b := make([]byte, readBufSize)
	for {
		n, err := connection.Read(b)
		if err != nil {
			// A lost acknowledgement or a changing network is recoverable.
			// Never stop every worker because one new path timed out.
			return fmt.Errorf("согласование транспорта: %w", err)
		}
		if string(b[:n]) == "WDTT_TRANSPORT_OK1" {
			return nil
		}
		// DTLS datagrams can arrive out of order. An already active device
		// can receive traffic on this path before its ACK arrives. Drop these
		// early data packets under the same fixed deadline, then await ACK.
		if (mode == experimentUplink && n >= 4 && b[0] >= 1 && b[0] <= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0) ||
			(n == 1 && b[0] == keepaliveByte) {
			continue
		}
		return fmt.Errorf("FATAL_TRANSPORT: сервер прислал неверное подтверждение транспорта")
	}
}

func (d *Dispatcher) isUserPacket(p []byte) bool { return isWireGuardUserDataPacket(p) }

// Resolve once per connection generation: all workers must agree on framing.
// Capabilities come from the authenticated GETCONF, never from an unauthenticated probe.
func (d *Dispatcher) resolveTransport(config string) string {
	if d.experiment != experimentAuto {
		return d.experiment
	}
	selected := uint32(1)
	if supportsAdaptiveTransport(config) {
		selected = 2
	}
	d.negotiatedTransport.CompareAndSwap(0, selected)
	if d.negotiatedTransport.Load() == 2 {
		return experimentUplink
	}
	return experimentStandard
}

func (d *Dispatcher) usesUplink() bool {
	return d.experiment == experimentUplink || (d.experiment == experimentAuto && d.negotiatedTransport.Load() == 2)
}

func supportsAdaptiveTransport(config string) bool {
	for _, line := range strings.Split(config, "\n") {
		if values, ok := strings.CutPrefix(strings.TrimSpace(line), "# WDTT_TRANSPORTS="); ok {
			for _, value := range strings.Split(values, ",") {
				if strings.TrimSpace(value) == "uplink2" {
					return true
				}
			}
		}
	}
	return false
}
