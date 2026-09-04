package main

import (
	"net"
	"testing"
	"time"
)

func TestDeviceWGRelayKeepsStableSourceAndChunksRepliesAcrossPaths(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	relay, first, err := acquireDeviceWGRelay("test-device", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.release(first)
	_, second, err := acquireDeviceWGRelay("test-device", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.release(second)

	read := func() *net.UDPAddr {
		t.Helper()
		buf := make([]byte, 64)
		if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		_, addr, err := listener.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return addr
	}
	if err := relay.writeFrom(first, []byte("first")); err != nil {
		t.Fatal(err)
	}
	firstSource := read()
	if err := relay.writeFrom(second, []byte("second")); err != nil {
		t.Fatal(err)
	}
	secondSource := read()
	if firstSource.Port != secondSource.Port {
		t.Fatalf("shared relay changed WireGuard source port: %d -> %d", firstSource.Port, secondSource.Port)
	}
	if _, err := listener.WriteToUDP([]byte("reply"), secondSource); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-first.downstream:
		if string(got) != "reply" {
			t.Fatalf("unexpected reply %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first scheduled path did not receive WireGuard reply")
	}
}
