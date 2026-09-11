package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseOpaqueHTTPSCommand(t *testing.T) {
	line := strings.Join([]string{
		"OPAQUE_HTTPS_POST",
		"request-1234",
		base64.RawURLEncoding.EncodeToString([]byte("https://example.org/status")),
		base64.RawURLEncoding.EncodeToString([]byte(`{"operation":"status"}`)),
	}, "|")
	command, err := parseOpaqueHTTPSCommand(line)
	if err != nil || command.requestID != "request-1234" || command.url != "https://example.org/status" {
		t.Fatalf("command rejected: %#v, %v", command, err)
	}
}

func TestHandleOpaqueHTTPSResponseUsesSharedAssembler(t *testing.T) {
	dispatcher := &Dispatcher{updateMetadataWaiters: make(map[string]*updateMetadataAssembly)}
	waiter := &updateMetadataAssembly{result: make(chan updateMetadataResult, 1)}
	dispatcher.updateMetadataWaiters["request-1234"] = waiter
	payload := []byte(`{"status":200,"body":"ok"}`)
	frame := []byte(
		opaqueHTTPSResponsePrefix + "request-1234|OK|0|1|" +
			base64.RawURLEncoding.EncodeToString(payload),
	)
	if !dispatcher.handleUpdateMetadataResponse(frame) {
		t.Fatal("opaque HTTPS response was not recognized")
	}
	result := <-waiter.result
	if result.err != nil || string(result.payload) != string(payload) {
		t.Fatalf("result = %q, %v", result.payload, result.err)
	}
}
