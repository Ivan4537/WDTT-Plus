package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestParseDeploySafeCommand(t *testing.T) {
	payload := []byte(`{"main_password":"secret","args":["list"]}`)
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	line := deploySafeCommandPrefix + "request-1234|" + digest + "|" +
		base64.RawURLEncoding.EncodeToString(payload) + "|" +
		base64.RawURLEncoding.EncodeToString([]byte("/tmp/result.json"))
	command, err := parseDeploySafeCommand(line)
	if err != nil {
		t.Fatal(err)
	}
	if command.requestID != "request-1234" || command.output != "/tmp/result.json" || string(command.payload) != string(payload) {
		t.Fatalf("unexpected command: %#v", command)
	}
}

func TestParseDeploySafeMetadata(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	metadata, err := parseDeploySafeMetadata([]byte("4096|" + digest))
	if err != nil || metadata.size != 4096 || metadata.digest != digest {
		t.Fatalf("unexpected metadata: %#v, %v", metadata, err)
	}
	if _, err := parseDeploySafeMetadata([]byte("0|" + digest)); err == nil {
		t.Fatal("empty response accepted")
	}
}
