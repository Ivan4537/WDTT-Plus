package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHandleUpdateMetadataResponseReassemblesOutOfOrderChunks(t *testing.T) {
	d := &Dispatcher{
		ctx:                   context.Background(),
		updateMetadataWaiters: make(map[string]*updateMetadataAssembly),
	}
	waiter := &updateMetadataAssembly{result: make(chan updateMetadataResult, 1)}
	d.updateMetadataWaiters["request-1234"] = waiter
	frames := [][]byte{
		[]byte("WDTT_UPDATE1_RESULT|request-1234|OK|1|2|" + base64.RawURLEncoding.EncodeToString([]byte("two"))),
		[]byte("WDTT_UPDATE1_RESULT|request-1234|OK|0|2|" + base64.RawURLEncoding.EncodeToString([]byte("one-"))),
	}
	for _, frame := range frames {
		if !d.handleUpdateMetadataResponse(frame) {
			t.Fatal("control response was not recognized")
		}
	}
	select {
	case result := <-waiter.result:
		if result.err != nil || string(result.payload) != "one-two" {
			t.Fatalf("result = %q, %v", result.payload, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("assembled response was not delivered")
	}
}

func TestHandleUpdateMetadataResponseDoesNotConsumeWireGuardPacket(t *testing.T) {
	d := &Dispatcher{}
	if d.handleUpdateMetadataResponse([]byte{4, 0, 0, 0, 1, 2, 3}) {
		t.Fatal("WireGuard packet was consumed as update metadata")
	}
}

func TestHandleUpdateAPKResponsePreservesBinaryPayload(t *testing.T) {
	d := &Dispatcher{ctx: context.Background(), updateMetadataWaiters: make(map[string]*updateMetadataAssembly)}
	waiter := &updateMetadataAssembly{result: make(chan updateMetadataResult, 1), ready: make(chan struct{}, 1)}
	d.updateMetadataWaiters["request-1234"] = waiter
	payload := []byte{0, 1, '|', 255, 10, 13, 0}
	header := updateAPKChunkResponsePrefix + "request-1234|OK|0|1|"
	packet := append([]byte(header), payload...)
	if !d.handleUpdateMetadataResponse(packet) {
		t.Fatal("binary APK response was not recognized")
	}
	result := <-waiter.result
	if string(result.payload) != string(payload) {
		t.Fatalf("payload = %v, want %v", result.payload, payload)
	}
}

func TestNormalizeUpdateMetadataRequestID(t *testing.T) {
	if normalizeUpdateMetadataRequestID("request-1234") != "request-1234" {
		t.Fatal("valid request ID rejected")
	}
	if normalizeUpdateMetadataRequestID("../../bad") != "" {
		t.Fatal("invalid request ID accepted")
	}
}

func TestEnqueueUpdateRelayRequestUsesAllWorkers(t *testing.T) {
	d := &Dispatcher{}
	workers := make([]*WorkerSlot, 4)
	for index := range workers {
		workers[index] = &WorkerSlot{SendCh: make(chan []byte, 4)}
	}
	for index := 0; index < 8; index++ {
		if !d.enqueueUpdateRelayRequest(workers, []byte("request")) {
			t.Fatalf("request %d was not queued", index)
		}
	}
	for index, worker := range workers {
		if queued := len(worker.SendCh); queued != 2 {
			t.Fatalf("worker %d received %d requests, want 2", index, queued)
		}
	}
}

func TestUpdateAPKParallelChunkLimitTracksWorkers(t *testing.T) {
	for _, test := range []struct {
		workers int
		want    int
	}{
		{workers: 0, want: 1},
		{workers: 1, want: 2},
		{workers: 9, want: 18},
		{workers: 27, want: 54},
		{workers: 36, want: updateAPKMaxParallelChunks},
	} {
		if got := updateAPKParallelChunkLimit(test.workers); got != test.want {
			t.Fatalf("workers %d: limit = %d, want %d", test.workers, got, test.want)
		}
	}
}

func TestParseUpdateAPKDownloadCommand(t *testing.T) {
	payload := []byte("apk")
	digest := sha256.Sum256(payload)
	line := updateAPKCommandPrefix + "request-1234|3|" + hex.EncodeToString(digest[:]) + "|" +
		base64.RawURLEncoding.EncodeToString([]byte("https://github.com/Ivan4537/WDTT-Plus/releases/download/v18/app.apk")) + "|" +
		base64.RawURLEncoding.EncodeToString([]byte(filepath.Join(t.TempDir(), "update.apk")))
	command, err := parseUpdateAPKDownloadCommand(line)
	if err != nil {
		t.Fatal(err)
	}
	if command.requestID != "request-1234" || command.size != 3 || command.sha256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected command: %#v", command)
	}
}

func TestParseUpdateAPKDownloadCommandRejectsUnsafePathAndDigest(t *testing.T) {
	encodedURL := base64.RawURLEncoding.EncodeToString([]byte("https://github.com/Ivan4537/WDTT-Plus/releases/download/v18/app.apk"))
	for _, line := range []string{
		updateAPKCommandPrefix + "request-1234|3|bad|" + encodedURL + "|" + base64.RawURLEncoding.EncodeToString([]byte("/tmp/update.apk")),
		updateAPKCommandPrefix + "request-1234|3|" + strings.Repeat("a", 64) + "|" + encodedURL + "|" + base64.RawURLEncoding.EncodeToString([]byte("relative.apk")),
	} {
		if _, err := parseUpdateAPKDownloadCommand(line); err == nil {
			t.Fatalf("accepted unsafe command %q", line)
		}
	}
}

func TestDownloadUpdateAPKReassemblesRelayedChunks(t *testing.T) {
	payload := []byte(strings.Repeat("relayed-apk", 3000))
	digest := sha256.Sum256(payload)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Dispatcher{
		ctx:                   ctx,
		updateMetadataWaiters: make(map[string]*updateMetadataAssembly),
	}
	worker := &WorkerSlot{SendCh: make(chan []byte, 128)}
	workers := []*WorkerSlot{worker}
	d.workers.Store(&workers)
	go func() {
		for {
			select {
			case packet := <-worker.SendCh:
				parts := strings.SplitN(string(packet), "|", 7)
				if len(parts) != 7 {
					continue
				}
				offset, _ := strconv.Atoi(parts[2])
				length, _ := strconv.Atoi(parts[3])
				requestID := parts[1]
				d.handleUpdateMetadataResponse([]byte(updateMetadataResponsePrefix + requestID + "|ACK|"))
				d.handleUpdateMetadataResponse([]byte(updateMetadataResponsePrefix + requestID + "|READY|"))
				for _, frame := range encodeTestUpdateFrames(requestID, payload[offset:offset+length]) {
					d.handleUpdateMetadataResponse(frame)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	outputPath := filepath.Join(t.TempDir(), "update.apk")
	command := updateAPKDownloadCommand{
		requestID:   "request-1234",
		size:        int64(len(payload)),
		sha256:      hex.EncodeToString(digest[:]),
		downloadURL: "https://github.com/Ivan4537/WDTT-Plus/releases/download/v18/app.apk",
		outputPath:  outputPath,
	}
	if err := d.downloadUpdateAPK(ctx, command); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(payload) {
		t.Fatal("relayed APK content changed")
	}
}

func TestRequestUpdateAPKChunkRetriesFailedPartOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Dispatcher{ctx: ctx, updateMetadataWaiters: make(map[string]*updateMetadataAssembly)}
	worker := &WorkerSlot{SendCh: make(chan []byte, 4)}
	workers := []*WorkerSlot{worker}
	d.workers.Store(&workers)
	payload := []byte("retried-part")
	go func() {
		for packet := range worker.SendCh {
			requestID := strings.SplitN(string(packet), "|", 3)[1]
			d.handleUpdateMetadataResponse([]byte(updateMetadataResponsePrefix + requestID + "|ACK|"))
			if strings.HasSuffix(requestID, "-0") {
				d.handleUpdateMetadataResponse([]byte(updateMetadataResponsePrefix + requestID + "|ERR|dHJhbnNpZW50"))
				continue
			}
			d.handleUpdateMetadataResponse([]byte(updateMetadataResponsePrefix + requestID + "|READY|"))
			for _, frame := range encodeTestUpdateFrames(requestID, payload) {
				d.handleUpdateMetadataResponse(frame)
			}
			return
		}
	}()
	command := updateAPKDownloadCommand{
		requestID:   "request-1234",
		size:        int64(len(payload)),
		sha256:      strings.Repeat("a", 64),
		downloadURL: "https://github.com/Ivan4537/WDTT-Plus/releases/download/v18/app.apk",
	}
	actual, err := d.requestUpdateAPKChunk(ctx, command, "encoded-url", 0, 0, len(payload))
	if err != nil || string(actual) != string(payload) {
		t.Fatalf("retried chunk = %q, %v", actual, err)
	}
}

func encodeTestUpdateFrames(requestID string, payload []byte) [][]byte {
	const chunkBytes = 700
	total := (len(payload) + chunkBytes - 1) / chunkBytes
	frames := make([][]byte, 0, total)
	for sequence, offset := 0, 0; offset < len(payload); sequence, offset = sequence+1, offset+chunkBytes {
		end := offset + chunkBytes
		if end > len(payload) {
			end = len(payload)
		}
		frames = append(frames, []byte(updateMetadataResponsePrefix+requestID+"|OK|"+
			strconv.Itoa(sequence)+"|"+strconv.Itoa(total)+"|"+
			base64.RawURLEncoding.EncodeToString(payload[offset:end])))
	}
	return frames
}
