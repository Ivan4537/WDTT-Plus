package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	updateMetadataCommandPrefix  = "UPDATE_METADATA|"
	updateMetadataRequestPrefix  = "WDTT_UPDATE1|"
	updateMetadataResponsePrefix = "WDTT_UPDATE1_RESULT|"
	updateMetadataResultPrefix   = "UPDATE_METADATA_RESULT|"
	updateAPKCommandPrefix       = "UPDATE_APK|"
	updateAPKChunkRequestPrefix  = "WDTT_UPDATE_APK1|"
	updateAPKChunkResponsePrefix = "WDTT_UPDATE_APK1_RESULT|"
	updateAPKProgressPrefix      = "UPDATE_APK_PROGRESS|"
	updateAPKResultPrefix        = "UPDATE_APK_RESULT|"
	updateMetadataMaxBytes       = 64 * 1024
	updateMetadataMaxChunks      = 128
	updateAPKMaxBytes            = 200 * 1024 * 1024
	updateAPKChunkBytes          = 16 * 1024
	updateAPKMaxParallelChunks   = 64
)

type updateMetadataResult struct {
	payload []byte
	err     error
}

type updateMetadataAssembly struct {
	total    int
	chunks   [][]byte
	received int
	ack      chan struct{}
	ready    chan struct{}
	result   chan updateMetadataResult
}

type updateAPKDownloadCommand struct {
	requestID   string
	size        int64
	sha256      string
	downloadURL string
	outputPath  string
}

func normalizeUpdateMetadataRequestID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 8 || len(value) > 64 {
		return ""
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return ""
	}
	return value
}

func (d *Dispatcher) requestUpdateMetadata(ctx context.Context, requestID string) ([]byte, error) {
	return d.requestUpdateRelay(ctx, requestID, []byte(updateMetadataRequestPrefix+requestID), false)
}

func (d *Dispatcher) requestUpdateRelay(
	ctx context.Context,
	requestID string,
	request []byte,
	waitForReady bool,
) ([]byte, error) {
	requestID = normalizeUpdateMetadataRequestID(requestID)
	if requestID == "" {
		return nil, errors.New("некорректный идентификатор запроса")
	}
	waiter := &updateMetadataAssembly{
		ack:    make(chan struct{}, 1),
		ready:  make(chan struct{}, 1),
		result: make(chan updateMetadataResult, 1),
	}
	d.updateMetadataMu.Lock()
	if d.updateMetadataWaiters == nil {
		d.updateMetadataWaiters = make(map[string]*updateMetadataAssembly)
	}
	if _, exists := d.updateMetadataWaiters[requestID]; exists {
		d.updateMetadataMu.Unlock()
		return nil, errors.New("запрос уже выполняется")
	}
	d.updateMetadataWaiters[requestID] = waiter
	d.updateMetadataMu.Unlock()
	defer func() {
		d.updateMetadataMu.Lock()
		delete(d.updateMetadataWaiters, requestID)
		d.updateMetadataMu.Unlock()
	}()

	workers := d.workers.Load()
	if workers == nil || len(*workers) == 0 {
		return nil, errors.New("рабочий канал WDTT ещё не готов")
	}
	if !d.enqueueUpdateRelayRequest(*workers, request) {
		return nil, errors.New("рабочие каналы WDTT заняты")
	}
	select {
	case <-waiter.ack:
	case <-time.After(1500 * time.Millisecond):
		return nil, errors.New("сервер WDTT ещё не поддерживает проверку через туннель")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.ctx.Done():
		return nil, errors.New("подключение WDTT остановлено")
	}
	if waitForReady {
		select {
		case <-waiter.ready:
		case result := <-waiter.result:
			return result.payload, result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.ctx.Done():
			return nil, errors.New("подключение WDTT остановлено")
		}
	}

	select {
	case result := <-waiter.result:
		return result.payload, result.err
	case <-time.After(func() time.Duration {
		if waitForReady {
			return 4 * time.Second
		}
		return time.Hour
	}()):
		return nil, errors.New("не все части ответа обновления получены")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.ctx.Done():
		return nil, errors.New("подключение WDTT остановлено")
	}
}

func (d *Dispatcher) enqueueUpdateRelayRequest(workers []*WorkerSlot, request []byte) bool {
	if len(workers) == 0 {
		return false
	}
	start := int(d.updateRelayNext.Add(1)-1) % len(workers)
	for offset := 0; offset < len(workers); offset++ {
		worker := workers[(start+offset)%len(workers)]
		if worker == nil || worker.SendCh == nil {
			continue
		}
		select {
		case worker.SendCh <- request:
			return true
		default:
		}
	}
	return false
}

func (d *Dispatcher) handleUpdateMetadataResponse(packet []byte) bool {
	value := string(packet)
	rawAPKChunk := strings.HasPrefix(value, updateAPKChunkResponsePrefix)
	encodedControlResponse := strings.HasPrefix(value, updateMetadataResponsePrefix) ||
		strings.HasPrefix(value, opaqueHTTPSResponsePrefix)
	if !rawAPKChunk && !encodedControlResponse {
		return false
	}
	parts := strings.SplitN(value, "|", 6)
	if len(parts) < 4 {
		return true
	}
	requestID := normalizeUpdateMetadataRequestID(parts[1])
	if requestID == "" {
		return true
	}

	d.updateMetadataMu.Lock()
	defer d.updateMetadataMu.Unlock()
	waiter := d.updateMetadataWaiters[requestID]
	if waiter == nil {
		return true
	}
	if parts[2] == "ACK" {
		select {
		case waiter.ack <- struct{}{}:
		default:
		}
		return true
	}
	if parts[2] == "READY" {
		select {
		case waiter.ready <- struct{}{}:
		default:
		}
		return true
	}
	if parts[2] == "ERR" {
		messageBytes, _ := base64.RawURLEncoding.DecodeString(parts[3])
		message := strings.TrimSpace(string(messageBytes))
		if message == "" {
			message = "сервер не выполнил служебный запрос"
		}
		select {
		case waiter.result <- updateMetadataResult{err: errors.New(message)}:
		default:
		}
		return true
	}
	if parts[2] != "OK" || len(parts) != 6 {
		return true
	}
	select {
	case waiter.ready <- struct{}{}:
	default:
	}
	sequence, sequenceErr := strconv.Atoi(parts[3])
	total, totalErr := strconv.Atoi(parts[4])
	if sequenceErr != nil || totalErr != nil || total < 1 || total > updateMetadataMaxChunks || sequence < 0 || sequence >= total {
		return true
	}
	var chunk []byte
	var decodeErr error
	if rawAPKChunk {
		chunk = []byte(parts[5])
	} else {
		chunk, decodeErr = base64.RawURLEncoding.DecodeString(parts[5])
	}
	if decodeErr != nil || len(chunk) == 0 || waiter.received+len(chunk) > updateMetadataMaxBytes {
		select {
		case waiter.result <- updateMetadataResult{err: errors.New("сервер вернул повреждённый служебный ответ")}:
		default:
		}
		return true
	}
	if waiter.total == 0 {
		waiter.total = total
		waiter.chunks = make([][]byte, total)
	}
	if waiter.total != total || waiter.chunks[sequence] != nil {
		return true
	}
	waiter.chunks[sequence] = chunk
	waiter.received += len(chunk)
	for _, item := range waiter.chunks {
		if item == nil {
			return true
		}
	}
	payload := make([]byte, 0, waiter.received)
	for _, item := range waiter.chunks {
		payload = append(payload, item...)
	}
	select {
	case waiter.result <- updateMetadataResult{payload: payload}:
	default:
	}
	return true
}

func parseUpdateAPKDownloadCommand(line string) (updateAPKDownloadCommand, error) {
	parts := strings.SplitN(strings.TrimPrefix(line, updateAPKCommandPrefix), "|", 5)
	if len(parts) != 5 {
		return updateAPKDownloadCommand{}, errors.New("некорректная команда загрузки APK")
	}
	requestID := normalizeUpdateMetadataRequestID(parts[0])
	size, sizeErr := strconv.ParseInt(parts[1], 10, 64)
	digest := strings.ToLower(parts[2])
	decodedURL, urlErr := base64.RawURLEncoding.DecodeString(parts[3])
	decodedPath, pathErr := base64.RawURLEncoding.DecodeString(parts[4])
	command := updateAPKDownloadCommand{
		requestID:   requestID,
		size:        size,
		sha256:      digest,
		downloadURL: string(decodedURL),
		outputPath:  string(decodedPath),
	}
	validDigest := len(digest) == 64
	if validDigest {
		_, decodeErr := hex.DecodeString(digest)
		validDigest = decodeErr == nil
	}
	cleanPath := filepath.Clean(command.outputPath)
	if requestID == "" || sizeErr != nil || size < 1 || size > updateAPKMaxBytes || !validDigest ||
		urlErr != nil || pathErr != nil || len(command.downloadURL) > 2048 || len(command.outputPath) > 1024 ||
		!filepath.IsAbs(cleanPath) || !strings.EqualFold(filepath.Ext(cleanPath), ".apk") {
		return updateAPKDownloadCommand{}, errors.New("некорректные параметры загрузки APK")
	}
	command.outputPath = cleanPath
	return command, nil
}

func (d *Dispatcher) downloadUpdateAPK(ctx context.Context, command updateAPKDownloadCommand) error {
	if info, err := os.Lstat(command.outputPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("путь APK не должен быть символической ссылкой")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(command.outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(command.outputPath)
		}
	}()

	encodedURL := base64.RawURLEncoding.EncodeToString([]byte(command.downloadURL))
	progressBytes := int64(0)
	lastReportedBytes := int64(0)
	chunkCount := int((command.size + updateAPKChunkBytes - 1) / updateAPKChunkBytes)
	workerCount := 0
	if workers := d.workers.Load(); workers != nil {
		workerCount = len(*workers)
	}
	parallelChunks := updateAPKParallelChunkLimit(workerCount)
	downloadCtx, cancelDownload := context.WithCancel(ctx)
	defer cancelDownload()
	results := make(chan updateAPKChunkResult, parallelChunks)
	nextChunk := 0
	inFlight := 0
	launchChunk := func(chunkIndex int) {
		offset := int64(chunkIndex * updateAPKChunkBytes)
		length := updateAPKChunkBytes
		if remaining := command.size - offset; remaining < int64(length) {
			length = int(remaining)
		}
		inFlight++
		go func() {
			payload, requestErr := d.requestUpdateAPKChunk(
				downloadCtx,
				command,
				encodedURL,
				chunkIndex,
				offset,
				length,
			)
			results <- updateAPKChunkResult{offset: offset, payload: payload, err: requestErr}
		}()
	}
	for nextChunk < chunkCount && inFlight < parallelChunks {
		launchChunk(nextChunk)
		nextChunk++
	}
	for inFlight > 0 {
		result := <-results
		inFlight--
		if result.err != nil {
			return result.err
		}
		if _, err := file.WriteAt(result.payload, result.offset); err != nil {
			return err
		}
		progressBytes += int64(len(result.payload))
		if progressBytes-lastReportedBytes >= 256*1024 || progressBytes == command.size {
			lastReportedBytes = progressBytes
			fmt.Printf("%s%s|%d|%d\n", updateAPKProgressPrefix, command.requestID, progressBytes, command.size)
		}
		if nextChunk < chunkCount {
			launchChunk(nextChunk)
			nextChunk++
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	digest, err := sha256File(command.outputPath)
	if err != nil {
		return err
	}
	if digest != command.sha256 {
		return errors.New("SHA-256 APK не совпал после передачи через WDTT")
	}
	succeeded = true
	return nil
}

func updateAPKParallelChunkLimit(workerCount int) int {
	if workerCount < 1 {
		return 1
	}
	parallel := workerCount * 2
	if parallel > updateAPKMaxParallelChunks {
		return updateAPKMaxParallelChunks
	}
	return parallel
}

type updateAPKChunkResult struct {
	offset  int64
	payload []byte
	err     error
}

func (d *Dispatcher) requestUpdateAPKChunk(
	ctx context.Context,
	command updateAPKDownloadCommand,
	encodedURL string,
	chunkIndex int,
	offset int64,
	length int,
) ([]byte, error) {
	var payload []byte
	var requestErr error
	for attempt := 0; attempt < 4; attempt++ {
		chunkRequestID := fmt.Sprintf("%s-%d-%d", command.requestID, chunkIndex, attempt)
		packet := []byte(fmt.Sprintf(
			"%s%s|%d|%d|%d|%s|%s",
			updateAPKChunkRequestPrefix,
			chunkRequestID,
			offset,
			length,
			command.size,
			command.sha256,
			encodedURL,
		))
		requestTimeout := 25 * time.Second
		if offset < int64(updateAPKMaxParallelChunks*updateAPKChunkBytes) {
			requestTimeout = 3 * time.Minute
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, requestTimeout)
		payload, requestErr = d.requestUpdateRelay(requestCtx, chunkRequestID, packet, true)
		requestCancel()
		if requestErr == nil && len(payload) == length {
			return payload, nil
		}
		if requestErr == nil {
			requestErr = errors.New("сервер вернул неполную часть APK")
		}
		select {
		case <-time.After(time.Duration(attempt+1) * 250 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, requestErr
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func printUpdateAPKResult(requestID string, requestErr error) {
	status := "OK"
	payload := ""
	if requestErr != nil {
		status = "ERR"
		message := requestErr.Error()
		if len(message) > 240 {
			message = message[:240]
		}
		payload = base64.RawURLEncoding.EncodeToString([]byte(message))
	}
	fmt.Printf("%s%s|%s|%s\n", updateAPKResultPrefix, requestID, status, payload)
}

func printUpdateMetadataResult(requestID string, payload []byte, requestErr error) {
	if requestErr != nil {
		message := requestErr.Error()
		if len(message) > 240 {
			message = message[:240]
		}
		fmt.Printf(
			"%s%s|ERR|%s\n",
			updateMetadataResultPrefix,
			requestID,
			base64.RawURLEncoding.EncodeToString([]byte(message)),
		)
		return
	}
	fmt.Printf(
		"%s%s|OK|%s\n",
		updateMetadataResultPrefix,
		requestID,
		base64.RawURLEncoding.EncodeToString(payload),
	)
}
