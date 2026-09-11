package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	deploySafeCommandPrefix      = "DEPLOY_SAFE|"
	deploySafeResultPrefix       = "DEPLOY_SAFE_RESULT|"
	deploySafeRequestPrefix      = "WDTT_DEPLOY1|"
	deploySafeChunkRequestPrefix = "WDTT_DEPLOY_CHUNK1|"
	deploySafeResponseMaxBytes   = 12 * 1024 * 1024
	deploySafeChunkBytes         = 16 * 1024
	deploySafeMaxParallelChunks  = 12
)

type deploySafeCommand struct {
	requestID string
	digest    string
	payload   []byte
	output    string
}

type deploySafeMetadata struct {
	size   int
	digest string
}

func parseDeploySafeCommand(line string) (deploySafeCommand, error) {
	parts := strings.SplitN(strings.TrimPrefix(line, deploySafeCommandPrefix), "|", 4)
	if len(parts) != 4 {
		return deploySafeCommand{}, errors.New("некорректная команда безопасной операции")
	}
	requestID := normalizeUpdateMetadataRequestID(parts[0])
	digest := strings.ToLower(parts[1])
	payload, payloadErr := base64.RawURLEncoding.DecodeString(parts[2])
	outputBytes, outputErr := base64.RawURLEncoding.DecodeString(parts[3])
	if requestID == "" || payloadErr != nil || outputErr != nil || len(payload) == 0 || len(payload) > 64*1024 || !validDeploySafeDigest(digest) {
		return deploySafeCommand{}, errors.New("некорректные параметры безопасной операции")
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != digest {
		return deploySafeCommand{}, errors.New("контрольная сумма безопасного запроса не совпала")
	}
	output := strings.TrimSpace(string(outputBytes))
	if output == "" || len(output) > 4096 {
		return deploySafeCommand{}, errors.New("некорректный путь результата безопасной операции")
	}
	return deploySafeCommand{requestID: requestID, digest: digest, payload: payload, output: output}, nil
}

func validDeploySafeDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func parseDeploySafeMetadata(payload []byte) (deploySafeMetadata, error) {
	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 {
		return deploySafeMetadata{}, errors.New("сервер вернул некорректное описание результата")
	}
	size, sizeErr := strconv.Atoi(parts[0])
	digest := strings.ToLower(parts[1])
	if sizeErr != nil || size < 1 || size > deploySafeResponseMaxBytes || !validDeploySafeDigest(digest) {
		return deploySafeMetadata{}, errors.New("сервер вернул недопустимый размер результата")
	}
	return deploySafeMetadata{size: size, digest: digest}, nil
}

func (d *Dispatcher) executeDeploySafe(ctx context.Context, command deploySafeCommand) error {
	downloadCtx, cancelDownload := context.WithCancel(ctx)
	defer cancelDownload()
	encodedRequest := base64.RawURLEncoding.EncodeToString(command.payload)
	metadataPayload, err := d.requestUpdateRelay(
		ctx,
		command.requestID,
		[]byte(deploySafeRequestPrefix+command.requestID+"|"+command.digest+"|"+encodedRequest),
		false,
	)
	if err != nil {
		if strings.Contains(err.Error(), "не поддерживает проверку через туннель") {
			return errors.New("сервер WDTT ещё не поддерживает безопасные операции через туннель")
		}
		return err
	}
	metadata, err := parseDeploySafeMetadata(metadataPayload)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(command.output); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("путь результата не должен быть символической ссылкой")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	file, err := os.OpenFile(command.output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(command.output)
		}
	}()

	chunkCount := (metadata.size + deploySafeChunkBytes - 1) / deploySafeChunkBytes
	parallel := deploySafeMaxParallelChunks
	if workers := d.workers.Load(); workers == nil || len(*workers) < parallel {
		if workers == nil || len(*workers) < 1 {
			parallel = 1
		} else {
			parallel = len(*workers)
		}
	}
	type chunkResult struct {
		offset  int
		payload []byte
		err     error
	}
	results := make(chan chunkResult, parallel)
	nextChunk := 0
	inFlight := 0
	launch := func(index int) {
		offset := index * deploySafeChunkBytes
		length := deploySafeChunkBytes
		if remaining := metadata.size - offset; remaining < length {
			length = remaining
		}
		inFlight++
		go func() {
			payload, requestErr := d.requestDeploySafeChunk(downloadCtx, command.requestID, metadata, index, offset, length)
			results <- chunkResult{offset: offset, payload: payload, err: requestErr}
		}()
	}
	for nextChunk < chunkCount && inFlight < parallel {
		launch(nextChunk)
		nextChunk++
	}
	for inFlight > 0 {
		result := <-results
		inFlight--
		if result.err != nil {
			cancelDownload()
			return result.err
		}
		if _, err := file.WriteAt(result.payload, int64(result.offset)); err != nil {
			return err
		}
		if nextChunk < chunkCount {
			launch(nextChunk)
			nextChunk++
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	digest, err := sha256File(command.output)
	if err != nil {
		return err
	}
	if digest != metadata.digest {
		return errors.New("контрольная сумма результата безопасной операции не совпала")
	}
	succeeded = true
	return nil
}

func (d *Dispatcher) requestDeploySafeChunk(
	ctx context.Context,
	baseID string,
	metadata deploySafeMetadata,
	chunkIndex int,
	offset int,
	length int,
) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		requestID := fmt.Sprintf("%s-%d-%d", baseID, chunkIndex, attempt)
		packet := []byte(fmt.Sprintf(
			"%s%s|%s|%d|%d|%s",
			deploySafeChunkRequestPrefix,
			requestID,
			baseID,
			offset,
			length,
			metadata.digest,
		))
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		payload, requestErr := d.requestUpdateRelay(requestCtx, requestID, packet, true)
		cancel()
		if requestErr == nil && len(payload) == length {
			return payload, nil
		}
		if requestErr == nil {
			requestErr = errors.New("сервер вернул неполную часть результата")
		}
		lastErr = requestErr
		select {
		case <-time.After(time.Duration(attempt+1) * 200 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func printDeploySafeResult(requestID string, err error) {
	if err == nil {
		fmt.Printf("%s%s|OK|\n", deploySafeResultPrefix, requestID)
		return
	}
	message := err.Error()
	if len(message) > 400 {
		message = message[:400]
	}
	fmt.Printf(
		"%s%s|ERR|%s\n",
		deploySafeResultPrefix,
		requestID,
		base64.RawURLEncoding.EncodeToString([]byte(message)),
	)
}
