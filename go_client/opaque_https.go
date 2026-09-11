package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	opaqueHTTPSCommandPrefix   = "OPAQUE_HTTPS_POST|"
	opaqueHTTPSResultPrefix    = "OPAQUE_HTTPS_RESULT|"
	opaqueHTTPSRequestPrefix   = "WDTT_HTTPS_POST1|"
	opaqueHTTPSResponsePrefix  = "WDTT_HTTPS_POST1_RESULT|"
	opaqueHTTPSMaxPayloadBytes = 768
	opaqueHTTPSMaxPacketBytes  = 1400
)

type opaqueHTTPSCommand struct {
	requestID string
	url       string
	payload   []byte
}

func parseOpaqueHTTPSCommand(line string) (opaqueHTTPSCommand, error) {
	parts := strings.SplitN(strings.TrimPrefix(line, opaqueHTTPSCommandPrefix), "|", 3)
	if len(parts) != 3 {
		return opaqueHTTPSCommand{}, errors.New("некорректная команда HTTPS-запроса")
	}
	requestID := normalizeUpdateMetadataRequestID(parts[0])
	decodedURL, urlErr := base64.RawURLEncoding.DecodeString(parts[1])
	payload, payloadErr := base64.RawURLEncoding.DecodeString(parts[2])
	command := opaqueHTTPSCommand{
		requestID: requestID,
		url:       strings.TrimSpace(string(decodedURL)),
		payload:   payload,
	}
	if requestID == "" || urlErr != nil || payloadErr != nil ||
		len(command.url) < 12 || len(command.url) > 2048 ||
		len(payload) == 0 || len(payload) > opaqueHTTPSMaxPayloadBytes {
		return opaqueHTTPSCommand{}, errors.New("некорректные параметры HTTPS-запроса")
	}
	return command, nil
}

func (d *Dispatcher) requestOpaqueHTTPS(ctx context.Context, command opaqueHTTPSCommand) ([]byte, error) {
	encodedURL := base64.RawURLEncoding.EncodeToString([]byte(command.url))
	encodedPayload := base64.RawURLEncoding.EncodeToString(command.payload)
	request := []byte(fmt.Sprintf(
		"%s%s|%s|%s",
		opaqueHTTPSRequestPrefix,
		command.requestID,
		encodedURL,
		encodedPayload,
	))
	if len(request) > opaqueHTTPSMaxPacketBytes {
		return nil, errors.New("HTTPS-запрос слишком большой")
	}
	return d.requestUpdateRelay(ctx, command.requestID, request, false)
}

func printOpaqueHTTPSResult(requestID string, payload []byte, requestErr error) {
	if requestErr != nil {
		message := requestErr.Error()
		if len(message) > 240 {
			message = message[:240]
		}
		fmt.Printf(
			"%s%s|ERR|%s\n",
			opaqueHTTPSResultPrefix,
			requestID,
			base64.RawURLEncoding.EncodeToString([]byte(message)),
		)
		return
	}
	fmt.Printf(
		"%s%s|OK|%s\n",
		opaqueHTTPSResultPrefix,
		requestID,
		base64.RawURLEncoding.EncodeToString(payload),
	)
}
