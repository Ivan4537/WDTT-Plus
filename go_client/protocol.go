package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type workerPolicyLimitError struct {
	maxWorkers int
}

func (e *workerPolicyLimitError) Error() string {
	return fmt.Sprintf("WORKER_POLICY_LIMIT:%d", e.maxWorkers)
}

func workerPolicyLimit(err error) (int, bool) {
	var policyError *workerPolicyLimitError
	if !errors.As(err, &policyError) {
		return 0, false
	}
	return policyError.maxWorkers, true
}

func shouldRetryWorkerPolicy(maxWorkers, requestedWorkers int) bool {
	return requestedWorkers > 0 && maxWorkers >= requestedWorkers
}

func parseConfigResponse(resp string) (string, error) {
	if resp == "NOCONF" {
		return "", nil
	}

	if strings.HasPrefix(resp, "POLICY:max_workers=") {
		value := strings.TrimSpace(strings.TrimPrefix(resp, "POLICY:max_workers="))
		maxWorkers, err := strconv.Atoi(value)
		if err != nil || maxWorkers < 1 || maxWorkers > 128 {
			return "", fmt.Errorf("некорректная политика мощности сервера")
		}
		return "", &workerPolicyLimitError{maxWorkers: maxWorkers}
	}

	if strings.HasPrefix(resp, "DENIED:") {
		reason := strings.TrimPrefix(resp, "DENIED:")
		switch reason {
		case "wrong_password":
			return "", fmt.Errorf("FATAL_AUTH: неверный пароль подключения")
		case "expired":
			return "", fmt.Errorf("FATAL_AUTH: срок действия пароля истёк")
		case "device_mismatch":
			return "", fmt.Errorf("FATAL_AUTH: пароль привязан к другому устройству")
		default:
			return "", fmt.Errorf("FATAL_AUTH: доступ запрещён (%s)", reason)
		}
	}
	return resp, nil
}

// RequestConfig запрашивает WireGuard конфиг через DTLS-соединение.
func RequestConfig(
	ctx context.Context,
	conn net.Conn,
	localPort, deviceID, password, deviceInfo, transportSession string,
) (string, error) {
	payload := fmt.Sprintf("GETCONF:%s|%s|%s", localPort, deviceID, password)
	safeDeviceInfo := strings.ReplaceAll(strings.TrimSpace(deviceInfo), "|", " ")
	safeTransportSession := normalizeTransportSession(transportSession)
	if safeDeviceInfo != "" || safeTransportSession != "" {
		payload += "|" + safeDeviceInfo
	}
	if safeTransportSession != "" {
		payload += "|" + safeTransportSession
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", fmt.Errorf("отправка GETCONF: %w", err)
	}

	b := make([]byte, 4096)
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", fmt.Errorf("установка дедлайна: %w", err)
	}
	stopRead := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now())
	})
	defer stopRead()
	n, err := conn.Read(b)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", fmt.Errorf("чтение ответа конфига: %w", err)
	}

	return parseConfigResponse(string(b[:n]))
}
