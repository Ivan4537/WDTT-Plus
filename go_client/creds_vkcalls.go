package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	neturl "net/url"
	"strings"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

const (
	vkCallsClientID   = "8093730"
	vkCallsAPIVersion = "5.276"
	vkCallsUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	vkCallsFloodPause = 60 * time.Second
)

var (
	errVKCallsFlood   = errors.New("VKCalls participant check flood")
	vkCallsFloodUntil atomic.Int64
)

func isVKCallsFloodError(err error) bool {
	return errors.Is(err, errVKCallsFlood)
}

func startVKCallsFloodPause(now time.Time) {
	vkCallsFloodUntil.Store(now.Add(vkCallsFloodPause).UnixNano())
}

func vkCallsFloodPauseRemaining(now time.Time) time.Duration {
	remaining := time.Unix(0, vkCallsFloodUntil.Load()).Sub(now)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

func stableVKCallsUUID(scope string) string {
	seed := getVKCallsDeviceID() + ":" + scope
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed)).String()
}

func getVKCredsViaVKCalls(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	deviceID := stableVKCallsUUID("vk")
	okDeviceID := stableVKCallsUUID("ok")
	name := generateName()
	joinURL := neturl.QueryEscape("https://vk.com/call/join/" + link)

	client, err := tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(profiles.Chrome_146),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	)
	if err != nil {
		return "", "", nil, fmt.Errorf("setup: %w", err)
	}

	doRequest := func(step, requestURL string) (map[string]interface{}, error) {
		req, err := fhttp.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewReader(nil))
		if err != nil {
			return nil, fmt.Errorf("%s create request: %w", step, err)
		}
		req.Header.Set("User-Agent", vkCallsUserAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s request: %w", step, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("%s read response: %w", step, err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("%s decode status=%d: %w", step, resp.StatusCode, err)
		}
		return result, nil
	}

	step1URL := fmt.Sprintf(
		"https://api.vk.me/method/auth.getAnonymToken?v=%s&client_id=%s&link=%s&device_id=%s&anonymName=%s&lang=ru",
		vkCallsAPIVersion, vkCallsClientID, joinURL, deviceID, neturl.QueryEscape(name),
	)
	step1, err := doRequest("auth.getAnonymToken", step1URL)
	if err != nil {
		return "", "", nil, err
	}
	anonymToken, err := extractVKCallsString(step1, "response", "token")
	if err != nil {
		return "", "", nil, fmt.Errorf("auth.getAnonymToken: %w", err)
	}

	step2URL := fmt.Sprintf(
		"https://api.vk.me/method/messages.getCallPreview?v=%s&anonymous_token=%s&device_id=%s&extended=1&fields=first_name,last_name,photo_200&lang=ru&link=%s",
		vkCallsAPIVersion, neturl.QueryEscape(anonymToken), deviceID, joinURL,
	)
	step2, err := doRequest("messages.getCallPreview", step2URL)
	if err != nil {
		return "", "", nil, err
	}
	if err := parseVKCallsAPIError(step2); err != nil {
		return "", "", nil, fmt.Errorf("messages.getCallPreview: %w", err)
	}
	userID, err := extractVKCallsNumber(step2, "response", "user_id")
	if err != nil {
		return "", "", nil, fmt.Errorf("messages.getCallPreview user_id: %w", err)
	}
	secret, err := extractVKCallsString(step2, "response", "secret")
	if err != nil {
		return "", "", nil, fmt.Errorf("messages.getCallPreview secret: %w", err)
	}

	step3URL := fmt.Sprintf(
		"https://api.vk.me/method/messages.getAnonymCallToken?v=%s&anonymous_token=%s&device_id=%s&link=%s&name=%s&user_id=%.0f&secret=%s&lang=ru",
		vkCallsAPIVersion, neturl.QueryEscape(anonymToken), deviceID, joinURL,
		neturl.QueryEscape(name), userID, neturl.QueryEscape(secret),
	)
	step3, err := doRequest("messages.getAnonymCallToken", step3URL)
	if err != nil {
		return "", "", nil, err
	}
	if err := parseVKCallsAPIError(step3); err != nil {
		return "", "", nil, fmt.Errorf("messages.getAnonymCallToken: %w", err)
	}
	okAnonymToken, err := extractVKCallsString(step3, "response", "token")
	if err != nil {
		return "", "", nil, fmt.Errorf("messages.getAnonymCallToken token: %w", err)
	}

	sessionData := neturl.QueryEscape(fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":"1.0.1"}`, okDeviceID))
	step4URL := "https://calls.okcdn.ru/fb.do?session_data=" + sessionData +
		"&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA"
	step4, err := doRequest("auth.anonymLogin", step4URL)
	if err != nil {
		return "", "", nil, err
	}
	sessionKey, err := extractVKCallsString(step4, "session_key")
	if err != nil {
		return "", "", nil, fmt.Errorf("auth.anonymLogin session_key: %w", err)
	}

	step5URL := fmt.Sprintf(
		"https://calls.okcdn.ru/fb.do?joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s",
		neturl.QueryEscape(link), neturl.QueryEscape(okAnonymToken), neturl.QueryEscape(sessionKey),
	)
	step5, err := doRequest("vchat.joinConversationByLink", step5URL)
	if err != nil {
		return "", "", nil, err
	}
	if err := parseVKCallsOKError(step5); err != nil {
		return "", "", nil, fmt.Errorf("vchat.joinConversationByLink: %w", err)
	}
	user, err := extractVKCallsString(step5, "turn_server", "username")
	if err != nil {
		return "", "", nil, err
	}
	pass, err := extractVKCallsString(step5, "turn_server", "credential")
	if err != nil {
		return "", "", nil, err
	}
	addrs := parseVKCallsTURNAddresses(step5)
	if len(addrs) == 0 {
		return "", "", nil, fmt.Errorf("turn_server.urls empty")
	}
	log.Printf("[STREAM %d] [VKCalls] TURN credentials получены, адресов=%d", streamID, len(addrs))
	return user, pass, addrs, nil
}

func extractVKCallsString(resp map[string]interface{}, keys ...string) (string, error) {
	var value interface{} = resp
	for _, key := range keys {
		object, ok := value.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("%s: expected object, got %T", key, value)
		}
		value = object[key]
	}
	result, ok := value.(string)
	if !ok || result == "" {
		return "", fmt.Errorf("%s: expected non-empty string, got %T", strings.Join(keys, "."), value)
	}
	return result, nil
}

func extractVKCallsNumber(resp map[string]interface{}, keys ...string) (float64, error) {
	var value interface{} = resp
	for _, key := range keys {
		object, ok := value.(map[string]interface{})
		if !ok {
			return 0, fmt.Errorf("%s: expected object, got %T", key, value)
		}
		value = object[key]
	}
	result, ok := value.(float64)
	if !ok {
		return 0, fmt.Errorf("%s: expected number, got %T", strings.Join(keys, "."), value)
	}
	return result, nil
}

func parseVKCallsTURNAddresses(resp map[string]interface{}) []string {
	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return nil
	}
	urls, ok := turnServer["urls"].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(urls))
	for _, raw := range urls {
		value, ok := raw.(string)
		if !ok {
			continue
		}
		value = strings.Split(value, "?")[0]
		value = strings.TrimPrefix(strings.TrimPrefix(value, "turn:"), "turns:")
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func parseVKCallsAPIError(resp map[string]interface{}) error {
	errObject, ok := resp["error"].(map[string]interface{})
	if !ok {
		return nil
	}
	code, _ := errObject["error_code"].(float64)
	message, _ := errObject["error_msg"].(string)
	if int(code) == 14 {
		return parseVkCaptchaError(errObject)
	}
	if code != 0 || message != "" {
		return fmt.Errorf("VK API error %.0f: %s", code, message)
	}
	return nil
}

func parseVKCallsOKError(resp map[string]interface{}) error {
	code, _ := resp["error_code"].(float64)
	if code == 0 {
		return nil
	}
	message, _ := resp["error_msg"].(string)
	if strings.Contains(strings.ToLower(message), "participant.check.flood") {
		return fmt.Errorf("%w: %s", errVKCallsFlood, message)
	}
	return fmt.Errorf("OK API error %.0f: %s", code, message)
}
