package main

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestStableVKCallsUUID(t *testing.T) {
	setVKCallsPreflight(true, "device-a")
	first := stableVKCallsUUID("vk")
	second := stableVKCallsUUID("vk")
	otherScope := stableVKCallsUUID("ok")
	if first != second {
		t.Fatalf("stable ID changed: %q != %q", first, second)
	}
	if first == otherScope {
		t.Fatal("VK and OK scopes must use different IDs")
	}
}

func TestParseVKCallsTURNAddresses(t *testing.T) {
	resp := map[string]interface{}{
		"turn_server": map[string]interface{}{
			"urls": []interface{}{
				"turn:1.2.3.4:3478?transport=udp",
				"turns:turn.example:443?transport=tcp",
				42,
			},
		},
	}
	want := []string{"1.2.3.4:3478", "turn.example:443"}
	if got := parseVKCallsTURNAddresses(resp); !reflect.DeepEqual(got, want) {
		t.Fatalf("addresses = %#v, want %#v", got, want)
	}
}

func TestParseVKCallsCaptchaError(t *testing.T) {
	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"error_code":   float64(14),
			"error_msg":    "Captcha needed",
			"redirect_uri": "https://id.vk.com/captcha?session_token=test",
		},
	}
	err := parseVKCallsAPIError(resp)
	var captchaErr *VkCaptchaError
	if !errors.As(err, &captchaErr) {
		t.Fatalf("expected VkCaptchaError, got %T: %v", err, err)
	}
	if captchaErr.RedirectURI == "" {
		t.Fatal("redirect_uri was not preserved")
	}
}

func TestParseVKCallsFloodError(t *testing.T) {
	err := parseVKCallsOKError(map[string]interface{}{
		"error_code": float64(4),
		"error_msg":  "REQUEST : error.webrtc.participant.check.flood",
	})
	if !isVKCallsFloodError(err) {
		t.Fatalf("expected VKCalls flood error, got %v", err)
	}
}

func TestVKCallsFloodPause(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	startVKCallsFloodPause(now)
	if got := vkCallsFloodPauseRemaining(now.Add(10 * time.Second)); got != 50*time.Second {
		t.Fatalf("pause remaining = %v, want 50s", got)
	}
	if got := vkCallsFloodPauseRemaining(now.Add(vkCallsFloodPause)); got != 0 {
		t.Fatalf("expired pause remaining = %v, want 0", got)
	}
	vkCallsFloodUntil.Store(0)
}

func TestExtractVKCallsValues(t *testing.T) {
	resp := map[string]interface{}{
		"response": map[string]interface{}{
			"token":   "token-value",
			"user_id": float64(123),
		},
	}
	if got, err := extractVKCallsString(resp, "response", "token"); err != nil || got != "token-value" {
		t.Fatalf("token = %q, err=%v", got, err)
	}
	if got, err := extractVKCallsNumber(resp, "response", "user_id"); err != nil || got != 123 {
		t.Fatalf("user_id = %v, err=%v", got, err)
	}
}

func TestNormalizeBooleanFlagArgs(t *testing.T) {
	args := []string{"client", "-peer", "host:1", "-vkcalls-preflight", "false", "-password", "secret"}
	want := []string{"client", "-peer", "host:1", "-vkcalls-preflight=false", "-password", "secret"}
	if got := normalizeBooleanFlagArgs(args, "-vkcalls-preflight"); !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestCaptchaResultRequestCorrelation(t *testing.T) {
	result := parseCaptchaResultPayload("200-7|success-token")
	if result.RequestID != "200-7" || result.Value != "success-token" {
		t.Fatalf("unexpected parsed result: %#v", result)
	}
	if !captchaResultMatchesRequest(result, "200-7") {
		t.Fatal("matching request ID was rejected")
	}
	if captchaResultMatchesRequest(result, "200-8") {
		t.Fatal("stale result matched a new request")
	}
	if !captchaResultMatchesRequest(parseCaptchaResultPayload("legacy-token"), "200-8") {
		t.Fatal("legacy result compatibility was lost")
	}
}

func TestCaptchaResultRoutesToMatchingWaiter(t *testing.T) {
	resetCaptchaResultRoutingForTest()

	firstCh, firstCleanup := registerCaptchaResultWaiter("100-1")
	defer firstCleanup()
	secondCh, secondCleanup := registerCaptchaResultWaiter("200-1")
	defer secondCleanup()

	enqueueCaptchaResult(CaptchaResult{RequestID: "200-1", Value: "second-token"})

	select {
	case got := <-secondCh:
		if got.Value != "second-token" {
			t.Fatalf("second waiter got %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("second waiter did not receive its result")
	}

	select {
	case got := <-firstCh:
		t.Fatalf("first waiter received another request result: %#v", got)
	default:
	}
}

func TestLateIdentifiedCaptchaResultDoesNotPoisonLegacyQueue(t *testing.T) {
	resetCaptchaResultRoutingForTest()

	enqueueCaptchaResult(CaptchaResult{RequestID: "missing", Value: "late-token"})

	select {
	case got := <-CaptchaResultChan:
		t.Fatalf("late identified result leaked into legacy queue: %#v", got)
	default:
	}
}

func resetCaptchaResultRoutingForTest() {
	for {
		select {
		case <-CaptchaResultChan:
		default:
			captchaResultWaiters.Lock()
			captchaResultWaiters.byRequestID = make(map[string]chan CaptchaResult)
			captchaResultWaiters.Unlock()
			return
		}
	}
}
