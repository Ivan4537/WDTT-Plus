package main

import (
	"errors"
	"testing"
	"time"
)

func TestTerminalGroupCredentialErrors(t *testing.T) {
	for _, message := range []string{"INVALID_JOIN_LINK", "ANON_BLOCKED", "CALL_FULL", "FATAL_AUTH"} {
		if !isTerminalGroupCredentialError(errors.New(message)) {
			t.Fatalf("%q must be terminal", message)
		}
	}
	if isTerminalGroupCredentialError(errors.New("CAPTCHA_WAIT_REQUIRED")) {
		t.Fatal("captcha wait must remain recoverable for an additional group")
	}
}

func TestCaptchaCredentialRetryDelay(t *testing.T) {
	if got := groupCredentialRetryDelay(errors.New("CAPTCHA_WAIT_REQUIRED")); got != 90*time.Second {
		t.Fatalf("captcha retry delay = %v", got)
	}
}

func TestWebViewTimeoutOrdering(t *testing.T) {
	if captchaAutoWebViewTimeout <= 18*time.Second {
		t.Fatalf("Go auto timeout %v must exceed Android WebView timeout", captchaAutoWebViewTimeout)
	}
	if captchaManualWebViewTimeout <= 180*time.Second {
		t.Fatalf("Go manual timeout %v must exceed Android WebView timeout", captchaManualWebViewTimeout)
	}
	if captchaSelectedWebViewTimeout <= 270*time.Second {
		t.Fatalf("selected timeout %v must cover two auto attempts plus manual fallback", captchaSelectedWebViewTimeout)
	}
}
