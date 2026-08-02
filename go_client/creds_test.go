package main

import (
	"errors"
	"testing"
)

func TestClassifyTerminalVKJoinError(t *testing.T) {
	tests := []struct {
		name string
		err  map[string]interface{}
		want string
	}{
		{
			name: "invalid link code",
			err: map[string]interface{}{
				"error_code": float64(9008),
				"error_msg":  "Join link is not valid",
			},
			want: "INVALID_JOIN_LINK",
		},
		{
			name: "anonymous blocked text",
			err: map[string]interface{}{
				"error_code": float64(1),
				"error_msg":  "anonymous join is disabled",
			},
			want: "ANON_BLOCKED",
		},
		{
			name: "call full text",
			err: map[string]interface{}{
				"error_code": float64(1),
				"error_msg":  "call is full",
			},
			want: "CALL_FULL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTerminalVKJoinError(tt.err)
			if got == nil || got.Error() != tt.want {
				t.Fatalf("got %v, want %s", got, tt.want)
			}
		})
	}
}

func TestClassifyTerminalVKJoinErrorIgnoresTransient(t *testing.T) {
	got := classifyTerminalVKJoinError(map[string]interface{}{
		"error_code": float64(14),
		"error_msg":  "Captcha needed",
	})
	if got != nil {
		t.Fatalf("unexpected terminal error: %v", got)
	}
}

func TestClassifyHashCheckErrorKeepsTerminalAndTransientStatusesSeparate(t *testing.T) {
	tests := []struct {
		errText string
		status  string
	}{
		{errText: "INVALID_JOIN_LINK: VK API error_code:9008", status: "dead"},
		{errText: "ANON_BLOCKED: anonymous join is disabled", status: "blocked"},
		{errText: "CALL_FULL: call is full", status: "full"},
		{errText: "vchat.joinConversationByLink: participant.check.flood", status: "limited"},
		{errText: "vchat.joinConversationByLink: VK HTTPS api.vk.me: timeout", status: "network"},
		{errText: "vchat.joinConversationByLink: unexpected response", status: "error"},
	}

	for _, test := range tests {
		t.Run(test.status+"_"+test.errText[:4], func(t *testing.T) {
			status, _ := classifyHashCheckError(errors.New(test.errText))
			if status != test.status {
				t.Fatalf("status = %q, want %q", status, test.status)
			}
		})
	}
}

func TestAuthErrorsFromSupersededCredentialsDoNotInvalidateFreshCache(t *testing.T) {
	const streamID = 9876540
	cacheID := getCacheID(streamID)
	credentialsStore.mu.Lock()
	delete(credentialsStore.caches, cacheID)
	credentialsStore.mu.Unlock()
	t.Cleanup(func() {
		credentialsStore.mu.Lock()
		delete(credentialsStore.caches, cacheID)
		credentialsStore.mu.Unlock()
	})

	cache := getStreamCache(streamID)
	cache.mutex.Lock()
	cache.creds = TurnCredentials{
		Username:    "fresh-user",
		Password:    "fresh-pass",
		ServerAddrs: []string{"turn:fresh.example:3478"},
		Link:        "fresh-link",
	}
	cache.mutex.Unlock()

	for attempt := 0; attempt < maxCacheErrors+2; attempt++ {
		if handleAuthError(streamID, "stale-user", "stale-pass") {
			t.Fatal("superseded credentials invalidated the fresh cache")
		}
	}
	if got := cache.errorCount.Load(); got != 0 {
		t.Fatalf("superseded errors were counted: %d", got)
	}

	for attempt := 1; attempt <= maxCacheErrors; attempt++ {
		invalidated := handleAuthError(streamID, "fresh-user", "fresh-pass")
		if invalidated != (attempt == maxCacheErrors) {
			t.Fatalf("attempt %d invalidated=%v", attempt, invalidated)
		}
	}
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	if cache.creds.Username != "" || cache.creds.Password != "" {
		t.Fatal("current credential failures did not invalidate the cache")
	}
}
