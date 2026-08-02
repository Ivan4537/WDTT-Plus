package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
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

func TestManagedHashFallbackUsesOnlyHashSpecificFailures(t *testing.T) {
	for _, message := range []string{"INVALID_JOIN_LINK", "ANON_BLOCKED", "CALL_FULL"} {
		if !isHashFallbackCredentialError(errors.New(message)) {
			t.Fatalf("%q must try the next managed-profile hash", message)
		}
	}
	for _, message := range []string{"CAPTCHA_WAIT_REQUIRED", "VK HTTPS timeout", "FATAL_AUTH"} {
		if isHashFallbackCredentialError(errors.New(message)) {
			t.Fatalf("%q must not fan out across all hashes", message)
		}
	}
}

func TestHashRefreshOrderRotatesReserveAfterTurnFailure(t *testing.T) {
	got := hashRefreshOrder(0, 4, true)
	want := []int{1, 2, 3, 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rotated order = %v, want %v", got, want)
	}

	got = hashRefreshOrder(2, 4, false)
	want = []int{2, 3, 0, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("regular refresh order = %v, want %v", got, want)
	}
}

func TestCaptchaCredentialRetryDelay(t *testing.T) {
	if got := groupCredentialRetryDelay(errors.New("CAPTCHA_WAIT_REQUIRED")); got != 90*time.Second {
		t.Fatalf("captcha retry delay = %v", got)
	}
}

func TestWorkerPolicyRetryDelayIsBounded(t *testing.T) {
	if got := workerPolicyRetryDelay(1); got != 5*time.Second {
		t.Fatalf("first policy retry delay = %v", got)
	}
	if got := workerPolicyRetryDelay(100); got != 15*time.Second {
		t.Fatalf("maximum policy retry delay = %v", got)
	}
}

func TestGroupCredentialsStateRejectsStaleReplacement(t *testing.T) {
	state := newGroupCredentialsState(Credentials{
		User:     "first-user",
		Pass:     "first-pass",
		TurnURLs: []string{"turn:first.example:3478"},
	})

	first, revision := state.snapshot()
	first.TurnURLs[0] = "mutated-outside-state"
	unchanged, unchangedRevision := state.snapshot()
	if unchanged.TurnURLs[0] != "turn:first.example:3478" {
		t.Fatal("snapshot must not expose the stored TURN URL slice")
	}
	if unchangedRevision != revision {
		t.Fatalf("initial revision changed: got %d, want %d", unchangedRevision, revision)
	}

	if !state.replaceIfCurrent(revision, Credentials{
		User:     "fresh-user",
		Pass:     "fresh-pass",
		TurnURLs: []string{"turn:fresh.example:3478"},
	}) {
		t.Fatal("current credential revision was not replaced")
	}
	if state.replaceIfCurrent(revision, first) {
		t.Fatal("a stale worker replaced newer credentials")
	}
	fresh, freshRevision := state.snapshot()
	if fresh.User != "fresh-user" || freshRevision != revision+1 {
		t.Fatalf("fresh credentials = %#v at revision %d", fresh, freshRevision)
	}
}

func TestCredentialRefreshRetryUsesShortBoundedJitter(t *testing.T) {
	for _, result := range []credentialRefreshResult{
		credentialRefreshApplied,
		credentialRefreshSuperseded,
	} {
		for workerIndex := 0; workerIndex < workersPerGroup; workerIndex++ {
			minimum := refreshedCredsRetryMin + time.Duration(workerIndex)*refreshedCredsRetrySlot
			maximum := minimum + refreshedCredsRetryJitterMax
			for attempt := 0; attempt < 100; attempt++ {
				delay := workerRetryDelayAfterCredentialRefresh(errors.New("TURN auth"), result, workerIndex)
				if delay < minimum || delay > maximum {
					t.Fatalf("worker %d short retry delay %v outside %v..%v", workerIndex, delay, minimum, maximum)
				}
			}
		}
	}

	delay := workerRetryDelayAfterCredentialRefresh(errors.New("TURN timeout"), credentialRefreshNone, 8)
	if delay < defaultWorkerRetryMin || delay > defaultWorkerRetryMax {
		t.Fatalf("ordinary retry delay %v outside %v..%v", delay, defaultWorkerRetryMin, defaultWorkerRetryMax)
	}
}

func TestCredentialRevisionsStayIndependentAtMaximumPower(t *testing.T) {
	const groupCount = 108 / workersPerGroup
	states := make([]*groupCredentialsState, groupCount)
	for group := range states {
		states[group] = newGroupCredentialsState(Credentials{
			User:     "initial",
			TurnURLs: []string{"turn:initial.example:3478"},
		})
	}

	var wg sync.WaitGroup
	wins := make([]int, groupCount)
	var winsMu sync.Mutex
	for group, state := range states {
		_, revision := state.snapshot()
		for worker := 0; worker < workersPerGroup; worker++ {
			wg.Add(1)
			go func(group, worker int, state *groupCredentialsState, revision uint64) {
				defer wg.Done()
				if state.replaceIfCurrent(revision, Credentials{
					User:     "fresh",
					TurnURLs: []string{"turn:fresh.example:3478"},
				}) {
					winsMu.Lock()
					wins[group]++
					winsMu.Unlock()
				}
			}(group, worker, state, revision)
		}
	}
	wg.Wait()

	for group, state := range states {
		if wins[group] != 1 {
			t.Fatalf("group %d accepted %d replacements, want exactly one", group, wins[group])
		}
		credentials, revision := state.snapshot()
		if credentials.User != "fresh" || revision != 2 {
			t.Fatalf("group %d credentials = %#v at revision %d", group, credentials, revision)
		}
	}
}

func TestTURNCapacityDoesNotInvalidateCredentials(t *testing.T) {
	for _, message := range []string{"TURN квота: error 486", "TURN Allocate: error 508", "allocation quota reached"} {
		err := errors.New(message)
		if !isTURNCapacityError(err) {
			t.Fatalf("%q must be classified as endpoint capacity", message)
		}
		if isCredentialTURNError(err) {
			t.Fatalf("%q must not invalidate VK credentials", message)
		}
	}

	for _, message := range []string{"TURN Allocate: error 401 Unauthorized", "invalid credential", "stale nonce", "allocation mismatch"} {
		err := errors.New(message)
		if !isCredentialTURNError(err) {
			t.Fatalf("%q must refresh credentials", message)
		}
		if isTURNCapacityError(err) {
			t.Fatalf("%q must not be classified as endpoint capacity", message)
		}
	}
}

func TestWrapHandshakeRetryUsesShortDedicatedWindow(t *testing.T) {
	minDelay, maxDelay := workerRetryDelayBounds(
		errors.New("WRAP_AUTH_TIMEOUT: отдельный DTLS-канал не ответил вовремя"),
	)
	if minDelay != time.Second || maxDelay != 3*time.Second {
		t.Fatalf("WRAP retry bounds = %v..%v, want 1s..3s", minDelay, maxDelay)
	}

	minDelay, maxDelay = workerRetryDelayBounds(errors.New("TURN Allocate timeout"))
	if minDelay != 5*time.Second || maxDelay != 15*time.Second {
		t.Fatalf("regular retry bounds = %v..%v, want 5s..15s", minDelay, maxDelay)
	}
}

func TestWrapHandshakeTimeoutAllowsFourFlightsBeforeFastRetry(t *testing.T) {
	if got := dtlsHandshakeTimeout(true); got != 8*time.Second {
		t.Fatalf("WRAP handshake timeout = %v, want 8s", got)
	}
	if got := dtlsHandshakeTimeout(false); got != 20*time.Second {
		t.Fatalf("regular handshake timeout = %v, want 20s", got)
	}
}

func TestConfigFirstStartGateOnlyBlocksFollowingWorkersWhenEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	regular := newConfigFirstStartGate(false)
	if err := regular.wait(ctx, 1); err != nil {
		t.Fatalf("regular start path was blocked: %v", err)
	}

	managed := newConfigFirstStartGate(true)
	if err := managed.wait(ctx, 0); err != nil {
		t.Fatalf("config worker was blocked: %v", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- managed.wait(ctx, 1)
	}()
	select {
	case err := <-waitDone:
		t.Fatalf("following worker passed before GETCONF: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	managed.release()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("following worker failed after GETCONF: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("following worker did not start after GETCONF")
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
