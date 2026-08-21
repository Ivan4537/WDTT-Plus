package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	neturl "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
)

// ─── VK Credential Sets (2 stable app_id with rotating fallback) ───

type VKCredentials struct {
	ClientID     string
	ClientSecret string
}

type legacyVKCredentialProvider string

const (
	legacyVKProviderCustom  legacyVKCredentialProvider = "legacy-custom"
	legacyVKProviderBuiltIn legacyVKCredentialProvider = "legacy-built-in"
)

type legacyVKCredentialCandidate struct {
	Credentials VKCredentials
	Provider    legacyVKCredentialProvider
}

var vkCredentialsList = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "MuAxFaKDYDOICzGnEOhp"},
	{ClientID: "8202606", ClientSecret: "lMRsTiMCyPnp5vfoldmn"},
}

var customVKCredentials *VKCredentials

// Full list of known credentials to match against when setting active client IDs
var knownVKCredentials = map[string]VKCredentials{
	"6287487": {ClientID: "6287487", ClientSecret: "MuAxFaKDYDOICzGnEOhp"},
	"8202606": {ClientID: "8202606", ClientSecret: "lMRsTiMCyPnp5vfoldmn"},
}

func SetActiveClientIds(ids string) {
	if ids == "" {
		return
	}
	var newCreds []VKCredentials
	for _, id := range strings.Split(ids, ",") {
		id = strings.TrimSpace(id)
		if cred, ok := knownVKCredentials[id]; ok {
			newCreds = append(newCreds, cred)
		}
	}
	if len(newCreds) > 0 {
		vkCredentialsList = newCreds
	}
}

func SetCustomVKCredentials(clientID, clientSecret string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" || len(clientID) > 20 {
		return errors.New("client ID must contain 1 to 20 digits")
	}
	for _, char := range clientID {
		if char < '0' || char > '9' {
			return errors.New("client ID must contain digits only")
		}
	}
	if strings.TrimSpace(clientSecret) == "" {
		return errors.New("client secret is empty")
	}
	credentials := VKCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	customVKCredentials = &credentials
	return nil
}

func legacyVKCredentialCandidates() []legacyVKCredentialCandidate {
	result := make([]legacyVKCredentialCandidate, 0, len(vkCredentialsList)+1)
	if customVKCredentials != nil {
		result = append(result, legacyVKCredentialCandidate{
			Credentials: *customVKCredentials,
			Provider:    legacyVKProviderCustom,
		})
	}
	for _, credentials := range vkCredentialsList {
		result = append(result, legacyVKCredentialCandidate{
			Credentials: credentials,
			Provider:    legacyVKProviderBuiltIn,
		})
	}
	return result
}

func GetActiveClientIdsString() string {
	var ids []string
	for _, cred := range vkCredentialsList {
		ids = append(ids, cred.ClientID)
	}
	return strings.Join(ids, ", ")
}

const vkCredentialAttemptLimit = 4

var hashCheckMode atomic.Bool

func SetHashCheckMode(enabled bool) {
	hashCheckMode.Store(enabled)
}

// ─── Credential Caching ───

type TurnCredentials struct {
	Username    string
	Password    string
	ServerAddrs []string
	ExpiresAt   time.Time
	Link        string
}

type fetchedTurnCredentials struct {
	Username    string
	Password    string
	ServerAddrs []string
	Lifetime    time.Duration
	Provider    string
}

type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
)

func credentialCacheLifetime(reported time.Duration) time.Duration {
	if reported <= 0 {
		return credentialLifetime - cacheSafetyMargin
	}
	if reported > 24*time.Hour {
		reported = 24 * time.Hour
	}
	margin := cacheSafetyMargin
	if reported <= 2*cacheSafetyMargin {
		margin = reported / 5
	}
	return reported - margin
}

var streamsPerCache = 10

func getCacheID(streamID int) int {
	return streamID / streamsPerCache
}

var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	log.Printf("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

func cloneStringSlice(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

func handleAuthError(streamID int, username, password string) bool {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cache.creds.Username == "" || cache.creds.Password == "" ||
		cache.creds.Username != username || cache.creds.Password != password {
		log.Printf("[STREAM %d] [TURN] Креды уже заменены; поздняя ошибка авторизации проигнорирована (cache=%d)", streamID, cacheID)
		return false
	}

	now := time.Now().Unix()

	if now-cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	log.Printf("[STREAM %d] Auth error (cache=%d, count=%d/%d)", streamID, cacheID, count, maxCacheErrors)

	if count >= maxCacheErrors {
		log.Printf("[VK Auth] Multiple auth errors detected (%d), invalidating cache %d", count, cacheID)
		cache.creds = TurnCredentials{}
		cache.errorCount.Store(0)
		cache.lastErrorTime.Store(0)
		log.Printf("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
		return true
	}
	return false
}

// ─── Captcha lockout ───

var globalCaptchaLockout atomic.Int64

var errCaptchaNextChallenge = errors.New("request fresh captcha challenge")

const (
	captchaAutoWebViewTimeout     = 25 * time.Second
	captchaManualWebViewTimeout   = 195 * time.Second
	captchaSelectedWebViewTimeout = 315 * time.Second
	captchaChallengeAttemptLimit  = 12
	captchaAutoSoftFailureLimit   = 4
)

// ─── Random delay ───

func vkDelayRandom(minMs, maxMs int) {
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func vkStringField(raw map[string]interface{}, key string) string {
	value, ok := raw[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func vkRequestParam(raw map[string]interface{}, key string) string {
	params, ok := raw["request_params"].([]interface{})
	if !ok {
		return ""
	}
	for _, item := range params {
		param, ok := item.(map[string]interface{})
		if !ok || vkStringField(param, "key") != key {
			continue
		}
		return vkStringField(param, "value")
	}
	return ""
}

func vkAPIErrorSummary(raw map[string]interface{}) string {
	if raw == nil {
		return "VK API error"
	}

	code := vkStringField(raw, "error_code")
	msg := vkStringField(raw, "error_msg")
	if msg == "" {
		msg = "unknown"
	}

	parts := []string{}
	if method := vkRequestParam(raw, "method"); method != "" {
		parts = append(parts, "method="+method)
	}
	if clientID := vkRequestParam(raw, "client_id"); clientID != "" {
		parts = append(parts, "client_id="+clientID)
	}
	if attempt := vkRequestParam(raw, "captcha_attempt"); attempt != "" {
		parts = append(parts, "captcha_attempt="+attempt)
	}
	if vkRequestParam(raw, "success_token") != "" {
		parts = append(parts, "captcha_solved=true")
	}

	suffix := ""
	if len(parts) > 0 {
		suffix = " (" + strings.Join(parts, ", ") + ")"
	}
	if code == "" {
		return "VK API error: " + msg + suffix
	}
	return "VK API error_code:" + code + " " + msg + suffix
}

func classifyTerminalVKJoinError(raw map[string]interface{}) error {
	code := vkStringField(raw, "error_code")
	msg := strings.ToLower(vkStringField(raw, "error_msg"))
	switch {
	case code == "9000" || code == "9008" ||
		strings.Contains(msg, "not valid") || strings.Contains(msg, "not found"):
		return fmt.Errorf("INVALID_JOIN_LINK")
	case strings.Contains(msg, "anonym"):
		return fmt.Errorf("ANON_BLOCKED")
	case strings.Contains(msg, "full"):
		return fmt.Errorf("CALL_FULL")
	default:
		return nil
	}
}

func vkResponseSummary(name string, resp map[string]interface{}) string {
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		return vkAPIErrorSummary(errObj)
	}
	keys := make([]string, 0, len(resp))
	for key := range resp {
		keys = append(keys, key)
	}
	return fmt.Sprintf("%s response missing expected fields (keys=%s)", name, strings.Join(keys, ","))
}

// ─── Cached credential fetcher ───

func getVkCredsCached(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.RLock()
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		expires := time.Until(cache.creds.ExpiresAt)
		u, p := cache.creds.Username, cache.creds.Password
		addr := cache.creds.ServerAddrs[streamID%len(cache.creds.ServerAddrs)]
		addrs := cloneStringSlice(cache.creds.ServerAddrs)
		cache.mutex.RUnlock()
		log.Printf("[STREAM %d] [VK Auth] Using cached credentials (cache=%d, expires in %v, selected=%s, urls=%d)", streamID, cacheID, expires.Truncate(time.Second), addr, len(addrs))
		return u, p, addrs, nil
	}
	cache.mutex.RUnlock()

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Double-check inside lock
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && len(cache.creds.ServerAddrs) > 0 {
		return cache.creds.Username, cache.creds.Password, cloneStringSlice(cache.creds.ServerAddrs), nil
	}

	fetched, err := fetchVkCredsSerialized(ctx, link, streamID)
	if err != nil {
		return "", "", nil, err
	}
	cacheLifetime := credentialCacheLifetime(fetched.Lifetime)

	cache.creds = TurnCredentials{
		Username:    fetched.Username,
		Password:    fetched.Password,
		ServerAddrs: fetched.ServerAddrs,
		ExpiresAt:   time.Now().Add(cacheLifetime),
		Link:        link,
	}
	log.Printf("[STREAM %d] [VK Provider] %s: TURN-данные сохранены на %v", streamID, fetched.Provider, cacheLifetime.Truncate(time.Second))
	return fetched.Username, fetched.Password, cloneStringSlice(fetched.ServerAddrs), nil
}

// ─── Serialized (throttled) fetcher ───

var (
	vkRequestMu           sync.Mutex
	globalLastVkFetchTime time.Time
)

func fetchVkCredsSerialized(ctx context.Context, link string, streamID int) (fetchedTurnCredentials, error) {
	vkRequestMu.Lock()
	defer vkRequestMu.Unlock()

	// Throttle: 3-6 seconds between requests
	minInterval := 3*time.Second + time.Duration(rand.Intn(3000))*time.Millisecond
	elapsed := time.Since(globalLastVkFetchTime)

	if !globalLastVkFetchTime.IsZero() && elapsed < minInterval {
		wait := minInterval - elapsed
		log.Printf("[STREAM %d] [VK Auth] Throttling: waiting %v to prevent rate limit...", streamID, wait.Truncate(time.Millisecond))
		select {
		case <-ctx.Done():
			return fetchedTurnCredentials{}, ctx.Err()
		case <-time.After(wait):
		}
	}

	defer func() {
		globalLastVkFetchTime = time.Now()
	}()

	return fetchVkCreds(ctx, link, streamID)
}

// ─── Main credential fetcher (rotates through stable credential sets) ───

func fetchVkCreds(ctx context.Context, link string, streamID int) (fetchedTurnCredentials, error) {
	if vkCallsPreflightEnabled.Load() {
		if pause := vkCallsFloodPauseRemaining(time.Now()); pause > 0 {
			log.Printf("[STREAM %d] [VKCalls] preflight временно пропущен после ограничения VK (%v); продолжаем резервную legacy-цепочку", streamID, pause.Truncate(time.Second))
		} else {
			log.Printf("[STREAM %d] [VKCalls] preflight", streamID)
			if user, pass, addrs, lifetime, err := getVKCredsViaVKCalls(ctx, link, streamID); err == nil {
				log.Printf("[STREAM %d] [VK Provider] modern-vkcalls: успешно", streamID)
				return fetchedTurnCredentials{
					Username:    user,
					Password:    pass,
					ServerAddrs: addrs,
					Lifetime:    lifetime,
					Provider:    "modern-vkcalls",
				}, nil
			} else {
				pause := vkCallsPreflightPauseForError(err)
				startVKCallsPreflightPause(time.Now(), pause)
				switch {
				case isVKCallsFloodError(err):
					log.Printf("[STREAM %d] [VKCalls] VK временно ограничил анонимный вход; продолжаем резервную legacy-цепочку", streamID)
				case pause == vkCallsCaptchaPause:
					log.Printf("[STREAM %d] [VKCalls] VKCalls запросил CAPTCHA; временно не повторяем preflight и продолжаем резервную legacy-цепочку", streamID)
				case pause > 0:
					log.Printf("[STREAM %d] [VKCalls] preflight не сработал: %v; временно не повторяем его и продолжаем резервную legacy-цепочку", streamID, err)
				default:
					log.Printf("[STREAM %d] [VKCalls] preflight не сработал: %v; продолжаем резервную legacy-цепочку", streamID, err)
				}
			}
		}
	}

	if time.Now().Unix() < globalCaptchaLockout.Load() {
		return fetchedTurnCredentials{}, fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active")
	}

	candidates := legacyVKCredentialCandidates()
	if len(candidates) == 0 {
		return fetchedTurnCredentials{}, errors.New("no legacy VK credentials configured")
	}
	attemptLimit := vkCredentialAttemptLimit
	if len(candidates) > attemptLimit {
		attemptLimit = len(candidates)
	}
	var lastErr error
	jar := tlsclient.NewCookieJar()

	for attempt := 0; attempt < attemptLimit; attempt++ {
		candidate := candidates[attempt%len(candidates)]
		creds := candidate.Credentials
		provider := string(candidate.Provider)
		log.Printf("[STREAM %d] [VK Provider] %s: пробуем client_id=%s (попытка %d/%d)", streamID, provider, creds.ClientID, attempt+1, attemptLimit)

		user, pass, addrs, err := getTokenChain(ctx, link, streamID, creds, jar)

		if err == nil {
			log.Printf("[STREAM %d] [VK Provider] %s: успешно", streamID, provider)
			return fetchedTurnCredentials{
				Username:    user,
				Password:    pass,
				ServerAddrs: addrs,
				Provider:    provider,
			}, nil
		}

		lastErr = err
		log.Printf("[STREAM %d] [VK Provider] %s: client_id=%s не сработал: %v", streamID, provider, creds.ClientID, err)

		if strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED") || strings.Contains(err.Error(), "FATAL_CAPTCHA") {
			return fetchedTurnCredentials{}, err
		}
		if strings.Contains(err.Error(), "INVALID_JOIN_LINK") || strings.Contains(err.Error(), "ANON_BLOCKED") || strings.Contains(err.Error(), "CALL_FULL") {
			return fetchedTurnCredentials{}, err
		}

		if strings.Contains(err.Error(), "error_code:29") || strings.Contains(err.Error(), "error_code: 29") || strings.Contains(err.Error(), "Rate limit") {
			log.Printf("[STREAM %d] [VK Auth] Rate limit detected, trying next credentials...", streamID)
		}

		if attempt%len(candidates) == len(candidates)-1 && attempt+1 < attemptLimit {
			wait := time.Duration(900+rand.Intn(900)) * time.Millisecond
			log.Printf("[STREAM %d] [VK Auth] Все legacy-провайдеры временно не сработали, повтор через %v...", streamID, wait)
			select {
			case <-ctx.Done():
				return fetchedTurnCredentials{}, ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	return fetchedTurnCredentials{}, fmt.Errorf("all VK credential providers failed: %w", lastErr)
}

// ─── Token chain: anon_token → getCallPreview → getAnonymousToken → OK session → joinConversation → TURN creds ───

func getTokenChain(ctx context.Context, link string, streamID int, creds VKCredentials, jar tlsclient.CookieJar) (string, string, []string, error) {
	profile := getRandomProfile()

	tlsProfile := profiles.Chrome_146
	if GetActiveFingerprint() == "firefox" {
		tlsProfile = profiles.Firefox_147
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(tlsProfile),
		tlsclient.WithCookieJar(jar),
	)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to initialize tls_client: %w", err)
	}

	name := generateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("[STREAM %d] [VK Auth] Identity - Name: %s | UA: %s", streamID, name, profile.UserAgent)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		parsedURL, err := neturl.Parse(url)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := fhttp.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("VK HTTPS %s: %w", domain, err)
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	// Step 1: get_anonym_token
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", creds.ClientID, creds.ClientSecret, creds.ClientID)
	resp, err := doRequest(data, "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", nil, err
	}
	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("unexpected anon token response: %s", vkResponseSummary("anon token", resp))
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing access_token in response: %s", vkResponseSummary("anon token", resp))
	}

	vkDelayRandom(100, 150)

	// Step 2: getCallPreview (mimics real VK client behavior)
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	_, err = doRequest(data, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id="+creds.ClientID)
	if err != nil {
		log.Printf("[STREAM %d] [VK Auth] Warning: getCallPreview failed: %v", streamID, err)
	}

	vkDelayRandom(200, 400)

	// Step 3: getAnonymousToken (with captcha handling)
	data = fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=%s", creds.ClientID)

	var token2 string
	var savedProfile *SavedProfile
	savedProfile, _ = LoadProfileFromDisk()
	internalErrorRetries := 0
	captchaChallengeAttempts := 0
	captchaStageAttempt := 1
	captchaAutoSoftFailures := 0

	for {
		resp, err = doRequest(data, urlAddr)
		if err != nil {
			return "", "", nil, err
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			captchaErr := parseVkCaptchaError(errObj)
			if captchaErr != nil && captchaErr.RedirectURI != "" && captchaErr.SessionToken != "" {
				captchaChallengeAttempts++
				if captchaChallengeAttempts > captchaChallengeAttemptLimit {
					log.Printf("[STREAM %d] [КАПЧА] Достигнут предел новых проверок", streamID)
					globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())
					return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}
				if _, hasStage := captchaSolveStage(captchaStageAttempt); !hasStage {
					log.Printf("[STREAM %d] [КАПЧА] Достигнут предел попыток", streamID)
					globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())
					return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				successToken, solveErr := solveCaptchaBySelectedMode(ctx, streamID, captchaStageAttempt, captchaErr, client, profile, savedProfile)
				if solveErr != nil {
					if errors.Is(solveErr, errCaptchaNextChallenge) {
						// Причина конкретного сбоя уже обработана на Android. Не выводим
						// её внутренний английский текст в пользовательский журнал.
						log.Printf("[STREAM %d] [КАПЧА] AUTO: текущий способ не завершил проверку; запрашиваем новую капчу", streamID)
						captchaStageAttempt, captchaAutoSoftFailures = captchaNextStageAfterSolverFailure(
							captchaStageAttempt,
							solveErr,
							captchaAutoSoftFailures,
						)
						data = buildCaptchaRetryData(link, escapedName, token1, captchaErr, "")
						timer := time.NewTimer(time.Duration(800+rand.Intn(500)) * time.Millisecond)
						select {
						case <-ctx.Done():
							timer.Stop()
							return "", "", nil, ctx.Err()
						case <-timer.C:
						}
						continue
					}
					log.Printf("[STREAM %d] [КАПЧА] Текущий способ не решил капчу; ждём безопасного повтора", streamID)
					globalCaptchaLockout.Store(time.Now().Add(60 * time.Second).Unix())
					return "", "", nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}

				// A solved token followed by another VK captcha is a fresh challenge,
				// not proof that Auto WebView should be downgraded for the next one.
				captchaStageAttempt = captchaStageAfterSolverSuccess(captchaStageAttempt)
				captchaAutoSoftFailures = 0
				data = buildCaptchaRetryData(link, escapedName, token1, captchaErr, successToken)
				continue
			}

			if termErr := classifyTerminalVKJoinError(errObj); termErr != nil {
				errSummary := vkAPIErrorSummary(errObj)
				log.Printf("[STREAM %d] [VK Auth] terminal join error: %s (%v)", streamID, errSummary, termErr)
				return "", "", nil, fmt.Errorf("%w: %s", termErr, errSummary)
			}

			errSummary := vkAPIErrorSummary(errObj)
			if vkStringField(errObj, "error_code") == "10" && internalErrorRetries < 2 {
				internalErrorRetries++
				wait := time.Duration(900+rand.Intn(1200)) * time.Millisecond
				log.Printf("[STREAM %d] [VK Auth] %s; retry %d/2 after %v", streamID, errSummary, internalErrorRetries, wait)
				select {
				case <-ctx.Done():
					return "", "", nil, ctx.Err()
				case <-time.After(wait):
				}
				continue
			}

			return "", "", nil, fmt.Errorf("%s", errSummary)
		}

		respMap, okLoop := resp["response"].(map[string]interface{})
		if !okLoop {
			return "", "", nil, fmt.Errorf("unexpected getAnonymousToken response: %s", vkResponseSummary("getAnonymousToken", resp))
		}
		token2, okLoop = respMap["token"].(string)
		if !okLoop {
			return "", "", nil, fmt.Errorf("missing token in response: %s", vkResponseSummary("getAnonymousToken", resp))
		}
		break
	}

	vkDelayRandom(100, 150)

	// Step 4: OK.ru anonymLogin
	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":1.1,"client_type":"SDK_JS"}`, uuid.New())
	data = fmt.Sprintf("session_data=%s&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", neturl.QueryEscape(sessionData))
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}
	token3, ok := resp["session_key"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing session_key in response: %s", vkResponseSummary("OK anonymLogin", resp))
	}

	vkDelayRandom(100, 150)

	// Step 5: joinConversationByLink → TURN creds
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	resp, err = doRequest(data, "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", nil, err
	}

	tsRaw, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("missing turn_server in response: %s", vkResponseSummary("joinConversationByLink", resp))
	}
	user, ok := tsRaw["username"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing username in turn_server")
	}
	pass, ok := tsRaw["credential"].(string)
	if !ok {
		return "", "", nil, fmt.Errorf("missing credential in turn_server")
	}
	urlsRaw, ok := tsRaw["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", nil, fmt.Errorf("missing or empty urls in turn_server")
	}

	log.Printf("[STREAM %d] [VK Auth] TURN urls (%d total):", streamID, len(urlsRaw))
	for i, u := range urlsRaw {
		log.Printf("[STREAM %d] [VK Auth]   [%d] %v", streamID, i, u)
	}

	var addresses []string
	for _, u := range urlsRaw {
		urlStr, ok := u.(string)
		if !ok {
			continue
		}
		if normalized := normalizeTURNURL(urlStr); normalized != "" {
			addresses = append(addresses, normalized)
		}
	}

	if len(addresses) == 0 {
		return "", "", nil, fmt.Errorf("no valid TURN addresses found")
	}

	return user, pass, addresses, nil
}

func solveCaptchaBySelectedMode(
	ctx context.Context,
	streamID int,
	attempt int,
	captchaErr *VkCaptchaError,
	client tlsclient.HttpClient,
	profile Profile,
	savedProfile *SavedProfile,
) (string, error) {
	switch getCaptchaMode() {
	case "wv":
		log.Printf("[STREAM %d] [КАПЧА] WBV: режим из настроек Android (attempt %d)", streamID, attempt)
		return requestWebViewCaptcha(ctx, streamID, captchaErr, "selected", captchaSelectedWebViewTimeout)
	}

	stage, hasStage := captchaSolveStage(attempt)
	if !hasStage {
		return "", fmt.Errorf("captcha solve stages exhausted")
	}
	log.Printf("[STREAM %d] [КАПЧА] AUTO: стадия %d/%d: %s", streamID, attempt, captchaSolveStageCount(), stage)

	var token string
	var solveErr error
	switch stage {
	case "Auto WebView":
		token, solveErr = requestWebViewCaptcha(ctx, streamID, captchaErr, "auto", captchaAutoWebViewTimeout)
	case "Go v2":
		token, solveErr = solveVkCaptchaV2Attempts(ctx, captchaErr, client, profile, savedProfile, 1)
	case "Manual WebView":
		active := globalActiveConnections.Load()
		if active > 0 {
			log.Printf("[STREAM %d] [КАПЧА] AUTO: ручной WebView нужен для добора потоков, активных соединений сейчас=%d", streamID, active)
		}
		token, solveErr = requestWebViewCaptcha(ctx, streamID, captchaErr, "manual", captchaManualWebViewTimeout)
	}
	if solveErr == nil {
		// WebView уже сообщает Android об успехе самостоятельно. Повторный
		// лог здесь нужен только для встроенного Go-способа, у которого нет
		// отдельного Android-события завершения.
		if stage == "Go v2" {
			log.Printf("[STREAM %d] [КАПЧА] AUTO: %s решил капчу", streamID, stage)
		}
		return token, nil
	}
	if ctx.Err() != nil {
		return "", solveErr
	}
	if _, hasNext := captchaSolveStage(attempt + 1); hasNext {
		return "", fmt.Errorf("%w: %s: %v", errCaptchaNextChallenge, stage, solveErr)
	}
	return "", solveErr
}

func captchaSolveStage(attempt int) (string, bool) {
	switch attempt {
	case 1:
		return "Auto WebView", true
	case 2:
		return "Auto WebView", true
	case 3:
		return "Go v2", true
	case 4:
		return "Manual WebView", true
	default:
		return "", false
	}
}

func captchaSolveStageCount() int {
	return 4
}

func captchaStageAfterSolverSuccess(_ int) int {
	return 1
}

func captchaNextStageAfterSolverFailure(attempt int, err error, autoSoftFailures int) (int, int) {
	if attempt <= 2 && captchaAutoFailureShouldRetryFreshAuto(err) && autoSoftFailures < captchaAutoSoftFailureLimit {
		return 1, autoSoftFailures + 1
	}
	return attempt + 1, autoSoftFailures
}

func captchaAutoFailureShouldRetryFreshAuto(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "error:auto_no_result") ||
		strings.Contains(text, "error:auto_check_not_sent") ||
		strings.Contains(text, "captcha_check_error") ||
		strings.Contains(text, "webview captcha timed out")
}

func buildCaptchaRetryData(link, escapedName, token1 string, captchaErr *VkCaptchaError, successToken string) string {
	appendRemixStlid := func(raw string) string {
		if captchaErr.RemixStlid == "" {
			return raw
		}
		return raw + "&remixstlid=" + neturl.QueryEscape(captchaErr.RemixStlid)
	}
	if captchaErr.CaptchaSid == "" {
		return appendRemixStlid(fmt.Sprintf(
			"vk_join_link=https://vk.ru/call/join/%s&name=%s&success_token=%s&access_token=%s",
			link,
			escapedName,
			neturl.QueryEscape(successToken),
			token1,
		))
	}
	captchaAttempt := captchaErr.CaptchaAttempt
	if captchaAttempt == "0" || captchaAttempt == "" {
		captchaAttempt = "1"
	}
	return appendRemixStlid(fmt.Sprintf(
		"vk_join_link=https://vk.ru/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
		link,
		escapedName,
		captchaErr.CaptchaSid,
		neturl.QueryEscape(successToken),
		captchaErr.CaptchaTs,
		captchaAttempt,
		token1,
	))
}

func requestWebViewCaptcha(ctx context.Context, streamID int, captchaErr *VkCaptchaError, mode string, timeout time.Duration) (string, error) {
	if CaptchaResultChan == nil || captchaErr == nil || captchaErr.RedirectURI == "" || captchaErr.SessionToken == "" {
		return "", fmt.Errorf("webview captcha data is incomplete")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "manual" && mode != "selected" {
		mode = "auto"
	}
	if timeout <= 0 {
		timeout = captchaAutoWebViewTimeout
	}

	requestID := nextCaptchaRequestID(streamID)
	resultCh, unregisterResultWaiter := registerCaptchaResultWaiter(requestID)
	defer unregisterResultWaiter()

	fmt.Printf("CAPTCHA_SOLVE|%s|%s|%s|%s\n", requestID, mode, captchaErr.RedirectURI, captchaErr.SessionToken)

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	handleResponse := func(response CaptchaResult) (string, bool, error) {
		if !captchaResultMatchesRequest(response, requestID) {
			log.Printf("[STREAM %d] [КАПЧА] WBV: игнорируем запоздалый результат request=%q, ожидается=%q", streamID, response.RequestID, requestID)
			return "", false, nil
		}
		result := strings.TrimSpace(response.Value)
		if result == "" {
			return "", true, fmt.Errorf("webview captcha returned empty result")
		}
		lowerResult := strings.ToLower(result)
		if lowerResult == "error:timeout" {
			return "", true, fmt.Errorf("webview captcha timed out")
		}
		if strings.HasPrefix(lowerResult, "error:") {
			return "", true, fmt.Errorf("webview captcha failed: %s", result)
		}
		return result, true, nil
	}

	for {
		select {
		case response := <-resultCh:
			if token, done, err := handleResponse(response); done || err != nil {
				return token, err
			}
		case response := <-CaptchaResultChan:
			if token, done, err := handleResponse(response); done || err != nil {
				return token, err
			}
		case <-waitCtx.Done():
			return "", fmt.Errorf("webview captcha timed out: %w", waitCtx.Err())
		}
	}
}

// ─── GetCreds returns TURN credentials for a given stream ───

func GetCreds(ctx context.Context, link string, streamID int) (string, string, []string, error) {
	return getVkCredsCached(ctx, link, streamID)
}
