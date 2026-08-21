package main

import (
	"context"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	workersPerGroup              = 9
	defaultCycleSecs             = 36000
	defaultWorkerRetryMin        = 5 * time.Second
	defaultWorkerRetryMax        = 15 * time.Second
	wrapHandshakeRetryMin        = 1 * time.Second
	wrapHandshakeRetryMax        = 3 * time.Second
	refreshedCredsRetryMin       = 500 * time.Millisecond
	refreshedCredsRetrySlot      = 250 * time.Millisecond
	refreshedCredsRetryJitterMax = 250 * time.Millisecond
	// VK-реквизиты запрашиваются последовательно. Меньший интервал старта
	// воркеров не должен превращать их в burst запросов к VK.
	credentialRequestCooldown = 100 * time.Millisecond
)

// workerStartInterval выбирает темп только для начального набора сессии.
// Несколько независимых VK-хешей распределяют нагрузку между группами, поэтому
// их можно запускать быстрее. Для единственного хеша и TCP/TLS режима «Сеть
// РТ» оставляем более щадящий темп: это снижает вероятность flood/CAPTCHA и
// всплеска тяжёлых TLS-подключений.
func workerStartInterval(hashCount int, turnStreamFirst bool) time.Duration {
	if turnStreamFirst {
		return 125 * time.Millisecond
	}
	switch {
	case hashCount >= 3:
		return 100 * time.Millisecond
	case hashCount == 2:
		return 125 * time.Millisecond
	default:
		return 150 * time.Millisecond
	}
}

// workerDistributionByHash возвращает, сколько воркеров получит каждый
// уникальный хеш. Одна группа всегда содержит workersPerGroup воркеров.
func workerDistributionByHash(workerCount, hashCount int) []int {
	if hashCount < 1 {
		return nil
	}
	distribution := make([]int, hashCount)
	groupCount := workerCount / workersPerGroup
	for group := 0; group < groupCount; group++ {
		distribution[group%hashCount] += workersPerGroup
	}
	return distribution
}

// startPacer распределяет первичные подключения всех групп по общей шкале
// времени. Это позволяет готовить группы параллельно, не создавая всплеск из
// десятков одновременных DTLS/TURN-handshake.
type startPacer struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newStartPacer(interval time.Duration) *startPacer {
	if interval < 0 {
		interval = 0
	}
	return &startPacer{interval: interval}
}

func (p *startPacer) reserve(now time.Time) time.Time {
	if p == nil {
		return now
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	scheduled := now
	if p.next.After(scheduled) {
		scheduled = p.next
	}
	p.next = scheduled.Add(p.interval)
	return scheduled
}

func (p *startPacer) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scheduled := p.reserve(time.Now())
	delay := time.Until(scheduled)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

type credentialFetchResult struct {
	user     string
	pass     string
	turnURLs []string
	err      error
}

// credentialRequestGate оставляет только один активный запрос реквизитов.
// Короткая пауза между запросами защищает VK-путь от стартового flood control,
// при этом группы больше не ждут полного запуска предыдущих девяти воркеров.
type credentialRequestGate struct {
	token    chan struct{}
	cooldown time.Duration
}

func newCredentialRequestGate(cooldown time.Duration) *credentialRequestGate {
	if cooldown < 0 {
		cooldown = 0
	}
	gate := &credentialRequestGate{
		token:    make(chan struct{}, 1),
		cooldown: cooldown,
	}
	gate.token <- struct{}{}
	return gate
}

func (g *credentialRequestGate) fetch(
	ctx context.Context,
	request func() (string, string, []string, error),
) credentialFetchResult {
	if g == nil {
		user, pass, turnURLs, err := request()
		return credentialFetchResult{user: user, pass: pass, turnURLs: turnURLs, err: err}
	}
	select {
	case <-g.token:
	case <-ctx.Done():
		return credentialFetchResult{err: ctx.Err()}
	}
	defer func() { g.token <- struct{}{} }()

	user, pass, turnURLs, err := request()
	if g.cooldown > 0 && ctx.Err() == nil {
		timer := time.NewTimer(g.cooldown)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
	return credentialFetchResult{user: user, pass: pass, turnURLs: turnURLs, err: err}
}

type credentialRefreshResult uint8

const (
	credentialRefreshNone credentialRefreshResult = iota
	credentialRefreshApplied
	credentialRefreshSuperseded
)

type groupCredentialsState struct {
	mu       sync.RWMutex
	value    Credentials
	revision uint64
}

func newGroupCredentialsState(value Credentials) *groupCredentialsState {
	value.TurnURLs = cloneStringSlice(value.TurnURLs)
	return &groupCredentialsState{value: value, revision: 1}
}

func (state *groupCredentialsState) snapshot() (Credentials, uint64) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	value := state.value
	value.TurnURLs = cloneStringSlice(value.TurnURLs)
	return value, state.revision
}

func (state *groupCredentialsState) isCurrent(revision uint64) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.revision == revision
}

func (state *groupCredentialsState) replaceIfCurrent(revision uint64, value Credentials) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.revision != revision {
		return false
	}
	value.TurnURLs = cloneStringSlice(value.TurnURLs)
	state.value = value
	state.revision++
	return true
}

func workerRetryDelayBounds(err error) (time.Duration, time.Duration) {
	if err != nil && strings.Contains(strings.ToUpper(err.Error()), "WRAP_AUTH_TIMEOUT") {
		return wrapHandshakeRetryMin, wrapHandshakeRetryMax
	}
	return defaultWorkerRetryMin, defaultWorkerRetryMax
}

func workerRetryDelay(err error) time.Duration {
	minDelay, maxDelay := workerRetryDelayBounds(err)
	steps := int((maxDelay-minDelay)/time.Second) + 1
	return minDelay + time.Duration(rand.Intn(steps))*time.Second
}

func workerRetryDelayAfterCredentialRefresh(err error, result credentialRefreshResult, workerIndex int) time.Duration {
	if result != credentialRefreshApplied && result != credentialRefreshSuperseded {
		return workerRetryDelay(err)
	}
	if workerIndex < 0 {
		workerIndex = 0
	}
	slot := workerIndex % workersPerGroup
	jitter := time.Duration(rand.Int63n(int64(refreshedCredsRetryJitterMax) + 1))
	return refreshedCredsRetryMin + time.Duration(slot)*refreshedCredsRetrySlot + jitter
}

type workerPolicyRetryGate struct {
	mu           sync.Mutex
	blockedUntil time.Time
	round        int
}

func workerPolicyRetryDelay(round int) time.Duration {
	if round < 1 {
		round = 1
	}
	delay := time.Duration(3+round*2) * time.Second
	if delay > 15*time.Second {
		return 15 * time.Second
	}
	return delay
}

// wait объединяет одновременные отказы всех воркеров в одно окно повтора.
// Небольшой разброс не даёт девяти DTLS-handshake стартовать в одну миллисекунду.
func (g *workerPolicyRetryGate) wait(ctx context.Context, workerID int) (bool, int, error) {
	g.mu.Lock()
	now := time.Now()
	startedRound := !now.Before(g.blockedUntil)
	if startedRound {
		g.round++
		g.blockedUntil = now.Add(workerPolicyRetryDelay(g.round))
	}
	round := g.round
	retryAt := g.blockedUntil.Add(time.Duration(workerID%workersPerGroup) * 250 * time.Millisecond)
	g.mu.Unlock()

	wait := time.Until(retryAt)
	if wait <= 0 {
		return startedRound, round, nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return startedRound, round, nil
	case <-ctx.Done():
		return startedRound, round, ctx.Err()
	}
}

func (g *workerPolicyRetryGate) reset() {
	g.mu.Lock()
	g.blockedUntil = time.Time{}
	g.round = 0
	g.mu.Unlock()
}

type configFirstStartGate struct {
	enabled bool
	ready   chan struct{}
	once    sync.Once
}

func newConfigFirstStartGate(enabled bool) *configFirstStartGate {
	gate := &configFirstStartGate{enabled: enabled}
	if enabled {
		gate.ready = make(chan struct{})
	}
	return gate
}

func (g *configFirstStartGate) wait(ctx context.Context, configWorker bool) error {
	if g == nil || !g.enabled || configWorker {
		return nil
	}
	select {
	case <-g.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *configFirstStartGate) release() {
	if g == nil || !g.enabled {
		return
	}
	g.once.Do(func() {
		close(g.ready)
	})
}

// WorkerGroup:
// Запускает 9 потоков с одними кредами. Ротации нет — работает до смерти воркеров.
func WorkerGroup(
	ctx context.Context,
	cancel context.CancelFunc,
	groupID int,
	hashIndex int,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	getConfig bool,
	configCh chan<- string,
	workerIDs []int,
	requestedWorkers int,
	hashFallback bool,
	pauseFlag *int32,
	deviceID, password, deviceInfo, transportSession string,
	stats *Stats,
	turnStreamFirst bool,
	configStartGate *configFirstStartGate,
	workerStarts *startPacer,
	credentialRequests *credentialRequestGate,
	waitForPrimaryCredentials <-chan struct{},
	signalPrimaryCredentials chan<- struct{},
) {
	var configSent int32
	if !getConfig {
		configSent = 1
	}
	// Doze-mode пауза
	for atomic.LoadInt32(pauseFlag) != 0 {
		if ctx.Err() != nil {
			return
		}
		time.Sleep(1 * time.Second)
	}
	if waitForPrimaryCredentials != nil {
		select {
		case <-waitForPrimaryCredentials:
		case <-ctx.Done():
			return
		}
	}

	hashCandidates := []string{tp.Hashes[hashIndex%len(tp.Hashes)]}
	if hashFallback && len(tp.Hashes) > 1 {
		hashCandidates = make([]string, 0, len(tp.Hashes))
		for offset := 0; offset < len(tp.Hashes); offset++ {
			hashCandidates = append(
				hashCandidates,
				tp.Hashes[(hashIndex+offset)%len(tp.Hashes)],
			)
		}
	}
	selectedHash := 0
	hash := hashCandidates[selectedHash]
	log.Printf("[ГРУППА #%d] Запрос реквизитов подключения", groupID)

	credStreamID := groupID * 100
	fetchCredentials := func(candidateHash string) credentialFetchResult {
		return credentialRequests.fetch(ctx, func() (string, string, []string, error) {
			return GetCreds(ctx, candidateHash, credStreamID)
		})
	}
	credentials := fetchCredentials(hash)
	user, pass, turnURLs, err := credentials.user, credentials.pass, credentials.turnURLs, credentials.err
	for err != nil &&
		selectedHash+1 < len(hashCandidates) &&
		isHashFallbackCredentialError(err) {
		selectedHash++
		hash = hashCandidates[selectedHash]
		log.Printf(
			"[ГРУППА #%d] Текущий VK-хеш недоступен; пробуем резерв %d из %d",
			groupID,
			selectedHash+1,
			len(hashCandidates),
		)
		credentials = fetchCredentials(hash)
		user, pass, turnURLs, err = credentials.user, credentials.pass, credentials.turnURLs, credentials.err
	}
	if signalPrimaryCredentials != nil {
		close(signalPrimaryCredentials)
	}
	if err != nil && getConfig {
		log.Printf("[ГРУППА #%d] Стартовые креды не получены: %v; завершаем запуск для чистого повтора", groupID, err)
		cancel()
		return
	}
	if err != nil {
		for attempt := 2; err != nil; attempt++ {
			if isTerminalGroupCredentialError(err) {
				log.Printf("[ГРУППА #%d] Креды недоступны без восстановления: %v", groupID, err)
				return
			}
			delay := groupCredentialRetryDelay(err)
			log.Printf("[ГРУППА #%d] Креды пока не получены: повтор %d через %v", groupID, attempt, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			credentials = fetchCredentials(hash)
			user, pass, turnURLs, err = credentials.user, credentials.pass, credentials.turnURLs, credentials.err
		}
	}
	credsState := newGroupCredentialsState(Credentials{
		User:          user,
		Pass:          pass,
		TurnURLs:      turnURLs,
		CacheStreamID: credStreamID,
	})

	initialCreds, _ := credsState.snapshot()
	log.Printf("[ГРУППА #%d] Креды OK, TURN: %v, %d воркеров", groupID, initialCreds.TurnURLs, len(workerIDs))

	var configRequestInFlight int32
	var wg sync.WaitGroup
	var refreshMu sync.Mutex
	var lastCredRefresh atomic.Int64
	var policyRetryGate workerPolicyRetryGate

	refreshCreds := func(reason string, failedRevision uint64) credentialRefreshResult {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		if !credsState.isCurrent(failedRevision) {
			log.Printf("[TURN] Креды уже заменены после этой попытки, используем актуальные (%s)", reason)
			return credentialRefreshSuperseded
		}

		now := time.Now().Unix()
		last := lastCredRefresh.Load()
		if last > 0 && now-last < 15 {
			log.Printf("[TURN] Креды уже обновлялись %d сек назад, ждём следующий retry (%s)", now-last, reason)
			return credentialRefreshNone
		}

		rotateForTurnFailure := hashFallback &&
			len(hashCandidates) > 1 &&
			strings.HasPrefix(strings.ToUpper(strings.TrimSpace(reason)), "TURN")
		order := hashRefreshOrder(selectedHash, len(hashCandidates), rotateForTurnFailure)
		var (
			u             string
			p             string
			urls          []string
			refreshErr    error
			nextHashIndex = selectedHash
		)
		for attempt, candidateIndex := range order {
			candidateHash := hashCandidates[candidateIndex]
			if attempt > 0 || candidateIndex != selectedHash {
				log.Printf(
					"[ГРУППА #%d] Пробуем резервный VK-хеш %d из %d после ошибки TURN",
					groupID,
					candidateIndex+1,
					len(hashCandidates),
				)
			}
			getStreamCache(credStreamID).invalidate(credStreamID)
			credentials := fetchCredentials(candidateHash)
			u, p, urls, refreshErr = credentials.user, credentials.pass, credentials.turnURLs, credentials.err
			if refreshErr == nil {
				nextHashIndex = candidateIndex
				break
			}
			if !isHashFallbackCredentialError(refreshErr) {
				break
			}
		}
		if refreshErr != nil {
			log.Printf("[TURN] Не удалось обновить креды после %s: %v", reason, refreshErr)
			return credentialRefreshNone
		}
		selectedHash = nextHashIndex
		hash = hashCandidates[selectedHash]

		replaced := credsState.replaceIfCurrent(failedRevision, Credentials{
			User:          u,
			Pass:          p,
			TurnURLs:      urls,
			CacheStreamID: credStreamID,
		})
		if !replaced {
			log.Printf("[TURN] Креды уже заменены во время обновления, используем актуальные (%s)", reason)
			return credentialRefreshSuperseded
		}
		lastCredRefresh.Store(time.Now().Unix())
		log.Printf("[TURN] Креды обновлены после %s, TURN urls=%d", reason, len(urls))
		return credentialRefreshApplied
	}

	for i, wid := range workerIDs {
		wg.Add(1)

		go func(workerIndex, wid int) {
			defer wg.Done()

			if err := configStartGate.wait(ctx, getConfig && workerIndex == 0); err != nil {
				return
			}

			if err := workerStarts.wait(ctx); err != nil {
				return
			}

			shouldGetConfig := getConfig
			attempt := 0

			for {
				if ctx.Err() != nil {
					return
				}

				getConf := false
				if shouldGetConfig && atomic.LoadInt32(&configSent) == 0 {
					getConf = atomic.CompareAndSwapInt32(&configRequestInFlight, 0, 1)
				}
				var cc chan<- string
				if getConf {
					cc = configCh
				}
				requireConfig := configStartGate.enabled && getConf
				var onConfigDelivered func()
				if requireConfig {
					onConfigDelivered = func() {
						atomic.StoreInt32(&configSent, 1)
						configStartGate.release()
						log.Printf("[ГРУППА #%d] Новое подключение зарегистрировано; запускаем остальные воркеры", groupID)
					}
				}

				credsSnapshot, credsRevision := credsState.snapshot()

				configDelivered, sessErr := RunSession(ctx, tp, peer, d, localPort,
					getConf, cc, requireConfig, onConfigDelivered, wid, &credsSnapshot,
					deviceID, password, deviceInfo,
					transportSession, stats, turnStreamFirst)
				refreshResult := credentialRefreshNone

				if getConf {
					if configDelivered {
						atomic.StoreInt32(&configSent, 1)
					} else {
						atomic.StoreInt32(&configRequestInFlight, 0)
					}
				}

				if sessErr != nil {
					if ctx.Err() != nil {
						return
					}
					if maxWorkers, limited := workerPolicyLimit(sessErr); limited {
						if shouldRetryWorkerPolicy(maxWorkers, requestedWorkers) {
							startedRound, round, waitErr := policyRetryGate.wait(ctx, wid)
							if startedRound && (round == 1 || round%6 == 0) {
								log.Printf(
									"[МОЩНОСТЬ] Лимит временно занят другими потоками этого доступа (максимум: %d); повторяем подключение",
									maxWorkers,
								)
							}
							if waitErr != nil {
								return
							}
							continue
						}
						log.Printf(
							"[МОЩНОСТЬ] Сервер остановил лишний поток согласно ограничению доступа (максимум: %d)",
							maxWorkers,
						)
						return
					}
					policyRetryGate.reset()
					errStr := sessErr.Error()
					errStrLower := strings.ToLower(errStr)

					turnAllocAttrMissing := strings.Contains(errStrLower, "turn allocate") &&
						strings.Contains(errStrLower, "attribute not found")
					turnCredRefreshNeeded := turnAllocAttrMissing || isCredentialTURNError(sessErr)
					turnCapacityLimited := isTURNCapacityError(sessErr)

					if strings.Contains(errStrLower, "rate limit") ||
						strings.Contains(errStrLower, "flood control") ||
						strings.Contains(errStrLower, "ip mismatch") ||
						strings.Contains(errStrLower, "error 29") {
						errStr += " (ошибка со стороны ВК)"
					}

					if strings.Contains(errStr, "хеш мёртв") ||
						strings.Contains(errStr, "FATAL_AUTH") {
						log.Printf("[ВОРКЕР #%d] Фатальная ошибка: %s", wid, errStr)
						return
					}

					attempt++
					if turnAllocAttrMissing {
						log.Printf("[ВОРКЕР #%d] [TURN] Allocate вернул неполный ответ, обновляем TURN-креды и повторяем (попытка %d): %s", wid, attempt, errStr)
						refreshResult = refreshCreds("TURN Allocate attribute-not-found", credsRevision)
					} else if turnCredRefreshNeeded {
						log.Printf("[ВОРКЕР #%d] [TURN] Ошибка allocation/кредов, обновляем TURN-креды и повторяем (попытка %d): %s", wid, attempt, errStr)
						refreshResult = refreshCreds("TURN allocation error", credsRevision)
					} else if turnCapacityLimited {
						log.Printf("[ВОРКЕР #%d] [TURN] Узел временно ограничил новые allocation; сохраняем креды и повторяем другие TURN-пути (попытка %d): %s", wid, attempt, errStr)
					} else {
						log.Printf("[ВОРКЕР #%d] Ошибка (попытка %d): %s", wid, attempt, errStr)
					}

					// Если ошибка STUN (credentials invalid), воркер не сможет переподключиться. Завершаем.
					isStunDeath := strings.Contains(errStrLower, "error 29") ||
						strings.Contains(errStrLower, "cannot create socket")

					if isStunDeath {
						log.Printf("[ВОРКЕР #%d] Невосстановимая TURN/STUN ошибка, завершение: %s", wid, errStr)
						return
					}
				}

				if ctx.Err() != nil {
					return
				}

				retryDelay := workerRetryDelayAfterCredentialRefresh(sessErr, refreshResult, workerIndex)
				select {
				case <-time.After(retryDelay):
				case <-ctx.Done():
					return
				}
			}
		}(i, wid)
	}

	wg.Wait()
	log.Printf("[ГРУППА #%d] Все воркеры группы завершились.", groupID)
}

func isTerminalGroupCredentialError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToUpper(err.Error())
	return strings.Contains(message, "INVALID_JOIN_LINK") ||
		strings.Contains(message, "ANON_BLOCKED") ||
		strings.Contains(message, "CALL_FULL") ||
		strings.Contains(message, "FATAL_AUTH")
}

func isHashFallbackCredentialError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToUpper(err.Error())
	return strings.Contains(message, "INVALID_JOIN_LINK") ||
		strings.Contains(message, "ANON_BLOCKED") ||
		strings.Contains(message, "CALL_FULL")
}

func hashRefreshOrder(current, total int, rotate bool) []int {
	if total <= 0 {
		return nil
	}
	current = ((current % total) + total) % total
	start := current
	if rotate && total > 1 {
		start = (current + 1) % total
	}
	order := make([]int, 0, total)
	for offset := 0; offset < total; offset++ {
		order = append(order, (start+offset)%total)
	}
	return order
}

func groupCredentialRetryDelay(err error) time.Duration {
	if err != nil {
		message := strings.ToUpper(err.Error())
		if strings.Contains(message, "CAPTCHA_WAIT_REQUIRED") || strings.Contains(message, "FATAL_CAPTCHA") {
			return 90 * time.Second
		}
	}
	return time.Duration(20+rand.Intn(21)) * time.Second
}

// ParseHashes — парсит строку хешей
func ParseHashes(raw string) []string {
	var result []string
	seen := make(map[string]struct{})
	for _, h := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		h = normalizeVKJoinHash(h)
		if h != "" {
			if _, exists := seen[h]; exists {
				continue
			}
			seen[h] = struct{}{}
			result = append(result, h)
		}
	}
	return result
}

func normalizeVKJoinHash(input string) string {
	s := strings.Trim(strings.TrimSpace(input), "<>\"'")
	if s == "" {
		return ""
	}

	lower := strings.ToLower(s)
	if idx := strings.Index(lower, "/call/join/"); idx >= 0 {
		s = s[idx+len("/call/join/"):]
	} else if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return ""
	}

	if idx := strings.IndexAny(s, "?#/"); idx != -1 {
		s = s[:idx]
	}
	return strings.Trim(strings.TrimSpace(s), "/")
}

// TurnParams — конфигурация TURN
type TurnParams struct {
	Host        string
	Port        string
	Hashes      []string
	TLSFrontSNI string
	Masque      *warpMasqueManager
	WrapKey     []byte // Password-derived WRAP key (32 bytes), nil = disabled
}

// Credentials — учетные данные TURN
type Credentials struct {
	User          string
	Pass          string
	TurnURLs      []string
	CacheStreamID int
}
