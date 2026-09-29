package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"wdtt.local/pathprobe"
)

const (
	defaultMaxWorkersPerAccess = 0
	defaultMaxHandshakes       = 32
	defaultHandshakeRate       = 24.0
	defaultClientMbps          = 0.0
)

type accessIdentity struct {
	id       string
	password string
	isMain   bool
}

func (i accessIdentity) valid() bool {
	return i.id != "" && i.password != ""
}

type wrappedSession struct {
	identity accessIdentity
}

var wrappedSessions sync.Map

func registerWrappedSession(addr net.Addr, identity accessIdentity) (string, *wrappedSession) {
	if addr == nil || !identity.valid() {
		return "", nil
	}
	key := addr.String()
	session := &wrappedSession{identity: identity}
	wrappedSessions.Store(key, session)
	return key, session
}

func unregisterWrappedSession(key string, session *wrappedSession) {
	if key == "" || session == nil {
		return
	}
	wrappedSessions.CompareAndDelete(key, session)
}

func wrappedIdentity(addr net.Addr) (accessIdentity, bool) {
	if addr == nil {
		return accessIdentity{}, false
	}
	value, ok := wrappedSessions.Load(addr.String())
	if !ok {
		return accessIdentity{}, false
	}
	session, ok := value.(*wrappedSession)
	if !ok || session == nil || !session.identity.valid() {
		return accessIdentity{}, false
	}
	return session.identity, true
}

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	now := time.Now()
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: now}
}

func (b *tokenBucket) allow(amount float64) bool {
	if b == nil || b.rate <= 0 || amount <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(time.Now())
	if b.tokens < amount {
		return false
	}
	b.tokens -= amount
	return true
}

func (b *tokenBucket) wait(ctx context.Context, amount int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.rate <= 0 || amount <= 0 {
		return nil
	}
	need := float64(amount)
	if need > b.burst {
		return errors.New("packet exceeds rate limiter burst capacity")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.mu.Lock()
		now := time.Now()
		b.refill(now)
		if b.tokens >= need {
			b.tokens -= need
			b.mu.Unlock()
			return nil
		}
		missing := need - b.tokens
		// Keep accumulated credit while waiting. Consuming a partial packet
		// here makes concurrent workers repeatedly destroy each other's
		// allowance and can stall a rate-limited access below its limit.
		wait := time.Duration(missing / b.rate * float64(time.Second))
		b.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (b *tokenBucket) refill(now time.Time) {
	if now.Before(b.last) {
		b.last = now
		return
	}
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
}

type accessRuntime struct {
	identity       accessIdentity
	activeWorkers  int
	everConnected  bool
	disconnectedAt time.Time
	currentDevice  string
	currentSession string
	workerAttempts map[uint32]uint64
	workers        map[*accessWorkerLease]struct{}
	upload         *tokenBucket
	download       *tokenBucket
	pendingDown    atomic.Int64
	pendingUp      atomic.Int64
}

type accessWorkerLease struct {
	worker     pathprobe.Worker
	retired    atomic.Bool
	runtime    *accessRuntime
	connection net.Conn
	session    string
}

type accessRuntimeRegistry struct {
	mu         sync.Mutex
	items      map[string]*accessRuntime
	maxWorkers int
	clientMbps float64
}

func newAccessRuntimeRegistry() *accessRuntimeRegistry {
	return &accessRuntimeRegistry{
		items:      make(map[string]*accessRuntime),
		maxWorkers: defaultMaxWorkersPerAccess,
		clientMbps: defaultClientMbps,
	}
}

var accessRuntimes = newAccessRuntimeRegistry()

func configureAccessRuntime(maxWorkers int, clientMbps float64) {
	if maxWorkers < 0 {
		maxWorkers = 0
	}
	if clientMbps < 0 {
		clientMbps = 0
	}
	accessRuntimes.mu.Lock()
	accessRuntimes.maxWorkers = maxWorkers
	accessRuntimes.clientMbps = clientMbps
	accessRuntimes.mu.Unlock()
}

func configuredAccessWorkerLimit() int {
	maxWorkers, _ := configuredAccessRuntimeLimits()
	return maxWorkers
}

func configuredAccessRuntimeLimits() (int, float64) {
	accessRuntimes.mu.Lock()
	defer accessRuntimes.mu.Unlock()
	return accessRuntimes.maxWorkers, accessRuntimes.clientMbps
}

func (r *accessRuntimeRegistry) getOrCreateLocked(identity accessIdentity) *accessRuntime {
	if item := r.items[identity.id]; item != nil {
		return item
	}
	bytesPerSecond := r.clientMbps * 1_000_000 / 8
	burst := bytesPerSecond / 4
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	if burst > 2*1024*1024 {
		burst = 2 * 1024 * 1024
	}
	item := &accessRuntime{
		identity: identity,
		workers:  make(map[*accessWorkerLease]struct{}),
		upload:   newTokenBucket(bytesPerSecond, burst),
		download: newTokenBucket(bytesPerSecond, burst),
	}
	r.items[identity.id] = item
	return item
}

func acquireAccessWorker(identity accessIdentity) (*accessRuntime, func(), bool) {
	runtime, _, release, ok := acquireAccessWorkerSession(identity, nil)
	return runtime, release, ok
}

func acquireAccessWorkerSession(
	identity accessIdentity,
	connection net.Conn,
) (*accessRuntime, *accessWorkerLease, func(), bool) {
	if !identity.valid() {
		return nil, nil, func() {}, false
	}
	accessRuntimes.mu.Lock()
	item := accessRuntimes.getOrCreateLocked(identity)
	activeForCurrentSession := item.activeWorkers
	if item.currentSession != "" {
		activeForCurrentSession = 0
		for worker := range item.workers {
			if worker.session == item.currentSession && !worker.retired.Load() {
				activeForCurrentSession++
			}
		}
	}
	if !identity.isMain && accessRuntimes.maxWorkers > 0 && activeForCurrentSession >= accessRuntimes.maxWorkers {
		accessRuntimes.mu.Unlock()
		atomic.AddInt64(&workerLimitRejections, 1)
		return nil, nil, func() {}, false
	}
	lease := &accessWorkerLease{
		runtime:    item,
		connection: connection,
		session:    item.currentSession,
	}
	item.workers[lease] = struct{}{}
	if item.activeWorkers == 0 && item.everConnected && !item.disconnectedAt.IsZero() {
		atomic.AddInt64(&reconnectCount, 1)
	}
	item.activeWorkers++
	item.everConnected = true
	item.disconnectedAt = time.Time{}
	accessRuntimes.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			accessRuntimes.mu.Lock()
			delete(item.workers, lease)
			if item.activeWorkers > 0 {
				item.activeWorkers--
			}
			if item.activeWorkers == 0 {
				item.disconnectedAt = time.Now()
			}
			accessRuntimes.mu.Unlock()
		})
	}
	return item, lease, release, true
}

// acquireAccessWorkerForSession admits an already authenticated GETCONF connection
// directly into its transport generation. A genuinely new generation replaces stale
// leases atomically before the worker limit is checked, so old UDP sessions cannot
// prevent the control connection from registering the replacement.
func acquireAccessWorkerForSession(
	identity accessIdentity,
	connection net.Conn,
	deviceID, session string,
	workerRef ...pathprobe.Worker,
) (*accessRuntime, *accessWorkerLease, func(), bool) {
	deviceID = strings.TrimSpace(deviceID)
	session = strings.TrimSpace(session)
	if !identity.valid() || deviceID == "" || !validTransportSession(session) {
		return nil, nil, func() {}, false
	}

	staleConnections := make([]net.Conn, 0)
	var ref pathprobe.Worker
	if len(workerRef) > 0 {
		ref = workerRef[0]
		if !ref.Valid() {
			return nil, nil, func() {}, false
		}
	}
	accessRuntimes.mu.Lock()
	item := accessRuntimes.getOrCreateLocked(identity)
	switch {
	case item.currentSession == "":
		item.workerAttempts = make(map[uint32]uint64)
		item.currentDevice = deviceID
		item.currentSession = session
		for worker := range item.workers {
			worker.session = session
		}
	case item.currentSession == session:
		if item.currentDevice != "" && item.currentDevice != deviceID {
			accessRuntimes.mu.Unlock()
			return nil, nil, func() {}, false
		}
		item.currentDevice = deviceID
	default:
		// The caller invokes this only after the persistent password/device binding
		// has authorized deviceID.
		item.currentDevice = deviceID
		item.currentSession = session
		item.workerAttempts = make(map[uint32]uint64)
		for worker := range item.workers {
			if worker.session == session {
				continue
			}
			worker.retired.Store(true)
			if worker.connection != nil {
				staleConnections = append(staleConnections, worker.connection)
			}
		}
	}
	if ref.Valid() && item.workerAttempts[ref.Slot] >= ref.Attempt {
		accessRuntimes.mu.Unlock()
		return nil, nil, func() {}, false
	}

	activeForSession := 0
	var replaced *accessWorkerLease
	for worker := range item.workers {
		if worker.session == session && !worker.retired.Load() {
			if ref.Valid() && worker.worker.Slot == ref.Slot {
				replaced = worker
				continue
			}
			activeForSession++
		}
	}
	if !identity.isMain && accessRuntimes.maxWorkers > 0 && activeForSession >= accessRuntimes.maxWorkers {
		accessRuntimes.mu.Unlock()
		atomic.AddInt64(&workerLimitRejections, 1)
		return nil, nil, func() {}, false
	}
	if replaced != nil {
		replaced.retired.Store(true)
		if replaced.connection != nil {
			staleConnections = append(staleConnections, replaced.connection)
		}
	}
	if ref.Valid() {
		if item.workerAttempts == nil {
			item.workerAttempts = make(map[uint32]uint64)
		}
		item.workerAttempts[ref.Slot] = ref.Attempt
	}

	lease := &accessWorkerLease{
		worker:     ref,
		runtime:    item,
		connection: connection,
		session:    session,
	}
	item.workers[lease] = struct{}{}
	if item.activeWorkers == 0 && item.everConnected && !item.disconnectedAt.IsZero() {
		atomic.AddInt64(&reconnectCount, 1)
	}
	item.activeWorkers++
	item.everConnected = true
	item.disconnectedAt = time.Time{}
	accessRuntimes.mu.Unlock()

	for _, staleConnection := range staleConnections {
		_ = staleConnection.SetDeadline(time.Now())
		_ = staleConnection.Close()
	}

	var once sync.Once
	release := func() {
		once.Do(func() {
			accessRuntimes.mu.Lock()
			delete(item.workers, lease)
			if item.activeWorkers > 0 {
				item.activeWorkers--
			}
			if item.activeWorkers == 0 {
				item.disconnectedAt = time.Now()
			}
			accessRuntimes.mu.Unlock()
		})
	}
	return item, lease, release, true
}

// activateAccessSession moves an authenticated device to a new transport generation.
// Workers from the preceding network are closed and stop consuming the current generation's
// quota immediately, even when their UDP sockets would otherwise linger until the idle timeout.
func activateAccessSession(lease *accessWorkerLease, deviceID, session string) bool {
	deviceID = strings.TrimSpace(deviceID)
	session = strings.TrimSpace(session)
	if lease == nil || lease.runtime == nil || deviceID == "" || !validTransportSession(session) {
		return false
	}

	item := lease.runtime
	staleConnections := make([]net.Conn, 0)
	accessRuntimes.mu.Lock()
	if _, exists := item.workers[lease]; !exists {
		accessRuntimes.mu.Unlock()
		return false
	}
	switch {
	case item.currentSession == "":
		item.currentDevice = deviceID
		item.currentSession = session
		for worker := range item.workers {
			worker.session = session
		}
	case item.currentSession == session:
		if item.currentDevice != "" && item.currentDevice != deviceID {
			accessRuntimes.mu.Unlock()
			return false
		}
		item.currentDevice = deviceID
		lease.session = session
	default:
		// handleConn calls this only after the persistent access binding has
		// authorized deviceID. A changed device therefore means an explicit
		// server-side rebind; close any sessions left by the previous device too.
		item.currentDevice = deviceID
		item.currentSession = session
		lease.session = session
		for worker := range item.workers {
			if worker == lease || worker.session == session {
				continue
			}
			if worker.connection != nil {
				staleConnections = append(staleConnections, worker.connection)
			}
		}
	}
	accessRuntimes.mu.Unlock()

	for _, connection := range staleConnections {
		_ = connection.SetDeadline(time.Now())
	}
	return true
}

func validTransportSession(value string) bool {
	if len(value) < 16 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func recordAccessTraffic(runtime *accessRuntime, downBytes, upBytes int64) {
	if runtime == nil {
		return
	}
	if downBytes > 0 {
		runtime.pendingDown.Add(downBytes)
	}
	if upBytes > 0 {
		runtime.pendingUp.Add(upBytes)
	}
}

func flushAccessTraffic() {
	accessRuntimes.mu.Lock()
	items := make([]*accessRuntime, 0, len(accessRuntimes.items))
	for _, item := range accessRuntimes.items {
		items = append(items, item)
	}
	accessRuntimes.mu.Unlock()

	dbMutex.Lock()
	defer dbMutex.Unlock()
	for _, item := range items {
		down := item.pendingDown.Swap(0)
		up := item.pendingUp.Swap(0)
		if down == 0 && up == 0 {
			continue
		}
		_ = addTrafficLocked(item.identity.password, item.identity.isMain, down, up)
	}
}

type accessIdentityState uint8

const (
	accessIdentityUnknown accessIdentityState = iota
	accessIdentityActive
	accessIdentityExpired
	accessIdentityDeactivated
)

func currentAccessIdentityState(identity accessIdentity) accessIdentityState {
	if !identity.valid() {
		return accessIdentityUnknown
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if identity.isMain {
		if db.MainPassword != "" && db.MainPassword == identity.password {
			return accessIdentityActive
		}
		return accessIdentityUnknown
	}
	entry, ok := db.Passwords[identity.password]
	if !ok || entry == nil {
		return accessIdentityUnknown
	}
	if isPasswordExpired(entry) {
		return accessIdentityExpired
	}
	if entry.IsDeactivated {
		return accessIdentityDeactivated
	}
	return accessIdentityActive
}

func accessIdentityExpiryUnix(identity accessIdentity) (int64, bool) {
	if !identity.valid() || identity.isMain {
		return 0, false
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	entry, ok := db.Passwords[identity.password]
	if !ok || entry == nil || entry.ExpiresAt <= 0 {
		return 0, false
	}
	return entry.ExpiresAt, true
}

func accessIdentityIsActive(identity accessIdentity) bool {
	return currentAccessIdentityState(identity) == accessIdentityActive
}

var (
	handshakeSlots        = make(chan struct{}, defaultMaxHandshakes)
	handshakeRateLimiter  = newTokenBucket(defaultHandshakeRate, defaultHandshakeRate*2)
	handshakeFailures     int64
	handshakeThrottles    int64
	workerLimitRejections int64
	reconnectCount        int64
)

func configureHandshakeLimits(maxConcurrent int, rate float64) {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if rate < 1 {
		rate = 1
	}
	handshakeSlots = make(chan struct{}, maxConcurrent)
	handshakeRateLimiter = newTokenBucket(rate, rate*2)
}

func acquireHandshake(ctx context.Context) (func(), bool) {
	if err := handshakeRateLimiter.wait(ctx, 1); err != nil {
		atomic.AddInt64(&handshakeThrottles, 1)
		return func() {}, false
	}
	select {
	case handshakeSlots <- struct{}{}:
		return func() { <-handshakeSlots }, true
	case <-ctx.Done():
		atomic.AddInt64(&handshakeThrottles, 1)
		return func() {}, false
	}
}

type procCPUSample struct {
	total uint64
	idle  uint64
}

type procNetworkSample struct {
	rxBytes uint64
	txBytes uint64
	drops   uint64
}

var (
	runtimeCPUMilli      int64
	runtimeMemoryMilli   int64
	runtimeNetworkRxKbps int64
	runtimeNetworkTxKbps int64
	runtimePacketDrops   int64
)

func systemMetricsLoop(ctx context.Context) {
	iface := getDefaultInterface()
	previousCPU, _ := readProcCPU()
	previousNetwork, _ := readProcNetwork(iface)
	previousAt := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			currentCPU, cpuErr := readProcCPU()
			if cpuErr == nil && currentCPU.total > previousCPU.total {
				totalDelta := currentCPU.total - previousCPU.total
				idleDelta := currentCPU.idle - previousCPU.idle
				busy := float64(totalDelta-idleDelta) / float64(totalDelta) * 100
				atomic.StoreInt64(&runtimeCPUMilli, int64(busy*1000))
				previousCPU = currentCPU
			}
			if memory, err := readProcMemoryPercent(); err == nil {
				atomic.StoreInt64(&runtimeMemoryMilli, int64(memory*1000))
			}
			currentNetwork, netErr := readProcNetwork(iface)
			elapsed := now.Sub(previousAt).Seconds()
			if netErr == nil && elapsed > 0 {
				if currentNetwork.rxBytes >= previousNetwork.rxBytes {
					rxMbps := float64(currentNetwork.rxBytes-previousNetwork.rxBytes) * 8 / elapsed / 1_000_000
					atomic.StoreInt64(&runtimeNetworkRxKbps, int64(rxMbps*1000))
				}
				if currentNetwork.txBytes >= previousNetwork.txBytes {
					txMbps := float64(currentNetwork.txBytes-previousNetwork.txBytes) * 8 / elapsed / 1_000_000
					atomic.StoreInt64(&runtimeNetworkTxKbps, int64(txMbps*1000))
				}
				udpDrops, _ := readProcUDPDrops()
				atomic.StoreInt64(
					&runtimePacketDrops,
					int64(currentNetwork.drops+udpDrops),
				)
				previousNetwork = currentNetwork
				previousAt = now
			}
		}
	}
}

func runtimeCPUPercent() float64 {
	return float64(atomic.LoadInt64(&runtimeCPUMilli)) / 1000
}

func runtimeMemoryPercent() float64 {
	return float64(atomic.LoadInt64(&runtimeMemoryMilli)) / 1000
}

func runtimeNetworkRxMbps() float64 {
	return float64(atomic.LoadInt64(&runtimeNetworkRxKbps)) / 1000
}

func runtimeNetworkTxMbps() float64 {
	return float64(atomic.LoadInt64(&runtimeNetworkTxKbps)) / 1000
}

func readProcCPU() (procCPUSample, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return procCPUSample{}, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return procCPUSample{}, errors.New("/proc/stat is empty")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return procCPUSample{}, errors.New("unexpected /proc/stat cpu row")
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, parseErr := strconv.ParseUint(field, 10, 64)
		if parseErr != nil {
			return procCPUSample{}, parseErr
		}
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return procCPUSample{total: total, idle: idle}, nil
}

func readProcMemoryPercent() (float64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	var total, available uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = value
		case "MemAvailable":
			available = value
		}
	}
	if total == 0 || available > total {
		return 0, errors.New("invalid /proc/meminfo")
	}
	return float64(total-available) / float64(total) * 100, nil
}

func readProcNetwork(iface string) (procNetworkSample, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return procNetworkSample{}, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	prefix := iface + ":"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
		if len(fields) < 16 {
			return procNetworkSample{}, fmt.Errorf("invalid /proc/net/dev row for %s", iface)
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		rxDrop, err2 := strconv.ParseUint(fields[3], 10, 64)
		tx, err3 := strconv.ParseUint(fields[8], 10, 64)
		txDrop, err4 := strconv.ParseUint(fields[11], 10, 64)
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			return procNetworkSample{}, err
		}
		return procNetworkSample{rxBytes: rx, txBytes: tx, drops: rxDrop + txDrop}, nil
	}
	if err := scanner.Err(); err != nil {
		return procNetworkSample{}, err
	}
	return procNetworkSample{}, fmt.Errorf("network interface %s not found", iface)
}

func readProcUDPDrops() (uint64, error) {
	data, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	for index := 0; index+1 < len(lines); index++ {
		if !strings.HasPrefix(lines[index], "Udp:") || !strings.HasPrefix(lines[index+1], "Udp:") {
			continue
		}
		headers := strings.Fields(strings.TrimPrefix(lines[index], "Udp:"))
		values := strings.Fields(strings.TrimPrefix(lines[index+1], "Udp:"))
		if len(headers) != len(values) {
			return 0, errors.New("invalid /proc/net/snmp Udp rows")
		}
		var drops uint64
		for position, header := range headers {
			if header != "InErrors" && header != "SndbufErrors" {
				continue
			}
			value, parseErr := strconv.ParseUint(values[position], 10, 64)
			if parseErr != nil {
				return 0, parseErr
			}
			drops += value
		}
		return drops, nil
	}
	return 0, errors.New("/proc/net/snmp has no Udp rows")
}
