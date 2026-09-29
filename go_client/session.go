package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wdtt.local/pathprobe"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

const (
	workerSendBuf                = 128
	sessionReadTimeout           = 30 * time.Second
	keepalivePongTimeout         = 75 * time.Second
	unansweredUserTrafficTimeout = 45 * time.Second
	readBufSize                  = 1600
	socketBufSize                = 625 * 1024
	keepaliveByte                = 0xFF // DTLS-level keepalive marker
	multipathRelayHello          = "WDTT_MUX1"
	keepaliveInterval            = 15 * time.Second
	workerWakeProbeRetryInterval = 3 * time.Second
	workerWakeProbeTimeout       = 12 * time.Second
	healthMonitorSuspendGap      = 30 * time.Second
	defaultHandshakeTimeout      = 20 * time.Second
	wrapHandshakeTimeout         = 8 * time.Second
)

func runWorkerWakeProbeLoop(
	ctx context.Context,
	slot *WorkerSlot,
	writeKeepalive func(time.Time) bool,
	timeout time.Duration,
	retryInterval time.Duration,
	onExpired func(uint64),
) {
	if slot == nil || slot.WakeCh == nil || writeKeepalive == nil {
		return
	}
	if timeout <= 0 {
		timeout = workerWakeProbeTimeout
	}
	if retryInterval <= 0 || retryInterval >= timeout {
		retryInterval = timeout
	}

	var activeGeneration uint64
	var timeoutTimer *time.Timer
	var retryTicker *time.Ticker
	var timeoutCh <-chan time.Time
	var retryCh <-chan time.Time
	stopProbe := func() {
		activeGeneration = 0
		if timeoutTimer != nil {
			if !timeoutTimer.Stop() {
				select {
				case <-timeoutTimer.C:
				default:
				}
			}
			timeoutTimer = nil
		}
		if retryTicker != nil {
			retryTicker.Stop()
			retryTicker = nil
		}
		timeoutCh = nil
		retryCh = nil
	}
	drainAcks := func() {
		if slot.WakeAckCh == nil {
			return
		}
		for {
			select {
			case <-slot.WakeAckCh:
			default:
				return
			}
		}
	}
	startProbe := func(generation uint64) bool {
		stopProbe()
		drainAcks()
		activeGeneration = generation
		if !writeKeepalive(time.Now()) {
			return false
		}
		timeoutTimer = time.NewTimer(timeout)
		timeoutCh = timeoutTimer.C
		if retryInterval < timeout {
			retryTicker = time.NewTicker(retryInterval)
			retryCh = retryTicker.C
		}
		return true
	}

	defer stopProbe()
	for {
		select {
		case <-ctx.Done():
			return
		case <-slot.SleepCh:
			// A wake probe is meaningful only while the device remains awake.
			// Cancelling it here prevents an intentional second sleep from being
			// misclassified as a dead transport path.
			stopProbe()
			drainAcks()
		case generation := <-slot.WakeCh:
			if generation == 0 {
				continue
			}
			if !startProbe(generation) {
				if onExpired != nil {
					onExpired(generation)
				}
				return
			}
		case generation := <-slot.WakeAckCh:
			if activeGeneration != 0 && generation >= activeGeneration {
				stopProbe()
			}
		case now := <-retryCh:
			if activeGeneration != 0 && !writeKeepalive(now) {
				generation := activeGeneration
				if onExpired != nil {
					onExpired(generation)
				}
				return
			}
		case <-timeoutCh:
			generation := activeGeneration
			// If the final pong and the timeout became ready together, prefer the
			// pong. Otherwise select could randomly discard a transport that did
			// answer within the probe window.
			if slot.WakeAckCh != nil {
				select {
				case acknowledged := <-slot.WakeAckCh:
					if generation != 0 && acknowledged >= generation {
						stopProbe()
						continue
					}
				default:
				}
			}
			if generation != 0 && onExpired != nil {
				onExpired(generation)
			}
			return
		}
	}
}

// Handshake semaphore: limit to 3 concurrent DTLS handshakes
var handshakeSem = make(chan struct{}, 3)

func dtlsHandshakeTimeout(useWrap bool) time.Duration {
	if useWrap {
		return wrapHandshakeTimeout
	}
	return defaultHandshakeTimeout
}

// NullLoggerFactory подавляет логи pion
type NullLoggerFactory struct{}

func (n *NullLoggerFactory) NewLogger(_ string) logging.LeveledLogger { return &NullLogger{} }

type NullLogger struct{}

func (n *NullLogger) Trace(_ string)                    {}
func (n *NullLogger) Tracef(_ string, _ ...interface{}) {}
func (n *NullLogger) Debug(_ string)                    {}
func (n *NullLogger) Debugf(_ string, _ ...interface{}) {}
func (n *NullLogger) Info(_ string)                     {}
func (n *NullLogger) Infof(_ string, _ ...interface{})  {}
func (n *NullLogger) Warn(_ string)                     {}
func (n *NullLogger) Warnf(_ string, _ ...interface{})  {}
func (n *NullLogger) Error(_ string)                    {}
func (n *NullLogger) Errorf(_ string, _ ...interface{}) {}

// connectedUDPConn — обёртка для connected UDP socket → PacketConn
type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

// splitFirstWriteConn fragments the first STUN request so its magic cookie
// crosses TCP segment boundaries. Some shallow DPI rules classify plain TURN
// by looking only at the first segment. This wrapper is enabled exclusively by
// stream-first connection modes; ordinary mode keeps the original writes.
type splitFirstWriteConn struct {
	net.Conn
	splitAt int
	delay   time.Duration
	done    atomic.Bool
}

func writeFull(conn net.Conn, payload []byte) (int, error) {
	total := 0
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		total += n
		payload = payload[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (conn *splitFirstWriteConn) Write(payload []byte) (int, error) {
	if !conn.done.CompareAndSwap(false, true) || len(payload) <= conn.splitAt {
		return conn.Conn.Write(payload)
	}
	first, err := writeFull(conn.Conn, payload[:conn.splitAt])
	if err != nil {
		return first, err
	}
	if conn.delay > 0 {
		time.Sleep(conn.delay)
	}
	second, err := writeFull(conn.Conn, payload[conn.splitAt:])
	return first + second, err
}

func normalizeTURNFrontSNI(value string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	if host == "" {
		return "", nil
	}
	if len(host) > 253 || net.ParseIP(host) != nil || strings.HasPrefix(host, ".") ||
		strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return "", fmt.Errorf("ожидалось доменное имя длиной до 253 символов")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("ожидалось доменное имя как ya.ru")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("некорректная метка домена")
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", fmt.Errorf("разрешены только латинские буквы, цифры, дефис и точки")
			}
		}
	}
	return host, nil
}

func verifyTURNPeerCertificate(state tls.ConnectionState, hostname string, roots *x509.CertPool) error {
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("TURN TLS не прислал сертификат")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		DNSName:       hostname,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("проверка цепочки сертификата TURN TLS: %w", err)
	}
	return nil
}

func turnTLSConfig(endpoint turnEndpoint, frontSNI string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	serverName := endpoint.Host
	if frontSNI != "" {
		serverName = frontSNI
	}
	if net.ParseIP(serverName) == nil {
		config.ServerName = serverName
	}

	// При подмене SNI имя сертификата ожидаемо относится к TURN-узлу, а не к
	// домену белого списка. VerifyConnection проверяет цепочку И настоящее
	// имя TURN-узла из реквизитов; frontSNI не является доверенной личностью.
	if frontSNI != "" && !strings.EqualFold(frontSNI, endpoint.Host) {
		config.InsecureSkipVerify = true // проверка перенесена в VerifyConnection
		config.VerifyConnection = func(state tls.ConnectionState) error {
			return verifyTURNPeerCertificate(state, endpoint.Host, nil)
		}
	}
	return config
}

func turnPathSNI(endpoint turnEndpoint, frontSNI string, rtMode bool) string {
	if endpoint.Transport != turnTransportTLS {
		if endpoint.Transport == turnTransportTCP && rtMode {
			return "SNI не применяется, первый STUN-запрос разделён для DPI"
		}
		return "SNI не применяется"
	}
	if frontSNI != "" {
		return "SNI=" + frontSNI
	}
	if net.ParseIP(endpoint.Host) == nil {
		return "SNI=" + endpoint.Host
	}
	return "без SNI"
}

func openTURNAllocation(
	ctx context.Context,
	endpoint turnEndpoint,
	peer *net.UDPAddr,
	creds *Credentials,
	sessionID int,
	frontSNI string,
	splitTCPFirstWrite bool,
) (*turn.Client, net.PacketConn, error) {
	turnAddr := endpoint.address()

	var turnConn net.PacketConn
	switch endpoint.Transport {
	case turnTransportUDP:
		dialer := &net.Dialer{Timeout: 6 * time.Second}
		raw, err := dialer.DialContext(ctx, "udp", turnAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("TURN UDP подключение %s: %w", turnAddr, err)
		}
		c := raw.(*net.UDPConn)
		_ = c.SetReadBuffer(socketBufSize)
		_ = c.SetWriteBuffer(socketBufSize)
		turnConn = &connectedUDPConn{c}
	case turnTransportTCP:
		dialCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		dialer := &net.Dialer{Timeout: 6 * time.Second, KeepAlive: 30 * time.Second}
		rawConn, err := dialer.DialContext(dialCtx, "tcp", turnAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("TURN TCP подключение %s: %w", turnAddr, err)
		}
		var conn net.Conn = rawConn
		if splitTCPFirstWrite {
			conn = &splitFirstWriteConn{Conn: rawConn, splitAt: 6, delay: 20 * time.Millisecond}
		}
		turnConn = turn.NewSTUNConn(conn)
	case turnTransportTLS:
		dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second},
			Config:    turnTLSConfig(endpoint, frontSNI),
		}
		conn, err := dialer.DialContext(dialCtx, "tcp", turnAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("TURN TLS подключение %s: %w", turnAddr, err)
		}
		turnConn = turn.NewSTUNConn(conn)
	default:
		return nil, nil, fmt.Errorf("неподдерживаемый TURN transport: %s", endpoint.Transport)
	}

	stop := context.AfterFunc(ctx, func() { _ = turnConn.Close() })
	defer stop()
	return allocateTURNOnConn(endpoint, peer, creds, turnConn)
}

func allocateTURNOnConn(
	endpoint turnEndpoint,
	peer *net.UDPAddr,
	creds *Credentials,
	turnConn net.PacketConn,
) (*turn.Client, net.PacketConn, error) {
	deletion := &turnDeletionTransport{PacketConn: turnConn, ack: make(chan struct{})}
	turnConn = deletion
	owned := false
	defer func() {
		if !owned {
			_ = turnConn.Close()
		}
	}()
	turnAddr := endpoint.address()

	// RequestedAddressFamily
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	tc, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   turnConn,
		Username:               creds.User,
		Password:               creds.Pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          &NullLoggerFactory{},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("TURN %s клиент %s: %w", endpoint.label(), turnAddr, err)
	}

	if err = tc.Listen(); err != nil {
		tc.Close()
		return nil, nil, fmt.Errorf("TURN %s Listen %s: %w", endpoint.label(), turnAddr, err)
	}

	relay, err := tc.Allocate()
	if err != nil {
		if isAuthError(err) {
			handleAuthError(creds.CacheStreamID, creds.User, creds.Pass)
		}
		errStr := err.Error()
		if strings.Contains(errStr, "Quota") || strings.Contains(errStr, "486") {
			tc.Close()
			return nil, nil, fmt.Errorf("TURN квота: %w", err)
		}
		tc.Close()
		return nil, nil, fmt.Errorf("TURN %s Allocate %s: %w", endpoint.label(), turnAddr, err)
	}

	owned = true
	return tc, &ownedTURNAllocation{PacketConn: relay, transport: turnConn, closeClient: tc.Close, deletion: deletion}, nil
}

func openTURNAllocationOverMasque(
	ctx context.Context,
	endpoint turnEndpoint,
	peer *net.UDPAddr,
	creds *Credentials,
	manager *warpMasqueManager,
	protocol warpMasqueProtocol,
) (*turn.Client, net.PacketConn, error) {
	if endpoint.Transport == turnTransportUDP {
		return nil, nil, errors.New("TURN/UDP нельзя передать через TCP-поток CONNECT-IP")
	}

	rawConn, err := manager.dialProtocol(ctx, endpoint.address(), protocol)
	if err != nil {
		return nil, nil, fmt.Errorf("MASQUE %s к %s: %w", protocol, endpoint.address(), err)
	}
	var conn net.Conn = rawConn
	if endpoint.Transport == turnTransportTLS {
		tlsConn := tls.Client(rawConn, turnTLSConfig(endpoint, ""))
		handshakeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err = tlsConn.HandshakeContext(handshakeCtx)
		cancel()
		if err != nil {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("TURN TLS внутри MASQUE %s к %s: %w", protocol, endpoint.address(), err)
		}
		conn = tlsConn
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	return allocateTURNOnConn(endpoint, peer, creds, turn.NewSTUNConn(conn))
}

func isCredentialTURNError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "turn allocate auth") ||
		strings.Contains(text, "unauthorized") ||
		strings.Contains(text, "authentication") ||
		strings.Contains(text, "error 401") ||
		strings.Contains(text, "invalid credential") ||
		strings.Contains(text, "stale nonce") ||
		strings.Contains(text, "allocation mismatch") ||
		strings.Contains(text, "attribute not found")
}

func isTURNCapacityError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "turn квота") ||
		strings.Contains(text, "error 508") ||
		strings.Contains(text, "quota")
}

func turnCandidateStages(candidates []turnEndpoint, useMasque bool) (direct, masque, finalUDP []turnEndpoint) {
	if !useMasque {
		return candidates, nil, nil
	}
	for _, candidate := range candidates {
		if candidate.Transport == turnTransportUDP {
			finalUDP = append(finalUDP, candidate)
			continue
		}
		direct = append(direct, candidate)
		masque = append(masque, candidate)
	}
	return direct, masque, finalUDP
}

func RunSession(
	ctx context.Context,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	getConfig bool,
	configCh chan<- string,
	requireConfig bool,
	onConfigDelivered func(),
	sessionID int,
	creds *Credentials,
	deviceID, password, deviceInfo, transportSession string,
	stats *Stats,
	preferTURNStream bool,
	turnCandidateRetry int,
	onTURNAllocated func(),
) (delivered bool, sessionErr error) {
	replacingUplink, recoveryComplete := d.uplinkRecovery.completion(sessionID)
	defer recoveryComplete()
	configDelivered := false
	useWrap := len(tp.WrapKey) == wrapKeyLen

	if len(creds.TurnURLs) == 0 {
		return false, fmt.Errorf("нет TURN URL в учетных данных")
	}
	candidates := sessionTURNCandidatesForAttempt(
		creds.TurnURLs,
		sessionID,
		turnCandidateRetry,
		tp,
		preferTURNStream,
	)
	if len(candidates) == 0 {
		return false, fmt.Errorf("нет пригодных TURN URL в учетных данных")
	}
	var autoLease *connectionLease
	var startupTimer *time.Timer
	if tp.Auto != nil {
		outerCtx := ctx
		var acquireErr error
		autoLease, acquireErr = tp.Auto.acquire(ctx, connectionPaths(candidates, tp, tp.NoUDP))
		if acquireErr != nil {
			return false, acquireErr
		}
		defer func() {
			failure := sessionErr
			if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
				failure = context.DeadlineExceeded
			}
			autoLease.finish(failure, outerCtx.Err() != nil)
		}()
		var cancelCause context.CancelCauseFunc
		ctx, cancelCause = context.WithCancelCause(ctx)
		attemptCancel := func() { cancelCause(context.Canceled) }
		autoLease.bind(attemptCancel)
		defer attemptCancel()
		// Includes Allocate, relay handshake and authenticated registration.
		budget := 30 * time.Second
		if autoLease.path.masque != "" {
			budget = 60 * time.Second
		}
		startupTimer = time.AfterFunc(budget, func() { cancelCause(context.DeadlineExceeded) })
		defer startupTimer.Stop()
		candidates = []turnEndpoint{autoLease.path.endpoint}
	}
	if tp.NoUDP {
		filtered := candidates[:0]
		for _, c := range candidates {
			if c.Transport != turnTransportUDP {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}
	directCandidates, masqueCandidates, finalUDPCandidates := turnCandidateStages(candidates, tp.Masque != nil)

	var tc *turn.Client
	var relay net.PacketConn
	var selectedEndpoint turnEndpoint
	var selectedMasqueProtocol warpMasqueProtocol
	var lastTURNErr error
	var err error
	if autoLease != nil {
		p := autoLease.path
		if p.masque != "" {
			tc, relay, err = openTURNAllocationOverMasque(ctx, p.endpoint, peer, creds, tp.Masque, p.masque)
		} else {
			tc, relay, err = openTURNAllocation(ctx, p.endpoint, peer, creds, sessionID, p.front, true)
		}
		if err != nil {
			return false, err
		}
		selectedEndpoint, selectedMasqueProtocol = p.endpoint, p.masque
	} else {
		for idx, candidate := range directCandidates {
			if !preferTURNStream && idx == 0 {
				log.Printf("[СЕССИЯ #%d] TURN %s (%s)", sessionID, candidate.label(), candidate.address())
			} else if !preferTURNStream {
				log.Printf("[СЕССИЯ #%d] [TURN] Резервный путь %s (%s) после ошибки: %v", sessionID, candidate.label(), candidate.address(), lastTURNErr)
			} else if idx == 0 {
				log.Printf("[СЕССИЯ #%d] [TURN] Путь %s (%s), %s", sessionID, candidate.label(), candidate.address(), turnPathSNI(candidate, tp.TLSFrontSNI, preferTURNStream))
			} else {
				log.Printf("[СЕССИЯ #%d] [TURN] Резервный путь %s (%s), %s, после ошибки: %v", sessionID, candidate.label(), candidate.address(), turnPathSNI(candidate, tp.TLSFrontSNI, preferTURNStream), lastTURNErr)
			}

			tc, relay, err = openTURNAllocation(ctx, candidate, peer, creds, sessionID, tp.TLSFrontSNI, preferTURNStream)
			if err == nil {
				selectedEndpoint = candidate
				break
			}
			lastTURNErr = err
			if isCredentialTURNError(err) {
				return false, err
			}
		}
		if relay == nil && tp.Masque != nil {
			log.Printf("[СЕССИЯ #%d] [MASQUE] Прямые TCP/TLS-пути не сработали; пробуем резерв MASQUE: %v", sessionID, lastTURNErr)
		masqueProtocols:
			for _, protocol := range tp.Masque.protocolOrder() {
				if tp.NoUDP && protocol == warpMasqueHTTP3 {
					continue
				}
				for _, candidate := range masqueCandidates {
					log.Printf("[СЕССИЯ #%d] [MASQUE] Пробуем TURN %s (%s) внутри CONNECT-IP %s", sessionID, candidate.label(), candidate.address(), protocol)
					tc, relay, err = openTURNAllocationOverMasque(ctx, candidate, peer, creds, tp.Masque, protocol)
					if err == nil {
						selectedEndpoint = candidate
						selectedMasqueProtocol = protocol
						tp.Masque.markPreferred(protocol)
						break masqueProtocols
					}
					lastTURNErr = err
					log.Printf("[СЕССИЯ #%d] [MASQUE] %s через %s не сработал: %v", sessionID, candidate.label(), protocol, err)
					if isCredentialTURNError(err) {
						return false, err
					}
				}
			}
		}
		if relay == nil && tp.Masque != nil {
			for _, candidate := range finalUDPCandidates {
				log.Printf("[СЕССИЯ #%d] [TURN] Последний резерв после MASQUE: %s (%s), после ошибки: %v", sessionID, candidate.label(), candidate.address(), lastTURNErr)
				tc, relay, err = openTURNAllocation(ctx, candidate, peer, creds, sessionID, tp.TLSFrontSNI, preferTURNStream)
				if err == nil {
					selectedEndpoint = candidate
					break
				}
				lastTURNErr = err
				if isCredentialTURNError(err) {
					return false, err
				}
			}
		}
	}
	if relay == nil && lastTURNErr == nil {
		return false, fmt.Errorf("нет разрешённых путей подключения")
	}
	if lastTURNErr != nil && relay == nil {
		return false, lastTURNErr
	}
	defer relay.Close()

	// Reset error count on successful allocation
	getStreamCache(creds.CacheStreamID).errorCount.Store(0)
	if onTURNAllocated != nil {
		onTURNAllocated()
	}

	if selectedMasqueProtocol != "" {
		log.Printf("[СЕССИЯ #%d] Relay: %s через TURN %s внутри MASQUE %s ✓", sessionID, relay.LocalAddr(), selectedEndpoint.label(), selectedMasqueProtocol)
	} else {
		log.Printf("[СЕССИЯ #%d] Relay: %s через TURN %s", sessionID, relay.LocalAddr(), selectedEndpoint.label())
	}
	// Pipe для DTLS ↔ TURN relay
	pipeA, pipeB := connutil.AsyncPacketPipe()

	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()

	// Keepalive goroutine (TURN binding request)
	var sessionWg sync.WaitGroup
	sessionWg.Add(1)
	go func() {
		defer sessionWg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-t.C:
				tc.SendBindingRequest()
			}
		}
	}()

	// Relay ↔ Pipe proxy (with RTP obfuscation)
	var relayWg sync.WaitGroup
	relayWg.Add(2)

	// Initialize obfs config per session
	var obfsCfg *ObfsConfig
	var obfsWriteState *ObfsState
	if useWrap {
		obfsCfg = NewObfsConfig()
		obfsWriteState = NewObfsState()
	}

	stopRelay := context.AfterFunc(sessCtx, func() {
		_ = relay.SetDeadline(time.Now())
		_ = pipeA.SetDeadline(time.Now())
	})
	defer stopRelay()

	// relay → pipeA (UNWRAP: strip RTP header + decrypt)
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		// Max incoming: RTP header (12) + AEAD tag (16) + padding.
		readBufLen := readBufSize + 80
		buf := make([]byte, readBufLen)
		plain := make([]byte, readBufSize)
		for {
			n, _, readErr := relay.ReadFrom(buf)
			if readErr != nil {
				return
			}
			payload := buf[:n]
			if useWrap {
				if !obfsIsRTPPacket(payload) {
					log.Printf("[СЕССИЯ #%d] OBFS unwrap: unexpected packet (n=%d)", sessionID, n)
					continue
				}
				m, wrapErr := obfsUnwrapPacket(tp.WrapKey, payload, plain)
				if wrapErr != nil {
					log.Printf("[СЕССИЯ #%d] OBFS unwrap: %v (n=%d)", sessionID, wrapErr, n)
					continue
				}
				payload = plain[:m]
			}
			if _, writeErr := pipeA.WriteTo(payload, peer); writeErr != nil {
				return
			}
		}
	}()

	// pipeA → relay (WRAP: add RTP header + encrypt)
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		b := make([]byte, readBufSize)
		var reusableWrap []byte
		for {
			n, _, readErr := pipeA.ReadFrom(b)
			if readErr != nil {
				return
			}
			out := b[:n]
			if useWrap {
				if obfsCfg != nil && obfsWriteState != nil {
					wrapped, wrapErr := obfsWrapPacketInto(reusableWrap, tp.WrapKey, out, obfsCfg, obfsWriteState)
					if wrapErr != nil {
						log.Printf("[СЕССИЯ #%d] OBFS wrap: %v", sessionID, wrapErr)
						return
					}
					out = wrapped
				}
			}
			if _, writeErr := relay.WriteTo(out, peer); writeErr != nil {
				return
			}
		}
	}()

	// Handshake, admission and experiment negotiation can all return early.
	// Close both directions before joining so a failed path cannot leave a
	// blocked pipe writer or TURN reader alive until process shutdown.
	defer func() {
		sessCancel()
		_ = relay.Close()
		_ = pipeA.Close()
		_ = pipeB.Close()
		relayWg.Wait()
		sessionWg.Wait()
	}()

	// DTLS с поддержкой Connection ID (без SNI)
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return false, fmt.Errorf("генерация сертификата: %w", err)
	}

	// Acquire handshake semaphore
	if autoLease != nil {
		autoLease.setStage("dtls")
	}
	select {
	case handshakeSem <- struct{}{}:
	case <-sessCtx.Done():
		return false, sessCtx.Err()
	}

	dtlsCfg := &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
		// No ServerName (SNI) — less detectable by DPI
	}

	dtlsConn, err := dtls.Client(pipeB, peer, dtlsCfg)
	if err != nil {
		<-handshakeSem
		return false, fmt.Errorf("DTLS клиент: %w", err)
	}
	defer dtlsConn.Close()

	hctx, hcancel := context.WithTimeout(sessCtx, dtlsHandshakeTimeout(useWrap))
	log.Printf("[ВОРКЕР #%d] [DTLS] Рукопожатие (Handshake)...", sessionID)
	err = dtlsConn.HandshakeContext(hctx)
	hcancel()
	<-handshakeSem // RELEASE SEMAPHORE IMMEDIATELY AFTER HANDSHAKE

	if err != nil {
		if useWrap {
			errStr := strings.ToLower(err.Error())
			if strings.Contains(errStr, "deadline") || strings.Contains(errStr, "timeout") {
				return false, fmt.Errorf("WRAP_AUTH_TIMEOUT: отдельный DTLS-канал не ответил вовремя")
			}
		}
		return false, fmt.Errorf("DTLS хендшейк до VPS %s не прошёл: %w", peer.String(), err)
	}
	log.Printf("[ВОРКЕР #%d] [DTLS] Соединение установлено ✓", sessionID)

	// Отмена должна прерывать и стартовый GETCONF. Раньше deadline
	// устанавливался только после получения конфига, поэтому остановка во время
	// подключения могла ждать принудительного завершения процесса на Android.
	stopDTLS := context.AfterFunc(sessCtx, func() {
		_ = dtlsConn.SetDeadline(time.Now())
	})
	defer stopDTLS()

	transportMode := tp.Experiment
	// Запрос конфига
	{ // Every worker must authenticate its device before joining the relay.
		if autoLease != nil {
			autoLease.setStage("registration")
		}
		conf, confErr := RequestConfig(
			sessCtx,
			dtlsConn,
			localPort,
			deviceID,
			password,
			deviceInfo,
			transportSession,
			pathprobe.Worker{Slot: uint32(sessionID), Attempt: d.workerAttempt.Add(1)},
		)
		if confErr != nil {
			if _, limited := workerPolicyLimit(confErr); limited {
				return false, confErr
			}
			errStr := confErr.Error()
			if strings.Contains(errStr, "FATAL_AUTH") {
				return false, confErr
			}
			return false, fmt.Errorf("регистрация нового подключения: %w", confErr)
		}
		if conf == "" {
			return false, fmt.Errorf("сервер ещё не выдал конфигурацию")
		}
		transportMode = d.resolveTransport(conf)
		if autoLease != nil {
			autoLease.setStage("protocol")
		}
		if err := negotiateTransportExperiment(sessCtx, dtlsConn, conf, transportMode); err != nil {
			return false, err
		}
		if autoLease != nil {
			autoLease.setStage("confirmation")
			if err := confirmConnectionPath(sessCtx, dtlsConn); err != nil {
				return false, err
			}
			if !startupTimer.Stop() || ctx.Err() != nil {
				return false, context.DeadlineExceeded
			}
			if !autoLease.accept() {
				return false, context.Canceled
			}
			if selectedMasqueProtocol != "" {
				tp.Masque.markPreferred(selectedMasqueProtocol)
			}
		}
		if getConfig && configCh != nil {
			select {
			case configCh <- conf:
				configDelivered = true
				log.Printf("[ВОРКЕР #%d] Конфиг получен", sessionID)
			default:
				configDelivered = true
				log.Printf("[ВОРКЕР #%d] Конфиг уже был доставлен другим воркером", sessionID)
			}
			if onConfigDelivered != nil {
				onConfigDelivered()
			}
		}
	}

	stats.ActiveConnections.Add(1)
	globalActiveConnections.Add(1)
	defer func() {
		stats.ActiveConnections.Add(-1)
		globalActiveConnections.Add(-1)
	}()

	log.Printf("[ВОРКЕР #%d] [READY] Туннель готов к работе ✓", sessionID)

	// Регистрация в диспетчере
	slot := &WorkerSlot{
		ID:        sessionID,
		SendCh:    make(chan []byte, workerSendBuf),
		WakeCh:    make(chan uint64, 1),
		SleepCh:   make(chan struct{}, 1),
		WakeAckCh: make(chan uint64, 1),
	}
	var uplinkReplacement atomic.Bool
	if transportMode == experimentUplink {
		slot.uplink = &uplinkQuality{id: sessionID, pacer: d.uplinkPacing}
		slot.uplink.sleeping = d.deviceSleeping.Load
		slot.uplink.probeWait = d.uplinkPacing.probes.Wait
		slot.uplink.replace = func() bool {
			if !d.canReplaceUplink(sessionID) {
				return false
			}
			uplinkReplacement.Store(true)
			return true
		}
		if replacingUplink {
			slot.uplink.muted.Store(true)
			slot.uplink.probation.Store(true)
		}
	}
	var measuredPackets <-chan timedDatagram
	if transportMetricsEnabled {
		slot.queue = newTransportQueue(workerSendBuf)
		measuredPackets = slot.queue.items
		go slot.queue.run(sessCtx, "client_uplink", transportMode)
	}
	d.Register(slot)
	d.uplinkRecovery.registered(sessionID)
	recoveryComplete()
	defer d.Unregister(slot)

	var lastServerRxAt atomic.Int64
	lastServerRxAt.Store(time.Now().UnixNano())
	var keepalivePongSeen atomic.Int32
	policyLimitCh := make(chan int, 1)
	var dtlsWriteMu sync.Mutex

	// Proxy DTLS ↔ Dispatcher
	var proxyWg sync.WaitGroup
	proxyWg.Add(5) // writer + reader + keepalive + wake probe + health monitor

	writeKeepalive := func(now time.Time) bool {
		ping := []byte{keepaliveByte}
		dtlsWriteMu.Lock()
		defer dtlsWriteMu.Unlock()
		_ = dtlsConn.SetWriteDeadline(now.Add(5 * time.Second))
		_, err := dtlsConn.Write(ping)
		return err == nil
	}

	if slot.uplink != nil {
		proxyWg.Add(1)
		go func() {
			defer proxyWg.Done()
			slot.uplink.run(sessCtx, func(p []byte) error {
				dtlsWriteMu.Lock()
				defer dtlsWriteMu.Unlock()
				_ = dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, err := dtlsConn.Write(p)
				return err
			}, sessCancel)
		}()
	}

	// DTLS Keepalive: prevents TURN allocation timeout and DTLS idle disconnect
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		// Проверяем каждый новый канал сразу, чтобы Android получил раннее
		// подтверждение, что новый процесс действительно видит сервер.
		if !writeKeepalive(time.Now()) {
			return
		}
		t := time.NewTicker(keepaliveInterval)
		defer t.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case now := <-t.C:
				if !writeKeepalive(now) {
					return
				}
			}
		}
	}()

	// A phone may keep a stale UDP/DTLS socket looking active throughout Doze.
	// Probe each existing worker independently on wake. Healthy workers stay in
	// place; only a worker that misses several quick pings is re-created by its
	// WorkerGroup with the already cached TURN credentials.
	go func() {
		defer proxyWg.Done()
		runWorkerWakeProbeLoop(
			sessCtx,
			slot,
			writeKeepalive,
			workerWakeProbeTimeout,
			workerWakeProbeRetryInterval,
			func(_ uint64) {
				log.Printf("[ВОРКЕР #%d] [HEALTH] канал не ответил на проверки после пробуждения, переподключаем только этот воркер", sessionID)
				sessCancel()
			},
		)
	}()

	// Health monitor: UDP can fail silently, so expect keepalive pongs or user traffic responses.
	go func() {
		defer proxyWg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		lastHealthCheckAt := time.Now()
		var schedulerResumeGraceUntil time.Time
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-t.C:
				now := time.Now()
				if now.Sub(lastHealthCheckAt) > healthMonitorSuspendGap {
					// DEVICE_SLEEP/WAKE может быть доставлен с задержкой отдельными
					// производителями Android. Большой разрыв самого Go-таймера —
					// дополнительный признак приостановки процесса в Doze.
					schedulerResumeGraceUntil = now.Add(deviceWakeHealthGrace)
				}
				lastHealthCheckAt = now
				if d.shouldSuppressTransportHealth(now) || now.Before(schedulerResumeGraceUntil) {
					continue
				}
				lastRxUnix := lastServerRxAt.Load()
				lastRx := time.Unix(0, lastRxUnix)

				if keepalivePongSeen.Load() != 0 && now.Sub(lastRx) > keepalivePongTimeout {
					log.Printf("[ВОРКЕР #%d] [HEALTH] сервер не отвечает на keepalive %.0f сек, перезапуск воркера", sessionID, now.Sub(lastRx).Seconds())
					sessCancel()
					return
				}

				if stalledFor, stalled := d.claimStalledUserTraffic(now, unansweredUserTrafficTimeout); stalled {
					log.Printf("[ВОРКЕР #%d] [HEALTH] отправлен пользовательский трафик, но ответа сервера нет %.0f сек, перезапуск воркера", sessionID, stalledFor.Seconds())
					sessCancel()
					return
				}
			}
		}
	}()

	// Writer: dispatcher → DTLS
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		var framedPacket []byte
		for {
			var pkt []byte
			select {
			case <-sessCtx.Done():
				return
			case queued := <-measuredPackets:
				slot.queue.noteDequeue(queued)
				pkt = queued.data
			case p, ok := <-slot.SendCh:
				if !ok {
					return
				}
				pkt = p
			}
			userTraffic := d.isUserPacket(pkt)
			writeStarted := time.Now()
			dtlsWriteMu.Lock()
			_ = dtlsConn.SetWriteDeadline(time.Now().Add(sessionReadTimeout))
			outgoing := pkt
			if slot.uplink != nil && len(pkt) >= 4 && pkt[0] >= 1 && pkt[0] <= 4 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
				outgoing = slot.uplink.frame(framedPacket, pkt, pathprobe.Data)
				framedPacket = outgoing[:0]
			}
			_, writeErr := dtlsConn.Write(outgoing)
			dtlsWriteMu.Unlock()
			if slot.queue != nil {
				slot.queue.noteWrite(writeStarted, len(pkt), writeErr)
			}
			putPktBuf(pkt)
			if writeErr != nil {
				log.Printf("[ВОРКЕР #%d] Ошибка Writer: %v", sessionID, writeErr)
				return
			}
			if userTraffic {
				d.noteUserTrafficSent(time.Now())
			}
		}
	}()

	// Reader: DTLS → dispatcher
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		var reportedWakeGeneration uint64
		noteKeepalivePong := func() {
			generation := d.wakeGeneration.Load()
			if generation > 0 {
				d.acknowledgeWorkerWake(slot, generation)
			}
			firstPong := keepalivePongSeen.CompareAndSwap(0, 1)
			if firstPong || generation > reportedWakeGeneration {
				reportedWakeGeneration = generation
				// Android использует этот сигнал как доказательство свежего
				// двустороннего пути, в том числе после каждого пробуждения.
				log.Printf("[HEALTH] сервер ответил на keepalive")
			}
		}
		for {
			pkt := getPktBuf(2048)
			_ = dtlsConn.SetReadDeadline(time.Now().Add(sessionReadTimeout))
			n, readErr := dtlsConn.Read(pkt)
			if readErr != nil {
				putPktBuf(pkt)
				if sessCtx.Err() != nil {
					return
				}
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					continue
				}
				log.Printf("[ВОРКЕР #%d] Ошибка Reader: %v", sessionID, readErr)
				return
			}

			lastServerRxAt.Store(time.Now().UnixNano())
			if slot.queue != nil {
				slot.queue.received.Add(uint64(n))
			}

			if _, policyErr := parseConfigResponse(string(pkt[:n])); policyErr != nil {
				if maxWorkers, limited := workerPolicyLimit(policyErr); limited {
					select {
					case policyLimitCh <- maxWorkers:
					default:
					}
					putPktBuf(pkt)
					return
				}
			}

			// Skip keepalive pong from server
			if n == 1 && pkt[0] == keepaliveByte {
				noteKeepalivePong()
				putPktBuf(pkt)
				continue
			}
			if slot.uplink != nil && slot.uplink.ack(pkt[:n], time.Now()) {
				putPktBuf(pkt)
				continue
			}
			if d.handleUpdateMetadataResponse(pkt[:n]) {
				putPktBuf(pkt)
				continue
			}
			if d.isUserPacket(pkt[:n]) {
				if d.noteUserTrafficResponse() {
					log.Printf("[HEALTH] пользовательский трафик снова получает ответы")
				}
			}

			pkt = pkt[:n]
			select {
			case d.ReturnCh <- pkt:
			case <-sessCtx.Done():
				putPktBuf(pkt)
				return
			}
		}
	}()

	proxyWg.Wait()
	sessCancel()
	relayWg.Wait()
	sessionWg.Wait()
	_ = pipeA.Close()
	_ = pipeB.Close()
	log.Printf("[СЕССИЯ #%d] Завершена", sessionID)
	select {
	case maxWorkers := <-policyLimitCh:
		return configDelivered, &workerPolicyLimitError{maxWorkers: maxWorkers}
	default:
	}
	if uplinkReplacement.Load() {
		return configDelivered, errUplinkPathReplacement
	}
	return configDelivered, nil
}
