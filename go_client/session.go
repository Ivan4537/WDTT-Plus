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
	keepaliveInterval            = 15 * time.Second
	defaultHandshakeTimeout      = 20 * time.Second
	wrapHandshakeTimeout         = 8 * time.Second
)

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
// the explicit «Сеть РТ» mode; ordinary operators keep the original writes.
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

func verifyTURNCertificateChainWithoutHostname(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("TURN TLS не прислал сертификат")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
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
	// домену белого списка. Отключаем только сопоставление имени: публичная CA-
	// цепочка всё равно проверяется в VerifyConnection.
	if frontSNI != "" && !strings.EqualFold(frontSNI, endpoint.Host) {
		config.InsecureSkipVerify = true // проверка перенесена в VerifyConnection
		config.VerifyConnection = verifyTURNCertificateChainWithoutHostname
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
		resolved, err := net.ResolveUDPAddr("udp", turnAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("TURN UDP резолв %s: %w", turnAddr, err)
		}
		c, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			return nil, nil, fmt.Errorf("TURN UDP подключение %s: %w", turnAddr, err)
		}
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

	return allocateTURNOnConn(endpoint, peer, creds, turnConn)
}

func allocateTURNOnConn(
	endpoint turnEndpoint,
	peer *net.UDPAddr,
	creds *Credentials,
	turnConn net.PacketConn,
) (*turn.Client, net.PacketConn, error) {
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
		_ = turnConn.Close()
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

	return tc, relay, nil
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
) (bool, error) {
	configDelivered := false

	if len(creds.TurnURLs) == 0 {
		return false, fmt.Errorf("нет TURN URL в учетных данных")
	}
	candidates := sessionTURNCandidatesWithPreference(
		creds.TurnURLs,
		sessionID,
		tp,
		preferTURNStream,
	)
	if len(candidates) == 0 {
		return false, fmt.Errorf("нет пригодных TURN URL в учетных данных")
	}
	directCandidates, masqueCandidates, finalUDPCandidates := turnCandidateStages(candidates, tp.Masque != nil)

	var tc *turn.Client
	var relay net.PacketConn
	var selectedEndpoint turnEndpoint
	var selectedMasqueProtocol warpMasqueProtocol
	var lastTURNErr error
	var err error
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
		log.Printf("[СЕССИЯ #%d] [MASQUE] Прямые TCP/TLS-пути «Сети РТ» не сработали; до UDP пробуем WARP CONNECT-IP: %v", sessionID, lastTURNErr)
	masqueProtocols:
		for _, protocol := range tp.Masque.protocolOrder() {
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
	if lastTURNErr != nil && relay == nil {
		return false, lastTURNErr
	}
	defer tc.Close()
	defer relay.Close()

	// Reset error count on successful allocation
	getStreamCache(creds.CacheStreamID).errorCount.Store(0)

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

	useWrap := len(tp.WrapKey) == wrapKeyLen

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
		for {
			n, _, readErr := pipeA.ReadFrom(b)
			if readErr != nil {
				return
			}
			out := b[:n]
			if useWrap {
				if obfsCfg != nil && obfsWriteState != nil {
					wrapped, wrapErr := obfsWrapPacket(tp.WrapKey, out, obfsCfg, obfsWriteState)
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

	// DTLS с поддержкой Connection ID (без SNI)
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return false, fmt.Errorf("генерация сертификата: %w", err)
	}

	// Acquire handshake semaphore
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

	stats.ActiveConnections.Add(1)
	globalActiveConnections.Add(1)
	defer func() {
		stats.ActiveConnections.Add(-1)
		globalActiveConnections.Add(-1)
	}()

	// Запрос конфига
	if getConfig && configCh != nil {
		conf, confErr := RequestConfig(
			sessCtx,
			dtlsConn,
			localPort,
			deviceID,
			password,
			deviceInfo,
			transportSession,
		)
		if confErr != nil {
			if _, limited := workerPolicyLimit(confErr); limited {
				return false, confErr
			}
			errStr := confErr.Error()
			if strings.Contains(errStr, "FATAL_AUTH") {
				return false, confErr
			}
			if requireConfig {
				return false, fmt.Errorf("регистрация нового подключения: %w", confErr)
			}
			log.Printf("[ВОРКЕР #%d] Ошибка конфига: %v", sessionID, confErr)
		} else if conf != "" {
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
		} else {
			if requireConfig {
				return false, fmt.Errorf("сервер ещё не выдал WireGuard-конфиг")
			}
			log.Printf("[ВОРКЕР #%d] Сервер ещё не выдал WireGuard-конфиг, повторим позже", sessionID)
		}
	}

	log.Printf("[ВОРКЕР #%d] [READY] Туннель готов к работе ✓", sessionID)

	// Регистрация в диспетчере
	slot := &WorkerSlot{
		ID:     sessionID,
		SendCh: make(chan []byte, workerSendBuf),
	}
	d.Register(slot)
	defer d.Unregister(slot)

	var lastServerRxAt atomic.Int64
	lastServerRxAt.Store(time.Now().UnixNano())
	var keepalivePongSeen atomic.Int32
	policyLimitCh := make(chan int, 1)

	// Proxy DTLS ↔ Dispatcher
	var proxyWg sync.WaitGroup
	proxyWg.Add(4) // writer + reader + keepalive + health monitor

	// DTLS Keepalive: prevents TURN allocation timeout and DTLS idle disconnect
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		t := time.NewTicker(keepaliveInterval)
		defer t.Stop()
		ping := []byte{keepaliveByte}
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-t.C:
				_ = dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := dtlsConn.Write(ping); err != nil {
					return
				}
			}
		}
	}()

	// Health monitor: UDP can fail silently, so expect keepalive pongs or user traffic responses.
	go func() {
		defer proxyWg.Done()
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-t.C:
				now := time.Now()
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
		for {
			select {
			case <-sessCtx.Done():
				return
			case pkt, ok := <-slot.SendCh:
				if !ok {
					return
				}
				userTraffic := isWireGuardUserDataPacket(pkt)
				_ = dtlsConn.SetWriteDeadline(time.Now().Add(sessionReadTimeout))
				_, writeErr := dtlsConn.Write(pkt)
				putPktBuf(pkt)
				if writeErr != nil {
					log.Printf("[ВОРКЕР #%d] Ошибка Writer: %v", sessionID, writeErr)
					return
				}
				if userTraffic {
					d.noteUserTrafficSent(time.Now())
				}
			}
		}
	}()

	// Reader: DTLS → dispatcher
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
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
				if keepalivePongSeen.CompareAndSwap(0, 1) {
					// Один сигнал на нативный процесс: Android использует его для
					// проверки таймерного возобновления, не засоряя лог каждым pong.
					log.Printf("[HEALTH] сервер ответил на keepalive")
				}
				putPktBuf(pkt)
				continue
			}
			if isWireGuardUserDataPacket(pkt[:n]) {
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
	return configDelivered, nil
}
