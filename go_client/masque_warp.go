package main

// The Cloudflare WARP MASQUE interoperability in this file is adapted from
// Diniboy1123/usque (MIT, commit 6aa03fc97d12848dce34eedbd187fb1077b5d1ea).
// It is intentionally isolated behind the explicit Android «Сеть РТ» +
// «MASQUE» opt-in. The ordinary WDTT transport never constructs this manager.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	warpConnectURI        = "https://cloudflareaccess.com"
	warpDefaultH2Endpoint = "162.159.198.2"
	warpMasqueMTU         = 1280
	warpConnectTimeout    = 12 * time.Second
	warpInnerDialTimeout  = 10 * time.Second
	warpAPIDialTimeout    = 10 * time.Second
	warpAPITLSTimeout     = 8 * time.Second
	warpAPIHeaderTimeout  = 12 * time.Second
	warpAPIFragmentSize   = 32
	warpAPIFragmentDelay  = 4 * time.Millisecond
	warpConfigVersion     = 1
	warpPacketHeadroom    = 1
)

var (
	warpAPIBaseURL           = "https://api.cloudflareclient.com/v0a4471"
	warpHTTPClient           = newWarpHTTPClient(false)
	warpFragmentedHTTPClient = newWarpHTTPClient(true)
	warpRelayHTTPClient      *http.Client
	warpRelayPreferred       atomic.Bool
)

// warpAPIFragmentConn divides only the first TLS ClientHello write. It leaves
// DNS, addresses, certificate validation and all later HTTPS bytes untouched.
// The wrapper is used only after a normal WARP API TLS handshake times out and
// only while the explicit Android «Сеть РТ» + «MASQUE» mode is enrolling.
type warpAPIFragmentConn struct {
	net.Conn
	mu         sync.Mutex
	fragmented bool
	chunkSize  int
	delay      time.Duration
}

func isTLSClientHello(payload []byte) bool {
	// TLS record: handshake(0x16), legacy record version 3.x, followed by
	// ClientHello handshake type(0x01).
	return len(payload) >= 9 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

func (conn *warpAPIFragmentConn) Write(payload []byte) (int, error) {
	conn.mu.Lock()
	shouldFragment := !conn.fragmented && isTLSClientHello(payload)
	if shouldFragment {
		conn.fragmented = true
	}
	conn.mu.Unlock()
	if !shouldFragment {
		return conn.Conn.Write(payload)
	}

	chunkSize := conn.chunkSize
	if chunkSize <= 0 {
		chunkSize = warpAPIFragmentSize
	}
	total := 0
	for offset := 0; offset < len(payload); {
		end := min(offset+chunkSize, len(payload))
		written, err := writeFull(conn.Conn, payload[offset:end])
		total += written
		if err != nil {
			return total, err
		}
		offset = end
		if offset < len(payload) && conn.delay > 0 {
			time.Sleep(conn.delay)
		}
	}
	return total, nil
}

func newWarpHTTPClient(fragmentClientHello bool) *http.Client {
	// setupGlobalResolver may replace net.DefaultResolver with a direct route
	// selected for VK. WARP enrollment must instead retain Android's original
	// resolver and normal hostname-based HTTPS. No public DNS, pinned API IPs or
	// address iteration are used here.
	dialer := &net.Dialer{
		Timeout:   warpAPIDialTimeout,
		KeepAlive: 30 * time.Second,
		Resolver:  deviceSystemResolver,
	}
	dialContext := dialer.DialContext
	forceHTTP2 := true
	var tlsConfig *tls.Config
	if fragmentClientHello {
		forceHTTP2 = false
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		}
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if tcp, ok := connection.(*net.TCPConn); ok {
				_ = tcp.SetNoDelay(true)
			}
			return &warpAPIFragmentConn{
				Conn:      connection,
				chunkSize: warpAPIFragmentSize,
				delay:     warpAPIFragmentDelay,
			}, nil
		}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			// Keep the normal dual-stack "tcp" network selected by net/http.
			// Android can therefore use IPv6 or its standard IPv4 fallback without
			// direct DNS servers, pinned addresses or manual address iteration.
			DialContext:           dialContext,
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     forceHTTP2,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   warpAPITLSTimeout,
			ResponseHeaderTimeout: warpAPIHeaderTimeout,
		},
	}
}

func normalizeWarpAPIRelayAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("локальный выход API WARP должен иметь формат адрес:порт")
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || !ip.IsLoopback() {
		return "", errors.New("выход API WARP разрешён только через loopback Android")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || !inRange(parsedPort, 1, 65535) {
		return "", errors.New("некорректный локальный порт выхода API WARP")
	}
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", parsedPort)), nil
}

func newWarpRelayHTTPClient(address string) (*http.Client, error) {
	normalized, err := normalizeWarpAPIRelayAddress(address)
	if err != nil {
		return nil, err
	}
	if normalized == "" {
		return nil, nil
	}
	dialer := &net.Dialer{Timeout: warpAPIDialTimeout, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, normalized)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   warpAPITLSTimeout,
			ResponseHeaderTimeout: warpAPIHeaderTimeout,
		},
	}, nil
}

func configureWarpAPIRelay(address string) error {
	client, err := newWarpRelayHTTPClient(address)
	if err != nil {
		return err
	}
	warpRelayHTTPClient = client
	warpRelayPreferred.Store(false)
	return nil
}

func inRange(value, minimum, maximum int) bool {
	return value >= minimum && value <= maximum
}

type warpMasqueProtocol string

const (
	warpMasqueHTTP2 warpMasqueProtocol = "HTTP/2"
	warpMasqueHTTP3 warpMasqueProtocol = "HTTP/3"
)

func warpMasqueProtocolOrder(preferred warpMasqueProtocol) []warpMasqueProtocol {
	if preferred == warpMasqueHTTP3 {
		return []warpMasqueProtocol{warpMasqueHTTP3, warpMasqueHTTP2}
	}
	return []warpMasqueProtocol{warpMasqueHTTP2, warpMasqueHTTP3}
}

type warpMasqueConfig struct {
	Version        int    `json:"version"`
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointH2V4   string `json:"endpoint_h2_v4"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	DeviceID       string `json:"device_id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

func (cfg *warpMasqueConfig) validate() error {
	if cfg == nil {
		return errors.New("пустая конфигурация WARP")
	}
	if cfg.Version != warpConfigVersion {
		return fmt.Errorf("неподдерживаемая версия конфигурации WARP: %d", cfg.Version)
	}
	if _, err := cfg.privateKey(); err != nil {
		return err
	}
	if _, err := cfg.endpointPublicKey(); err != nil {
		return err
	}
	if net.ParseIP(cfg.EndpointV4) == nil {
		return fmt.Errorf("некорректный WARP HTTP/3 endpoint: %q", cfg.EndpointV4)
	}
	if cfg.EndpointH2V4 == "" {
		cfg.EndpointH2V4 = warpDefaultH2Endpoint
	}
	if net.ParseIP(cfg.EndpointH2V4) == nil {
		return fmt.Errorf("некорректный WARP HTTP/2 endpoint: %q", cfg.EndpointH2V4)
	}
	if ip, err := netip.ParseAddr(cfg.IPv4); err != nil || !ip.Is4() {
		return fmt.Errorf("некорректный внутренний IPv4 WARP: %q", cfg.IPv4)
	}
	return nil
}

func (cfg *warpMasqueConfig) privateKey() (*ecdsa.PrivateKey, error) {
	encoded, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("декодирование приватного ключа WARP: %w", err)
	}
	key, err := x509.ParseECPrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("разбор приватного ключа WARP: %w", err)
	}
	return key, nil
}

func (cfg *warpMasqueConfig) endpointPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(cfg.EndpointPubKey))
	if block == nil {
		return nil, errors.New("декодирование закреплённого ключа WARP endpoint")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("разбор закреплённого ключа WARP endpoint: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("закреплённый ключ WARP endpoint не является ECDSA")
	}
	return key, nil
}

func loadWarpMasqueConfig(path string) (*warpMasqueConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg warpMasqueConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("разбор конфигурации WARP: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveWarpMasqueConfig(path string, cfg *warpMasqueConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("создание каталога конфигурации WARP: %w", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("кодирование конфигурации WARP: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".rt-masque-*.tmp")
	if err != nil {
		return fmt.Errorf("создание временной конфигурации WARP: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("права конфигурации WARP: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("запись конфигурации WARP: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("синхронизация конфигурации WARP: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("закрытие конфигурации WARP: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("сохранение конфигурации WARP: %w", err)
	}
	committed = true
	return nil
}

type warpRegistrationRequest struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FCMToken  string `json:"fcm_token"`
	TOS       string `json:"tos"`
	Model     string `json:"model"`
	Serial    string `json:"serial_number"`
	OSVersion string `json:"os_version"`
	KeyType   string `json:"key_type"`
	TunType   string `json:"tunnel_type"`
	Locale    string `json:"locale"`
}

type warpEnrollRequest struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

type warpAccountData struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

type warpAPIRequestPhase string

const (
	warpAPIPhasePreparing warpAPIRequestPhase = "подготовка HTTPS-запроса"
	warpAPIPhaseDNS       warpAPIRequestPhase = "системный DNS Android"
	warpAPIPhaseTCP       warpAPIRequestPhase = "подключение TCP/443"
	warpAPIPhaseTLS       warpAPIRequestPhase = "TLS-рукопожатие"
	warpAPIPhaseWrite     warpAPIRequestPhase = "отправка HTTP-запроса"
	warpAPIPhaseResponse  warpAPIRequestPhase = "ожидание HTTP-ответа"
)

// warpAPIRequestTrace records only protocol phases. It deliberately does not
// retain the request URL, device ID, authorization token or resolved address.
type warpAPIRequestTrace struct {
	mu             sync.Mutex
	phase          warpAPIRequestPhase
	requestWritten bool
	dnsLogged      bool
	tcpLogged      bool
	tlsLogged      bool
	writeLogged    bool
	responseLogged bool
	serverRelay    bool
}

func newWarpAPIRequestTrace(serverRelay ...bool) *warpAPIRequestTrace {
	return &warpAPIRequestTrace{
		phase:       warpAPIPhasePreparing,
		serverRelay: len(serverRelay) > 0 && serverRelay[0],
	}
}

func (trace *warpAPIRequestTrace) setPhase(phase warpAPIRequestPhase) {
	trace.mu.Lock()
	trace.phase = phase
	trace.mu.Unlock()
}

func (trace *warpAPIRequestTrace) snapshot() (warpAPIRequestPhase, bool) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.phase, trace.requestWritten
}

func (trace *warpAPIRequestTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			trace.setPhase(warpAPIPhaseDNS)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err != nil {
				return
			}
			trace.mu.Lock()
			shouldLog := !trace.dnsLogged
			trace.dnsLogged = true
			trace.mu.Unlock()
			if shouldLog {
				logMasque("API Cloudflare: системный DNS Android разрешил адрес ✓")
			}
		},
		ConnectStart: func(_, _ string) {
			trace.setPhase(warpAPIPhaseTCP)
		},
		ConnectDone: func(_, _ string, err error) {
			if err != nil {
				return
			}
			trace.mu.Lock()
			shouldLog := !trace.tcpLogged
			trace.tcpLogged = true
			trace.mu.Unlock()
			if shouldLog {
				if trace.serverRelay {
					logMasque("API Cloudflare: защищённый выход через сервер профиля доступен ✓")
				} else {
					logMasque("API Cloudflare: TCP/443 через системную сеть Android установлен ✓")
				}
			}
		},
		TLSHandshakeStart: func() {
			trace.setPhase(warpAPIPhaseTLS)
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				return
			}
			trace.mu.Lock()
			shouldLog := !trace.tlsLogged
			trace.tlsLogged = true
			trace.mu.Unlock()
			if shouldLog {
				protocol := state.NegotiatedProtocol
				if protocol == "h2" {
					protocol = "HTTP/2"
				} else if protocol == "" {
					protocol = "HTTP/1.1"
				}
				logMasque("API Cloudflare: TLS-рукопожатие завершено, согласован %s ✓", protocol)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			trace.mu.Lock()
			trace.phase = warpAPIPhaseWrite
			if info.Err == nil {
				trace.requestWritten = true
				trace.phase = warpAPIPhaseResponse
			}
			shouldLog := info.Err == nil && !trace.writeLogged
			if shouldLog {
				trace.writeLogged = true
			}
			trace.mu.Unlock()
			if shouldLog {
				logMasque("API Cloudflare: HTTP-запрос отправлен, ожидаем ответ...")
			}
		},
		GotFirstResponseByte: func() {
			trace.mu.Lock()
			trace.phase = warpAPIPhaseResponse
			shouldLog := !trace.responseLogged
			trace.responseLogged = true
			trace.mu.Unlock()
			if shouldLog {
				logMasque("API Cloudflare: получен первый байт HTTP-ответа ✓")
			}
		},
	}
}

func warpAPIRequest(ctx context.Context, method, url, token string, body any, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var resp *http.Response
	requestClient := warpHTTPClient
	fragmentedTLSAttempt := false
	serverRelayAttempt := false
	maxAttempts := 2
	if warpRelayHTTPClient != nil && warpRelayPreferred.Load() {
		requestClient = warpRelayHTTPClient
		serverRelayAttempt = true
		maxAttempts = 1
	} else if warpRelayHTTPClient != nil {
		maxAttempts = 3
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, requestErr := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(encoded))
		if requestErr != nil {
			return requestErr
		}
		req.Header.Set("User-Agent", "WARP for Android")
		req.Header.Set("CF-Client-Version", "a-6.35-4471")
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("Connection", "Keep-Alive")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		requestTrace := newWarpAPIRequestTrace(serverRelayAttempt)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), requestTrace.clientTrace()))
		resp, err = requestClient.Do(req)
		if err == nil {
			break
		}
		phase, requestWritten := requestTrace.snapshot()
		diagnosis := warpAPINetworkError(err, phase)
		if serverRelayAttempt {
			diagnosis = warpAPIRelayNetworkError(err, phase)
		}
		if attempt == 1 && !requestWritten && ctx.Err() == nil && warpAPICanRetryBeforeWrite(err) {
			requestClient.CloseIdleConnections()
			if warpAPIIsTLSHandshakeTimeout(err, phase) {
				fragmentedTLSAttempt = true
				requestClient = warpFragmentedHTTPClient
				logMasque("API Cloudflare: обычный TLS не прошёл до отправки данных — повторяем через TLS 1.2/HTTP 1.1 с разделённым ClientHello")
			} else {
				logMasque("API Cloudflare: %v; данные устройства ещё не отправлялись — выполняем одну безопасную повторную попытку", diagnosis)
			}
			continue
		}
		if attempt == 2 && warpRelayHTTPClient != nil && !requestWritten &&
			ctx.Err() == nil && warpAPICanRetryBeforeWrite(err) {
			requestClient.CloseIdleConnections()
			requestClient = warpRelayHTTPClient
			serverRelayAttempt = true
			logMasque("API Cloudflare: прямые HTTPS-пути недоступны до отправки данных — пробуем защищённый выход через сервер профиля")
			continue
		}
		if serverRelayAttempt {
			return diagnosis
		}
		if fragmentedTLSAttempt {
			detail := strings.TrimPrefix(diagnosis.Error(), "WARP API: ")
			return fmt.Errorf("WARP API: резерв TLS 1.2/HTTP 1.1 с разделённым ClientHello не сработал: %s", detail)
		}
		return diagnosis
	}
	if serverRelayAttempt {
		warpRelayPreferred.Store(true)
		logMasque("API Cloudflare: защищённый выход через сервер профиля сработал ✓")
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 1<<20)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("чтение ответа WARP API (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New(warpAPIErrorMessage(resp.StatusCode, responseBody))
	}
	contentType := strings.Join(strings.Fields(resp.Header.Get("Content-Type")), " ")
	if len(contentType) > 80 {
		contentType = contentType[:80]
	}
	if contentType == "" {
		contentType = "не указан"
	}
	trimmedBody := bytes.TrimSpace(responseBody)
	if len(trimmedBody) == 0 {
		return fmt.Errorf("WARP API вернул пустой ответ: HTTP %d, Content-Type=%s", resp.StatusCode, contentType)
	}
	if !json.Valid(trimmedBody) {
		return fmt.Errorf(
			"WARP API вернул ответ не в формате JSON: HTTP %d, Content-Type=%s, размер=%d байт",
			resp.StatusCode,
			contentType,
			len(responseBody),
		)
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return fmt.Errorf(
			"структура JSON-ответа WARP API несовместима: HTTP %d, Content-Type=%s: %w",
			resp.StatusCode,
			contentType,
			err,
		)
	}
	return nil
}

func warpAPIRelayNetworkError(err error, phase warpAPIRequestPhase) error {
	var requestErr *url.Error
	if errors.As(err, &requestErr) {
		err = requestErr.Err
	}
	var certificateErr x509.UnknownAuthorityError
	if errors.As(err, &certificateErr) {
		return errors.New("WARP API: выход через сервер профиля получил недоверенный сертификат Cloudflare; регистрация остановлена")
	}
	lowerDetail := strings.ToLower(err.Error())
	if strings.Contains(lowerDetail, "tls handshake timeout") || phase == warpAPIPhaseTLS {
		return fmt.Errorf(
			"WARP API: выход через сервер профиля установлен, но TLS-рукопожатие Cloudflare не завершилось за %d с",
			int(warpAPITLSTimeout/time.Second),
		)
	}
	if phase == warpAPIPhaseResponse {
		return fmt.Errorf(
			"WARP API: HTTPS-запрос через сервер профиля отправлен, но Cloudflare не ответил за %d с",
			int(warpAPIHeaderTimeout/time.Second),
		)
	}
	if phase == warpAPIPhaseTCP {
		return fmt.Errorf(
			"WARP API: локальный SSH-выход не установил TCP-путь к Cloudflare за %d с",
			int(warpAPIDialTimeout/time.Second),
		)
	}
	base := strings.TrimPrefix(warpAPINetworkError(err, phase).Error(), "WARP API: ")
	return fmt.Errorf("WARP API: выход через сервер профиля не сработал: %s", base)
}

// http.Client includes the full request URL in *url.Error. The MASQUE PATCH
// URL contains the Cloudflare device ID, so unwrap it before logging while
// retaining a useful network diagnosis.
func warpAPINetworkError(err error, phase warpAPIRequestPhase) error {
	var requestErr *url.Error
	if errors.As(err, &requestErr) {
		err = requestErr.Err
	}
	detail := strings.Join(strings.Fields(err.Error()), " ")
	lowerDetail := strings.ToLower(detail)
	if strings.Contains(lowerDetail, "tls handshake timeout") {
		return fmt.Errorf(
			"WARP API: тайм-аут TLS-рукопожатия (%d с) после успешного TCP/443; Cloudflare не завершил установку защищённого HTTPS-соединения",
			int(warpAPITLSTimeout/time.Second),
		)
	}
	if strings.Contains(lowerDetail, "timeout awaiting response headers") ||
		strings.Contains(lowerDetail, "timeout awaiting response") {
		return fmt.Errorf(
			"WARP API: HTTP-запрос отправлен, но Cloudflare не прислал заголовки ответа за %d с",
			int(warpAPIHeaderTimeout/time.Second),
		)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return warpAPITimeoutForPhase(phase)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		dnsDetail := strings.Join(strings.Fields(dnsErr.Err), " ")
		if dnsDetail == "" {
			dnsDetail = "адрес не найден"
		}
		return fmt.Errorf("WARP API: системный DNS Android не разрешил %s: %s", dnsErr.Name, dnsDetail)
	}
	var certificateErr x509.UnknownAuthorityError
	if errors.As(err, &certificateErr) {
		return errors.New("WARP API: сертификат TLS выпущен неизвестным центром сертификации")
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return warpAPITimeoutForPhase(phase)
	}
	if len(detail) > 200 {
		detail = detail[:200]
	}
	return fmt.Errorf("WARP API: сетевая ошибка на фазе «%s»: %s", phase, detail)
}

func warpAPITimeoutForPhase(phase warpAPIRequestPhase) error {
	switch phase {
	case warpAPIPhaseDNS:
		return errors.New("WARP API: тайм-аут системного DNS Android при разрешении адреса Cloudflare")
	case warpAPIPhaseTCP:
		return fmt.Errorf(
			"WARP API: тайм-аут подключения TCP/443 к Cloudflare (%d с) после ответа системного DNS Android",
			int(warpAPIDialTimeout/time.Second),
		)
	case warpAPIPhaseTLS:
		return fmt.Errorf(
			"WARP API: тайм-аут TLS-рукопожатия (%d с) после успешного TCP/443; Cloudflare не завершил установку защищённого HTTPS-соединения",
			int(warpAPITLSTimeout/time.Second),
		)
	case warpAPIPhaseWrite:
		return errors.New("WARP API: тайм-аут при отправке HTTPS-запроса в Cloudflare")
	case warpAPIPhaseResponse:
		return fmt.Errorf(
			"WARP API: HTTP-запрос отправлен, но Cloudflare не прислал ответ за %d с",
			int(warpAPIHeaderTimeout/time.Second),
		)
	default:
		return errors.New("WARP API: превышено общее время ожидания HTTPS-запроса")
	}
}

func warpAPICanRetryBeforeWrite(err error) bool {
	var requestErr *url.Error
	if errors.As(err, &requestErr) {
		err = requestErr.Err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var certificateErr x509.UnknownAuthorityError
	if errors.As(err, &certificateErr) {
		return false
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func warpAPIIsTLSHandshakeTimeout(err error, phase warpAPIRequestPhase) bool {
	if phase != warpAPIPhaseTLS {
		return false
	}
	var requestErr *url.Error
	if errors.As(err, &requestErr) {
		err = requestErr.Err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if strings.Contains(strings.ToLower(err.Error()), "tls handshake timeout") {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

func warpAPIErrorMessage(status int, responseBody []byte) string {
	var payload struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	details := make([]string, 0, 2)
	if json.Unmarshal(responseBody, &payload) == nil {
		for _, item := range payload.Errors {
			message := strings.Join(strings.Fields(item.Message), " ")
			if len(message) > 160 {
				message = message[:160]
			}
			if item.Code != 0 && message != "" {
				details = append(details, fmt.Sprintf("code=%d %s", item.Code, message))
			} else if item.Code != 0 {
				details = append(details, fmt.Sprintf("code=%d", item.Code))
			} else if message != "" {
				details = append(details, message)
			}
			if len(details) == 2 {
				break
			}
		}
	}
	if len(details) == 0 {
		return fmt.Sprintf("WARP API HTTP %d", status)
	}
	return fmt.Sprintf("WARP API HTTP %d: %s", status, strings.Join(details, "; "))
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func endpointHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		host = strings.Trim(host, "[]")
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("некорректный endpoint %q", raw)
		}
		return host, nil
	}
	host := strings.Trim(raw, "[]")
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("некорректный endpoint %q", raw)
	}
	return host, nil
}

func enrollWarpMasque(ctx context.Context, deviceName string) (*warpMasqueConfig, error) {
	wgKey, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("этап 1/4, создание ключа устройства WARP: %w", err)
	}
	serial, err := randomBytes(8)
	if err != nil {
		return nil, fmt.Errorf("этап 1/4, создание идентификатора устройства WARP: %w", err)
	}
	registration := warpRegistrationRequest{
		Key:       base64.StdEncoding.EncodeToString(wgKey),
		TOS:       time.Now().Format("2006-01-02T15:04:05.000-07:00"),
		Model:     "Android",
		Serial:    hex.EncodeToString(serial),
		KeyType:   "curve25519",
		TunType:   "wireguard",
		Locale:    "ru_RU",
		InstallID: "",
		FCMToken:  "",
		OSVersion: "",
	}
	var registered warpAccountData
	if err := warpAPIRequest(ctx, http.MethodPost, warpAPIBaseURL+"/reg", "", registration, &registered); err != nil {
		return nil, fmt.Errorf("этап 1/4, создание устройства WARP: %w", err)
	}
	if registered.ID == "" || registered.Token == "" {
		return nil, errors.New("этап 1/4, создание устройства WARP: Cloudflare не вернул ID или токен")
	}
	logMasque("этап 1/4 завершён: устройство WARP создано в Cloudflare; этап 2/4 — включаем для него MASQUE")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("этап 2/4, создание ключа MASQUE: %w", err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("этап 2/4, кодирование приватного ключа MASQUE: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("этап 2/4, кодирование публичного ключа MASQUE: %w", err)
	}
	enrollment := warpEnrollRequest{
		Key:     base64.StdEncoding.EncodeToString(publicDER),
		KeyType: "secp256r1",
		TunType: "masque",
		Name:    deviceName,
	}
	var enrolled warpAccountData
	url := warpAPIBaseURL + "/reg/" + registered.ID
	if err := warpAPIRequest(ctx, http.MethodPatch, url, registered.Token, enrollment, &enrolled); err != nil {
		return nil, fmt.Errorf("этап 2/4, включение MASQUE для устройства WARP: %w", err)
	}
	if len(enrolled.Config.Peers) == 0 {
		return nil, errors.New("этап 2/4, включение MASQUE: Cloudflare не вернул адрес MASQUE")
	}
	logMasque("этап 2/4 завершён: Cloudflare принял ключ MASQUE; этап 3/4 — проверяем адреса и ключ сервера")
	endpoint, err := endpointHost(enrolled.Config.Peers[0].Endpoint.V4)
	if err != nil {
		return nil, fmt.Errorf("этап 3/4, проверка адреса MASQUE: %w", err)
	}
	cfg := &warpMasqueConfig{
		Version:        warpConfigVersion,
		PrivateKey:     base64.StdEncoding.EncodeToString(privateDER),
		EndpointV4:     endpoint,
		EndpointH2V4:   warpDefaultH2Endpoint,
		EndpointPubKey: enrolled.Config.Peers[0].PublicKey,
		DeviceID:       enrolled.ID,
		AccessToken:    registered.Token,
		IPv4:           enrolled.Config.Interface.Addresses.V4,
		IPv6:           enrolled.Config.Interface.Addresses.V6,
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("этап 3/4, проверка ответа Cloudflare: неполная конфигурация WARP: %w", err)
	}
	logMasque("этап 3/4 завершён: конфигурация MASQUE корректна")
	return cfg, nil
}

func warpMasqueTLSConfig(cfg *warpMasqueConfig, sni string, protocol warpMasqueProtocol) (*tls.Config, error) {
	privateKey, err := cfg.privateKey()
	if err != nil {
		return nil, err
	}
	endpointKey, err := cfg.endpointPublicKey()
	if err != nil {
		return nil, err
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("клиентский сертификат WARP: %w", err)
	}
	nextProto := http3.NextProtoH3
	if protocol == warpMasqueHTTP2 {
		nextProto = "h2"
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER},
			PrivateKey:  privateKey,
		}},
		ServerName:         sni,
		NextProtos:         []string{nextProto},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // имя подменено; ниже обязательный pin ключа endpoint
	}
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("WARP endpoint не прислал сертификат")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		actual, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !actual.Equal(endpointKey) {
			return errors.New("публичный ключ WARP endpoint не совпал с enrollment")
		}
		return nil
	}
	return tlsConfig, nil
}

type warpMasqueOuter struct {
	ipConn        *connectip.Conn
	cancel        context.CancelFunc
	udpConn       *net.UDPConn
	quicConn      *quic.Conn
	h3Transport   *http3.Transport
	h2Transport   *http2.Transport
	h2RawConnLock sync.Mutex
	h2RawConn     net.Conn
}

func (outer *warpMasqueOuter) close() {
	if outer == nil {
		return
	}
	if outer.ipConn != nil {
		_ = outer.ipConn.Close()
	}
	if outer.cancel != nil {
		outer.cancel()
	}
	if outer.h3Transport != nil {
		_ = outer.h3Transport.Close()
	}
	if outer.quicConn != nil {
		_ = outer.quicConn.CloseWithError(0, "WDTT shutdown")
	}
	if outer.udpConn != nil {
		_ = outer.udpConn.Close()
	}
	if outer.h2Transport != nil {
		outer.h2Transport.CloseIdleConnections()
	}
	outer.h2RawConnLock.Lock()
	if outer.h2RawConn != nil {
		_ = outer.h2RawConn.Close()
		outer.h2RawConn = nil
	}
	outer.h2RawConnLock.Unlock()
}

func connectWarpMasque(ctx context.Context, cfg *warpMasqueConfig, sni string, protocol warpMasqueProtocol) (*warpMasqueOuter, error) {
	tlsConfig, err := warpMasqueTLSConfig(cfg, sni, protocol)
	if err != nil {
		return nil, err
	}
	template := uritemplate.MustNew(warpConnectURI)
	headers := http.Header{"User-Agent": []string{""}}

	if protocol == warpMasqueHTTP2 {
		endpoint := &net.TCPAddr{IP: net.ParseIP(cfg.EndpointH2V4), Port: 443}
		outer := &warpMasqueOuter{}
		transport := &http2.Transport{
			DialTLSContext: func(dialCtx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				raw, err := (&net.Dialer{Timeout: warpConnectTimeout, KeepAlive: 30 * time.Second}).DialContext(dialCtx, network, endpoint.String())
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(raw, tlsConfig.Clone())
				if err := tlsConn.HandshakeContext(dialCtx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				outer.h2RawConnLock.Lock()
				outer.h2RawConn = tlsConn
				outer.h2RawConnLock.Unlock()
				return tlsConn, nil
			},
		}
		outer.h2Transport = transport
		h2Headers := headers.Clone()
		h2Headers.Set("cf-connect-proto", "cf-connect-ip")
		h2Headers.Set("pq-enabled", "false")
		ipConn, _, err := connectip.DialH2(ctx, &http.Client{Transport: transport}, template, h2Headers)
		if err != nil {
			outer.close()
			return nil, fmt.Errorf("CONNECT-IP HTTP/2: %w", err)
		}
		outer.ipConn = ipConn
		return outer, nil
	}

	endpoint := &net.UDPAddr{IP: net.ParseIP(cfg.EndpointV4), Port: 443}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	outer := &warpMasqueOuter{udpConn: udpConn}
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	quicConn, err := qtr.Dial(ctx, endpoint, tlsConfig, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 20 * time.Second,
	})
	if err != nil {
		outer.close()
		return nil, fmt.Errorf("QUIC WARP: %w", err)
	}
	outer.quicConn = quicConn
	h3Transport := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			0x276: 1,
		},
		DisableCompression: true,
	}
	outer.h3Transport = h3Transport
	ipConn, _, err := connectip.Dial(ctx, h3Transport.NewClientConn(quicConn), template, "cf-connect-ip", headers, true)
	if err != nil {
		outer.close()
		return nil, fmt.Errorf("CONNECT-IP HTTP/3: %w", err)
	}
	outer.ipConn = ipConn
	return outer, nil
}

type warpMasqueTransport struct {
	protocol warpMasqueProtocol
	device   tun.Device
	network  *netstack.Net
	outer    *warpMasqueOuter
	done     chan struct{}
	close    sync.Once
}

func startWarpMasqueTransport(ctx context.Context, cfg *warpMasqueConfig, sni string, protocol warpMasqueProtocol) (*warpMasqueTransport, error) {
	localAddresses := make([]netip.Addr, 0, 2)
	v4, err := netip.ParseAddr(cfg.IPv4)
	if err != nil {
		return nil, err
	}
	localAddresses = append(localAddresses, v4)
	if v6, err := netip.ParseAddr(cfg.IPv6); err == nil && v6.Is6() {
		localAddresses = append(localAddresses, v6)
	}
	dnsServers := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	device, network, err := netstack.CreateNetTUN(localAddresses, dnsServers, warpMasqueMTU)
	if err != nil {
		return nil, fmt.Errorf("создание MASQUE netstack: %w", err)
	}
	// CONNECT-IP uses the request context for the lifetime of the HTTP stream.
	// Keep it alive after setup, but still bound a stalled handshake.
	connectCtx, cancel := context.WithCancel(ctx)
	timeout := time.AfterFunc(warpConnectTimeout, cancel)
	outer, err := connectWarpMasque(connectCtx, cfg, sni, protocol)
	timeout.Stop()
	if err != nil {
		cancel()
		_ = device.Close()
		return nil, err
	}
	outer.cancel = cancel
	transport := &warpMasqueTransport{
		protocol: protocol,
		device:   device,
		network:  network,
		outer:    outer,
		done:     make(chan struct{}),
	}
	transport.startPumps(ctx)
	return transport, nil
}

func (transport *warpMasqueTransport) alive() bool {
	select {
	case <-transport.done:
		return false
	default:
		return true
	}
}

func (transport *warpMasqueTransport) Close() {
	if transport == nil {
		return
	}
	transport.close.Do(func() {
		close(transport.done)
		if transport.outer != nil {
			transport.outer.close()
		}
		if transport.device != nil {
			_ = transport.device.Close()
		}
	})
}

func (transport *warpMasqueTransport) startPumps(ctx context.Context) {
	fail := func(err error) {
		if err != nil && ctx.Err() == nil && transport.alive() {
			logMasque("туннель %s потерян: %v", transport.protocol, err)
		}
		transport.Close()
	}
	go func() {
		buffer := make([]byte, warpMasqueMTU+warpPacketHeadroom)
		bufs := [][]byte{buffer[warpPacketHeadroom:]}
		sizes := []int{0}
		for {
			_, err := transport.device.Read(bufs, sizes, 0)
			if err != nil {
				fail(err)
				return
			}
			n := sizes[0]
			if n <= 0 {
				continue
			}
			icmp, err := transport.outer.ipConn.WritePacketBuffer(buffer, warpPacketHeadroom, n)
			if err != nil {
				fail(err)
				return
			}
			if len(icmp) > 0 {
				if _, err := transport.device.Write([][]byte{icmp}, 0); err != nil {
					fail(err)
					return
				}
			}
		}
	}()
	go func() {
		for {
			packet, err := transport.outer.ipConn.ReadPacketZeroCopy(true)
			if err != nil {
				fail(err)
				return
			}
			if _, err := transport.device.Write([][]byte{packet}, 0); err != nil {
				fail(err)
				return
			}
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			transport.Close()
		case <-transport.done:
		}
	}()
}

func (transport *warpMasqueTransport) DialContext(ctx context.Context, target string) (net.Conn, error) {
	if transport == nil || !transport.alive() {
		return nil, net.ErrClosed
	}
	dialCtx, cancel := context.WithTimeout(ctx, warpInnerDialTimeout)
	defer cancel()
	return transport.network.DialContext(dialCtx, "tcp", target)
}

type warpMasqueManager struct {
	ctx       context.Context
	path      string
	sni       string
	acceptTOS bool

	mu         sync.Mutex
	config     *warpMasqueConfig
	configErr  error
	retryAfter time.Time
	preferred  warpMasqueProtocol
	transports map[warpMasqueProtocol]*warpMasqueTransport
	failures   map[warpMasqueProtocol]warpMasqueFailure
}

type warpMasqueFailure struct {
	err        error
	retryAfter time.Time
}

func newWarpMasqueManager(ctx context.Context, path, sni string, acceptTOS bool) (*warpMasqueManager, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("не указан путь конфигурации WARP MASQUE")
	}
	if normalized, err := normalizeTURNFrontSNI(sni); err != nil || normalized == "" {
		return nil, errors.New("для WARP MASQUE нужен корректный SNI белого списка")
	} else {
		sni = normalized
	}
	return &warpMasqueManager{
		ctx:        ctx,
		path:       path,
		sni:        sni,
		acceptTOS:  acceptTOS,
		transports: make(map[warpMasqueProtocol]*warpMasqueTransport),
		failures:   make(map[warpMasqueProtocol]warpMasqueFailure),
	}, nil
}

func (manager *warpMasqueManager) ensureConfigLocked() (*warpMasqueConfig, error) {
	if manager.config != nil {
		return manager.config, nil
	}
	if manager.configErr != nil && time.Now().Before(manager.retryAfter) {
		return nil, manager.configErr
	}
	cfg, err := loadWarpMasqueConfig(manager.path)
	if err == nil {
		manager.config = cfg
		manager.configErr = nil
		return cfg, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		manager.configErr = fmt.Errorf("сохранённая конфигурация WARP повреждена: %w", err)
		manager.retryAfter = time.Now().Add(5 * time.Minute)
		return nil, manager.configErr
	}
	if !manager.acceptTOS {
		return nil, errors.New("для первой регистрации WARP требуется согласие с условиями Cloudflare")
	}
	logMasque("регистрация начата: этап 1/4 — создаём отдельное устройство WARP в Cloudflare")
	enrollCtx, cancel := context.WithTimeout(manager.ctx, 40*time.Second)
	defer cancel()
	cfg, err = enrollWarpMasque(enrollCtx, "WDTT Plus")
	if err != nil {
		manager.configErr = err
		manager.retryAfter = time.Now().Add(30 * time.Second)
		return nil, manager.configErr
	}
	logMasque("этап 4/4 — сохраняем регистрацию WARP только в приватном хранилище приложения")
	if err := saveWarpMasqueConfig(manager.path, cfg); err != nil {
		manager.configErr = fmt.Errorf("этап 4/4, сохранение регистрации WARP: %w", err)
		manager.retryAfter = time.Now().Add(30 * time.Second)
		return nil, manager.configErr
	}
	manager.config = cfg
	manager.configErr = nil
	logMasque("этап 4/4 завершён: регистрация WARP сохранена в приватном хранилище приложения ✓")
	return cfg, nil
}

func (manager *warpMasqueManager) transportLocked(protocol warpMasqueProtocol) (*warpMasqueTransport, error) {
	if current := manager.transports[protocol]; current != nil {
		if current.alive() {
			return current, nil
		}
		delete(manager.transports, protocol)
	}
	if failure, ok := manager.failures[protocol]; ok {
		if time.Now().Before(failure.retryAfter) {
			return nil, failure.err
		}
		delete(manager.failures, protocol)
	}
	cfg, err := manager.ensureConfigLocked()
	if err != nil {
		return nil, err
	}
	logMasque("устанавливаем CONNECT-IP %s через TCP/443 или QUIC/443; внешний SNI=%s", protocol, manager.sni)
	transport, err := startWarpMasqueTransport(manager.ctx, cfg, manager.sni, protocol)
	if err != nil {
		manager.failures[protocol] = warpMasqueFailure{
			err:        err,
			retryAfter: time.Now().Add(30 * time.Second),
		}
		return nil, err
	}
	manager.transports[protocol] = transport
	delete(manager.failures, protocol)
	logMasque("CONNECT-IP %s установлен ✓", protocol)
	return transport, nil
}

func (manager *warpMasqueManager) DialContext(ctx context.Context, target string) (net.Conn, warpMasqueProtocol, error) {
	order := manager.protocolOrder()

	var failures []string
	for _, protocol := range order {
		conn, err := manager.dialProtocol(ctx, target, protocol)
		if err == nil {
			manager.markPreferred(protocol)
			return conn, protocol, nil
		}
		failures = append(failures, fmt.Sprintf("%s к %s: %v", protocol, target, err))
	}
	return nil, "", fmt.Errorf("ни один MASQUE-путь не сработал: %s", strings.Join(failures, "; "))
}

func (manager *warpMasqueManager) prewarmConfig() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	_, err := manager.ensureConfigLocked()
	manager.mu.Unlock()
	if err != nil {
		if manager.ctx.Err() == nil {
			logMasque("фоновая подготовка WARP пока не выполнена: %v", err)
		}
		return
	}
	logMasque("конфигурация WARP подготовлена; прямые пути продолжают иметь приоритет ✓")
}

func (manager *warpMasqueManager) protocolOrder() []warpMasqueProtocol {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return warpMasqueProtocolOrder(manager.preferred)
}

func (manager *warpMasqueManager) dialProtocol(ctx context.Context, target string, protocol warpMasqueProtocol) (net.Conn, error) {
	manager.mu.Lock()
	transport, err := manager.transportLocked(protocol)
	manager.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return transport.DialContext(ctx, target)
}

func (manager *warpMasqueManager) markPreferred(protocol warpMasqueProtocol) {
	manager.mu.Lock()
	manager.preferred = protocol
	manager.mu.Unlock()
}

func (manager *warpMasqueManager) Close() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for protocol, transport := range manager.transports {
		transport.Close()
		delete(manager.transports, protocol)
	}
}

func logMasque(format string, args ...any) {
	log.Printf("[MASQUE] "+format, args...)
}
