package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"crypto/cipher"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
)

const (
	wdttServerVersion     = "17"
	wgIfaceName           = "wdtt0"
	wgServerAddr          = "10.66.66.1"
	wgServerCIDR          = wgServerAddr + "/24"
	defaultInternalWGPort = 56001
	defaultDNS            = "1.1.1.1"
	wgMTU                 = 1280
	keepalive             = 25
	dtlsKeepaliveByte     = 0xFF
	dtlsClientIdleTimeout = 90 * time.Second
	multipathRelayHello   = "WDTT_MUX1"
	multipathRelayChunk   = 16
)

// A WireGuard peer has one roaming UDP endpoint. Previously every DTLS worker
// opened its own localhost UDP socket, so packets from one phone continuously
// replaced that endpoint and replies were sent through an arbitrary worker.
// A deviceWGRelay gives all workers of one device one stable source socket and
// only multiplexes the already-encrypted WireGuard datagrams around it.
type deviceWGAttachment struct {
	downstream chan []byte
}

type deviceWGRelay struct {
	key         string
	conn        *net.UDPConn
	mu          sync.Mutex
	attachments map[*deviceWGAttachment]struct{}
	order       []*deviceWGAttachment
	rrIndex     int
	rrCount     int
	closed      bool
}

var deviceWGRelays = struct {
	sync.Mutex
	byKey map[string]*deviceWGRelay
}{byKey: make(map[string]*deviceWGRelay)}

func acquireDeviceWGRelay(deviceID, wgEndpoint string) (*deviceWGRelay, *deviceWGAttachment, error) {
	key := deviceID + "\x00" + wgEndpoint
	deviceWGRelays.Lock()
	defer deviceWGRelays.Unlock()

	relay := deviceWGRelays.byKey[key]
	if relay == nil {
		remote, err := net.ResolveUDPAddr("udp", wgEndpoint)
		if err != nil {
			return nil, nil, err
		}
		conn, err := net.DialUDP("udp", nil, remote)
		if err != nil {
			return nil, nil, err
		}
		_ = conn.SetReadBuffer(2 * 1024 * 1024)
		_ = conn.SetWriteBuffer(2 * 1024 * 1024)
		relay = &deviceWGRelay{
			key:         key,
			conn:        conn,
			attachments: make(map[*deviceWGAttachment]struct{}),
		}
		deviceWGRelays.byKey[key] = relay
		go relay.readLoop()
	}
	attachment := &deviceWGAttachment{downstream: make(chan []byte, 384)}
	relay.attachments[attachment] = struct{}{}
	relay.order = append(relay.order, attachment)
	return relay, attachment, nil
}

func (relay *deviceWGRelay) release(attachment *deviceWGAttachment) {
	if relay == nil || attachment == nil {
		return
	}
	deviceWGRelays.Lock()
	defer deviceWGRelays.Unlock()
	relay.mu.Lock()
	delete(relay.attachments, attachment)
	for i, candidate := range relay.order {
		if candidate == attachment {
			relay.order = append(relay.order[:i], relay.order[i+1:]...)
			break
		}
	}
	if len(relay.order) == 0 {
		relay.rrIndex = 0
		relay.rrCount = 0
	} else {
		relay.rrIndex %= len(relay.order)
	}
	empty := len(relay.attachments) == 0
	if empty && !relay.closed {
		relay.closed = true
		_ = relay.conn.Close()
	}
	relay.mu.Unlock()
	if empty && deviceWGRelays.byKey[relay.key] == relay {
		delete(deviceWGRelays.byKey, relay.key)
	}
}

func (relay *deviceWGRelay) writeFrom(attachment *deviceWGAttachment, packet []byte) error {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return net.ErrClosed
	}
	if _, ok := relay.attachments[attachment]; !ok {
		return net.ErrClosed
	}
	_, err := relay.conn.Write(packet)
	return err
}

func (relay *deviceWGRelay) nextAttachment() *deviceWGAttachment {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed || len(relay.order) == 0 {
		return nil
	}
	for attempts := 0; attempts < len(relay.order); attempts++ {
		index := relay.rrIndex % len(relay.order)
		attachment := relay.order[index]
		if _, attached := relay.attachments[attachment]; attached {
			relay.rrCount++
			if relay.rrCount >= multipathRelayChunk {
				relay.rrIndex = (index + 1) % len(relay.order)
				relay.rrCount = 0
			}
			return attachment
		}
		relay.rrIndex = (index + 1) % len(relay.order)
		relay.rrCount = 0
	}
	return nil
}

func (relay *deviceWGRelay) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, err := relay.conn.Read(buf)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buf[:n]...)
		attachment := relay.nextAttachment()
		if attachment == nil {
			continue
		}
		select {
		case attachment.downstream <- packet:
		default:
			// A blocked DTLS path must not stall the shared WireGuard reader.
		}
	}
}

func deviceLogRef(deviceID string) string {
	clean := strings.TrimSpace(deviceID)
	if clean == "" {
		return "unknown"
	}
	sum := sha256.Sum256([]byte(clean))
	return hex.EncodeToString(sum[:6])
}

// ==================== База данных ====================

type ClientDevice struct {
	DeviceID       string `json:"device_id"`
	IP             string `json:"ip"`
	PrivKey        string `json:"priv_key"`
	PubKey         string `json:"pub_key"`
	Name           string `json:"name,omitempty"`
	Manufacturer   string `json:"manufacturer,omitempty"`
	Brand          string `json:"brand,omitempty"`
	Model          string `json:"model,omitempty"`
	AndroidVersion string `json:"android_version,omitempty"`
	SDK            int    `json:"sdk,omitempty"`
	ABI            string `json:"abi,omitempty"`
	AppVersion     string `json:"app_version,omitempty"`
	Locale         string `json:"locale,omitempty"`
	Country        string `json:"country,omitempty"`
	TimeZone       string `json:"time_zone,omitempty"`
	RemoteIP       string `json:"remote_ip,omitempty"`
	LastSeenAt     int64  `json:"last_seen_at,omitempty"`
}

type PasswordEntry struct {
	DeviceID       string                   `json:"device_id"`  // пусто = ещё не привязан
	ExpiresAt      int64                    `json:"expires_at"` // unix timestamp
	PurgeAfter     int64                    `json:"purge_after,omitempty"`
	DownBytes      int64                    `json:"down_bytes"` // скачано клиентом
	UpBytes        int64                    `json:"up_bytes"`   // отдано клиентом
	Traffic        []TrafficBucket          `json:"traffic,omitempty"`
	TrafficImports map[string]TrafficImport `json:"traffic_imports,omitempty"`
	Label          string                   `json:"label,omitempty"`
	VkHash         string                   `json:"vk_hash,omitempty"`
	Ports          string                   `json:"ports,omitempty"` // "dtls,wg,tun"
	IsDeactivated  bool                     `json:"is_deactivated,omitempty"`
	BindHistory    []BindHistoryEntry       `json:"bind_history,omitempty"`
}

type TrafficImport struct {
	DownBytes int64 `json:"down_bytes"`
	UpBytes   int64 `json:"up_bytes"`
	AppliedAt int64 `json:"applied_at"`
}

type AdminProfileEntry struct {
	VkHashes        string   `json:"vk_hashes,omitempty"`
	SecondaryVkHash string   `json:"secondary_vk_hash,omitempty"`
	ProfileName     string   `json:"profile_name,omitempty"`
	WorkersPerHash  int      `json:"workers_per_hash,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	ListenPort      int      `json:"listen_port,omitempty"`
	SNI             string   `json:"sni,omitempty"`
	NoDNS           bool     `json:"no_dns,omitempty"`
	VpnDNSSelection string   `json:"vpn_dns_selection,omitempty"`
	VpnDNSCustom    string   `json:"vpn_dns_custom,omitempty"`
	Ports           string   `json:"ports,omitempty"`      // "dtls,wg,tun"
	DeviceIDs       []string `json:"device_ids,omitempty"` // устройства, подключавшиеся по main_password
	UpdatedAt       int64    `json:"updated_at,omitempty"`
}

type TrafficBucket struct {
	Date      string `json:"date"`
	DownBytes int64  `json:"down_bytes"`
	UpBytes   int64  `json:"up_bytes"`
}

type BindHistoryEntry struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
	DeviceIP   string `json:"device_ip,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	Country    string `json:"country,omitempty"`
	BoundAt    int64  `json:"bound_at,omitempty"`
	UnboundAt  int64  `json:"unbound_at,omitempty"`
	EventAt    int64  `json:"event_at,omitempty"`
	Status     string `json:"status"`
	Note       string `json:"note,omitempty"`
}

type Database struct {
	MainPassword   string                    `json:"main_password"`
	AdminID        string                    `json:"admin_id"`
	BotToken       string                    `json:"bot_token"`
	DNS            string                    `json:"dns,omitempty"`
	MaxPasswords   int                       `json:"max_passwords,omitempty"`
	DefaultPorts   string                    `json:"default_ports,omitempty"`
	PublicIP       string                    `json:"public_ip,omitempty"`
	AdminProfile   AdminProfileEntry         `json:"admin_profile,omitempty"`
	AdminDownBytes int64                     `json:"admin_down_bytes,omitempty"`
	AdminUpBytes   int64                     `json:"admin_up_bytes,omitempty"`
	AdminTraffic   []TrafficBucket           `json:"admin_traffic,omitempty"`
	Passwords      map[string]*PasswordEntry `json:"passwords"`
	Devices        map[string]*ClientDevice  `json:"devices"`
}

type deviceInfoPayload struct {
	Name           string `json:"name"`
	Manufacturer   string `json:"manufacturer"`
	Brand          string `json:"brand"`
	Model          string `json:"model"`
	AndroidVersion string `json:"android_version"`
	SDK            int    `json:"sdk"`
	ABI            string `json:"abi"`
	AppVersion     string `json:"app_version"`
	Locale         string `json:"locale"`
	Country        string `json:"country"`
	TimeZone       string `json:"time_zone"`
}

var (
	db      *Database
	dbMutex sync.Mutex
	dbFile  string
)

var dbTrafficDirty int32

var serverDNS atomic.Value
var serverDefaultPorts atomic.Value
var serverPublicIPOverride atomic.Value

func setServerDNS(value string) {
	if strings.TrimSpace(value) == "" {
		value = defaultDNS
	}
	serverDNS.Store(value)
}

func getServerDNS() string {
	value, _ := serverDNS.Load().(string)
	if strings.TrimSpace(value) == "" {
		return defaultDNS
	}
	return value
}

func setServerDefaultPorts(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "56000,56001,9000"
	}
	serverDefaultPorts.Store(value)
}

func getServerDefaultPorts() string {
	value, _ := serverDefaultPorts.Load().(string)
	if strings.TrimSpace(value) == "" {
		return "56000,56001,9000"
	}
	return value
}

func setServerPublicIPOverride(value string) {
	serverPublicIPOverride.Store(strings.TrimSpace(value))
}

func getServerPublicIPOverride() string {
	value, _ := serverPublicIPOverride.Load().(string)
	return strings.TrimSpace(value)
}

var serverWrapKeys = newWrapKeyStore()

const (
	passChars                    = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
	generatedPasswordLen         = 16
	defaultMaxGeneratedPasswords = 50
)

var maxGeneratedPasswords = defaultMaxGeneratedPasswords

func generatePassword() string {
	b := make([]byte, generatedPasswordLen)
	randomBytes := make([]byte, len(b))
	if _, err := rand.Read(randomBytes); err != nil {
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = passChars[int(now+int64(i))%len(passChars)]
		}
		return string(b)
	}
	for i, raw := range randomBytes {
		b[i] = passChars[int(raw)%len(passChars)]
	}
	return string(b)
}

func normalizeClientPassword(input string) (string, error) {
	password := strings.TrimSpace(input)
	if len(password) != generatedPasswordLen {
		return "", fmt.Errorf("пароль клиента должен содержать ровно %d символов", generatedPasswordLen)
	}
	for _, ch := range password {
		if !strings.ContainsRune(passChars, ch) {
			return "", errors.New("пароль клиента содержит недопустимые символы")
		}
	}
	return password, nil
}

var publicIP string = ""

func getPublicIP() string {
	if override := getServerPublicIPOverride(); override != "" {
		return override
	}
	if publicIP != "" {
		return publicIP
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	defer resp.Body.Close()
	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	publicIP = string(bytes.TrimSpace(ipBytes))
	return publicIP
}

func stripVkUrl(url string) string {
	url = strings.TrimSpace(url)
	if idx := strings.LastIndex(url, "/"); idx != -1 {
		url = url[idx+1:]
	}
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	return strings.TrimSpace(url)
}

type wrapKeyEntry struct {
	identity accessIdentity
	key      []byte
}

type wrapKeyStore struct {
	mu      sync.RWMutex
	entries []wrapKeyEntry
}

func newWrapKeyStore() *wrapKeyStore {
	return &wrapKeyStore{}
}

func deriveWrapKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("empty password")
	}
	key := make([]byte, wrapKeyLen)
	reader := hkdf.New(
		sha256.New,
		[]byte(password),
		[]byte("WDTT-WRAP-v1"),
		[]byte("rtp-obfs/chacha20poly1305"),
	)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive wrap key: %w", err)
	}
	return key, nil
}

func wrapKeyID(password string) string {
	sum := sha256.Sum256([]byte("WDTT-WRAP-ID-v1\x00" + password))
	return hex.EncodeToString(sum[:8])
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (s *wrapKeyStore) SetPasswords(mainPassword string, generated []string) error {
	next := make([]wrapKeyEntry, 0, len(generated)+1)
	seen := make(map[string]struct{}, len(generated)+1)

	if mainPassword != "" {
		key, err := deriveWrapKey(mainPassword)
		if err != nil {
			return err
		}
		next = append(next, wrapKeyEntry{
			identity: accessIdentity{id: "main", password: mainPassword, isMain: true},
			key:      key,
		})
		seen["main"] = struct{}{}
	}

	for _, password := range generated {
		if password == "" {
			continue
		}
		id := "pass:" + wrapKeyID(password)
		if _, exists := seen[id]; exists {
			continue
		}
		key, err := deriveWrapKey(password)
		if err != nil {
			for _, entry := range next {
				zeroBytes(entry.key)
			}
			return err
		}
		next = append(next, wrapKeyEntry{
			identity: accessIdentity{id: id, password: password},
			key:      key,
		})
		seen[id] = struct{}{}
	}

	s.mu.Lock()
	old := s.entries
	s.entries = next
	s.mu.Unlock()
	for _, entry := range old {
		aeadCache.Delete(string(entry.key))
		zeroBytes(entry.key)
	}
	return nil
}

func (s *wrapKeyStore) AddPassword(password string) error {
	key, err := deriveWrapKey(password)
	if err != nil {
		return err
	}
	id := "pass:" + wrapKeyID(password)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if entry.identity.id == id {
			zeroBytes(key)
			return nil
		}
	}
	s.entries = append(s.entries, wrapKeyEntry{
		identity: accessIdentity{id: id, password: password},
		key:      key,
	})
	return nil
}

func (s *wrapKeyStore) RemovePassword(password string) {
	id := "pass:" + wrapKeyID(password)

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, entry := range s.entries {
		if entry.identity.id != id {
			continue
		}
		aeadCache.Delete(string(entry.key))
		zeroBytes(entry.key)
		copy(s.entries[i:], s.entries[i+1:])
		s.entries[len(s.entries)-1] = wrapKeyEntry{}
		s.entries = s.entries[:len(s.entries)-1]
		return
	}
}

func (s *wrapKeyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *wrapKeyStore) Unwrap(raw, dst []byte) ([]byte, accessIdentity, int, error) {
	if !obfsIsRTPPacket(raw) {
		return nil, accessIdentity{}, 0, errors.New("wrap: non-obfs packet")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return nil, accessIdentity{}, 0, errors.New("wrap: no active keys")
	}
	for _, entry := range s.entries {
		m, err := obfsUnwrapPacket(entry.key, raw, dst)
		if err == nil {
			return append([]byte(nil), entry.key...), entry.identity, m, nil
		}
	}
	return nil, accessIdentity{}, 0, errors.New("wrap: auth failed")
}

func refreshWrapKeysFromDBLocked() error {
	passwords := make([]string, 0, len(db.Passwords))
	for password, entry := range db.Passwords {
		if entry != nil && !entry.IsDeactivated && !isPasswordPurgeable(entry) {
			passwords = append(passwords, password)
		}
	}
	return serverWrapKeys.SetPasswords(db.MainPassword, passwords)
}

func rememberAdminDeviceID(profile *AdminProfileEntry, deviceID string) bool {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false
	}
	for _, existing := range profile.DeviceIDs {
		if existing == deviceID {
			return false
		}
	}
	profile.DeviceIDs = append(profile.DeviceIDs, deviceID)
	return true
}

func adminDeviceIDSet(loaded *Database) map[string]struct{} {
	result := make(map[string]struct{}, len(loaded.AdminProfile.DeviceIDs))
	for _, deviceID := range loaded.AdminProfile.DeviceIDs {
		deviceID = strings.TrimSpace(deviceID)
		if deviceID != "" {
			result[deviceID] = struct{}{}
		}
	}
	return result
}

func initDB(dir, mainPass, adminID, botToken, dnsValue string) error {
	dbFile = filepath.Join(dir, "passwords.json")
	loaded, err := loadDatabaseFile(dbFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("загрузка passwords.json: %w", err)
		}
		if _, previousErr := os.Lstat(dbFile + databasePreviousSuffix); previousErr == nil {
			return fmt.Errorf("основная база отсутствует, но найдена предыдущая копия; автоматическое создание пустой базы запрещено")
		} else if !os.IsNotExist(previousErr) {
			return fmt.Errorf("проверка предыдущей копии базы: %w", previousErr)
		}
		if strings.TrimSpace(mainPass) == "" {
			return errors.New("passwords.json отсутствует и главный пароль для первой установки не задан")
		}
		loaded = &Database{
			Passwords: make(map[string]*PasswordEntry),
			Devices:   make(map[string]*ClientDevice),
		}
	}
	db = loaded
	if mainPass != "" || db.MainPassword == "" {
		db.MainPassword = mainPass
	}
	if adminID != "" || db.AdminID == "" {
		db.AdminID = adminID
	}
	if botToken != "" || db.BotToken == "" {
		db.BotToken = botToken
	}
	if dnsValue == "" {
		dnsValue = db.DNS
	}
	if dnsValue == "" {
		dnsValue = defaultDNS
	}
	normalizedDNS, err := normalizeDNSInput(dnsValue)
	if err != nil {
		return fmt.Errorf("некорректный DNS в passwords.json или параметре -dns: %w", err)
	}
	db.DNS = normalizedDNS
	setServerDNS(normalizedDNS)
	if db.MaxPasswords > 0 && maxGeneratedPasswords == defaultMaxGeneratedPasswords {
		if db.MaxPasswords > 500 {
			maxGeneratedPasswords = 500
		} else {
			maxGeneratedPasswords = db.MaxPasswords
		}
	}
	db.MaxPasswords = maxGeneratedPasswords
	if strings.TrimSpace(db.DefaultPorts) == "" {
		db.DefaultPorts = "56000,56001,9000"
	}
	if strings.TrimSpace(db.MainPassword) == "" {
		return errors.New("main_password в passwords.json пуст; запуск без явного восстановления запрещён")
	}
	db.AdminProfile = normalizeAdminProfileForStorage(db.AdminProfile, db.DefaultPorts)
	setServerDefaultPorts(db.DefaultPorts)
	setServerPublicIPOverride(db.PublicIP)
	if err := saveDB(); err != nil {
		return err
	}
	if err := refreshWrapKeysFromDBLocked(); err != nil {
		return fmt.Errorf("инициализация ключей обёртки: %w", err)
	}
	return nil
}

// botRuntimeCredentials returns the values persisted in the protected database.
// Deploy updates intentionally do not put these values back into systemd or the
// process command line, so every restart must use the database as the runtime
// source of truth.
func botRuntimeCredentials() (string, string) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if db == nil {
		return "", ""
	}
	return strings.TrimSpace(db.BotToken), strings.TrimSpace(db.AdminID)
}

func saveDB() error {
	if err := persistDatabaseFile(dbFile, db); err != nil {
		log.Printf("[DB] сохранение отклонено: %v", err)
		return err
	}
	return nil
}

func isPasswordExpired(entry *PasswordEntry) bool {
	return isPasswordExpiredAt(entry, time.Now().Unix())
}

func isPasswordExpiredAt(entry *PasswordEntry, nowUnix int64) bool {
	if entry == nil {
		return true
	}
	if entry.ExpiresAt == 0 {
		return false // бессрочный
	}
	return nowUnix >= entry.ExpiresAt
}

func passwordPurgeDeadline(entry *PasswordEntry) int64 {
	if entry == nil || entry.ExpiresAt == 0 {
		return 0
	}
	if entry.PurgeAfter > entry.ExpiresAt {
		return entry.PurgeAfter
	}
	return entry.ExpiresAt
}

func isPasswordRetainedExpiredAt(entry *PasswordEntry, nowUnix int64) bool {
	return isPasswordExpiredAt(entry, nowUnix) && !isPasswordPurgeableAt(entry, nowUnix)
}

func isPasswordPurgeable(entry *PasswordEntry) bool {
	return isPasswordPurgeableAt(entry, time.Now().Unix())
}

func isPasswordPurgeableAt(entry *PasswordEntry, nowUnix int64) bool {
	if entry == nil {
		return true
	}
	if entry.ExpiresAt < 0 {
		return true
	}
	deadline := passwordPurgeDeadline(entry)
	return deadline > 0 && nowUnix >= deadline
}

func setPasswordExpiryPreservingRetention(entry *PasswordEntry, expiresAt int64) {
	if entry == nil {
		return
	}
	retentionDuration := entry.PurgeAfter - entry.ExpiresAt
	entry.ExpiresAt = expiresAt
	entry.PurgeAfter = 0
	if expiresAt > 0 && retentionDuration > 0 {
		purgeAfter := expiresAt + retentionDuration
		if purgeAfter >= expiresAt {
			entry.PurgeAfter = purgeAfter
		}
	}
}

func getNextIP() string {
	used := make(map[string]bool)
	for _, dev := range db.Devices {
		used[dev.IP] = true
	}
	for i := 2; i <= 250; i++ {
		ip := fmt.Sprintf("10.66.66.%d", i)
		if !used[ip] {
			return ip
		}
	}
	return ""
}

func removePeerFromWG(wgDev wgDevice, dev *ClientDevice) {
	if wgDev == nil || dev == nil || dev.PubKey == "" {
		return
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return
	}
	wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
}

func upsertPeerInWG(wgDev wgDevice, dev *ClientDevice) {
	if wgDev == nil || dev == nil || dev.PubKey == "" || dev.IP == "" {
		return
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return
	}
	wgDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, dev.IP))
}

func cleanupExpiredPasswordsLocked(wgDev wgDevice) int {
	return cleanupExpiredPasswordsLockedAt(wgDev, time.Now().Unix())
}

func cleanupExpiredPasswordsLockedAt(wgDev wgDevice, nowUnix int64) int {
	removed := 0
	adminDevices := adminDeviceIDSet(db)
	deviceCandidates := make(map[string]struct{})
	for p, entry := range db.Passwords {
		if isPasswordPurgeableAt(entry, nowUnix) {
			if entry != nil && entry.DeviceID != "" {
				markActiveBindUnbound(entry, entry.DeviceID, nowUnix)
				deviceCandidates[entry.DeviceID] = struct{}{}
			}
			delete(db.Passwords, p)
			serverWrapKeys.RemovePassword(p)
			removed++
		}
	}
	for deviceID := range deviceCandidates {
		if _, isAdminDevice := adminDevices[deviceID]; isAdminDevice || databaseUsesDeviceID(db, deviceID) {
			continue
		}
		removePeerFromWG(wgDev, db.Devices[deviceID])
		delete(db.Devices, deviceID)
	}
	return removed
}

func databaseUsesDeviceID(loaded *Database, deviceID string) bool {
	return databaseUsesDeviceIDExcept(loaded, deviceID, "")
}

func databaseUsesDeviceIDExcept(loaded *Database, deviceID, excludedPassword string) bool {
	if loaded == nil || deviceID == "" {
		return false
	}
	for password, entry := range loaded.Passwords {
		if excludedPassword != "" && password == excludedPassword {
			continue
		}
		if entry != nil && entry.DeviceID == deviceID {
			return true
		}
	}
	return false
}

func cleanupExpiredPasswords(wgDev wgDevice) int {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	removed := cleanupExpiredPasswordsLocked(wgDev)
	if removed > 0 {
		if err := saveDB(); err != nil {
			log.Printf("[DB] не удалось сохранить очистку истёкших записей: %v", err)
		}
	}
	return removed
}

func cleanDeviceInfoText(value string, limit int) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	if limit > 0 && len(value) > limit {
		value = value[:limit]
	}
	return value
}

func parseDeviceInfoPayload(raw string) deviceInfoPayload {
	var info deviceInfoPayload
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return info
	}
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return deviceInfoPayload{}
	}
	info.Name = cleanDeviceInfoText(info.Name, 80)
	info.Manufacturer = cleanDeviceInfoText(info.Manufacturer, 40)
	info.Brand = cleanDeviceInfoText(info.Brand, 40)
	info.Model = cleanDeviceInfoText(info.Model, 80)
	info.AndroidVersion = cleanDeviceInfoText(info.AndroidVersion, 24)
	info.ABI = cleanDeviceInfoText(info.ABI, 32)
	info.AppVersion = cleanDeviceInfoText(info.AppVersion, 32)
	info.Locale = cleanDeviceInfoText(info.Locale, 32)
	info.Country = cleanDeviceInfoText(info.Country, 32)
	info.TimeZone = cleanDeviceInfoText(info.TimeZone, 64)
	if info.SDK < 0 || info.SDK > 1000 {
		info.SDK = 0
	}
	return info
}

func remoteIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func applyDeviceInfo(dev *ClientDevice, info deviceInfoPayload, remoteIP string, now int64) {
	if dev == nil {
		return
	}
	if info.Name != "" {
		dev.Name = info.Name
	}
	if info.Manufacturer != "" {
		dev.Manufacturer = info.Manufacturer
	}
	if info.Brand != "" {
		dev.Brand = info.Brand
	}
	if info.Model != "" {
		dev.Model = info.Model
	}
	if info.AndroidVersion != "" {
		dev.AndroidVersion = info.AndroidVersion
	}
	if info.SDK > 0 {
		dev.SDK = info.SDK
	}
	if info.ABI != "" {
		dev.ABI = info.ABI
	}
	if info.AppVersion != "" {
		dev.AppVersion = info.AppVersion
	}
	if info.Locale != "" {
		dev.Locale = info.Locale
	}
	if info.Country != "" {
		dev.Country = info.Country
	}
	if info.TimeZone != "" {
		dev.TimeZone = info.TimeZone
	}
	if remoteIP != "" {
		dev.RemoteIP = remoteIP
	}
	dev.LastSeenAt = now
}

func deviceDisplayNameFromInfo(deviceID string, info deviceInfoPayload) string {
	if info.Name != "" {
		return info.Name
	}
	parts := []string{}
	if info.Manufacturer != "" {
		parts = append(parts, info.Manufacturer)
	}
	if info.Model != "" {
		parts = append(parts, info.Model)
	}
	name := strings.TrimSpace(strings.Join(parts, " "))
	if name != "" {
		return name
	}
	if deviceID != "" {
		return deviceID
	}
	return "unknown"
}

func deviceDisplayName(dev *ClientDevice) string {
	if dev == nil {
		return ""
	}
	if strings.TrimSpace(dev.Name) != "" {
		return dev.Name
	}
	parts := []string{}
	if strings.TrimSpace(dev.Manufacturer) != "" {
		parts = append(parts, dev.Manufacturer)
	}
	if strings.TrimSpace(dev.Model) != "" {
		parts = append(parts, dev.Model)
	}
	name := strings.TrimSpace(strings.Join(parts, " "))
	if name != "" {
		return name
	}
	return dev.DeviceID
}

func appendBindHistory(entry *PasswordEntry, event BindHistoryEntry) {
	if entry == nil {
		return
	}
	if event.EventAt == 0 {
		event.EventAt = time.Now().Unix()
	}
	entry.BindHistory = append(entry.BindHistory, event)
	if len(entry.BindHistory) > 50 {
		entry.BindHistory = entry.BindHistory[len(entry.BindHistory)-50:]
	}
}

func markActiveBindUnbound(entry *PasswordEntry, deviceID string, ts int64) {
	if entry == nil || deviceID == "" {
		return
	}
	for i := len(entry.BindHistory) - 1; i >= 0; i-- {
		h := &entry.BindHistory[i]
		if h.DeviceID == deviceID && h.Status == "active" && h.UnboundAt == 0 {
			h.Status = "unbound"
			h.UnboundAt = ts
			h.EventAt = ts
			return
		}
	}
}

func expiredPasswordJanitor(ctx context.Context, wgDev wgDevice) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if removed := cleanupExpiredPasswords(wgDev); removed > 0 {
				log.Printf("[DB] Удалено истёкших паролей: %d", removed)
			}
		}
	}
}

func syncPersistedPeersToWG(_ wgDevice) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	count := 0
	for _, dev := range db.Devices {
		if dev.PubKey != "" && dev.IP != "" {
			count++
		}
	}
	if count > 0 {
		log.Printf("[WG] Сохранённых устройств: %d; peer'ы добавятся при новом GETCONF", count)
	}
}

// ==================== Пул буферов ====================

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1600)
		return &b
	},
}

func getBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) { bufPool.Put(b) }

// ==================== Оптимизация ====================

func enableBBR() {
	log.Println("[SYS] Оптимизация сетевого стека...")
	out, _ := runCmd("bash", "-c", "sysctl net.ipv4.tcp_congestion_control")
	cmds := [][]string{
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.core.rmem_max=25165824"},
		{"sysctl", "-w", "net.core.wmem_max=25165824"},
		{"sysctl", "-w", "net.core.rmem_default=4194304"},
		{"sysctl", "-w", "net.core.wmem_default=4194304"},
		{"sysctl", "-w", "net.core.netdev_max_backlog=16384"},
		{"sysctl", "-w", "net.ipv4.udp_rmem_min=262144"},
		{"sysctl", "-w", "net.ipv4.udp_wmem_min=262144"},
		{"sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 25165824"},
		{"sysctl", "-w", "net.ipv4.tcp_wmem=4096 65536 25165824"},
	}
	if !strings.Contains(out, "bbr") {
		cmds = append(cmds, []string{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"})
	}
	for _, cmd := range cmds {
		runCmd(cmd[0], cmd[1:]...)
	}
	log.Println("[SYS] Сетевые буферы, fq и BBR настроены ✓")
}

// ==================== Статистика ====================

var (
	totalBytesFromClient int64
	totalBytesToClient   int64
	activeConns          int32
	totalConns           int64
	natType              string = "Инициализация..."
	serverStartTime      time.Time
)

const trafficHistoryDays = 400

func trafficDayKey(t time.Time) string {
	return t.Format("2006-01-02")
}

func addTrafficBucket(buckets []TrafficBucket, day string, downBytes, upBytes int64) []TrafficBucket {
	if downBytes == 0 && upBytes == 0 {
		return buckets
	}
	for i := range buckets {
		if buckets[i].Date == day {
			buckets[i].DownBytes += downBytes
			buckets[i].UpBytes += upBytes
			return pruneTrafficBuckets(buckets, time.Now())
		}
	}
	buckets = append(buckets, TrafficBucket{
		Date:      day,
		DownBytes: downBytes,
		UpBytes:   upBytes,
	})
	return pruneTrafficBuckets(buckets, time.Now())
}

func pruneTrafficBuckets(buckets []TrafficBucket, now time.Time) []TrafficBucket {
	if len(buckets) == 0 {
		return buckets
	}
	cutoff := now.AddDate(0, 0, -trafficHistoryDays).Format("2006-01-02")
	write := 0
	for _, bucket := range buckets {
		if bucket.Date >= cutoff {
			buckets[write] = bucket
			write++
		}
	}
	return buckets[:write]
}

func addTrafficLocked(password string, isMainPassword bool, downBytes, upBytes int64) bool {
	if password == "" {
		return true
	}
	day := trafficDayKey(time.Now())
	if isMainPassword {
		db.AdminDownBytes += downBytes
		db.AdminUpBytes += upBytes
		db.AdminTraffic = addTrafficBucket(db.AdminTraffic, day, downBytes, upBytes)
		atomic.StoreInt32(&dbTrafficDirty, 1)
		return true
	}
	entry, ok := db.Passwords[password]
	if !ok || entry == nil || isPasswordExpired(entry) || entry.IsDeactivated {
		return false
	}
	entry.DownBytes += downBytes
	entry.UpBytes += upBytes
	entry.Traffic = addTrafficBucket(entry.Traffic, day, downBytes, upBytes)
	atomic.StoreInt32(&dbTrafficDirty, 1)
	return true
}

func statsLoop(ctx context.Context, configDir string) {
	serverStartTime = time.Now()
	statsFile := filepath.Join(configDir, "server.log")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	defer func() {
		flushAccessTraffic()
		dbMutex.Lock()
		if atomic.SwapInt32(&dbTrafficDirty, 0) == 1 {
			if err := saveDB(); err != nil {
				atomic.StoreInt32(&dbTrafficDirty, 1)
			}
		}
		dbMutex.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flushAccessTraffic()
			fromC := atomic.LoadInt64(&totalBytesFromClient)
			toC := atomic.LoadInt64(&totalBytesToClient)
			active := atomic.LoadInt32(&activeConns)
			total := atomic.LoadInt64(&totalConns)
			uptime := time.Since(serverStartTime)

			log.Printf("[СТАТ] Активных: %d | Всего: %d | CPU: %.1f%% | RAM: %.1f%% | NAT: %s | ↑%.2f МБ | ↓%.2f МБ",
				active, total, runtimeCPUPercent(), runtimeMemoryPercent(), natType,
				float64(fromC)/1024/1024,
				float64(toC)/1024/1024,
			)

			// Пишем server.log
			dbMutex.Lock()
			numPasswords := len(db.Passwords)
			numDevices := len(db.Devices)
			if atomic.SwapInt32(&dbTrafficDirty, 0) == 1 {
				if err := saveDB(); err != nil {
					atomic.StoreInt32(&dbTrafficDirty, 1)
				}
			}
			dbMutex.Unlock()

			uptimeStr := formatUptime(uptime)
			downGB := float64(toC) / (1024 * 1024 * 1024)
			upGB := float64(fromC) / (1024 * 1024 * 1024)

			statsJSON, _ := json.Marshal(map[string]interface{}{
				"active":    active,
				"total":     total,
				"nat":       natType,
				"uptime":    uptimeStr,
				"down_gb":   fmt.Sprintf("%.2f", downGB),
				"up_gb":     fmt.Sprintf("%.2f", upGB),
				"passwords": numPasswords,
				"devices":   numDevices,
				"timestamp": time.Now().Unix(),
			})
			os.WriteFile(statsFile, statsJSON, 0644)
		}
	}
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dд %dч %dм", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dч %dм", hours, mins)
	}
	return fmt.Sprintf("%dм", mins)
}

// ==================== Утилиты ====================

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runCmdSilent(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func isNetTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func getDefaultInterface() string {
	out := runCmdSilent("bash", "-c", "ip route show default | awk '/default/ {print $5}' | head -1")
	if out != "" {
		return strings.TrimSpace(out)
	}
	out = runCmdSilent("bash", "-c", "ip -o link show | awk -F': ' '{print $2}' | grep -v -E 'lo|wg|tun|wdtt' | head -1")
	if out != "" {
		return strings.TrimSpace(out)
	}
	return "eth0"
}

// ==================== Ключи ====================

type wgKeys struct {
	serverPrivate, serverPublic, clientPrivate, clientPublic string
}

func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("key length %d != 32", len(b))
	}
	return hex.EncodeToString(b), nil
}

func generateKeyPair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}

func loadOrGenerateKeys(dir string) (*wgKeys, error) {
	f := filepath.Join(dir, "wg-keys.dat")
	if info, err := os.Lstat(f); err == nil {
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
			return nil, errors.New("wg-keys.dat должен быть обычным непустым файлом допустимого размера")
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("чтение wg-keys.dat: %w", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 4 {
			return nil, errors.New("wg-keys.dat должен содержать ровно четыре ключа")
		}
		keys := &wgKeys{
			serverPrivate: strings.TrimSpace(lines[0]),
			serverPublic:  strings.TrimSpace(lines[1]),
			clientPrivate: strings.TrimSpace(lines[2]),
			clientPublic:  strings.TrimSpace(lines[3]),
		}
		for _, k := range []string{keys.serverPrivate, keys.serverPublic,
			keys.clientPrivate, keys.clientPublic} {
			if _, err := b64ToHex(k); err != nil {
				return nil, fmt.Errorf("wg-keys.dat содержит некорректный ключ: %w", err)
			}
		}
		log.Printf("[WG] Ключи загружены из %s", f)
		return keys, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("проверка wg-keys.dat: %w", err)
	}
	if len(db.Passwords) != 0 || len(db.Devices) != 0 || len(db.AdminProfile.DeviceIDs) != 0 {
		return nil, errors.New("wg-keys.dat отсутствует при существующих доступах или устройствах; автоматическая замена ключей запрещена")
	}
	log.Println("[WG] Генерирую новые ключи...")
	sPriv, sPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	cPriv, cPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	keys := &wgKeys{sPriv, sPub, cPriv, cPub}
	if err := ensurePrivateDatabaseDirectory(dir); err != nil {
		return nil, err
	}
	if err := writeSyncedFileAtomically(f, []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n",
		keys.serverPrivate, keys.serverPublic,
		keys.clientPrivate, keys.clientPublic)), 0600); err != nil {
		return nil, fmt.Errorf("сохранение новых WireGuard-ключей: %w", err)
	}
	log.Printf("[WG] Ключи сохранены в %s", f)
	return keys, nil
}

// ==================== NAT ====================

func setupFullConeNAT(wgIface string) error {
	log.Println("[NAT] ══════════════════════════════════════")

	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

	extIface := getDefaultInterface()
	log.Printf("[NAT] Внешний: %s", extIface)

	switch {
	case commandExists("iptables"):
		for i := 0; i < 5; i++ {
			exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", wgServerCIDR, "-o", extIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "MASQUERADE").Run()
		}
		exec.Command("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", wgServerCIDR, "-o", extIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "MASQUERADE").Run()
		natType = "MASQUERADE iptables ✅"
		setupForwardRules(wgIface)
	case commandExists("nft"):
		setupNftNAT(extIface)
		natType = "MASQUERADE nft ✅"
		setupForwardRules(wgIface)
	default:
		natType = "NAT не настроен: нет iptables/nft"
		log.Printf("[NAT] WARNING: %s", natType)
	}

	log.Printf("[NAT] Режим: %s", natType)
	log.Println("[NAT] ══════════════════════════════════════")
	return nil
}

func setupNftNAT(extIface string) {
	exec.Command("nft", "add", "table", "ip", "wdtt").Run()
	exec.Command("nft", "add", "chain", "ip", "wdtt", "postrouting", "{ type nat hook postrouting priority 100; }").Run()
	exec.Command("nft", "add", "rule", "ip", "wdtt", "postrouting", "ip", "saddr", wgServerCIDR, "oifname", extIface, "masquerade").Run()
}

func setupForwardRules(wgIface string) {
	if commandExists("iptables") {
		for i := 0; i < 5; i++ {
			exec.Command("iptables", "-D", "FORWARD", "-i", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
			exec.Command("iptables", "-D", "FORWARD", "-o", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
		}
		exec.Command("iptables", "-A", "FORWARD", "-i", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
		exec.Command("iptables", "-A", "FORWARD", "-o", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
		return
	}
	if commandExists("nft") {
		exec.Command("nft", "add", "table", "inet", "wdtt").Run()
		exec.Command("nft", "add", "chain", "inet", "wdtt", "forward", "{ type filter hook forward priority 0; policy accept; }").Run()
		exec.Command("nft", "add", "rule", "inet", "wdtt", "forward", "iifname", wgIface, "accept").Run()
		exec.Command("nft", "add", "rule", "inet", "wdtt", "forward", "oifname", wgIface, "accept").Run()
	}
}

// ==================== WireGuard ====================

func startUserspaceWG(keys *wgKeys, wgPort int) (*device.Device, error) {
	runCmdSilent("ip", "link", "del", wgIfaceName)
	time.Sleep(100 * time.Millisecond)

	tunDev, err := tun.CreateTUN(wgIfaceName, wgMTU)
	if err != nil {
		return nil, fmt.Errorf("CreateTUN: %w", err)
	}

	ifaceName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("TUN name: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[WG] ")
	bind := conn.NewDefaultBind()
	dev := device.NewDevice(tunDev, bind, logger)

	serverPrivHex, _ := b64ToHex(keys.serverPrivate)

	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\n",
		serverPrivHex, wgPort,
	)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("IpcSet: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device.Up: %w", err)
	}

	if err := configureInterface(ifaceName); err != nil {
		dev.Close()
		return nil, err
	}

	if err := setupFullConeNAT(ifaceName); err != nil {
		dev.Close()
		return nil, err
	}

	go func() {
		uapiFile, err := ipc.UAPIOpen(ifaceName)
		if err != nil {
			return
		}
		uapi, err := ipc.UAPIListen(ifaceName, uapiFile)
		if err != nil {
			return
		}
		defer uapi.Close()
		for {
			c, err := uapi.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	log.Printf("[WG] Запущен на порту %d", wgPort)
	return dev, nil
}

func configureInterface(ifaceName string) error {
	for _, cmd := range [][]string{
		{"ip", "addr", "add", wgServerCIDR, "dev", ifaceName},
		{"ip", "link", "set", "mtu", fmt.Sprintf("%d", wgMTU), "dev", ifaceName},
		{"ip", "link", "set", ifaceName, "up"},
	} {
		out, err := runCmd(cmd[0], cmd[1:]...)
		if err != nil && !strings.Contains(out, "File exists") {
			return fmt.Errorf("%s: %s", strings.Join(cmd, " "), out)
		}
	}
	return nil
}

func buildClientConfig(serverPublic, clientPrivate, clientIP, clientPort string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%s
PersistentKeepalive = %d`,
		clientPrivate, clientIP, getServerDNS(), wgMTU,
		serverPublic, clientPort, keepalive,
	)
}

// ==================== Main ====================

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println(wdttServerVersion)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		os.Exit(runAdminCLI(os.Args[2:]))
	}

	listen := flag.String("listen", "0.0.0.0:56000", "DTLS адрес")
	wgPort := flag.Int("wg-port", defaultInternalWGPort, "WireGuard UDP порт")
	configDir := flag.String("config-dir", "/etc/wdtt", "директория конфигурации")
	mainPass := flag.String("password", "", "пароль владельца")
	adminID := flag.String("admin", "", "Telegram Admin ID")
	botToken := flag.String("bot-token", "", "Telegram Bot Token")
	dnsValue := flag.String("dns", "", "DNS для WireGuard-клиентов, через запятую; пустое значение сохраняет DNS из базы")
	maxPasswordsFlag := flag.Int("max-passwords", defaultMaxGeneratedPasswords, "максимум активных сгенерированных паролей")
	maxWorkersFlag := flag.Int("max-workers-per-access", defaultMaxWorkersPerAccess, "максимум одновременных DTLS-воркеров одного доступа; 0 отключает лимит")
	maxHandshakesFlag := flag.Int("max-handshakes", defaultMaxHandshakes, "максимум одновременных DTLS-рукопожатий")
	handshakeRateFlag := flag.Float64("handshake-rate", defaultHandshakeRate, "допустимые DTLS-рукопожатия в секунду")
	clientMbpsFlag := flag.Float64("max-client-mbps", defaultClientMbps, "общий лимит Мбит/с на один доступ; 0 отключает")
	wgBackendFlag := flag.String("wg-backend", "auto", "WireGuard backend: auto, kernel или userspace")
	flag.Parse()

	if *maxPasswordsFlag < 1 {
		log.Printf("[DB] -max-passwords=%d некорректен, использую 1", *maxPasswordsFlag)
		maxGeneratedPasswords = 1
	} else if *maxPasswordsFlag > 500 {
		log.Printf("[DB] -max-passwords=%d слишком большой, ограничиваю до 500", *maxPasswordsFlag)
		maxGeneratedPasswords = 500
	} else {
		maxGeneratedPasswords = *maxPasswordsFlag
	}
	if *maxWorkersFlag < 0 || *maxWorkersFlag > 128 {
		log.Printf("[LIMIT] -max-workers-per-access=%d некорректен, использую %d", *maxWorkersFlag, defaultMaxWorkersPerAccess)
		*maxWorkersFlag = defaultMaxWorkersPerAccess
	}
	if *maxHandshakesFlag < 1 || *maxHandshakesFlag > 256 {
		log.Printf("[LIMIT] -max-handshakes=%d некорректен, использую %d", *maxHandshakesFlag, defaultMaxHandshakes)
		*maxHandshakesFlag = defaultMaxHandshakes
	}
	if *handshakeRateFlag < 1 || *handshakeRateFlag > 1000 {
		log.Printf("[LIMIT] -handshake-rate=%.1f некорректен, использую %.1f", *handshakeRateFlag, defaultHandshakeRate)
		*handshakeRateFlag = defaultHandshakeRate
	}
	if *clientMbpsFlag < 0 || *clientMbpsFlag > 1000 {
		log.Printf("[LIMIT] -max-client-mbps=%.1f некорректен, использую %.1f", *clientMbpsFlag, defaultClientMbps)
		*clientMbpsFlag = defaultClientMbps
	}
	configureAccessRuntime(*maxWorkersFlag, *clientMbpsFlag)
	configureHandshakeLimits(*maxHandshakesFlag, *handshakeRateFlag)

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("══════════════════════════════════════════")
	log.Println("   WDTT Server v2 (Multi-User)")
	log.Println("══════════════════════════════════════════")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		cancel()
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	if err := initDB(*configDir, *mainPass, *adminID, *botToken, *dnsValue); err != nil {
		log.Fatalf("[DB] Безопасный запуск остановлен: %v", err)
	}

	keys, err := loadOrGenerateKeys(*configDir)
	if err != nil {
		log.Fatalf("[WG] Ключи: %v", err)
	}

	enableBBR()

	wgDev, err := startWGBackend(*wgBackendFlag, keys, *wgPort, *configDir)
	if err != nil {
		log.Fatalf("[WG] Запуск: %v", err)
	}
	if removed := cleanupExpiredPasswords(wgDev); removed > 0 {
		log.Printf("[DB] Удалено истёкших паролей при старте: %d", removed)
	}
	syncPersistedPeersToWG(wgDev)
	if err := startAdminSocket(ctx, *configDir, wgDev); err != nil {
		log.Fatalf("[ADMIN] Локальное управление: %v", err)
	}
	startServerBackupScheduler(ctx, *configDir)
	defer func() {
		wgDev.Close()
		runCmdSilent("ip", "link", "del", wgIfaceName)
	}()

	go statsLoop(ctx, *configDir)
	go systemMetricsLoop(ctx)
	go expiredPasswordJanitor(ctx, wgDev)
	storedBotToken, storedAdminID := botRuntimeCredentials()
	go botLoop(storedBotToken, storedAdminID, wgDev)

	addr, _ := net.ResolveUDPAddr("udp", *listen)
	cert, _ := selfsign.GenerateSelfSigned()
	if serverWrapKeys.Count() == 0 {
		log.Fatalf("[WRAP] нет активных паролей для WRAP")
	}

	wrapListener, err := listenWrapped(addr, serverWrapKeys)
	if err != nil {
		log.Fatalf("[WRAP] %v", err)
	}

	listener, err := dtls.NewListenerWithOptions(wrapListener, dtls.WithCertificates(cert), dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret), dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
	if err != nil {
		log.Fatalf("[DTLS] %v", err)
	}
	context.AfterFunc(ctx, func() { listener.Close() })

	wgEndpoint := fmt.Sprintf("127.0.0.1:%d", *wgPort)

	log.Printf("   DTLS: %s | WG: %s | NAT: %s", *listen, wgEndpoint, natType)
	log.Printf("   WRAP: password HKDF + RTP AEAD | keys: %d", serverWrapKeys.Count())
	log.Println("[SERVER] Готов")

	var wg sync.WaitGroup
	for {
		dtlsConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			default:
			}
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			handleConn(ctx, c, wgEndpoint, wgDev, keys, *configDir)
		}(dtlsConn)
	}
}

// ==================== Обработка соединений ====================

func denyExpiredAccess(clientConn net.Conn, identity accessIdentity) {
	if clientConn == nil || !identity.valid() || identity.isMain {
		return
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	request := strings.TrimSpace(string(buf[:n]))
	if !strings.HasPrefix(request, "GETCONF:") {
		return
	}
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(request, "GETCONF:")), "|")
	if len(parts) < 3 || parts[2] != identity.password {
		_, _ = clientConn.Write([]byte("DENIED:wrong_password"))
		return
	}
	_, _ = clientConn.Write([]byte("DENIED:expired"))
}

func handleConn(ctx context.Context, clientConn net.Conn, wgEndpoint string, wgDev wgDevice, keys *wgKeys, configDir string) {
	atomic.AddInt64(&totalConns, 1)

	var connDevice *ClientDevice

	dtlsConn, ok := clientConn.(*dtls.Conn)
	if !ok {
		return
	}

	hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
	releaseHandshake, acquired := acquireHandshake(hctx)
	if !acquired {
		hcancel()
		return
	}
	if err := dtlsConn.HandshakeContext(hctx); err != nil {
		releaseHandshake()
		failures := atomic.AddInt64(&handshakeFailures, 1)
		if failures <= 5 || failures%100 == 0 {
			log.Printf("[DTLS] Рукопожатие от %s не завершено: %v", clientConn.RemoteAddr(), err)
		}
		hcancel()
		return
	}
	releaseHandshake()
	hcancel()

	// The WRAP identity is selected while DTLS reads its first encrypted packet.
	// It therefore becomes available only after a successful handshake.
	identity, ok := wrappedIdentity(clientConn.RemoteAddr())
	if !ok {
		failures := atomic.AddInt64(&handshakeFailures, 1)
		if failures <= 5 || failures%100 == 0 {
			log.Printf("[WRAP] Не удалось связать соединение %s с доступом", clientConn.RemoteAddr())
		}
		return
	}
	switch currentAccessIdentityState(identity) {
	case accessIdentityExpired:
		denyExpiredAccess(clientConn, identity)
		return
	case accessIdentityActive:
		// Continue with the normal worker path.
	default:
		return
	}
	sendWorkerPolicy := func() {
		if maxWorkers := configuredAccessWorkerLimit(); maxWorkers > 0 {
			_ = clientConn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			_, _ = clientConn.Write([]byte(fmt.Sprintf("POLICY:max_workers=%d", maxWorkers)))
			_ = clientConn.SetWriteDeadline(time.Time{})
		}
	}
	var runtimeLease *accessRuntime
	var workerLease *accessWorkerLease
	var releaseWorker func()
	workerAdmitted := false

	buf := make([]byte, 1600)
	// GETCONF is sent immediately after the client handshake. Give it a short
	// pre-admission window so a new authenticated transport generation can replace
	// stale leases even when the old generation has filled the worker quota. Regular
	// data workers still enter the normal quota before waiting for user traffic.
	clientConn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	n, err := clientConn.Read(buf)
	if err != nil {
		if networkError, timedOut := err.(net.Error); timedOut && networkError.Timeout() {
			runtimeLease, workerLease, releaseWorker, ok =
				acquireAccessWorkerSession(identity, clientConn)
			if !ok {
				sendWorkerPolicy()
				return
			}
			workerAdmitted = true
			defer releaseWorker()
			clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err = clientConn.Read(buf)
		}
	}
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	firstPacket := buf[:n]
	firstStr := string(firstPacket)

	if strings.HasPrefix(firstStr, "GETCONF:") {
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(firstStr, "GETCONF:")), "|")
		clientPort := "9000"
		deviceID := "unknown"
		password := ""
		deviceInfo := deviceInfoPayload{}
		transportSession := ""
		if len(parts) > 0 {
			clientPort = parts[0]
		}
		if len(parts) > 1 {
			deviceID = parts[1]
		}
		if len(parts) > 2 {
			password = parts[2]
		}
		if len(parts) > 3 {
			deviceInfo = parseDeviceInfoPayload(parts[3])
		}
		if len(parts) > 4 {
			transportSession = strings.TrimSpace(parts[4])
		}
		if password != identity.password {
			atomic.AddInt64(&handshakeFailures, 1)
			_, _ = clientConn.Write([]byte("DENIED:wrong_password"))
			return
		}
		remoteIP := remoteIPFromAddr(clientConn.RemoteAddr())
		nowUnix := time.Now().Unix()
		authorized := false
		configResponse := ""

		dbMutex.Lock()

		// Проверяем пароль
		isMainPass := password != "" && password == db.MainPassword
		entry, isGenPass := db.Passwords[password]
		valid := isMainPass || (isGenPass && !isPasswordExpired(entry))

		if valid && isGenPass && entry.IsDeactivated {
			clientConn.Write([]byte("DENIED:deactivated"))
			log.Printf(
				"[WG] Отказ: пароль %s деактивирован, устройство %s",
				maskPassword(password),
				deviceLogRef(deviceID),
			)
			dbMutex.Unlock()
		} else if valid && isGenPass && entry.DeviceID != "" && entry.DeviceID != deviceID {
			previousHistoryLength := len(entry.BindHistory)
			appendBindHistory(entry, BindHistoryEntry{
				DeviceID:   deviceID,
				DeviceName: deviceDisplayNameFromInfo(deviceID, deviceInfo),
				RemoteIP:   remoteIP,
				Country:    deviceInfo.Country,
				EventAt:    nowUnix,
				Status:     "denied_mismatch",
				Note:       "пароль уже привязан к другому устройству",
			})
			if err := saveDB(); err != nil {
				entry.BindHistory = entry.BindHistory[:previousHistoryLength]
			}
			// Пароль уже привязан к другому устройству
			clientConn.Write([]byte("DENIED:device_mismatch"))
			log.Printf(
				"[WG] Отказ: пароль %s уже привязан; сохранённое устройство %s, запрос %s",
				maskPassword(password),
				deviceLogRef(entry.DeviceID),
				deviceLogRef(deviceID),
			)
			dbMutex.Unlock()
		} else if valid {
			newlyBound := false
			previousDeviceID := ""
			previousHistoryLength := 0
			previousAdminDeviceIDs := append([]string(nil), db.AdminProfile.DeviceIDs...)
			if entry != nil {
				previousDeviceID = entry.DeviceID
				previousHistoryLength = len(entry.BindHistory)
			}

			// Привязываем пароль к устройству при первом использовании
			if isGenPass && entry.DeviceID == "" {
				entry.DeviceID = deviceID
				newlyBound = true
				log.Printf(
					"[WG] Пароль %s привязан к устройству %s",
					maskPassword(password),
					deviceLogRef(deviceID),
				)
			}
			if isMainPass {
				rememberAdminDeviceID(&db.AdminProfile, deviceID)
			}

			dev, exists := db.Devices[deviceID]
			var previousDevice ClientDevice
			if exists && dev != nil {
				previousDevice = *dev
			}
			if !exists {
				dev = &ClientDevice{DeviceID: deviceID, IP: getNextIP()}
				privB64, pubB64, keyErr := generateKeyPair()
				if keyErr == nil && dev.IP != "" {
					dev.PrivKey = privB64
					dev.PubKey = pubB64
					applyDeviceInfo(dev, deviceInfo, remoteIP, nowUnix)
					db.Devices[deviceID] = dev
					log.Printf("[WG] Новое устройство %s", deviceLogRef(deviceID))
				} else {
					dev = nil
				}
			} else {
				applyDeviceInfo(dev, deviceInfo, remoteIP, nowUnix)
			}
			if dev != nil {
				if newlyBound {
					appendBindHistory(entry, BindHistoryEntry{
						DeviceID:   deviceID,
						DeviceName: deviceDisplayName(dev),
						DeviceIP:   dev.IP,
						RemoteIP:   dev.RemoteIP,
						Country:    dev.Country,
						BoundAt:    nowUnix,
						EventAt:    nowUnix,
						Status:     "active",
					})
				}
				if err := saveDB(); err != nil {
					if exists {
						*dev = previousDevice
					} else {
						delete(db.Devices, deviceID)
					}
					if entry != nil {
						entry.DeviceID = previousDeviceID
						entry.BindHistory = entry.BindHistory[:previousHistoryLength]
					}
					db.AdminProfile.DeviceIDs = previousAdminDeviceIDs
					dev = nil
					configResponse = "DENIED:server_storage"
				}
			}
			if dev != nil {
				connDevice = dev
				authorized = true
				configResponse = buildClientConfig(keys.serverPublic, dev.PrivKey, dev.IP, clientPort)
			} else {
				configResponse = "NOCONF"
			}
			dbMutex.Unlock()
		} else {
			if isGenPass && isPasswordExpired(entry) {
				clientConn.Write([]byte("DENIED:expired"))
				log.Printf(
					"[WG] Отказ: пароль %s истёк, устройство %s",
					maskPassword(password),
					deviceLogRef(deviceID),
				)
			} else {
				clientConn.Write([]byte("DENIED:wrong_password"))
				log.Printf("[WG] Отказ (неверный пароль), устройство %s", deviceLogRef(deviceID))
			}
			dbMutex.Unlock()
		}
		if !authorized {
			if configResponse != "" {
				_, _ = clientConn.Write([]byte(configResponse))
			}
			return
		}

		if workerAdmitted {
			if transportSession != "" &&
				!activateAccessSession(workerLease, deviceID, transportSession) {
				return
			}
		} else if transportSession != "" {
			runtimeLease, workerLease, releaseWorker, ok = acquireAccessWorkerForSession(
				identity,
				clientConn,
				deviceID,
				transportSession,
			)
		} else {
			runtimeLease, workerLease, releaseWorker, ok =
				acquireAccessWorkerSession(identity, clientConn)
		}
		if !workerAdmitted && !ok {
			sendWorkerPolicy()
			return
		}
		if !workerAdmitted {
			workerAdmitted = true
			defer releaseWorker()
		}
		_, _ = clientConn.Write([]byte(configResponse))

		clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
		firstStr = string(firstPacket)
	} else if !workerAdmitted {
		runtimeLease, workerLease, releaseWorker, ok =
			acquireAccessWorkerSession(identity, clientConn)
		if !ok {
			sendWorkerPolicy()
			return
		}
		workerAdmitted = true
		defer releaseWorker()
	}

	switch currentAccessIdentityState(identity) {
	case accessIdentityExpired:
		_, _ = clientConn.Write([]byte("DENIED:expired"))
		return
	case accessIdentityActive:
		// Continue with the authenticated request.
	default:
		return
	}

	atomic.AddInt32(&activeConns, 1)
	defer atomic.AddInt32(&activeConns, -1)

	if firstStr == "READY" {
		if !accessIdentityIsActive(identity) {
			return
		}
		clientConn.Write([]byte("READY_OK"))
		clientConn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
	}

	// WDTT_MUX1 is sent by current clients before their first WireGuard packet.
	// Older clients retain the independent-socket path unchanged.
	useMultipathRelay := firstStr == multipathRelayHello && connDevice != nil
	var relay *deviceWGRelay
	var relayAttachment *deviceWGAttachment
	var wgConn net.Conn
	if useMultipathRelay {
		var relayErr error
		relay, relayAttachment, relayErr = acquireDeviceWGRelay(connDevice.DeviceID, wgEndpoint)
		if relayErr != nil {
			return
		}
		defer relay.release(relayAttachment)
		firstPacket = nil
	} else {
		wgConn, err = net.Dial("udp", wgEndpoint)
		if err != nil {
			return
		}
		defer wgConn.Close()

		if uc, ok := wgConn.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(2 * 1024 * 1024)
			_ = uc.SetWriteBuffer(2 * 1024 * 1024)
		}
	}

	if !accessIdentityIsActive(identity) {
		return
	}
	if connDevice != nil {
		upsertPeerInWG(wgDev, connDevice)
	}

	writeToWG := func(packet []byte) error {
		if relay != nil {
			return relay.writeFrom(relayAttachment, packet)
		}
		_, err := wgConn.Write(packet)
		return err
	}
	if len(firstPacket) > 0 {
		if err := runtimeLease.upload.wait(ctx, len(firstPacket)); err != nil {
			return
		}
		if err := writeToWG(firstPacket); err != nil {
			return
		}
		atomic.AddInt64(&totalBytesFromClient, int64(len(firstPacket)))
		recordAccessTraffic(runtimeLease, 0, int64(len(firstPacket)))
	}

	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	var clientWriteMu sync.Mutex
	writeClientPacket := func(packet []byte) error {
		clientWriteMu.Lock()
		defer clientWriteMu.Unlock()
		clientConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err := clientConn.Write(packet)
		clientConn.SetWriteDeadline(time.Time{})
		return err
	}
	updateRelayGate := make(chan struct{}, 16)

	if _, limited := accessIdentityExpiryUnix(identity); limited {
		go func() {
			for {
				expiresAt, stillLimited := accessIdentityExpiryUnix(identity)
				if !stillLimited {
					return
				}
				delay := time.Until(time.Unix(expiresAt, 0))
				if delay < 0 {
					delay = 0
				}
				timer := time.NewTimer(delay)
				select {
				case <-pctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					return
				case <-timer.C:
				}
				if !accessIdentityIsActive(identity) {
					pcancel()
					return
				}
				// The access was renewed before the old deadline. Read the new
				// expiration value and arm the monitor again.
			}
		}()
	}

	context.AfterFunc(pctx, func() {
		clientConn.SetDeadline(time.Now())
		if wgConn != nil {
			wgConn.SetDeadline(time.Now())
		}
	})

	var proxyWg sync.WaitGroup
	proxyWg.Add(2)

	// Клиент → WG
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		lastAccessCheck := time.Now()
		for {
			select {
			case <-pctx.Done():
				return
			default:
			}
			clientConn.SetReadDeadline(time.Now().Add(dtlsClientIdleTimeout))
			nn, err := clientConn.Read(*b)
			if err != nil {
				return
			}
			// Reply to DTLS keepalive packets so clients can detect silent UDP stalls.
			if nn == 1 && (*b)[0] == dtlsKeepaliveByte {
				if err := writeClientPacket([]byte{dtlsKeepaliveByte}); err != nil {
					return
				}
				continue
			}
			if requestID, ok := parseUpdateMetadataRequest((*b)[:nn]); ok {
				if err := writeClientPacket([]byte(updateMetadataResponsePrefix + requestID + "|ACK|")); err != nil {
					return
				}
				select {
				case updateRelayGate <- struct{}{}:
					go func() {
						defer func() { <-updateRelayGate }()
						requestCtx, requestCancel := context.WithTimeout(pctx, 10*time.Second)
						defer requestCancel()
						payload, fetchErr := cachedOfficialUpdateMetadata(requestCtx)
						for _, frame := range encodeUpdateMetadataResponse(requestID, payload, fetchErr) {
							if writeClientPacket(frame) != nil {
								return
							}
						}
					}()
				default:
					for _, frame := range encodeUpdateMetadataResponse(
						requestID,
						nil,
						errors.New("проверка обновления уже выполняется"),
					) {
						if writeClientPacket(frame) != nil {
							return
						}
					}
				}
				continue
			}
			if request, ok := parseOpaqueHTTPSRequest((*b)[:nn]); ok {
				if err := writeClientPacket([]byte(opaqueHTTPSResponsePrefix + request.requestID + "|ACK|")); err != nil {
					return
				}
				select {
				case updateRelayGate <- struct{}{}:
					go func() {
						defer func() { <-updateRelayGate }()
						requestCtx, requestCancel := context.WithTimeout(pctx, 10*time.Second)
						defer requestCancel()
						payload, relayErr := executeOpaqueHTTPSPost(requestCtx, request)
						for _, frame := range encodeOpaqueHTTPSResponse(request.requestID, payload, relayErr) {
							if writeClientPacket(frame) != nil {
								return
							}
						}
					}()
				default:
					for _, frame := range encodeOpaqueHTTPSResponse(
						request.requestID,
						nil,
						errors.New("защищённый HTTPS-канал занят"),
					) {
						if writeClientPacket(frame) != nil {
							return
						}
					}
				}
				continue
			}
			if request, ok := parseUpdateAPKChunkRequest((*b)[:nn]); ok {
				if err := writeClientPacket([]byte(updateMetadataResponsePrefix + request.requestID + "|ACK|")); err != nil {
					return
				}
				select {
				case updateRelayGate <- struct{}{}:
					go func() {
						defer func() { <-updateRelayGate }()
						requestCtx, requestCancel := context.WithTimeout(pctx, 3*time.Minute)
						defer requestCancel()
						payload, fetchErr := cachedOfficialUpdateAPKChunk(requestCtx, request)
						if fetchErr == nil {
							if writeClientPacket([]byte(updateAPKChunkResponsePrefix+request.requestID+"|READY|")) != nil {
								return
							}
						}
						for _, frame := range encodeUpdateAPKChunkResponse(request.requestID, payload, fetchErr) {
							if err := runtimeLease.download.wait(pctx, len(frame)); err != nil {
								return
							}
							if writeClientPacket(frame) != nil {
								return
							}
							atomic.AddInt64(&totalBytesToClient, int64(len(frame)))
							time.Sleep(100 * time.Microsecond)
						}
					}()
				default:
					for _, frame := range encodeUpdateAPKChunkResponse(
						request.requestID,
						nil,
						errors.New("канал загрузки обновления занят"),
					) {
						if writeClientPacket(frame) != nil {
							return
						}
					}
				}
				continue
			}
			if request, ok := parseDeploySafeStartRequest((*b)[:nn]); ok {
				if err := writeClientPacket([]byte(updateMetadataResponsePrefix + request.requestID + "|ACK|")); err != nil {
					return
				}
				select {
				case updateRelayGate <- struct{}{}:
					go func() {
						defer func() { <-updateRelayGate }()
						payload, digest, relayErr := executeCachedDeploySafeRequest(
							configDir,
							wgDev,
							identity,
							request,
						)
						metadata := []byte(fmt.Sprintf("%d|%s", len(payload), digest))
						for _, frame := range encodeUpdateMetadataResponse(request.requestID, metadata, relayErr) {
							if err := runtimeLease.download.wait(pctx, len(frame)); err != nil {
								return
							}
							if writeClientPacket(frame) != nil {
								return
							}
							atomic.AddInt64(&totalBytesToClient, int64(len(frame)))
						}
					}()
				default:
					for _, frame := range encodeUpdateMetadataResponse(
						request.requestID,
						nil,
						errors.New("канал безопасных операций занят"),
					) {
						if writeClientPacket(frame) != nil {
							return
						}
					}
				}
				continue
			}
			if request, ok := parseDeploySafeChunkRequest((*b)[:nn]); ok {
				if err := writeClientPacket([]byte(updateMetadataResponsePrefix + request.requestID + "|ACK|")); err != nil {
					return
				}
				select {
				case updateRelayGate <- struct{}{}:
					go func() {
						defer func() { <-updateRelayGate }()
						payload, relayErr := readDeploySafeChunk(identity, request)
						if relayErr == nil {
							if writeClientPacket([]byte(updateAPKChunkResponsePrefix+request.requestID+"|READY|")) != nil {
								return
							}
						}
						for _, frame := range encodeUpdateAPKChunkResponse(request.requestID, payload, relayErr) {
							if err := runtimeLease.download.wait(pctx, len(frame)); err != nil {
								return
							}
							if writeClientPacket(frame) != nil {
								return
							}
							atomic.AddInt64(&totalBytesToClient, int64(len(frame)))
							time.Sleep(100 * time.Microsecond)
						}
					}()
				default:
					for _, frame := range encodeUpdateAPKChunkResponse(
						request.requestID,
						nil,
						errors.New("канал безопасных операций занят"),
					) {
						if writeClientPacket(frame) != nil {
							return
						}
					}
				}
				continue
			}
			if time.Since(lastAccessCheck) >= 5*time.Second {
				if !accessIdentityIsActive(identity) {
					return
				}
				lastAccessCheck = time.Now()
			}
			if err := runtimeLease.upload.wait(pctx, nn); err != nil {
				return
			}
			if err := writeToWG((*b)[:nn]); err != nil {
				return
			}
			atomic.AddInt64(&totalBytesFromClient, int64(nn))
			recordAccessTraffic(runtimeLease, 0, int64(nn))
		}
	}()

	// WG → Клиент
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		lastAccessCheck := time.Now()
		for {
			select {
			case <-pctx.Done():
				return
			default:
			}
			var packet []byte
			if relay != nil {
				select {
				case packet = <-relayAttachment.downstream:
				case <-pctx.Done():
					return
				}
				nn := len(packet)
				copy(*b, packet)
				_ = nn
			} else {
				wgConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
				nn, err := wgConn.Read(*b)
				if err != nil {
					if isNetTimeout(err) {
						if pctx.Err() != nil {
							return
						}
						continue
					}
					return
				}
				packet = append(packet, (*b)[:nn]...)
			}
			nn := len(packet)
			if time.Since(lastAccessCheck) >= 5*time.Second {
				if !accessIdentityIsActive(identity) {
					return
				}
				lastAccessCheck = time.Now()
			}
			if err := runtimeLease.download.wait(pctx, nn); err != nil {
				return
			}
			if err := writeClientPacket(packet); err != nil {
				return
			}
			atomic.AddInt64(&totalBytesToClient, int64(nn))
			recordAccessTraffic(runtimeLease, int64(nn), 0)
		}
	}()

	proxyWg.Wait()
}

const (
	wrapNonceLen = 12
	wrapKeyLen   = 32
)

var aeadCache sync.Map

func getAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("obfs: key must be %d bytes", wrapKeyLen)
	}
	keyStr := string(key)
	if val, ok := aeadCache.Load(keyStr); ok {
		return val.(cipher.AEAD), nil
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	aeadCache.Store(keyStr, aead)
	return aead, nil
}

// ==================== RTP Обфускация ====================

type ObfsConfig struct {
	SSRC        uint32
	PayloadType uint8
	PaddingMax  int
}

type ObfsState struct {
	mu      sync.Mutex
	initSeq uint16
	initTs  uint32
	count   uint64
}

func NewObfsConfig() *ObfsConfig {
	var buf [4]byte
	rand.Read(buf[:])
	return &ObfsConfig{
		SSRC:        binary.BigEndian.Uint32(buf[:]),
		PayloadType: 111,
		PaddingMax:  24,
	}
}

func NewObfsState() *ObfsState {
	var buf [6]byte
	rand.Read(buf[:])
	return &ObfsState{
		initSeq: binary.BigEndian.Uint16(buf[0:2]),
		initTs:  binary.BigEndian.Uint32(buf[2:6]),
		count:   0,
	}
}

func obfsBuildNonce(ssrc uint32, seq uint16, ts uint32) [wrapNonceLen]byte {
	var n [wrapNonceLen]byte
	binary.BigEndian.PutUint32(n[0:4], ssrc)
	binary.BigEndian.PutUint16(n[4:6], seq)
	binary.BigEndian.PutUint32(n[8:12], ts)
	return n
}

func obfsWrapPacket(key, payload []byte, cfg *ObfsConfig, state *ObfsState) ([]byte, error) {
	return obfsWrapPacketInto(nil, key, payload, cfg, state)
}

func obfsWrapPacketInto(dst, key, payload []byte, cfg *ObfsConfig, state *ObfsState) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("obfs: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	if len(payload) == 0 {
		return nil, errors.New("obfs: empty payload")
	}
	state.mu.Lock()
	c := state.count
	state.count++
	state.mu.Unlock()

	seq := state.initSeq + uint16(c)
	ts := state.initTs + uint32(c)*960 + uint32(c>>16)

	nonce := obfsBuildNonce(cfg.SSRC, seq, ts)
	padRand := 0
	if cfg.PaddingMax > 0 {
		var rndBuf [1]byte
		rand.Read(rndBuf[:])
		padRand = int(rndBuf[0]) % cfg.PaddingMax
	}
	padTotal := padRand + 1
	outLen := 12 + len(payload) + chacha20poly1305.Overhead + padTotal
	if cap(dst) < outLen {
		dst = make([]byte, outLen)
	}
	out := dst[:outLen]

	out[0] = 0x80 | 0x20
	out[1] = cfg.PayloadType & 0x7F
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint32(out[4:8], ts)
	binary.BigEndian.PutUint32(out[8:12], cfg.SSRC)

	aead, err := getAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("obfs: cipher init: %w", err)
	}
	sealed := aead.Seal(out[12:12], nonce[:], payload, out[:12])
	padStart := 12 + len(sealed)
	if padRand > 0 {
		rand.Read(out[padStart : padStart+padRand])
	}
	out[outLen-1] = byte(padTotal)
	return out, nil
}

func obfsUnwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("obfs: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	if len(wire) < 13 {
		return 0, errors.New("obfs: packet too short")
	}
	if (wire[0] >> 6) != 2 {
		return 0, errors.New("obfs: not RTP v2")
	}
	seq := binary.BigEndian.Uint16(wire[2:4])
	ts := binary.BigEndian.Uint32(wire[4:8])
	ssrc := binary.BigEndian.Uint32(wire[8:12])

	payloadEnd := len(wire)
	if wire[0]&0x20 != 0 {
		padLen := int(wire[len(wire)-1])
		if padLen == 0 || padLen > payloadEnd-12 {
			return 0, fmt.Errorf("obfs: invalid padding length %d", padLen)
		}
		payloadEnd -= padLen
	}
	ciphertextLen := payloadEnd - 12
	if ciphertextLen <= chacha20poly1305.Overhead {
		return 0, errors.New("obfs: no payload")
	}
	if ciphertextLen-chacha20poly1305.Overhead > len(dst) {
		return 0, errors.New("obfs: dst buffer too small")
	}
	nonce := obfsBuildNonce(ssrc, seq, ts)
	aead, err := getAEAD(key)
	if err != nil {
		return 0, fmt.Errorf("obfs: cipher init: %w", err)
	}
	plain, err := aead.Open(dst[:0], nonce[:], wire[12:payloadEnd], wire[:12])
	if err != nil {
		return 0, fmt.Errorf("obfs: auth: %w", err)
	}
	return len(plain), nil
}

func obfsIsRTPPacket(wire []byte) bool {
	if len(wire) < 13 {
		return false
	}
	if (wire[0] >> 6) != 2 {
		return false
	}
	pt := wire[1] & 0x7F
	return pt == 111
}

func listenWrapped(addr *net.UDPAddr, keys *wrapKeyStore) (dtlsnet.PacketListener, error) {
	if keys == nil || keys.Count() == 0 {
		return nil, errors.New("wrap: no active keys")
	}
	listenConfig := opportunisticUDPListenConfig{
		Backlog:         4096,
		AcceptFilter:    obfsIsRTPPacket,
		ReadBufferSize:  16 * 1024 * 1024,
		WriteBufferSize: 16 * 1024 * 1024,
		ReadBatchSize:   opportunisticUDPDefaultReadBatchSize,
		WriteBatchSize:  opportunisticUDPDefaultWriteBatchSize,
		WriteQueueSize:  opportunisticUDPDefaultWriteQueueSize,
	}
	inner, err := listenOpportunisticUDP("udp", addr, listenConfig)
	if err != nil {
		return nil, fmt.Errorf("wrap: udp listen: %w", err)
	}
	log.Printf(
		"[UDP] ReadBatch=%d | WriteBatch=opportunistic/%d | queue=%d",
		listenConfig.ReadBatchSize,
		listenConfig.WriteBatchSize,
		listenConfig.WriteQueueSize,
	)
	return &wrapPacketListener{
		inner: inner,
		keys:  keys,
	}, nil
}

type wrapPacketListener struct {
	inner dtlsnet.PacketListener
	keys  *wrapKeyStore
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	return &wrapPacketConn{inner: pc, keys: l.keys}, addr, nil
}

func (l *wrapPacketListener) Close() error   { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

type wrapPacketConn struct {
	inner      net.PacketConn
	keys       *wrapKeyStore
	key        []byte
	identity   accessIdentity
	sessionKey string
	session    *wrappedSession
	selected   int32
	authLog    int32
	obfsCfg    *ObfsConfig
	obfsWrite  *ObfsState

	stateMu    sync.Mutex
	stateCond  *sync.Cond
	activeOps  int
	closing    bool
	closeOnce  sync.Once
	closeError error
}

var wrapWireBufferPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 2048)
		return &buffer
	},
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Extra space for RTP header (12) + AEAD tag (16) + padding.
	buffer := wrapWireBufferPool.Get().(*[]byte)
	if cap(*buffer) < len(p)+80 {
		*buffer = make([]byte, len(p)+80)
	}
	buf := (*buffer)[:len(p)+80]
	defer wrapWireBufferPool.Put(buffer)
	n, addr, err := c.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	raw := buf[:n]

	c.stateMu.Lock()
	if c.closing {
		c.stateMu.Unlock()
		return 0, addr, net.ErrClosed
	}
	if atomic.LoadInt32(&c.selected) == 0 {
		key, identity, m, uErr := c.keys.Unwrap(raw, p)
		if uErr != nil {
			c.stateMu.Unlock()
			if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
				log.Printf("[WRAP] Отказ: RTP AEAD auth failed from %s (keys=%d)", addr.String(), c.keys.Count())
			}
			return 0, addr, uErr
		}
		c.key = key
		c.identity = identity
		c.sessionKey, c.session = registerWrappedSession(addr, identity)
		c.obfsCfg = NewObfsConfig()
		c.obfsWrite = NewObfsState()
		atomic.StoreInt32(&c.selected, 1)
		c.stateMu.Unlock()
		if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
			log.Printf("[WRAP] OK: ключ выбран для %s (keys=%d)", addr.String(), c.keys.Count())
		}
		return m, addr, nil
	}

	key := c.key
	c.activeOps++
	c.stateMu.Unlock()
	defer c.finishOperation()

	m, uErr := obfsUnwrapPacket(key, raw, p)
	if uErr != nil {
		return 0, addr, fmt.Errorf("obfs unwrap: %w", uErr)
	}
	return m, addr, nil
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.stateMu.Lock()
	if c.closing {
		c.stateMu.Unlock()
		return 0, net.ErrClosed
	}
	if atomic.LoadInt32(&c.selected) == 0 || len(c.key) != wrapKeyLen {
		c.stateMu.Unlock()
		return 0, errors.New("wrap: key not selected")
	}
	if c.obfsCfg == nil || c.obfsWrite == nil {
		c.obfsCfg = NewObfsConfig()
		c.obfsWrite = NewObfsState()
	}
	key := c.key
	obfsCfg := *c.obfsCfg
	obfsWrite := c.obfsWrite
	c.activeOps++
	c.stateMu.Unlock()
	defer c.finishOperation()

	buffer := wrapWireBufferPool.Get().(*[]byte)
	defer wrapWireBufferPool.Put(buffer)
	wrapped, wErr := obfsWrapPacketInto((*buffer)[:0], key, p, &obfsCfg, obfsWrite)
	if wErr != nil {
		return 0, fmt.Errorf("obfs wrap: %w", wErr)
	}
	if _, err := c.inner.WriteTo(wrapped, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) finishOperation() {
	c.stateMu.Lock()
	c.activeOps--
	if c.activeOps == 0 && c.stateCond != nil {
		c.stateCond.Broadcast()
	}
	c.stateMu.Unlock()
}

func (c *wrapPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.stateMu.Lock()
		c.closing = true
		if c.stateCond == nil {
			c.stateCond = sync.NewCond(&c.stateMu)
		}
		sessionKey := c.sessionKey
		session := c.session
		c.stateMu.Unlock()

		unregisterWrappedSession(sessionKey, session)
		closeError := c.inner.Close()

		c.stateMu.Lock()
		for c.activeOps > 0 {
			c.stateCond.Wait()
		}
		zeroBytes(c.key)
		c.key = nil
		c.closeError = closeError
		c.stateMu.Unlock()
	})

	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.closeError
}
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

const (
	updateMetadataRequestPrefix  = "WDTT_UPDATE1|"
	updateMetadataResponsePrefix = "WDTT_UPDATE1_RESULT|"
	updateAPKChunkRequestPrefix  = "WDTT_UPDATE_APK1|"
	updateAPKChunkResponsePrefix = "WDTT_UPDATE_APK1_RESULT|"
	updateMetadataMaxBodyBytes   = 1024 * 1024
	updateMetadataChunkBytes     = 700
	updateMetadataCacheTTL       = 5 * time.Minute
	updateAPKMaxBytes            = 200 * 1024 * 1024
	updateAPKChunkMaxBytes       = 32 * 1024
	updateAPKFrameBytes          = 1100
	updateAPKCacheTTL            = 6 * time.Hour
)

var updateMetadataVersionPattern = regexp.MustCompile(`(?i)^v?(\d+)$`)

type relayedUpdateAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	SizeBytes   int64  `json:"size"`
	Digest      string `json:"digest,omitempty"`
}

type relayedUpdateMetadata struct {
	VersionTag string               `json:"version_tag"`
	ReleaseURL string               `json:"release_url"`
	Source     string               `json:"source"`
	Assets     []relayedUpdateAsset `json:"assets,omitempty"`
}

type githubUpdateRelease struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
		Digest             string `json:"digest"`
	} `json:"assets"`
}

type githubUpdateTag struct {
	Name string `json:"name"`
}

var updateMetadataRelayCache = struct {
	sync.Mutex
	payload   []byte
	expiresAt time.Time
}{}

var updateMetadataHTTPClient = &http.Client{Timeout: 8 * time.Second}

type updateAPKChunkRequest struct {
	requestID   string
	offset      int64
	length      int
	size        int64
	sha256      string
	downloadURL string
}

var updateAPKRelayCache = struct {
	sync.Mutex
	path        string
	downloadURL string
	size        int64
	sha256      string
	expiresAt   time.Time
}{}

var updateAPKHTTPClient = &http.Client{
	Timeout: 3 * time.Minute,
	CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !isTrustedUpdateRedirectURL(request.URL) {
			return errors.New("GitHub перенаправил APK на недоверенный адрес")
		}
		return nil
	},
}

func parseUpdateMetadataRequest(packet []byte) (string, bool) {
	value := string(packet)
	if !strings.HasPrefix(value, updateMetadataRequestPrefix) {
		return "", false
	}
	requestID := strings.TrimPrefix(value, updateMetadataRequestPrefix)
	if len(requestID) < 8 || len(requestID) > 64 {
		return "", false
	}
	for _, char := range requestID {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return "", false
	}
	return requestID, true
}

func parseUpdateAPKChunkRequest(packet []byte) (updateAPKChunkRequest, bool) {
	value := string(packet)
	if !strings.HasPrefix(value, updateAPKChunkRequestPrefix) {
		return updateAPKChunkRequest{}, false
	}
	parts := strings.SplitN(value, "|", 7)
	if len(parts) != 7 {
		return updateAPKChunkRequest{}, false
	}
	requestID := normalizeUpdateRelayRequestID(parts[1])
	offset, offsetErr := strconv.ParseInt(parts[2], 10, 64)
	length64, lengthErr := strconv.ParseInt(parts[3], 10, 32)
	size, sizeErr := strconv.ParseInt(parts[4], 10, 64)
	digest := strings.ToLower(parts[5])
	decodedURL, decodeErr := base64.RawURLEncoding.DecodeString(parts[6])
	request := updateAPKChunkRequest{
		requestID:   requestID,
		offset:      offset,
		length:      int(length64),
		size:        size,
		sha256:      digest,
		downloadURL: string(decodedURL),
	}
	validDigest := len(digest) == 64
	if validDigest {
		_, decodeErr := hex.DecodeString(digest)
		validDigest = decodeErr == nil
	}
	if requestID == "" || offsetErr != nil || lengthErr != nil || sizeErr != nil || decodeErr != nil ||
		offset < 0 || length64 < 1 || length64 > updateAPKChunkMaxBytes || size < 1 || size > updateAPKMaxBytes ||
		offset >= size || int64(length64) > size-offset || !validDigest || !isOfficialUpdateAssetURL(request.downloadURL) {
		return updateAPKChunkRequest{}, false
	}
	return request, true
}

func normalizeUpdateRelayRequestID(value string) string {
	if len(value) < 8 || len(value) > 64 {
		return ""
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return ""
	}
	return value
}

const (
	opaqueHTTPSRequestPrefix    = "WDTT_HTTPS_POST1|"
	opaqueHTTPSResponsePrefix   = "WDTT_HTTPS_POST1_RESULT|"
	opaqueHTTPSMaxPayloadBytes  = 768
	opaqueHTTPSMaxResponseBytes = 32 * 1024
	opaqueHTTPSMaxPacketBytes   = 1400
)

type opaqueHTTPSRequest struct {
	requestID string
	url       string
	payload   []byte
}

type opaqueHTTPSResponse struct {
	Status   int    `json:"status"`
	Body     string `json:"body"`
	CodeHint string `json:"code_hint,omitempty"`
}

func parseOpaqueHTTPSRequest(packet []byte) (opaqueHTTPSRequest, bool) {
	if len(packet) > opaqueHTTPSMaxPacketBytes {
		return opaqueHTTPSRequest{}, false
	}
	value := string(packet)
	if !strings.HasPrefix(value, opaqueHTTPSRequestPrefix) {
		return opaqueHTTPSRequest{}, false
	}
	parts := strings.SplitN(value, "|", 4)
	if len(parts) != 4 {
		return opaqueHTTPSRequest{}, false
	}
	requestID := normalizeUpdateRelayRequestID(parts[1])
	decodedURL, urlErr := base64.RawURLEncoding.DecodeString(parts[2])
	payload, payloadErr := base64.RawURLEncoding.DecodeString(parts[3])
	request := opaqueHTTPSRequest{
		requestID: requestID,
		url:       strings.TrimSpace(string(decodedURL)),
		payload:   payload,
	}
	if requestID == "" || urlErr != nil || payloadErr != nil ||
		len(request.url) < 12 || len(request.url) > 2048 ||
		len(payload) == 0 || len(payload) > opaqueHTTPSMaxPayloadBytes || !json.Valid(payload) {
		return opaqueHTTPSRequest{}, false
	}
	return request, true
}

func executeOpaqueHTTPSPost(ctx context.Context, request opaqueHTTPSRequest) ([]byte, error) {
	target, addresses, err := validateOpaqueHTTPSTarget(ctx, request.url)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, address := range addresses {
				conn, dialErr := dialer.DialContext(
					dialCtx,
					network,
					net.JoinHostPort(address.String(), "443"),
				)
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   9 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("HTTPS-служба вернула перенаправление")
		},
	}
	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		target.String(),
		bytes.NewReader(request.payload),
	)
	if err != nil {
		return nil, errors.New("некорректный HTTPS-запрос")
	}
	httpRequest.Header.Set("Content-Type", "application/json; charset=utf-8")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("HTTPS-служба не ответила: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, opaqueHTTPSMaxResponseBytes+1))
	if err != nil {
		return nil, errors.New("не удалось прочитать ответ HTTPS-службы")
	}
	if len(body) > opaqueHTTPSMaxResponseBytes {
		return nil, errors.New("ответ HTTPS-службы слишком большой")
	}
	result, err := json.Marshal(opaqueHTTPSResponse{
		Status: response.StatusCode,
		Body:   string(body),
		CodeHint: truncateOpaqueHTTPSValue(
			strings.TrimSpace(response.Header.Get("X-WDTT-Access-Code")),
			128,
		),
	})
	if err != nil {
		return nil, errors.New("не удалось подготовить ответ HTTPS-службы")
	}
	return result, nil
}

func truncateOpaqueHTTPSValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func validateOpaqueHTTPSTarget(ctx context.Context, rawURL string) (*url.URL, []netip.Addr, error) {
	target, err := url.ParseRequestURI(strings.TrimSpace(rawURL))
	if err != nil || target.Scheme != "https" || target.Hostname() == "" ||
		target.User != nil || target.RawQuery != "" || target.Fragment != "" ||
		(target.Port() != "" && target.Port() != "443") || net.ParseIP(target.Hostname()) != nil {
		return nil, nil, errors.New("разрешён только публичный HTTPS-адрес без перенаправлений")
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || !strings.Contains(host, ".") {
		return nil, nil, errors.New("локальный HTTPS-адрес запрещён")
	}
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(resolved) == 0 {
		return nil, nil, errors.New("не удалось определить адрес HTTPS-службы")
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, item := range resolved {
		address, ok := netip.AddrFromSlice(item.IP)
		if !ok || !isPublicOpaqueHTTPSAddress(address.Unmap()) {
			return nil, nil, errors.New("HTTPS-служба разрешилась в непубличную сеть")
		}
		addresses = append(addresses, address.Unmap())
	}
	return target, addresses, nil
}

func isPublicOpaqueHTTPSAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() ||
		address.IsMulticast() {
		return false
	}
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("2001:db8::/32"),
	} {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func encodeUpdateMetadataResponse(requestID string, payload []byte, fetchErr error) [][]byte {
	return encodeControlResponse(updateMetadataResponsePrefix, requestID, payload, fetchErr)
}

func encodeOpaqueHTTPSResponse(requestID string, payload []byte, fetchErr error) [][]byte {
	return encodeControlResponse(opaqueHTTPSResponsePrefix, requestID, payload, fetchErr)
}

func encodeControlResponse(responsePrefix, requestID string, payload []byte, fetchErr error) [][]byte {
	if fetchErr != nil {
		message := fetchErr.Error()
		if len(message) > 240 {
			message = message[:240]
		}
		encoded := base64.RawURLEncoding.EncodeToString([]byte(message))
		return [][]byte{[]byte(responsePrefix + requestID + "|ERR|" + encoded)}
	}
	if len(payload) == 0 {
		return [][]byte{[]byte(responsePrefix + requestID + "|ERR|empty")}
	}
	total := (len(payload) + updateMetadataChunkBytes - 1) / updateMetadataChunkBytes
	frames := make([][]byte, 0, total)
	for sequence, offset := 0, 0; offset < len(payload); sequence, offset = sequence+1, offset+updateMetadataChunkBytes {
		end := offset + updateMetadataChunkBytes
		if end > len(payload) {
			end = len(payload)
		}
		encoded := base64.RawURLEncoding.EncodeToString(payload[offset:end])
		frames = append(frames, []byte(fmt.Sprintf(
			"%s%s|OK|%d|%d|%s",
			responsePrefix,
			requestID,
			sequence,
			total,
			encoded,
		)))
	}
	return frames
}

func encodeUpdateAPKChunkResponse(requestID string, payload []byte, fetchErr error) [][]byte {
	if fetchErr != nil {
		message := fetchErr.Error()
		if len(message) > 240 {
			message = message[:240]
		}
		encoded := base64.RawURLEncoding.EncodeToString([]byte(message))
		return [][]byte{[]byte(updateAPKChunkResponsePrefix + requestID + "|ERR|" + encoded)}
	}
	if len(payload) == 0 || len(payload) > updateAPKChunkMaxBytes {
		return [][]byte{[]byte(updateAPKChunkResponsePrefix + requestID + "|ERR|empty")}
	}
	total := (len(payload) + updateAPKFrameBytes - 1) / updateAPKFrameBytes
	frames := make([][]byte, 0, total)
	for sequence, offset := 0, 0; offset < len(payload); sequence, offset = sequence+1, offset+updateAPKFrameBytes {
		end := offset + updateAPKFrameBytes
		if end > len(payload) {
			end = len(payload)
		}
		header := fmt.Sprintf("%s%s|OK|%d|%d|", updateAPKChunkResponsePrefix, requestID, sequence, total)
		frame := make([]byte, 0, len(header)+end-offset)
		frame = append(frame, header...)
		frame = append(frame, payload[offset:end]...)
		frames = append(frames, frame)
	}
	return frames
}

func cachedOfficialUpdateMetadata(ctx context.Context) ([]byte, error) {
	updateMetadataRelayCache.Lock()
	defer updateMetadataRelayCache.Unlock()
	if len(updateMetadataRelayCache.payload) > 0 && time.Now().Before(updateMetadataRelayCache.expiresAt) {
		return append([]byte(nil), updateMetadataRelayCache.payload...), nil
	}
	metadata, err := fetchOfficialUpdateMetadata(ctx, updateMetadataHTTPClient)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	updateMetadataRelayCache.payload = append(updateMetadataRelayCache.payload[:0], payload...)
	updateMetadataRelayCache.expiresAt = time.Now().Add(updateMetadataCacheTTL)
	return append([]byte(nil), payload...), nil
}

func cachedOfficialUpdateAPKChunk(ctx context.Context, request updateAPKChunkRequest) ([]byte, error) {
	updateAPKRelayCache.Lock()
	defer updateAPKRelayCache.Unlock()

	cacheMatches := updateAPKRelayCache.path != "" &&
		updateAPKRelayCache.downloadURL == request.downloadURL &&
		updateAPKRelayCache.size == request.size &&
		updateAPKRelayCache.sha256 == request.sha256 &&
		time.Now().Before(updateAPKRelayCache.expiresAt)
	if cacheMatches {
		if info, err := os.Stat(updateAPKRelayCache.path); err == nil && info.Mode().IsRegular() && info.Size() == request.size {
			return readUpdateAPKChunk(updateAPKRelayCache.path, request.offset, request.length)
		}
	}

	newPath, err := downloadOfficialUpdateAPK(ctx, updateAPKHTTPClient, request)
	if err != nil {
		return nil, err
	}
	oldPath := updateAPKRelayCache.path
	updateAPKRelayCache.path = newPath
	updateAPKRelayCache.downloadURL = request.downloadURL
	updateAPKRelayCache.size = request.size
	updateAPKRelayCache.sha256 = request.sha256
	updateAPKRelayCache.expiresAt = time.Now().Add(updateAPKCacheTTL)
	if oldPath != "" && oldPath != newPath {
		_ = os.Remove(oldPath)
	}
	return readUpdateAPKChunk(newPath, request.offset, request.length)
}

func downloadOfficialUpdateAPK(
	ctx context.Context,
	client *http.Client,
	request updateAPKChunkRequest,
) (resultPath string, resultErr error) {
	if !isOfficialUpdateAssetURL(request.downloadURL) || request.size < 1 || request.size > updateAPKMaxBytes {
		return "", errors.New("некорректные данные APK")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, request.downloadURL, nil)
	if err != nil {
		return "", err
	}
	httpRequest.Header.Set("Accept", "application/vnd.android.package-archive,application/octet-stream")
	httpRequest.Header.Set("User-Agent", "WDTT-Server/update-relay")
	response, err := client.Do(httpRequest)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.CopyN(io.Discard, response.Body, 4096)
		return "", fmt.Errorf("GitHub вернул HTTP %d при скачивании APK", response.StatusCode)
	}
	if response.ContentLength > 0 && response.ContentLength != request.size {
		return "", errors.New("размер APK не совпал с данными выпуска")
	}

	temporary, err := os.CreateTemp("", "wdtt-update-*.apk")
	if err != nil {
		return "", err
	}
	resultPath = temporary.Name()
	defer func() {
		if closeErr := temporary.Close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
		if resultErr != nil {
			_ = os.Remove(resultPath)
			resultPath = ""
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", err
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(response.Body, request.size+1))
	if err != nil {
		return "", err
	}
	if written != request.size {
		return "", errors.New("размер скачанного APK не совпал с данными выпуска")
	}
	if actual := hex.EncodeToString(digest.Sum(nil)); actual != request.sha256 {
		return "", errors.New("SHA-256 скачанного APK не совпал с данными выпуска")
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	return resultPath, nil
}

func readUpdateAPKChunk(path string, offset int64, length int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload := make([]byte, length)
	if _, err := file.ReadAt(payload, offset); err != nil {
		return nil, err
	}
	return payload, nil
}

func isTrustedUpdateRedirectURL(value *url.URL) bool {
	if value == nil || value.Scheme != "https" || value.User != nil || (value.Port() != "" && value.Port() != "443") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	return host == "objects.githubusercontent.com" ||
		host == "release-assets.githubusercontent.com" ||
		strings.HasSuffix(host, ".release-assets.githubusercontent.com")
}

func fetchOfficialUpdateMetadata(ctx context.Context, client *http.Client) (relayedUpdateMetadata, error) {
	latestRelease, releaseErr := fetchLatestStableGitHubRelease(ctx, client)
	latestTag, tagErr := fetchLatestGitHubTag(ctx, client)

	var releaseMetadata *relayedUpdateMetadata
	if releaseErr == nil {
		converted := convertGitHubRelease(latestRelease)
		releaseMetadata = &converted
	}
	if releaseMetadata == nil && latestTag == "" {
		return relayedUpdateMetadata{}, errors.Join(releaseErr, tagErr)
	}
	if latestTag == "" {
		return *releaseMetadata, nil
	}
	if releaseMetadata == nil || updateVersionNumber(releaseMetadata.VersionTag) < updateVersionNumber(latestTag) {
		return relayedUpdateMetadata{
			VersionTag: latestTag,
			ReleaseURL: "https://github.com/Ivan4537/WDTT-Plus/tree/" + latestTag,
			Source:     "tag",
		}, nil
	}
	return *releaseMetadata, nil
}

func fetchLatestStableGitHubRelease(ctx context.Context, client *http.Client) (githubUpdateRelease, error) {
	var releases []githubUpdateRelease
	if err := fetchGitHubUpdateJSON(
		ctx,
		client,
		"https://api.github.com/repos/Ivan4537/WDTT-Plus/releases?per_page=30",
		&releases,
	); err != nil {
		return githubUpdateRelease{}, err
	}
	var best githubUpdateRelease
	bestVersion := -1
	for _, release := range releases {
		version := updateVersionNumber(release.TagName)
		if release.Draft || release.Prerelease || version < 0 || version <= bestVersion {
			continue
		}
		best = release
		bestVersion = version
	}
	if bestVersion < 0 {
		return githubUpdateRelease{}, errors.New("GitHub не вернул стабильный выпуск")
	}
	return best, nil
}

func fetchLatestGitHubTag(ctx context.Context, client *http.Client) (string, error) {
	var tags []githubUpdateTag
	if err := fetchGitHubUpdateJSON(
		ctx,
		client,
		"https://api.github.com/repos/Ivan4537/WDTT-Plus/tags?per_page=100",
		&tags,
	); err != nil {
		return "", err
	}
	best := -1
	for _, tag := range tags {
		if version := updateVersionNumber(tag.Name); version > best {
			best = version
		}
	}
	if best < 0 {
		return "", errors.New("GitHub не вернул подходящий тег")
	}
	return "v" + strconv.Itoa(best), nil
}

func fetchGitHubUpdateJSON(ctx context.Context, client *http.Client, rawURL string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "WDTT-Server/update-relay")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.CopyN(io.Discard, response.Body, 4096)
		return fmt.Errorf("GitHub API вернул HTTP %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, updateMetadataMaxBodyBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(payload) > updateMetadataMaxBodyBytes {
		return errors.New("ответ GitHub превышает допустимый размер")
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("некорректный ответ GitHub: %w", err)
	}
	return nil
}

func convertGitHubRelease(release githubUpdateRelease) relayedUpdateMetadata {
	metadata := relayedUpdateMetadata{
		VersionTag: normalizeUpdateVersionTag(release.TagName),
		ReleaseURL: release.HTMLURL,
		Source:     "release",
	}
	for _, asset := range release.Assets {
		if len(metadata.Assets) >= 8 || !strings.HasSuffix(strings.ToLower(asset.Name), ".apk") {
			continue
		}
		if !isOfficialUpdateAssetURL(asset.BrowserDownloadURL) {
			continue
		}
		metadata.Assets = append(metadata.Assets, relayedUpdateAsset{
			Name:        asset.Name,
			DownloadURL: asset.BrowserDownloadURL,
			SizeBytes:   asset.Size,
			Digest:      asset.Digest,
		})
	}
	return metadata
}

func isOfficialUpdateAssetURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() == "github.com" && parsed.User == nil &&
		(parsed.Port() == "" || parsed.Port() == "443") && parsed.RawQuery == "" && parsed.Fragment == "" &&
		strings.HasPrefix(parsed.EscapedPath(), "/Ivan4537/WDTT-Plus/releases/download/")
}

func updateVersionNumber(value string) int {
	match := updateMetadataVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 2 {
		return -1
	}
	version, err := strconv.Atoi(match[1])
	if err != nil {
		return -1
	}
	return version
}

func normalizeUpdateVersionTag(value string) string {
	version := updateVersionNumber(value)
	if version < 0 {
		return ""
	}
	return "v" + strconv.Itoa(version)
}

const (
	deploySafeRequestPrefix      = "WDTT_DEPLOY1|"
	deploySafeChunkRequestPrefix = "WDTT_DEPLOY_CHUNK1|"
	deploySafeRequestMaxBytes    = 64 * 1024
	deploySafeResponseMaxBytes   = 12 * 1024 * 1024
	deploySafeChunkMaxBytes      = 32 * 1024
	deploySafeCacheTTL           = 5 * time.Minute
)

type deploySafeStartRequest struct {
	requestID string
	digest    string
	payload   []byte
}

type deploySafeChunkRequest struct {
	requestID string
	baseID    string
	offset    int
	length    int
	digest    string
}

type deploySafeCacheEntry struct {
	requestDigest string
	createdAt     time.Time
	ready         chan struct{}
	payload       []byte
	digest        string
	err           error
}

var deploySafeRelayCache = struct {
	sync.Mutex
	entries map[string]*deploySafeCacheEntry
}{entries: make(map[string]*deploySafeCacheEntry)}

var deploySafeBackupIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$`)

func parseDeploySafeStartRequest(packet []byte) (deploySafeStartRequest, bool) {
	value := string(packet)
	if !strings.HasPrefix(value, deploySafeRequestPrefix) {
		return deploySafeStartRequest{}, false
	}
	parts := strings.SplitN(value, "|", 4)
	if len(parts) != 4 {
		return deploySafeStartRequest{}, false
	}
	requestID := normalizeUpdateRelayRequestID(parts[1])
	digest := strings.ToLower(parts[2])
	payload, decodeErr := base64.RawURLEncoding.DecodeString(parts[3])
	if requestID == "" || !validHexDigest(digest) || decodeErr != nil || len(payload) == 0 || len(payload) > deploySafeRequestMaxBytes {
		return deploySafeStartRequest{}, false
	}
	actual := sha256.Sum256(payload)
	if hex.EncodeToString(actual[:]) != digest {
		return deploySafeStartRequest{}, false
	}
	return deploySafeStartRequest{requestID: requestID, digest: digest, payload: payload}, true
}

func parseDeploySafeChunkRequest(packet []byte) (deploySafeChunkRequest, bool) {
	value := string(packet)
	if !strings.HasPrefix(value, deploySafeChunkRequestPrefix) {
		return deploySafeChunkRequest{}, false
	}
	parts := strings.SplitN(value, "|", 6)
	if len(parts) != 6 {
		return deploySafeChunkRequest{}, false
	}
	requestID := normalizeUpdateRelayRequestID(parts[1])
	baseID := normalizeUpdateRelayRequestID(parts[2])
	offset64, offsetErr := strconv.ParseInt(parts[3], 10, 32)
	length64, lengthErr := strconv.ParseInt(parts[4], 10, 32)
	digest := strings.ToLower(parts[5])
	if requestID == "" || baseID == "" || offsetErr != nil || lengthErr != nil ||
		offset64 < 0 || length64 < 1 || length64 > deploySafeChunkMaxBytes || !validHexDigest(digest) {
		return deploySafeChunkRequest{}, false
	}
	return deploySafeChunkRequest{
		requestID: requestID,
		baseID:    baseID,
		offset:    int(offset64),
		length:    int(length64),
		digest:    digest,
	}, true
}

func validHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func deploySafeCacheKey(identity accessIdentity, requestID string) string {
	return identity.id + ":" + requestID
}

func executeCachedDeploySafeRequest(
	configDir string,
	wgDev wgDevice,
	identity accessIdentity,
	request deploySafeStartRequest,
) ([]byte, string, error) {
	key := deploySafeCacheKey(identity, request.requestID)
	now := time.Now()
	deploySafeRelayCache.Lock()
	for cacheKey, entry := range deploySafeRelayCache.entries {
		if now.Sub(entry.createdAt) > deploySafeCacheTTL {
			delete(deploySafeRelayCache.entries, cacheKey)
		}
	}
	entry := deploySafeRelayCache.entries[key]
	if entry != nil {
		if entry.requestDigest != request.digest {
			deploySafeRelayCache.Unlock()
			return nil, "", errors.New("идентификатор безопасного запроса уже использован")
		}
		ready := entry.ready
		deploySafeRelayCache.Unlock()
		select {
		case <-ready:
			return append([]byte(nil), entry.payload...), entry.digest, entry.err
		case <-time.After(3 * time.Minute):
			return nil, "", errors.New("безопасная операция на сервере не завершилась вовремя")
		}
	}
	entry = &deploySafeCacheEntry{
		requestDigest: request.digest,
		createdAt:     now,
		ready:         make(chan struct{}),
	}
	deploySafeRelayCache.entries[key] = entry
	deploySafeRelayCache.Unlock()

	payload, err := executeDeploySafeAdminRequest(configDir, wgDev, request.payload)
	digest := ""
	if err == nil {
		if len(payload) == 0 || len(payload) > deploySafeResponseMaxBytes {
			err = errors.New("ответ безопасной операции имеет недопустимый размер")
		} else {
			sum := sha256.Sum256(payload)
			digest = hex.EncodeToString(sum[:])
		}
	}
	deploySafeRelayCache.Lock()
	entry.payload = append([]byte(nil), payload...)
	entry.digest = digest
	entry.err = err
	close(entry.ready)
	deploySafeRelayCache.Unlock()
	return append([]byte(nil), payload...), digest, err
}

func executeDeploySafeAdminRequest(configDir string, wgDev wgDevice, payload []byte) ([]byte, error) {
	var request adminRequest
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, errors.New("некорректный безопасный запрос управления")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("некорректный безопасный запрос управления")
	}
	if !isRelayedDeployAdminCommandAllowed(request.Args) {
		return nil, errors.New("операция недоступна через активный VPN")
	}
	response, err := executeLiveAdminRequest(configDir, request, wgDev)
	if err != nil {
		response = adminErrorResponse(err)
	}
	encoded, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		return nil, fmt.Errorf("не удалось сформировать ответ управления: %w", marshalErr)
	}
	return encoded, nil
}

func isRelayedDeployAdminCommandAllowed(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "list":
		return len(args) == 1
	case "details":
		return len(args) == 3 && args[1] == "--password" && strings.TrimSpace(args[2]) != ""
	case "backup-status":
		return len(args) == 1
	case "backup-verify", "backup-export":
		return len(args) == 3 && args[1] == "--id" && deploySafeBackupIDPattern.MatchString(args[2])
	case "backup-create":
		return len(args) == 3 && args[1] == "--reason" && args[2] == "manual"
	case "safe-inspect":
		return validateDeploySafeInspectArgs(args[1:]) == nil
	default:
		return false
	}
}

func readDeploySafeChunk(identity accessIdentity, request deploySafeChunkRequest) ([]byte, error) {
	key := deploySafeCacheKey(identity, request.baseID)
	deploySafeRelayCache.Lock()
	entry := deploySafeRelayCache.entries[key]
	if entry == nil {
		deploySafeRelayCache.Unlock()
		return nil, errors.New("результат безопасной операции больше недоступен")
	}
	ready := entry.ready
	deploySafeRelayCache.Unlock()
	select {
	case <-ready:
	case <-time.After(3 * time.Minute):
		return nil, errors.New("безопасная операция на сервере не завершилась вовремя")
	}
	deploySafeRelayCache.Lock()
	defer deploySafeRelayCache.Unlock()
	if entry.err != nil {
		return nil, entry.err
	}
	if entry.digest != request.digest || request.offset > len(entry.payload) || request.length > len(entry.payload)-request.offset {
		return nil, errors.New("запрошена недопустимая часть ответа")
	}
	return append([]byte(nil), entry.payload[request.offset:request.offset+request.length]...), nil
}

const deploySafeInspectOutputMaxBytes = 11 * 1024 * 1024

var deploySafeInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)

func validateDeploySafeInspectArgs(args []string) error {
	if len(args) == 0 {
		return errors.New("не указан вид безопасной проверки")
	}
	switch args[0] {
	case "outbound-status", "outbound-diagnostics", "outbound-snapshot", "tun-candidates", "existing-install", "database-snapshot":
		if len(args) != 1 {
			return errors.New("у безопасной проверки есть лишние параметры")
		}
	case "server-diagnostics":
		if len(args) != 4 {
			return errors.New("не указаны ожидаемые порты диагностики")
		}
		for _, value := range args[1:] {
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return errors.New("некорректный ожидаемый порт диагностики")
			}
		}
	case "check-wireguard":
		if len(args) != 2 || (args[1] != "wireguard_vps" && args[1] != "warp_free" && args[1] != "imported_wg") {
			return errors.New("некорректный режим WireGuard-проверки")
		}
	case "check-tun":
		if len(args) != 2 || !deploySafeInterfacePattern.MatchString(args[1]) {
			return errors.New("некорректное имя TUN-интерфейса")
		}
	case "check-local-proxy":
		if len(args) != 4 || !deploySafePort(args[1]) || !deploySafePlainValue(args[2], 128, false) || !deploySafePlainValue(args[3], 256, false) {
			return errors.New("некорректные параметры локального прокси")
		}
	case "check-external-proxy":
		if len(args) != 6 || (args[1] != "Socks5" && args[1] != "Http") ||
			!deploySafeHost(args[2]) || !deploySafePort(args[3]) ||
			!deploySafePlainValue(args[4], 128, true) || !deploySafePlainValue(args[5], 256, true) {
			return errors.New("некорректные параметры внешнего прокси")
		}
	case "config-export":
		if len(args) != 2 || (args[1] != "true" && args[1] != "false") {
			return errors.New("некорректный режим экспорта настроек")
		}
	default:
		return errors.New("неизвестная безопасная проверка")
	}
	return nil
}

func adminSafeInspect(configDir string, args []string) (adminResponse, error) {
	if err := validateDeploySafeInspectArgs(args); err != nil {
		return adminResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	var output string
	var err error
	switch args[0] {
	case "outbound-status":
		output = deploySafeOutboundStatus(ctx, configDir)
	case "outbound-diagnostics":
		output = deploySafeOutboundDiagnostics(ctx, configDir)
	case "outbound-snapshot":
		output, err = deploySafeOutboundSnapshot(ctx, configDir)
	case "tun-candidates":
		output, err = deploySafeTunCandidates()
	case "existing-install":
		output = deploySafeExistingInstall(ctx, configDir)
	case "database-snapshot":
		output, err = deploySafeReadRegularFile(filepath.Join(configDir, "passwords.json"), 5_000_000, true)
	case "server-diagnostics":
		output = deploySafeServerDiagnostics(ctx, configDir, args[1], args[2], args[3])
	case "check-wireguard":
		output, err = deploySafeCheckWireGuard(ctx, configDir, args[1])
	case "check-tun":
		output, err = deploySafeCheckTun(ctx, args[1])
	case "check-local-proxy":
		output, err = deploySafeCheckLocalProxy(ctx, args[1], args[2], args[3])
	case "check-external-proxy":
		output, err = deploySafeCheckExternalProxy(ctx, args[1], args[2], args[3], args[4], args[5])
	case "config-export":
		output, err = deploySafeConfigExport(configDir, args[1] == "true")
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), "WDTT_ERROR=") {
			return adminResponse{OK: true, SafeOutput: err.Error()}, nil
		}
		return adminResponse{}, err
	}
	if len(output) == 0 || len(output) > deploySafeInspectOutputMaxBytes {
		return adminResponse{}, errors.New("ответ безопасной проверки имеет недопустимый размер")
	}
	return adminResponse{OK: true, SafeOutput: output}, nil
}

func deploySafeReadRegularFile(path string, limit int64, required bool) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return "", nil
		}
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > limit {
		return "", fmt.Errorf("небезопасный или слишком большой файл настроек: %s", filepath.Base(path))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func deploySafeConfigExport(configDir string, includeWGKeys bool) (string, error) {
	database, err := deploySafeReadRegularFile(filepath.Join(configDir, "passwords.json"), 5_000_000, true)
	if err != nil {
		return "", err
	}
	wgKeys := ""
	if includeWGKeys {
		wgKeys, err = deploySafeReadRegularFile(filepath.Join(configDir, "wg-keys.dat"), 4096, true)
		if err != nil {
			return "", err
		}
	}
	outbound, err := deploySafeReadRegularFile(filepath.Join(configDir, "outbound-profile.env"), 2*1024*1024, false)
	if err != nil {
		return "", err
	}
	policy, err := deploySafeReadRegularFile(filepath.Join(configDir, "backup-policy.json"), 64*1024, false)
	if err != nil {
		return "", err
	}
	if policy == "" {
		policy = `{"enabled":false,"interval_hours":24,"retention_count":14}`
	}
	document := map[string]string{
		"passwords_b64":        deploySafeB64(database),
		"wg_keys_b64":          deploySafeB64(wgKeys),
		"outbound_profile_b64": deploySafeB64(outbound),
		"backup_policy_b64":    deploySafeB64(policy),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func deploySafePort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func deploySafePlainValue(value string, limit int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > limit || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	return true
}

func deploySafeHost(value string) bool {
	if !deploySafePlainValue(value, 253, false) || strings.ContainsAny(value, "/:@[] ") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func deploySafeCommand(ctx context.Context, name string, args ...string) string {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil && len(output) == 0 {
		return ""
	}
	if len(output) > 128*1024 {
		output = output[:128*1024]
	}
	return strings.TrimSpace(string(output))
}

func deploySafeCommandOK(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	if len(output) > 128*1024 {
		return "", errors.New("ответ системной проверки слишком большой")
	}
	return strings.TrimSpace(string(output)), nil
}

func deploySafeServiceState(ctx context.Context, unit string, enabled bool) string {
	verb := "is-active"
	if enabled {
		verb = "is-enabled"
	}
	state := strings.TrimSpace(deploySafeCommand(ctx, "systemctl", verb, unit))
	if state == "" {
		return "неизвестно"
	}
	return strings.Split(state, "\n")[0]
}

func deploySafeReadJSON(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 2*1024*1024 {
		return nil
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil {
		return nil
	}
	return value
}

func deploySafeJSONText(value map[string]any, key string) string {
	if value == nil {
		return ""
	}
	text, _ := value[key].(string)
	return strings.TrimSpace(text)
}

func deploySafeOutboundMode(configDir string) (string, string, string) {
	value := deploySafeReadJSON(filepath.Join(configDir, "outbound.json"))
	mode := deploySafeJSONText(value, "outboundMode")
	if mode == "" {
		mode = "direct"
	}
	return mode, deploySafeJSONText(value, "detail"), deploySafeJSONText(value, "updatedAt")
}

func deploySafeModeLabel(mode string) string {
	switch mode {
	case "direct":
		return "прямой выход"
	case "external_proxy":
		return "внешний TCP-прокси"
	case "tun_interface":
		return "существующий TUN-интерфейс"
	case "warp_free":
		return "бесплатный WARP"
	case "imported_wg":
		return "VPN/WireGuard-файл"
	case "wireguard_vps":
		return "выход через другой сервер"
	default:
		return mode
	}
}

func deploySafeWDTTSource(ctx context.Context) string {
	output := deploySafeCommand(ctx, "ip", "-4", "-o", "addr", "show", "dev", "wdtt0", "scope", "global")
	for _, field := range strings.Fields(output) {
		if ip, _, err := net.ParseCIDR(field); err == nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

func deploySafePublicIP(ctx context.Context, source string) string {
	args := []string{"-4fsS", "--connect-timeout", "4", "--max-time", "10"}
	if source != "" {
		args = append(args, "--interface", source)
	}
	args = append(args, "https://api.ipify.org")
	output, err := deploySafeCommandOK(ctx, "curl", args...)
	if err != nil || net.ParseIP(output) == nil {
		return ""
	}
	return output
}

func deploySafeOutboundStatus(ctx context.Context, configDir string) string {
	mode, _, _ := deploySafeOutboundMode(configDir)
	serverIP := deploySafePublicIP(ctx, "")
	if serverIP == "" {
		serverIP = "не удалось определить"
	}
	source := deploySafeWDTTSource(ctx)
	exitIP := serverIP
	if mode != "direct" && mode != "external_proxy" {
		exitIP = deploySafePublicIP(ctx, source)
		if exitIP == "" {
			exitIP = "не удалось проверить"
		}
	}
	lines := []string{
		"Текущий выход WDTT: " + deploySafeModeLabel(mode),
		"Интерфейс клиентов: wdtt0",
		"Внешний IP самого сервера: " + serverIP,
		"Проверочный выход WDTT: " + exitIP,
		"Прокси на этом VPS: " + deploySafeServiceState(ctx, "wdtt-3proxy.service", false),
		"Автозапуск прокси на этом VPS: " + deploySafeServiceState(ctx, "wdtt-3proxy.service", true),
		"Внешний TCP-прокси WDTT: " + deploySafeServiceState(ctx, "wdtt-redsocks.service", false),
		"WireGuard-выход: " + deploySafeServiceState(ctx, "wdtt-wg-exit.service", false),
		"TUN-выход: " + deploySafeServiceState(ctx, "wdtt-tun-exit.service", false),
	}
	if rules := deploySafeCommand(ctx, "ip", "rule", "show"); rules != "" {
		if strings.Contains(rules, "lookup 100") || strings.Contains(rules, "lookup wdtt-exit") {
			lines = append(lines, "Правило маршрутизации подсети WDTT: применено")
		} else {
			lines = append(lines, "Правило маршрутизации подсети WDTT: отсутствует")
		}
	}
	return strings.Join(lines, "\n")
}

func deploySafeOutboundDiagnostics(ctx context.Context, configDir string) string {
	sections := []string{deploySafeOutboundStatus(ctx, configDir)}
	for _, command := range [][]string{
		{"ip", "rule", "show"},
		{"ip", "route", "show", "table", "100"},
		{"ip", "route", "show", "table", "110"},
		{"iptables", "-t", "nat", "-S"},
		{"iptables", "-S", "FORWARD"},
	} {
		output := deploySafeCommand(ctx, command[0], command[1:]...)
		if output != "" {
			sections = append(sections, strings.Join(command, " ")+":\n"+output)
		}
	}
	return strings.Join(sections, "\n\n")
}

func deploySafeCheckWireGuard(ctx context.Context, configDir, expectedMode string) (string, error) {
	mode, _, _ := deploySafeOutboundMode(configDir)
	if _, err := deploySafeCommandOK(ctx, "wg", "show", "wg-wdtt-exit"); err != nil {
		return "", errors.New("WDTT_ERROR=wireguard_not_active")
	}
	source := deploySafeWDTTSource(ctx)
	if source == "" {
		return "", errors.New("WDTT_ERROR=wdtt_test_source_missing")
	}
	ip := deploySafePublicIP(ctx, source)
	if ip == "" {
		return "", errors.New("WDTT_ERROR=wireguard_exit_check_failed")
	}
	message := fmt.Sprintf("Проверка успешна: WDTT-пользователи выходят через WireGuard. Проверочный IP: %s", ip)
	if mode != expectedMode {
		message = fmt.Sprintf("Предупреждение: активен режим %s, ожидался %s.\n%s", deploySafeModeLabel(mode), deploySafeModeLabel(expectedMode), message)
	}
	return message, nil
}

func deploySafeCheckTun(ctx context.Context, interfaceName string) (string, error) {
	if deploySafeFileFirstLine("/etc/wdtt-plus/tun-exit/owner") != "WDTT_TUN_EXIT_V1" ||
		deploySafeFileFirstLine("/etc/wdtt-plus/tun-exit/interface") != interfaceName {
		return "", errors.New("WDTT_ERROR=tun_exit_not_owned")
	}
	if !deploySafeActive(ctx, "wdtt-tun-exit.service") {
		return "", errors.New("WDTT_ERROR=tun_exit_service_inactive")
	}
	source := deploySafeWDTTSource(ctx)
	if source == "" {
		return "", errors.New("WDTT_ERROR=wdtt_test_source_missing")
	}
	ip := deploySafePublicIP(ctx, source)
	if ip == "" {
		return "", errors.New("WDTT_ERROR=tun_exit_check_failed")
	}
	return fmt.Sprintf("Проверка успешна: WDTT-пользователи выходят через TUN-интерфейс %s. Проверочный IP: %s", interfaceName, ip), nil
}

func deploySafeCheckLocalProxy(ctx context.Context, port, login, password string) (string, error) {
	if state := deploySafeServiceState(ctx, "wdtt-3proxy.service", false); state != "active" && state != "неизвестно" {
		return "", errors.New("WDTT_ERROR=local_proxy_service_inactive")
	}
	proxy := "127.0.0.1:" + port
	ip, commandErr := deploySafeCommandOK(ctx, "curl", "--proxy-user", login+":"+password, "--socks5-hostname", proxy, "-4fsS", "--connect-timeout", "4", "--max-time", "15", "https://api.ipify.org")
	if commandErr != nil || net.ParseIP(ip) == nil {
		return "", errors.New("WDTT_ERROR=local_proxy_check_failed")
	}
	return fmt.Sprintf("Проверка успешна: SOCKS5 на %s отвечает с указанными логином и паролем. Выходной IP: %s", proxy, ip), nil
}

func deploySafeCheckExternalProxy(ctx context.Context, kind, host, port, login, password string) (string, error) {
	scheme := "http"
	if kind == "Socks5" {
		scheme = "socks5h"
	}
	args := []string{"--proxy", scheme + "://" + host + ":" + port}
	if login != "" {
		args = append(args, "--proxy-user", login+":"+password)
	}
	args = append(args, "-4fsS", "--connect-timeout", "5", "--max-time", "18", "https://api.ipify.org")
	ip, commandErr := deploySafeCommandOK(ctx, "curl", args...)
	if commandErr != nil || net.ParseIP(ip) == nil {
		return "", errors.New("WDTT_ERROR=external_proxy_check_failed")
	}
	return fmt.Sprintf("Проверка успешна: внешний TCP-прокси отвечает. IP через прокси: %s", ip), nil
}

func deploySafeReadEnv(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 2*1024*1024 {
		return map[string]string{}
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || !regexp.MustCompile(`^[A-Z0-9_]+$`).MatchString(name) {
			continue
		}
		result[name] = strings.TrimSpace(value)
	}
	return result
}

func deploySafeFlag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func deploySafeActive(ctx context.Context, unit string) bool {
	return deploySafeServiceState(ctx, unit, false) == "active"
}

func deploySafeEnabled(ctx context.Context, unit string) bool {
	state := deploySafeServiceState(ctx, unit, true)
	return state == "enabled" || state == "static"
}

func deploySafeFileFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 64*1024 {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
}

func deploySafeB64(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func deploySafeOutboundSnapshot(ctx context.Context, configDir string) (string, error) {
	mode, detail, updatedAt := deploySafeOutboundMode(configDir)
	profilePath := filepath.Join(configDir, "outbound-profile.env")
	profile := deploySafeReadEnv(profilePath)
	warpSelection := deploySafeReadEnv("/etc/wdtt-plus/warp/selected.env")
	line := func(name, value string) string {
		return name + "=" + strings.ReplaceAll(strings.ReplaceAll(value, "\n", ""), "\r", "")
	}
	localJSON := deploySafeReadJSON(filepath.Join(configDir, "local-proxy.json"))
	localPort := profile["LOCAL_PROXY_PORT"]
	if localPort == "" && localJSON != nil {
		if number, ok := localJSON["socks5Port"].(float64); ok {
			localPort = strconv.Itoa(int(number))
		}
	}
	localLoginB64 := profile["LOCAL_PROXY_LOGIN_B64"]
	localPasswordB64 := profile["LOCAL_PROXY_PASSWORD_B64"]
	if localLoginB64 == "" {
		localLoginB64 = deploySafeB64(deploySafeJSONText(localJSON, "login"))
	}
	if localPasswordB64 == "" {
		localPasswordB64 = deploySafeB64(deploySafeJSONText(localJSON, "password"))
	}
	tunInterface := ""
	if encoded := profile["TUN_INTERFACE_B64"]; encoded != "" {
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			tunInterface = string(decoded)
		}
	}
	if tunInterface == "" {
		tunInterface = deploySafeFileFirstLine("/etc/wdtt-plus/tun-exit/interface")
	}
	ipRules := deploySafeCommand(ctx, "ip", "rule", "show")
	route100 := deploySafeCommand(ctx, "ip", "route", "show", "table", "100")
	route110 := deploySafeCommand(ctx, "ip", "route", "show", "table", "110")
	iptablesNat := deploySafeCommand(ctx, "iptables", "-t", "nat", "-S")
	iptablesForward := deploySafeCommand(ctx, "iptables", "-S", "FORWARD")
	wgOwner := deploySafeFileFirstLine("/etc/wdtt-plus/wg-exit/owner")
	wgConfigOwner := deploySafeFileFirstLine("/etc/wdtt-plus/wg-exit/config-owner")
	localPresent := localJSON != nil
	if _, err := os.Stat(filepath.Join(configDir, "3proxy.cfg")); err == nil {
		localPresent = true
	}
	externalPresent := profile["EXTERNAL_PROXY_HOST_B64"] != "" || mode == "external_proxy"
	wgPresent := profile["IMPORTED_WG_CONFIG_B64"] != "" || mode == "warp_free" || mode == "wireguard_vps" || mode == "imported_wg"
	tunPresent := tunInterface != "" || mode == "tun_interface"
	values := []string{
		line("WDTT_OUTBOUND_MODE", mode), line("WDTT_OUTBOUND_DETAIL_B64", deploySafeB64(detail)), line("WDTT_OUTBOUND_UPDATED_AT", updatedAt),
		line("WDTT_HAS_PROFILE", deploySafeFlag(len(profile) > 0)),
		line("WDTT_LOCAL_PROXY_PRESENT", deploySafeFlag(localPresent)), line("WDTT_LOCAL_PROXY_ACTIVE", deploySafeFlag(deploySafeActive(ctx, "wdtt-3proxy.service"))),
		line("WDTT_LOCAL_PROXY_PORT", localPort), line("WDTT_LOCAL_PROXY_LOGIN_B64", localLoginB64), line("WDTT_LOCAL_PROXY_PASSWORD_B64", localPasswordB64),
		line("WDTT_LOCAL_PROXY_SERVICE_ENABLED", deploySafeFlag(deploySafeEnabled(ctx, "wdtt-3proxy.service"))),
		line("WDTT_EXTERNAL_PROXY_PRESENT", deploySafeFlag(externalPresent)), line("WDTT_EXTERNAL_PROXY_ACTIVE", deploySafeFlag(deploySafeActive(ctx, "wdtt-redsocks.service") && strings.Contains(iptablesNat, "WDTT_PROXY_OUT"))),
		line("WDTT_EXTERNAL_PROXY_KIND_NAME", profile["EXTERNAL_PROXY_KIND"]), line("WDTT_EXTERNAL_PROXY_HOST_B64", profile["EXTERNAL_PROXY_HOST_B64"]), line("WDTT_EXTERNAL_PROXY_PORT", profile["EXTERNAL_PROXY_PORT"]),
		line("WDTT_EXTERNAL_PROXY_LOGIN_B64", profile["EXTERNAL_PROXY_LOGIN_B64"]), line("WDTT_EXTERNAL_PROXY_PASSWORD_B64", profile["EXTERNAL_PROXY_PASSWORD_B64"]),
		line("WDTT_EXTERNAL_PROXY_PROFILE_SAVED", deploySafeFlag(profile["EXTERNAL_PROXY_HOST_B64"] != "")), line("WDTT_EXTERNAL_PROXY_SERVICE_ACTIVE", deploySafeFlag(deploySafeActive(ctx, "wdtt-redsocks.service"))),
		line("WDTT_EXTERNAL_PROXY_ROUTE_ACTIVE", deploySafeFlag(strings.Contains(iptablesNat, "WDTT_PROXY_OUT"))), line("WDTT_EXTERNAL_PROXY_SERVICE_ENABLED", deploySafeFlag(deploySafeEnabled(ctx, "wdtt-redsocks.service"))),
		line("WDTT_WG_PRESENT", deploySafeFlag(wgPresent)), line("WDTT_WG_ACTIVE", deploySafeFlag(deploySafeActive(ctx, "wdtt-wg-exit.service") && strings.Contains(route100, "default"))),
		line("WDTT_WG_VPS_HOST_B64", profile["WG_VPS_HOST_B64"]), line("WDTT_WG_VPS_SSH_PORT", profile["WG_VPS_SSH_PORT"]), line("WDTT_WG_VPS_USER_B64", profile["WG_VPS_USER_B64"]),
		line("WDTT_WG_VPS_PASSWORD_B64", ""), line("WDTT_WG_VPS_PORT", profile["WG_VPS_PORT"]), line("WDTT_WG_VPS_DNS_B64", profile["WG_VPS_DNS_B64"]),
		line("WDTT_WARP_PRESENT", deploySafeFlag(mode == "warp_free" || fileExists("/etc/wdtt-plus/warp/wgcf-profile.conf"))), line("WDTT_WARP_MTU", warpSelection["WARP_MTU"]), line("WDTT_IMPORTED_WG_CONFIG_B64", profile["IMPORTED_WG_CONFIG_B64"]),
		line("WDTT_WG_INTERFACE_ACTIVE", deploySafeFlag(deploySafeCommand(ctx, "wg", "show", "wg-wdtt-exit") != "")), line("WDTT_WG_SERVICE_ACTIVE", deploySafeFlag(deploySafeActive(ctx, "wdtt-wg-exit.service"))),
		line("WDTT_WG_POLICY_RULE_ACTIVE", deploySafeFlag(strings.Contains(ipRules, "lookup 100") || strings.Contains(ipRules, "lookup wdtt-exit"))),
		line("WDTT_WG_DEFAULT_ROUTE_ACTIVE", deploySafeFlag(strings.Contains(route100, "default") && strings.Contains(route100, "wg-wdtt-exit"))),
		line("WDTT_WG_NAT_ACTIVE", deploySafeFlag(strings.Contains(iptablesNat, "WDTT_EXIT") && strings.Contains(iptablesNat, "MASQUERADE"))),
		line("WDTT_WG_OWNER_MODE", wgOwner), line("WDTT_WG_CONFIG_OWNER_MODE", wgConfigOwner), line("WDTT_WG_MATCHES_WARP", deploySafeFlag(mode == "warp_free" && wgPresent)),
		line("WDTT_WG_SERVICE_ENABLED", deploySafeFlag(deploySafeEnabled(ctx, "wdtt-wg-exit.service"))),
		line("WDTT_TUN_INTERFACE_B64", deploySafeB64(tunInterface)), line("WDTT_TUN_PROFILE_SAVED", deploySafeFlag(profile["TUN_INTERFACE_B64"] != "")), line("WDTT_TUN_PRESENT", deploySafeFlag(tunPresent)),
		line("WDTT_TUN_INTERFACE_ACTIVE", deploySafeFlag(tunInterface != "" && deploySafeFileFirstLine(filepath.Join("/sys/class/net", tunInterface, "operstate")) == "up")),
		line("WDTT_TUN_SERVICE_ACTIVE", deploySafeFlag(deploySafeActive(ctx, "wdtt-tun-exit.service"))), line("WDTT_TUN_SERVICE_ENABLED", deploySafeFlag(deploySafeEnabled(ctx, "wdtt-tun-exit.service"))),
		line("WDTT_TUN_POLICY_RULE_ACTIVE", deploySafeFlag(strings.Contains(ipRules, "lookup 110"))), line("WDTT_TUN_DEFAULT_ROUTE_ACTIVE", deploySafeFlag(strings.Contains(route110, "default") && (tunInterface == "" || strings.Contains(route110, tunInterface)))),
		line("WDTT_TUN_FAIL_CLOSED_ACTIVE", deploySafeFlag(strings.Contains(route110, "unreachable default"))), line("WDTT_TUN_FORWARD_RULES_ACTIVE", deploySafeFlag(strings.Contains(iptablesForward, "WDTT_TUN_EXIT"))),
		line("WDTT_TUN_IP_FORWARD_ACTIVE", deploySafeFlag(deploySafeFileFirstLine("/proc/sys/net/ipv4/ip_forward") == "1")),
	}
	return strings.Join(values, "\n"), nil
}

func deploySafeTunCandidates() (string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", err
	}
	lines := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" || name == "wdtt0" || name == "wg-wdtt-exit" || !deploySafeInterfacePattern.MatchString(name) {
			continue
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", name, "tun_flags")); err != nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("WDTT_TUN_CANDIDATE=%s|%s", name, deploySafeFlag(deploySafeFileFirstLine(filepath.Join("/sys/class/net", name, "operstate")) == "up")))
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		return "WDTT_TUN_CANDIDATES_EMPTY=1", nil
	}
	return strings.Join(lines, "\n"), nil
}

func deploySafeExistingInstall(ctx context.Context, configDir string) string {
	flag := func(path string, directory bool) string {
		info, err := os.Stat(path)
		return deploySafeFlag(err == nil && info.IsDir() == directory)
	}
	active := deploySafeServiceState(ctx, "wdtt.service", false)
	standaloneManaged := false
	ownership, ownershipErr := os.ReadFile("/var/lib/wdtt-server-installer/ownership")
	unit, unitErr := os.ReadFile("/etc/systemd/system/wdtt.service")
	if ownershipErr == nil && unitErr == nil &&
		strings.Contains(string(ownership), "Managed by WDTT Plus standalone server installer") &&
		strings.Contains(string(unit), "# Managed by WDTT Plus standalone server installer") {
		standaloneManaged = true
	}
	androidManaged := unitErr == nil &&
		strings.Contains(string(unit), "# Managed by WDTT Plus Android deploy") &&
		strings.Contains(string(unit), "# WDTT deploy compatibility: 1")
	return strings.Join([]string{
		"SERVICE=" + flag("/etc/systemd/system/wdtt.service", false),
		"BINARY=" + flag("/usr/local/bin/wdtt-server", false),
		"CONFIG_DIR=" + flag(configDir, true),
		"ACCESS_DB=" + flag(filepath.Join(configDir, "passwords.json"), false),
		"WG_KEYS=" + flag(filepath.Join(configDir, "wg-keys.dat"), false),
		"ACTIVE=" + active,
		"WDTT_STANDALONE_MANAGED=" + deploySafeFlag(standaloneManaged),
		"WDTT_ANDROID_DEPLOY_MANAGED=" + deploySafeFlag(androidManaged),
		"WDTT_LEGACY_ANDROID_DEPLOY_CANDIDATE=0",
		"WDTT_ANDROID_DATA_PRESERVED=" + deploySafeFlag(fileExists(filepath.Join(configDir, ".android-deploy-preserved"))),
		"WDTT_INCOMPLETE_ANDROID_DEPLOY_CANDIDATE=0",
	}, "\n")
}

func deploySafeDiagLine(severity, title, status, details, recommendation string) string {
	clean := func(value string) string {
		value = strings.NewReplacer("\n", " ", "\r", " ", "|", " ").Replace(value)
		value = strings.Join(strings.Fields(value), " ")
		if len(value) > 700 {
			value = value[:700]
		}
		return value
	}
	return strings.Join([]string{"WDTT_SERVER_DIAG", severity, clean(title), clean(status), clean(details), clean(recommendation)}, "|")
}

func deploySafeServerDiagnostics(ctx context.Context, configDir, dtlsPort, wgPort, clientPort string) string {
	service := deploySafeServiceState(ctx, "wdtt.service", false)
	severity := "WARNING"
	if service == "active" {
		severity = "OK"
	}
	lines := []string{
		deploySafeDiagLine(severity, "WDTT сервер", "служба "+service,
			fmt.Sprintf("Бинарный файл=%t, каталог настроек=%t, база доступа=%t.", fileExists("/usr/local/bin/wdtt-server"), fileExists(configDir), fileExists(filepath.Join(configDir, "passwords.json"))),
			"Если служба не активна, проверьте журнал wdtt.service или обновите сервер с сохранением данных."),
		deploySafeDiagLine("INFO", "Порты активного профиля", "проверка без изменений",
			fmt.Sprintf("Ожидаются DTLS UDP %s, WireGuard UDP %s; локальный Android-порт %s проверяется на телефоне.", dtlsPort, wgPort, clientPort),
			"При несовпадении портов проверьте настройки профиля и серверной службы."),
		deploySafeDiagLine("INFO", "Выходной IP / прокси", deploySafeModeLabel(func() string { mode, _, _ := deploySafeOutboundMode(configDir); return mode }()),
			strings.ReplaceAll(deploySafeOutboundStatus(ctx, configDir), "\n", "; "), "Откройте выбранный режим для отдельной функциональной проверки."),
	}
	return strings.Join(lines, "\n")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
