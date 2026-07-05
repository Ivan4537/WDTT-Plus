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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	pionudp "github.com/pion/transport/v4/udp"
)

const (
	wgIfaceName           = "wdtt0"
	wgServerAddr          = "10.66.66.1"
	wgServerCIDR          = wgServerAddr + "/24"
	defaultInternalWGPort = 56001
	defaultDNS            = "1.1.1.1"
	wgMTU                 = 1280
	keepalive             = 25
	dtlsKeepaliveByte     = 0xFF
	dtlsClientIdleTimeout = 90 * time.Second
)

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
	DeviceID      string             `json:"device_id"`  // пусто = ещё не привязан
	ExpiresAt     int64              `json:"expires_at"` // unix timestamp
	DownBytes     int64              `json:"down_bytes"` // скачано клиентом
	UpBytes       int64              `json:"up_bytes"`   // отдано клиентом
	Traffic       []TrafficBucket    `json:"traffic,omitempty"`
	Label         string             `json:"label,omitempty"`
	VkHash        string             `json:"vk_hash,omitempty"`
	Ports         string             `json:"ports,omitempty"` // "dtls,wg,tun"
	IsDeactivated bool               `json:"is_deactivated,omitempty"`
	BindHistory   []BindHistoryEntry `json:"bind_history,omitempty"`
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
	id  string
	key []byte
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
		next = append(next, wrapKeyEntry{id: "main", key: key})
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
		next = append(next, wrapKeyEntry{id: id, key: key})
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
		if entry.id == id {
			zeroBytes(key)
			return nil
		}
	}
	s.entries = append(s.entries, wrapKeyEntry{id: id, key: key})
	return nil
}

func (s *wrapKeyStore) RemovePassword(password string) {
	id := "pass:" + wrapKeyID(password)

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, entry := range s.entries {
		if entry.id != id {
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

func (s *wrapKeyStore) Unwrap(raw, dst []byte) ([]byte, int, error) {
	if !obfsIsRTPPacket(raw) {
		return nil, 0, errors.New("wrap: non-obfs packet")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return nil, 0, errors.New("wrap: no active keys")
	}
	for _, entry := range s.entries {
		m, err := obfsUnwrapPacket(entry.key, raw, dst)
		if err == nil {
			return append([]byte(nil), entry.key...), m, nil
		}
	}
	return nil, 0, errors.New("wrap: auth failed")
}

func refreshWrapKeysFromDBLocked() error {
	passwords := make([]string, 0, len(db.Passwords))
	for password, entry := range db.Passwords {
		if !isPasswordExpired(entry) && entry != nil && !entry.IsDeactivated {
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

func initDB(dir, mainPass, adminID, botToken, dnsValue string) {
	dbFile = filepath.Join(dir, "passwords.json")
	db = &Database{
		Passwords: make(map[string]*PasswordEntry),
		Devices:   make(map[string]*ClientDevice),
	}
	data, err := os.ReadFile(dbFile)
	if err == nil {
		json.Unmarshal(data, db)
	}
	if db.Passwords == nil {
		db.Passwords = make(map[string]*PasswordEntry)
	}
	if db.Devices == nil {
		db.Devices = make(map[string]*ClientDevice)
	}
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
	db.DNS = dnsValue
	setServerDNS(dnsValue)
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
	db.AdminProfile = normalizeAdminProfileForStorage(db.AdminProfile, db.DefaultPorts)
	setServerDefaultPorts(db.DefaultPorts)
	setServerPublicIPOverride(db.PublicIP)
	saveDB()
	if err := refreshWrapKeysFromDBLocked(); err != nil {
		log.Fatalf("[WRAP] init keys: %v", err)
	}
}

func saveDB() {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		log.Printf("[DB] marshal error: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(dbFile), 0700); err != nil {
		log.Printf("[DB] mkdir error: %v", err)
		return
	}
	tmp := dbFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("[DB] write error: %v", err)
		return
	}
	if err := os.Rename(tmp, dbFile); err != nil {
		log.Printf("[DB] rename error: %v", err)
	}
}

func isPasswordExpired(entry *PasswordEntry) bool {
	if entry == nil {
		return true
	}
	if entry.ExpiresAt == 0 {
		return false // бессрочный
	}
	return time.Now().Unix() > entry.ExpiresAt
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

func removePeerFromWG(wgDev *device.Device, dev *ClientDevice) {
	if wgDev == nil || dev == nil || dev.PubKey == "" {
		return
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return
	}
	wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
}

func upsertPeerInWG(wgDev *device.Device, dev *ClientDevice) {
	if wgDev == nil || dev == nil || dev.PubKey == "" || dev.IP == "" {
		return
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return
	}
	wgDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, dev.IP))
}

func cleanupExpiredPasswordsLocked(wgDev *device.Device) int {
	removed := 0
	nowUnix := time.Now().Unix()
	adminDevices := adminDeviceIDSet(db)
	for p, entry := range db.Passwords {
		if isPasswordExpired(entry) {
			if entry != nil && entry.DeviceID != "" {
				markActiveBindUnbound(entry, entry.DeviceID, nowUnix)
				if _, isAdminDevice := adminDevices[entry.DeviceID]; !isAdminDevice {
					removePeerFromWG(wgDev, db.Devices[entry.DeviceID])
					delete(db.Devices, entry.DeviceID)
				}
			}
			delete(db.Passwords, p)
			serverWrapKeys.RemovePassword(p)
			removed++
		}
	}
	return removed
}

func cleanupExpiredPasswords(wgDev *device.Device) int {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	removed := cleanupExpiredPasswordsLocked(wgDev)
	if removed > 0 {
		saveDB()
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

func expiredPasswordJanitor(ctx context.Context, wgDev *device.Device) {
	ticker := time.NewTicker(1 * time.Hour)
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

func syncPersistedPeersToWG(_ *device.Device) {
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
	log.Println("[SYS] Оптимизация TCP...")
	out, _ := runCmd("bash", "-c", "sysctl net.ipv4.tcp_congestion_control")
	if strings.Contains(out, "bbr") {
		log.Println("[SYS] BBR уже активен ✓")
		return
	}
	cmds := [][]string{
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"},
		{"sysctl", "-w", "net.core.rmem_max=25165824"},
		{"sysctl", "-w", "net.core.wmem_max=25165824"},
		{"sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 25165824"},
		{"sysctl", "-w", "net.ipv4.tcp_wmem=4096 65536 25165824"},
	}
	for _, cmd := range cmds {
		runCmd(cmd[0], cmd[1:]...)
	}
	log.Println("[SYS] BBR включен ✓")
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fromC := atomic.LoadInt64(&totalBytesFromClient)
			toC := atomic.LoadInt64(&totalBytesToClient)
			active := atomic.LoadInt32(&activeConns)
			total := atomic.LoadInt64(&totalConns)
			uptime := time.Since(serverStartTime)

			log.Printf("[СТАТ] Активных: %d | Всего: %d | NAT: %s | ↑%.2f МБ | ↓%.2f МБ",
				active, total, natType,
				float64(fromC)/1024/1024,
				float64(toC)/1024/1024,
			)

			// Пишем server.log
			dbMutex.Lock()
			numPasswords := len(db.Passwords)
			numDevices := len(db.Devices)
			if atomic.SwapInt32(&dbTrafficDirty, 0) == 1 {
				saveDB()
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
	if data, err := os.ReadFile(f); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) >= 4 {
			keys := &wgKeys{
				serverPrivate: strings.TrimSpace(lines[0]),
				serverPublic:  strings.TrimSpace(lines[1]),
				clientPrivate: strings.TrimSpace(lines[2]),
				clientPublic:  strings.TrimSpace(lines[3]),
			}
			for _, k := range []string{keys.serverPrivate, keys.serverPublic,
				keys.clientPrivate, keys.clientPublic} {
				if _, err := b64ToHex(k); err != nil {
					goto generate
				}
			}
			log.Printf("[WG] Ключи загружены из %s", f)
			return keys, nil
		}
	}
generate:
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
	os.MkdirAll(dir, 0700)
	os.WriteFile(f, []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n",
		keys.serverPrivate, keys.serverPublic,
		keys.clientPrivate, keys.clientPublic)), 0600)
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
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		os.Exit(runAdminCLI(os.Args[2:]))
	}

	listen := flag.String("listen", "0.0.0.0:56000", "DTLS адрес")
	wgPort := flag.Int("wg-port", defaultInternalWGPort, "WireGuard UDP порт")
	configDir := flag.String("config-dir", "/etc/wdtt", "директория конфигурации")
	mainPass := flag.String("password", "", "пароль владельца")
	adminID := flag.String("admin", "", "Telegram Admin ID")
	botToken := flag.String("bot-token", "", "Telegram Bot Token")
	dnsValue := flag.String("dns", defaultDNS, "DNS для WireGuard-клиентов, через запятую")
	maxPasswordsFlag := flag.Int("max-passwords", defaultMaxGeneratedPasswords, "максимум активных сгенерированных паролей")
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

	initDB(*configDir, *mainPass, *adminID, *botToken, *dnsValue)

	keys, err := loadOrGenerateKeys(*configDir)
	if err != nil {
		log.Fatalf("[WG] Ключи: %v", err)
	}

	enableBBR()

	wgDev, err := startUserspaceWG(keys, *wgPort)
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
	defer func() {
		wgDev.Close()
		runCmdSilent("ip", "link", "del", wgIfaceName)
	}()

	go statsLoop(ctx, *configDir)
	go expiredPasswordJanitor(ctx, wgDev)
	go botLoop(*botToken, *adminID, wgDev)

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
			handleConn(ctx, c, wgEndpoint, wgDev, keys)
		}(dtlsConn)
	}
}

// ==================== Обработка соединений ====================

func handleConn(ctx context.Context, clientConn net.Conn, wgEndpoint string, wgDev *device.Device, keys *wgKeys) {
	atomic.AddInt64(&totalConns, 1)

	var connPassword string
	var connIsMainPass bool
	var connDevice *ClientDevice

	dtlsConn, ok := clientConn.(*dtls.Conn)
	if !ok {
		return
	}

	hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
	if err := dtlsConn.HandshakeContext(hctx); err != nil {
		hcancel()
		return
	}
	hcancel()

	atomic.AddInt32(&activeConns, 1)
	defer atomic.AddInt32(&activeConns, -1)

	buf := make([]byte, 1600)
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := clientConn.Read(buf)
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
		remoteIP := remoteIPFromAddr(clientConn.RemoteAddr())
		nowUnix := time.Now().Unix()

		dbMutex.Lock()

		// Проверяем пароль
		isMainPass := password != "" && password == db.MainPassword
		entry, isGenPass := db.Passwords[password]
		valid := isMainPass || (isGenPass && !isPasswordExpired(entry))

		if valid && isGenPass && entry.IsDeactivated {
			clientConn.Write([]byte("DENIED:deactivated"))
			log.Printf("[WG] Отказ: пароль %s деактивирован, запрос от %s", maskPassword(password), deviceID)
			dbMutex.Unlock()
		} else if valid && isGenPass && entry.DeviceID != "" && entry.DeviceID != deviceID {
			appendBindHistory(entry, BindHistoryEntry{
				DeviceID:   deviceID,
				DeviceName: deviceDisplayNameFromInfo(deviceID, deviceInfo),
				RemoteIP:   remoteIP,
				Country:    deviceInfo.Country,
				EventAt:    nowUnix,
				Status:     "denied_mismatch",
				Note:       "пароль уже привязан к другому устройству",
			})
			saveDB()
			// Пароль уже привязан к другому устройству
			clientConn.Write([]byte("DENIED:device_mismatch"))
			log.Printf("[WG] Отказ: пароль %s привязан к %s, запрос от %s", maskPassword(password), entry.DeviceID, deviceID)
			dbMutex.Unlock()
		} else if valid {
			connPassword = password
			connIsMainPass = isMainPass
			newlyBound := false

			// Привязываем пароль к устройству при первом использовании
			if isGenPass && entry.DeviceID == "" {
				entry.DeviceID = deviceID
				newlyBound = true
				log.Printf("[WG] Пароль %s привязан к устройству %s", maskPassword(password), deviceID)
			}
			if isMainPass {
				rememberAdminDeviceID(&db.AdminProfile, deviceID)
			}

			dev, exists := db.Devices[deviceID]
			if !exists {
				dev = &ClientDevice{DeviceID: deviceID, IP: getNextIP()}
				privB64, pubB64, keyErr := generateKeyPair()
				if keyErr == nil && dev.IP != "" {
					dev.PrivKey = privB64
					dev.PubKey = pubB64
					applyDeviceInfo(dev, deviceInfo, remoteIP, nowUnix)
					db.Devices[deviceID] = dev
					saveDB()
					log.Printf("[WG] Новое устройство %s (IP: %s)", deviceID, dev.IP)
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
				saveDB()
			}
			if dev != nil {
				connDevice = dev
				clientConn.Write([]byte(buildClientConfig(keys.serverPublic, dev.PrivKey, dev.IP, clientPort)))
			} else {
				clientConn.Write([]byte("NOCONF"))
			}
			dbMutex.Unlock()
		} else {
			if isGenPass && isPasswordExpired(entry) {
				clientConn.Write([]byte("DENIED:expired"))
				log.Printf("[WG] Отказ: пароль %s истёк, от %s", maskPassword(password), deviceID)
			} else {
				clientConn.Write([]byte("DENIED:wrong_password"))
				log.Printf("[WG] Отказ (неверный пароль) от %s", deviceID)
			}
			dbMutex.Unlock()
		}

		clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
		firstStr = string(firstPacket)
	}

	if firstStr == "READY" {
		clientConn.Write([]byte("READY_OK"))
		clientConn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
	}

	// WG прокси
	wgConn, err := net.Dial("udp", wgEndpoint)
	if err != nil {
		return
	}
	defer wgConn.Close()

	if uc, ok := wgConn.(*net.UDPConn); ok {
		uc.SetReadBuffer(2 * 1024 * 1024)
		uc.SetWriteBuffer(2 * 1024 * 1024)
	}

	if connDevice != nil {
		upsertPeerInWG(wgDev, connDevice)
	}

	if _, err := wgConn.Write(firstPacket); err != nil {
		return
	}
	atomic.AddInt64(&totalBytesFromClient, int64(len(firstPacket)))
	if connPassword != "" {
		dbMutex.Lock()
		if !addTrafficLocked(connPassword, connIsMainPass, 0, int64(len(firstPacket))) {
			dbMutex.Unlock()
			return
		}
		dbMutex.Unlock()
	}

	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()

	context.AfterFunc(pctx, func() {
		clientConn.SetDeadline(time.Now())
		wgConn.SetDeadline(time.Now())
	})

	var proxyWg sync.WaitGroup
	proxyWg.Add(2)

	// Клиент → WG
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
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
				clientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, err := clientConn.Write([]byte{dtlsKeepaliveByte})
				clientConn.SetWriteDeadline(time.Time{})
				if err != nil {
					return
				}
				continue
			}
			atomic.AddInt64(&totalBytesFromClient, int64(nn))
			if connPassword != "" {
				dbMutex.Lock()
				if !addTrafficLocked(connPassword, connIsMainPass, 0, int64(nn)) {
					dbMutex.Unlock()
					return
				}
				dbMutex.Unlock()
			}
			if _, err := wgConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()

	// WG → Клиент
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		for {
			select {
			case <-pctx.Done():
				return
			default:
			}
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
			atomic.AddInt64(&totalBytesToClient, int64(nn))
			if connPassword != "" {
				dbMutex.Lock()
				if !addTrafficLocked(connPassword, connIsMainPass, int64(nn), 0) {
					dbMutex.Unlock()
					return
				}
				dbMutex.Unlock()
			}
			if _, err := clientConn.Write((*b)[:nn]); err != nil {
				return
			}
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

func obfsBuildNonce(ssrc uint32, seq uint16, ts uint32) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[0:4], ssrc)
	binary.BigEndian.PutUint16(n[4:6], seq)
	binary.BigEndian.PutUint32(n[8:12], ts)
	return n
}

func obfsWrapPacket(key, payload []byte, cfg *ObfsConfig, state *ObfsState) ([]byte, error) {
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
	out := make([]byte, outLen)

	out[0] = 0x80 | 0x20
	out[1] = cfg.PayloadType & 0x7F
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint32(out[4:8], ts)
	binary.BigEndian.PutUint32(out[8:12], cfg.SSRC)

	aead, err := getAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("obfs: cipher init: %w", err)
	}
	sealed := aead.Seal(out[12:12], nonce, payload, out[:12])
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
	plain, err := aead.Open(dst[:0], nonce, wire[12:payloadEnd], wire[:12])
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
	inner, err := pionudp.Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wrap: udp listen: %w", err)
	}
	return &wrapPacketListener{
		inner: dtlsnet.PacketListenerFromListener(inner),
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
	inner     net.PacketConn
	keys      *wrapKeyStore
	key       []byte
	selected  int32
	authLog   int32
	obfsCfg   *ObfsConfig
	obfsWrite *ObfsState
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Extra space for RTP header (12) + AEAD tag (16) + padding.
	buf := make([]byte, len(p)+80)
	n, addr, err := c.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	raw := buf[:n]

	if atomic.LoadInt32(&c.selected) == 0 {
		key, m, uErr := c.keys.Unwrap(raw, p)
		if uErr != nil {
			if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
				log.Printf("[WRAP] Отказ: RTP AEAD auth failed from %s (keys=%d)", addr.String(), c.keys.Count())
			}
			return 0, addr, uErr
		}
		c.key = key
		c.obfsCfg = NewObfsConfig()
		c.obfsWrite = NewObfsState()
		atomic.StoreInt32(&c.selected, 1)
		if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
			log.Printf("[WRAP] OK: ключ выбран для %s (keys=%d)", addr.String(), c.keys.Count())
		}
		return m, addr, nil
	}

	m, uErr := obfsUnwrapPacket(c.key, raw, p)
	if uErr != nil {
		return 0, addr, fmt.Errorf("obfs unwrap: %w", uErr)
	}
	return m, addr, nil
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if atomic.LoadInt32(&c.selected) == 0 || len(c.key) != wrapKeyLen {
		return 0, errors.New("wrap: key not selected")
	}
	if c.obfsCfg == nil || c.obfsWrite == nil {
		c.obfsCfg = NewObfsConfig()
		c.obfsWrite = NewObfsState()
	}
	wrapped, wErr := obfsWrapPacket(c.key, p, c.obfsCfg, c.obfsWrite)
	if wErr != nil {
		return 0, fmt.Errorf("obfs wrap: %w", wErr)
	}
	if _, err := c.inner.WriteTo(wrapped, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) Close() error                       { return c.inner.Close() }
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
