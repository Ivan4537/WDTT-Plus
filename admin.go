package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type adminResponse struct {
	OK              bool                `json:"ok"`
	Code            string              `json:"code,omitempty"`
	Message         string              `json:"message,omitempty"`
	RestartRequired bool                `json:"restart_required,omitempty"`
	Server          *adminServerInfo    `json:"server,omitempty"`
	Password        *adminPasswordInfo  `json:"password,omitempty"`
	Passwords       []adminPasswordInfo `json:"passwords,omitempty"`
	ClientState     *adminClientState   `json:"client_state,omitempty"`
}

type adminClientState struct {
	Version        int                      `json:"version"`
	Password       string                   `json:"password"`
	DownBytes      int64                    `json:"down_bytes"`
	UpBytes        int64                    `json:"up_bytes"`
	Traffic        []TrafficBucket          `json:"traffic,omitempty"`
	TrafficImports map[string]TrafficImport `json:"traffic_imports,omitempty"`
	BindHistory    []BindHistoryEntry       `json:"bind_history,omitempty"`
}

type adminRequest struct {
	MainPassword string   `json:"main_password"`
	Args         []string `json:"args"`
}

type adminCommandError struct {
	code    string
	message string
}

func (e *adminCommandError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func newAdminCommandError(code, message string) error {
	return &adminCommandError{code: code, message: message}
}

func adminErrorResponse(err error) adminResponse {
	response := adminResponse{OK: false}
	if err == nil {
		return response
	}
	response.Message = err.Error()
	var coded *adminCommandError
	if errors.As(err, &coded) {
		response.Code = coded.code
	}
	return response
}

type adminLiveSnapshot struct {
	password string
	device   *ClientDevice
}

type adminServerInfo struct {
	WDTTPlusVersion        string             `json:"wdtt_plus_version"`
	BinarySHA256           string             `json:"binary_sha256,omitempty"`
	WGBackend              string             `json:"wg_backend,omitempty"`
	ConfigDir              string             `json:"config_dir"`
	PublicIP               string             `json:"public_ip,omitempty"`
	EffectivePublic        string             `json:"effective_public_ip,omitempty"`
	DNS                    string             `json:"dns,omitempty"`
	DefaultPorts           string             `json:"default_ports"`
	MaxPasswords           int                `json:"max_passwords"`
	MaxWorkersPerAccess    int                `json:"max_workers_per_access"`
	MaxClientMbps          float64            `json:"max_client_mbps"`
	PasswordCount          int                `json:"password_count"`
	ActivePasswordCount    int                `json:"active_password_count"`
	RetainedExpiredCount   int                `json:"retained_expired_count"`
	AvailablePasswordCount int                `json:"available_password_count"`
	DeviceCount            int                `json:"device_count"`
	OwnerDeviceCount       int                `json:"owner_device_count"`
	ExpiredCount           int                `json:"expired_count"`
	OrphanDeviceCount      int                `json:"orphan_device_count"`
	ActiveConnections      int32              `json:"active_connections"`
	CPUPercent             float64            `json:"cpu_percent"`
	MemoryPercent          float64            `json:"memory_percent"`
	NetworkRxMbps          float64            `json:"network_rx_mbps"`
	NetworkTxMbps          float64            `json:"network_tx_mbps"`
	PacketDrops            int64              `json:"packet_drops"`
	Reconnects             int64              `json:"reconnects"`
	HandshakeFailures      int64              `json:"handshake_failures"`
	HandshakeThrottles     int64              `json:"handshake_throttles"`
	WorkerLimitRejects     int64              `json:"worker_limit_rejections"`
	UDPWriteSingle         uint64             `json:"udp_write_single"`
	UDPWriteBatchCalls     uint64             `json:"udp_write_batch_calls"`
	UDPWriteBatchMessages  uint64             `json:"udp_write_batch_messages"`
	UDPWritePartialBatches uint64             `json:"udp_write_partial_batches"`
	UDPWriteErrors         uint64             `json:"udp_write_errors"`
	UDPWriteQueueHighWater uint64             `json:"udp_write_queue_high_water"`
	OrphanDevices          []adminDeviceInfo  `json:"orphan_devices,omitempty"`
	Traffic                adminTrafficPeriod `json:"traffic"`
	AdminTraffic           adminTrafficPeriod `json:"admin_traffic"`
	AdminProfile           AdminProfileEntry  `json:"admin_profile,omitempty"`
}

var (
	runningBinarySHA256Once sync.Once
	runningBinarySHA256Sum  string
)

func runningBinarySHA256() string {
	runningBinarySHA256Once.Do(func() {
		executable, err := os.Executable()
		if err != nil {
			return
		}
		source, err := os.Open(executable)
		if err != nil {
			return
		}
		defer source.Close()
		digest := sha256.New()
		if _, err := io.Copy(digest, source); err != nil {
			return
		}
		runningBinarySHA256Sum = fmt.Sprintf("%x", digest.Sum(nil))
	})
	return runningBinarySHA256Sum
}

type adminTrafficValue struct {
	Down int64 `json:"down"`
	Up   int64 `json:"up"`
}

type adminTrafficPeriod struct {
	Today adminTrafficValue `json:"today"`
	Week  adminTrafficValue `json:"week"`
	Month adminTrafficValue `json:"month"`
	All   adminTrafficValue `json:"all"`
}

type adminDeviceInfo struct {
	DeviceID       string `json:"device_id"`
	IP             string `json:"ip,omitempty"`
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

type adminPasswordInfo struct {
	Password        string             `json:"password"`
	Label           string             `json:"label,omitempty"`
	VkHash          string             `json:"vk_hash,omitempty"`
	Ports           string             `json:"ports"`
	Status          string             `json:"status"`
	ExpiresAt       int64              `json:"expires_at,omitempty"`
	PurgeAfter      int64              `json:"purge_after,omitempty"`
	DownBytes       int64              `json:"down_bytes,omitempty"`
	UpBytes         int64              `json:"up_bytes,omitempty"`
	DeviceID        string             `json:"device_id,omitempty"`
	DeviceName      string             `json:"device_name,omitempty"`
	DeviceIP        string             `json:"device_ip,omitempty"`
	DeviceLastSeen  int64              `json:"device_last_seen,omitempty"`
	BindEventsCount int                `json:"bind_events_count,omitempty"`
	Traffic         adminTrafficPeriod `json:"traffic"`
	Device          *adminDeviceInfo   `json:"device,omitempty"`
	BindHistory     []BindHistoryEntry `json:"bind_history,omitempty"`
}

func runAdminCLI(args []string) int {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configDir := fs.String("config-dir", "/etc/wdtt", "директория конфигурации WDTT")
	mainPassword := fs.String("main-password", "", "главный пароль администратора для проверки")
	offline := fs.Bool("offline", false, "изменить остановленный сервер напрямую (потребуется запуск сервиса)")
	if err := fs.Parse(args); err != nil {
		writeAdminError(err)
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		writeAdminError(errors.New("укажите admin-команду"))
		return 2
	}

	if !*offline {
		response, err := callAdminSocket(*configDir, adminRequest{
			MainPassword: *mainPassword,
			Args:         rest,
		})
		if err != nil {
			writeAdminError(fmt.Errorf("admin_socket_unavailable: %w; заново установите сервер из WDTT Plus или используйте --offline только при остановленном wdtt.service", err))
			return 1
		}
		writeAdminJSON(response)
		if !response.OK {
			return 1
		}
		return 0
	}

	loaded, err := readAdminDB(*configDir)
	if err != nil {
		writeAdminError(err)
		return 1
	}
	if strings.TrimSpace(*mainPassword) != "" && loaded.MainPassword != *mainPassword {
		writeAdminError(errors.New("главный пароль администратора не совпадает"))
		return 1
	}
	response, err := executeAdminCommand(*configDir, loaded, rest, nil, false)
	if err != nil {
		writeAdminError(err)
		return 1
	}
	writeAdminJSON(response)
	return 0
}

func executeAdminCommand(configDir string, loaded *Database, rest []string, wgDev wgDevice, live bool) (adminResponse, error) {
	var response adminResponse
	var err error
	snapshot := captureAdminLiveSnapshot(loaded, rest)
	if live && len(rest) > 0 && rest[0] == "create" {
		cleanupExpiredPasswordsLocked(wgDev)
	}
	switch rest[0] {
	case "list":
		response = adminResponse{
			OK:        true,
			Server:    buildAdminServerInfo(configDir, loaded),
			Passwords: buildAdminPasswordList(loaded),
		}
	case "details":
		response, err = adminPasswordDetails(configDir, loaded, rest[1:])
	case "export-client-state":
		response, err = adminExportClientState(configDir, loaded, rest[1:])
	case "create":
		response, err = adminCreatePassword(configDir, loaded, rest[1:])
	case "import-client-state":
		response, err = adminImportClientState(configDir, loaded, rest[1:])
	case "delete":
		response, err = adminDeletePassword(configDir, loaded, rest[1:])
	case "unbind":
		response, err = adminUnbindPassword(configDir, loaded, rest[1:])
	case "deactivate":
		response, err = adminSetPasswordActivation(configDir, loaded, rest[1:], true)
	case "activate":
		response, err = adminSetPasswordActivation(configDir, loaded, rest[1:], false)
	case "set-label":
		response, err = adminSetPasswordLabel(configDir, loaded, rest[1:])
	case "set-hash":
		response, err = adminSetPasswordHash(configDir, loaded, rest[1:])
	case "set-expiry":
		response, err = adminSetPasswordExpiry(configDir, loaded, rest[1:])
	case "set-retention":
		response, err = adminSetPasswordRetention(configDir, loaded, rest[1:])
	case "set-ports":
		response, err = adminSetPasswordPorts(configDir, loaded, rest[1:])
	case "set-password":
		response, err = adminSetPassword(configDir, loaded, rest[1:])
	case "update-client":
		response, err = adminUpdateClient(configDir, loaded, rest[1:])
	case "set-dns":
		response, err = adminSetDNS(configDir, loaded, rest[1:])
	case "set-limit":
		response, err = adminSetLimit(configDir, loaded, rest[1:])
	case "set-default-ports":
		response, err = adminSetDefaultPorts(configDir, loaded, rest[1:])
	case "set-public-ip":
		response, err = adminSetPublicIP(configDir, loaded, rest[1:])
	case "update-settings":
		response, err = adminUpdateSettings(configDir, loaded, rest[1:])
	case "update-admin-profile":
		response, err = adminUpdateAdminProfile(configDir, loaded, rest[1:])
	case "refresh-public-ip":
		response, err = adminRefreshPublicIP(configDir, loaded, live)
	case "cleanup-expired":
		response, err = adminCleanupExpired(configDir, loaded, wgDev, live)
	case "cleanup-orphans":
		response, err = adminCleanupOrphans(configDir, loaded, wgDev, live)
	case "reset-traffic":
		response, err = adminResetTraffic(configDir, loaded)
	case "merge-client-traffic":
		response, err = adminMergeClientTraffic(configDir, loaded, rest[1:])
	case "restart":
		response = adminResponse{OK: true, Message: "Перезапуск сервиса", RestartRequired: true}
	default:
		err = fmt.Errorf("неизвестная admin-команда: %s", rest[0])
	}
	if err != nil || !live {
		return response, err
	}
	if err := applyLiveAdminEffects(configDir, loaded, rest, response, snapshot, wgDev); err != nil {
		return adminResponse{}, err
	}
	if rest[0] != "restart" {
		response.RestartRequired = false
	}
	return response, nil
}

func captureAdminLiveSnapshot(loaded *Database, args []string) adminLiveSnapshot {
	if len(args) == 0 {
		return adminLiveSnapshot{}
	}
	switch args[0] {
	case "delete", "unbind", "deactivate", "activate":
		password, err := adminPasswordArg(args[0], args[1:])
		if err != nil {
			return adminLiveSnapshot{}
		}
		snapshot := adminLiveSnapshot{password: password}
		if entry := loaded.Passwords[password]; entry != nil && entry.DeviceID != "" {
			if dev := loaded.Devices[entry.DeviceID]; dev != nil {
				copyOfDevice := *dev
				snapshot.device = &copyOfDevice
			}
		}
		return snapshot
	case "set-password":
		fs := flag.NewFlagSet("set-password", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		password := fs.String("password", "", "текущий пароль клиента")
		_ = fs.String("new-password", "", "новый пароль клиента")
		if err := fs.Parse(args[1:]); err != nil || strings.TrimSpace(*password) == "" {
			return adminLiveSnapshot{}
		}
		snapshot := adminLiveSnapshot{password: strings.TrimSpace(*password)}
		if entry := loaded.Passwords[snapshot.password]; entry != nil && entry.DeviceID != "" {
			if dev := loaded.Devices[entry.DeviceID]; dev != nil {
				copyOfDevice := *dev
				snapshot.device = &copyOfDevice
			}
		}
		return snapshot
	default:
		return adminLiveSnapshot{}
	}
}

func applyLiveAdminEffects(configDir string, loaded *Database, args []string, response adminResponse, snapshot adminLiveSnapshot, wgDev wgDevice) error {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "create":
		if response.Password == nil {
			return errors.New("сервер создал клиента без пароля")
		}
		if response.Password.Status != "active" {
			break
		}
		password := response.Password.Password
		if err := serverWrapKeys.AddPassword(password); err != nil {
			delete(loaded.Passwords, password)
			_ = saveAdminDB(configDir, loaded)
			return fmt.Errorf("не удалось добавить WRAP-ключ: %w", err)
		}
	case "delete":
		if shouldRemoveAdminSnapshotPeer(loaded, snapshot) {
			removePeerFromWG(wgDev, snapshot.device)
		}
		serverWrapKeys.RemovePassword(snapshot.password)
	case "unbind":
		if shouldRemoveAdminSnapshotPeer(loaded, snapshot) {
			removePeerFromWG(wgDev, snapshot.device)
		}
	case "deactivate":
		if shouldRemoveAdminSnapshotPeer(loaded, snapshot) {
			removePeerFromWG(wgDev, snapshot.device)
		}
		serverWrapKeys.RemovePassword(snapshot.password)
	case "activate":
		if err := serverWrapKeys.AddPassword(snapshot.password); err != nil {
			if entry := loaded.Passwords[snapshot.password]; entry != nil {
				entry.IsDeactivated = true
				_ = saveAdminDB(configDir, loaded)
			}
			return fmt.Errorf("не удалось вернуть WRAP-ключ: %w", err)
		}
		upsertPeerInWG(wgDev, snapshot.device)
	case "set-password":
		if response.Password == nil {
			return errors.New("сервер изменил пароль клиента без нового значения")
		}
		newPassword := response.Password.Password
		entry := loaded.Passwords[newPassword]
		if entry != nil && !entry.IsDeactivated && !isPasswordPurgeable(entry) {
			if err := serverWrapKeys.AddPassword(newPassword); err != nil {
				if entry != nil {
					delete(loaded.Passwords, newPassword)
					loaded.Passwords[snapshot.password] = entry
					_ = saveAdminDB(configDir, loaded)
				}
				return fmt.Errorf("не удалось заменить WRAP-ключ: %w", err)
			}
		}
		serverWrapKeys.RemovePassword(snapshot.password)
		if shouldRemoveAdminSnapshotPeer(loaded, snapshot) {
			removePeerFromWG(wgDev, snapshot.device)
		}
	case "set-expiry":
		if response.Password == nil {
			return errors.New("сервер обновил срок клиента без состояния доступа")
		}
		password := response.Password.Password
		if response.Password.Status == "active" {
			if err := serverWrapKeys.AddPassword(password); err != nil {
				return fmt.Errorf("не удалось вернуть WRAP-ключ после продления: %w", err)
			}
		} else if response.Password.Status == "deactivated" {
			serverWrapKeys.RemovePassword(password)
		}
	case "set-dns", "update-settings":
		setServerDNS(loaded.DNS)
		setServerDefaultPorts(loaded.DefaultPorts)
		setServerPublicIPOverride(loaded.PublicIP)
		maxGeneratedPasswords = loaded.MaxPasswords
		if loaded.PublicIP == "" {
			publicIP = ""
		}
	case "set-limit":
		maxGeneratedPasswords = loaded.MaxPasswords
	case "set-default-ports":
		setServerDefaultPorts(loaded.DefaultPorts)
	case "set-public-ip":
		setServerPublicIPOverride(loaded.PublicIP)
		if loaded.PublicIP == "" {
			publicIP = ""
		}
	}
	return nil
}

func isAdminSnapshotDevice(loaded *Database, snapshot adminLiveSnapshot) bool {
	if snapshot.device == nil {
		return false
	}
	_, ok := adminDeviceIDSet(loaded)[snapshot.device.DeviceID]
	return ok
}

func shouldRemoveAdminSnapshotPeer(loaded *Database, snapshot adminLiveSnapshot) bool {
	if snapshot.device == nil || isAdminSnapshotDevice(loaded, snapshot) {
		return false
	}
	return !databaseUsesDeviceIDExcept(loaded, snapshot.device.DeviceID, snapshot.password)
}

func adminSocketPath(configDir string) string {
	if filepath.Clean(configDir) == "/etc/wdtt" {
		return "/run/wdtt/admin.sock"
	}
	return filepath.Join(configDir, "admin.sock")
}

func callAdminSocket(configDir string, request adminRequest) (adminResponse, error) {
	conn, err := net.DialTimeout("unix", adminSocketPath(configDir), 3*time.Second)
	if err != nil {
		return adminResponse{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return adminResponse{}, err
	}
	var response adminResponse
	if err := json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&response); err != nil {
		return adminResponse{}, err
	}
	return response, nil
}

func startAdminSocket(ctx context.Context, configDir string, wgDev wgDevice) error {
	path := adminSocketPath(configDir)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return err
	}
	context.AfterFunc(ctx, func() {
		listener.Close()
		_ = os.Remove(path)
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("[ADMIN] socket accept: %v", err)
				}
				return
			}
			go handleAdminSocketConn(conn, configDir, wgDev)
		}
	}()
	log.Printf("[ADMIN] Локальное управление: %s", path)
	return nil
}

func handleAdminSocketConn(conn net.Conn, configDir string, wgDev wgDevice) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var request adminRequest
	if err := json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Message: "некорректный admin-запрос"})
		return
	}
	if len(request.Args) == 0 {
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Message: "не указана admin-команда"})
		return
	}
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if strings.TrimSpace(request.MainPassword) == "" || db.MainPassword != request.MainPassword {
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Message: "главный пароль администратора не совпадает"})
		return
	}
	response, err := executeAdminCommand(configDir, db, request.Args, wgDev, true)
	if err != nil {
		response = adminErrorResponse(err)
	}
	_ = json.NewEncoder(conn).Encode(response)
}

func readAdminDB(configDir string) (*Database, error) {
	path := filepath.Join(configDir, "passwords.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no_passwords_json: %s", path)
		}
		return nil, err
	}
	var loaded Database
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil, fmt.Errorf("bad_passwords_json: %w", err)
	}
	ensureAdminDBDefaults(&loaded)
	return &loaded, nil
}

func ensureAdminDBDefaults(loaded *Database) {
	if loaded.Passwords == nil {
		loaded.Passwords = make(map[string]*PasswordEntry)
	}
	if loaded.Devices == nil {
		loaded.Devices = make(map[string]*ClientDevice)
	}
	if strings.TrimSpace(loaded.DNS) == "" {
		loaded.DNS = defaultDNS
	}
	if strings.TrimSpace(loaded.DefaultPorts) == "" {
		loaded.DefaultPorts = "56000,56001,9000"
	}
	if loaded.MaxPasswords <= 0 {
		loaded.MaxPasswords = defaultMaxGeneratedPasswords
	}
	if loaded.MaxPasswords > 500 {
		loaded.MaxPasswords = 500
	}
	loaded.AdminProfile = normalizeAdminProfileForStorage(loaded.AdminProfile, loaded.DefaultPorts)
}

func normalizeAdminProfileForStorage(profile AdminProfileEntry, defaultPorts string) AdminProfileEntry {
	normalizedDefaultPorts, err := parsePortsSpec(defaultPorts)
	if err != nil {
		normalizedDefaultPorts = "56000,56001,9000"
	}
	profile.VkHashes = strings.TrimSpace(profile.VkHashes)
	profile.SecondaryVkHash = strings.TrimSpace(profile.SecondaryVkHash)
	profile.ProfileName = normalizeAdminProfileName(profile.ProfileName)
	if profile.WorkersPerHash < 1 || profile.WorkersPerHash > 128 {
		profile.WorkersPerHash = 16
	}
	protocol, err := normalizeAdminProfileProtocol(profile.Protocol)
	if err != nil {
		protocol = "udp"
	}
	profile.Protocol = protocol
	ports, err := parsePortsSpec(profile.Ports)
	if err != nil {
		ports = normalizedDefaultPorts
	}
	profile.Ports = ports
	if profile.ListenPort < 1 || profile.ListenPort > 65535 {
		profile.ListenPort = adminProfileDefaultListenPort(profile.Ports)
	}
	profile.SNI = normalizeAdminProfileSNI(profile.SNI)
	profile.VpnDNSSelection = normalizeAdminProfileVpnDNSSelection(profile.VpnDNSSelection)
	if profile.VpnDNSSelection == "custom" {
		custom, err := normalizeAdminProfileVpnDNSCustom(profile.VpnDNSCustom)
		if err != nil || custom == "" {
			profile.VpnDNSSelection = ""
			profile.VpnDNSCustom = ""
		} else {
			profile.VpnDNSCustom = custom
		}
	} else {
		profile.VpnDNSCustom = ""
	}
	profile.DeviceIDs = normalizeAdminProfileDeviceIDs(profile.DeviceIDs)
	return profile
}

func normalizeAdminProfileForView(profile AdminProfileEntry, defaultPorts string) AdminProfileEntry {
	return normalizeAdminProfileForStorage(profile, defaultPorts)
}

func normalizeAdminProfileProtocol(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "udp", nil
	}
	switch value {
	case "udp", "tcp":
		return value, nil
	default:
		return "", errors.New("protocol должен быть udp или tcp")
	}
}

func normalizeAdminProfileSNI(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	if len([]rune(value)) > 253 {
		value = string([]rune(value)[:253])
	}
	return value
}

func normalizeAdminProfileVpnDNSSelection(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "profile", "custom", "cloudflare", "google", "quad9", "adguard", "xbox", "comss":
		return value
	default:
		return ""
	}
}

func normalizeAdminProfileVpnDNSCustom(value string) (string, error) {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(parts) == 0 {
		return "", nil
	}
	if len(parts) > 2 {
		return "", errors.New("можно сохранить не больше двух DNS-адресов VPN")
	}
	seen := make(map[string]struct{}, len(parts))
	normalized := make([]string, 0, len(parts))
	for _, raw := range parts {
		value := strings.TrimSpace(raw)
		parsed := net.ParseIP(value)
		ipv4 := parsed.To4()
		if parsed == nil || ipv4 == nil || value != net.IP(ipv4).String() {
			return "", errors.New("DNS внутри VPN должен быть IPv4-адресом")
		}
		if ipv4.IsUnspecified() || ipv4.IsLoopback() || ipv4.IsMulticast() || value == "255.255.255.255" {
			return "", errors.New("DNS внутри VPN содержит недопустимый IPv4-адрес")
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return strings.Join(normalized, ","), nil
}

func normalizeAdminProfileName(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if isDefaultAdminProfileName(value) {
		return ""
	}
	runes := []rune(value)
	if len(runes) > 48 {
		value = string(runes[:48])
	}
	return value
}

func isDefaultAdminProfileName(value string) bool {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
	switch normalized {
	case "VPN1", "VPN2", "VPN3", "ВПН1", "ВПН2", "ВПН3":
		return true
	default:
		return false
	}
}

func normalizeAdminProfileDeviceIDs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
		if len(cleaned) >= 64 {
			break
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

func adminProfileDefaultListenPort(ports string) int {
	parts := strings.Split(ports, ",")
	if len(parts) == 3 {
		if port, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && port >= 1 && port <= 65535 {
			return port
		}
	}
	return 9000
}

func saveAdminDB(configDir string, loaded *Database) error {
	ensureAdminDBDefaults(loaded)
	data, err := json.MarshalIndent(loaded, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(configDir, "passwords.json")
	tmp := path + ".admin.tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func buildAdminServerInfo(configDir string, loaded *Database) *adminServerInfo {
	expired := 0
	active := 0
	retainedExpired := 0
	occupied := 0
	nowUnix := time.Now().Unix()
	usedDevices := make(map[string]struct{})
	clientDevices := make(map[string]struct{})
	for _, entry := range loaded.Passwords {
		if entry == nil {
			continue
		}
		if !isPasswordPurgeableAt(entry, nowUnix) {
			occupied++
		}
		if isPasswordExpiredAt(entry, nowUnix) {
			expired++
			if isPasswordRetainedExpiredAt(entry, nowUnix) {
				retainedExpired++
			}
		} else if !entry.IsDeactivated {
			active++
		}
		if entry.DeviceID != "" {
			usedDevices[entry.DeviceID] = struct{}{}
			clientDevices[entry.DeviceID] = struct{}{}
		}
		for _, event := range entry.BindHistory {
			deviceID := strings.TrimSpace(event.DeviceID)
			if deviceID == "" || event.Status == "denied_mismatch" {
				continue
			}
			if event.BoundAt > 0 || event.Status == "active" || event.Status == "unbound" {
				clientDevices[deviceID] = struct{}{}
			}
		}
	}
	ownerDevices := adminDeviceIDSet(loaded)
	for deviceID := range ownerDevices {
		usedDevices[deviceID] = struct{}{}
	}
	orphans := 0
	orphanDevices := make([]adminDeviceInfo, 0)
	for deviceID := range loaded.Devices {
		if _, used := usedDevices[deviceID]; !used {
			orphans++
			if dev := loaded.Devices[deviceID]; dev != nil {
				orphanDevices = append(orphanDevices, buildAdminDeviceInfo(dev))
			}
		}
	}
	sort.SliceStable(orphanDevices, func(i, j int) bool {
		return strings.ToLower(orphanDevices[i].Name+orphanDevices[i].DeviceID) < strings.ToLower(orphanDevices[j].Name+orphanDevices[j].DeviceID)
	})
	effectivePublic := loaded.PublicIP
	if effectivePublic == "" {
		effectivePublic = publicIP
	}
	available := loaded.MaxPasswords - occupied
	if available < 0 {
		available = 0
	}
	maxWorkersPerAccess, maxClientMbps := configuredAccessRuntimeLimits()
	udpWriteStats := currentOpportunisticUDPWriteStats()
	return &adminServerInfo{
		WDTTPlusVersion:        wdttServerVersion,
		BinarySHA256:           runningBinarySHA256(),
		WGBackend:              activeWGBackend.Load(),
		ConfigDir:              configDir,
		PublicIP:               loaded.PublicIP,
		EffectivePublic:        effectivePublic,
		DNS:                    loaded.DNS,
		DefaultPorts:           loaded.DefaultPorts,
		MaxPasswords:           loaded.MaxPasswords,
		MaxWorkersPerAccess:    maxWorkersPerAccess,
		MaxClientMbps:          maxClientMbps,
		PasswordCount:          len(loaded.Passwords),
		ActivePasswordCount:    active,
		RetainedExpiredCount:   retainedExpired,
		AvailablePasswordCount: available,
		DeviceCount:            len(clientDevices),
		OwnerDeviceCount:       len(ownerDevices),
		ExpiredCount:           expired,
		OrphanDeviceCount:      orphans,
		ActiveConnections:      atomic.LoadInt32(&activeConns),
		CPUPercent:             runtimeCPUPercent(),
		MemoryPercent:          runtimeMemoryPercent(),
		NetworkRxMbps:          runtimeNetworkRxMbps(),
		NetworkTxMbps:          runtimeNetworkTxMbps(),
		PacketDrops:            atomic.LoadInt64(&runtimePacketDrops),
		Reconnects:             atomic.LoadInt64(&reconnectCount),
		HandshakeFailures:      atomic.LoadInt64(&handshakeFailures),
		HandshakeThrottles:     atomic.LoadInt64(&handshakeThrottles),
		WorkerLimitRejects:     atomic.LoadInt64(&workerLimitRejections),
		UDPWriteSingle:         udpWriteStats.SingleWrites,
		UDPWriteBatchCalls:     udpWriteStats.BatchCalls,
		UDPWriteBatchMessages:  udpWriteStats.BatchMessages,
		UDPWritePartialBatches: udpWriteStats.PartialBatchWrites,
		UDPWriteErrors:         udpWriteStats.WriteErrors,
		UDPWriteQueueHighWater: udpWriteStats.QueueHighWater,
		OrphanDevices:          orphanDevices,
		Traffic:                buildAdminDatabaseTraffic(loaded),
		AdminTraffic:           buildAdminTrafficPeriod(loaded.AdminTraffic, loaded.AdminDownBytes, loaded.AdminUpBytes),
		AdminProfile:           buildAdminProfileInfo(loaded),
	}
}

func buildAdminProfileInfo(loaded *Database) AdminProfileEntry {
	return normalizeAdminProfileForView(loaded.AdminProfile, loaded.DefaultPorts)
}

func buildAdminPasswordList(loaded *Database) []adminPasswordInfo {
	result := make([]adminPasswordInfo, 0, len(loaded.Passwords))
	for password, entry := range loaded.Passwords {
		info := buildAdminPasswordInfo(loaded, password, entry)
		info.Device = nil
		info.BindHistory = nil
		result = append(result, info)
	}
	sort.SliceStable(result, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(result[i].Label))
		right := strings.ToLower(strings.TrimSpace(result[j].Label))
		if left == "" {
			left = strings.ToLower(result[i].Password)
		}
		if right == "" {
			right = strings.ToLower(result[j].Password)
		}
		return left < right
	})
	return result
}

func adminPasswordDetails(configDir string, loaded *Database, args []string) (adminResponse, error) {
	password, err := adminPasswordArg("details", args)
	if err != nil {
		return adminResponse{}, err
	}
	entry, err := requireAdminPassword(loaded, password)
	if err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK: true, Server: buildAdminServerInfo(configDir, loaded),
		Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, password, entry)),
	}, nil
}

func adminExportClientState(configDir string, loaded *Database, args []string) (adminResponse, error) {
	password, err := adminPasswordArg("export-client-state", args)
	if err != nil {
		return adminResponse{}, err
	}
	entry, err := requireAdminPassword(loaded, password)
	if err != nil {
		return adminResponse{}, err
	}
	state := &adminClientState{
		Version:        1,
		Password:       password,
		DownBytes:      entry.DownBytes,
		UpBytes:        entry.UpBytes,
		Traffic:        append([]TrafficBucket(nil), entry.Traffic...),
		TrafficImports: cloneTrafficImports(entry.TrafficImports),
		BindHistory:    append([]BindHistoryEntry(nil), entry.BindHistory...),
	}
	return adminResponse{
		OK:          true,
		Message:     "Состояние клиента подготовлено",
		Server:      buildAdminServerInfo(configDir, loaded),
		Password:    ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, password, entry)),
		ClientState: state,
	}, nil
}

func adminImportClientState(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("import-client-state", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	operationID := fs.String("operation-id", "", "уникальный идентификатор переноса")
	encoded := fs.String("state", "", "base64url-состояние клиента")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	key := strings.TrimSpace(*operationID)
	if key == "" || len(key) > 160 {
		return adminResponse{}, errors.New("operation-id должен содержать 1..160 символов")
	}
	entry, err := requireAdminPassword(loaded, strings.TrimSpace(*password))
	if err != nil {
		return adminResponse{}, err
	}
	if entry.TrafficImports != nil {
		if _, applied := entry.TrafficImports[key]; applied {
			return adminResponse{
				OK:       true,
				Message:  "Состояние клиента уже было перенесено",
				Server:   buildAdminServerInfo(configDir, loaded),
				Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, strings.TrimSpace(*password), entry)),
			}, nil
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*encoded))
	if err != nil || len(raw) == 0 || len(raw) > 128<<10 {
		return adminResponse{}, errors.New("состояние клиента повреждено или слишком велико")
	}
	var state adminClientState
	if err := json.Unmarshal(raw, &state); err != nil {
		return adminResponse{}, errors.New("состояние клиента имеет неверный формат")
	}
	if err := validateAdminClientState(&state, strings.TrimSpace(*password)); err != nil {
		return adminResponse{}, err
	}
	if entry.DeviceID != "" || entry.DownBytes != 0 || entry.UpBytes != 0 ||
		len(entry.Traffic) != 0 || len(entry.BindHistory) != 0 {
		return adminResponse{}, newAdminCommandError(
			"target_not_empty",
			"целевой клиент уже содержит устройство или статистику",
		)
	}
	previousDown := entry.DownBytes
	previousUp := entry.UpBytes
	previousTraffic := append([]TrafficBucket(nil), entry.Traffic...)
	previousImports := cloneTrafficImports(entry.TrafficImports)
	previousHistory := append([]BindHistoryEntry(nil), entry.BindHistory...)

	entry.DownBytes = state.DownBytes
	entry.UpBytes = state.UpBytes
	entry.Traffic = append([]TrafficBucket(nil), state.Traffic...)
	entry.TrafficImports = cloneTrafficImports(state.TrafficImports)
	if entry.TrafficImports == nil {
		entry.TrafficImports = make(map[string]TrafficImport)
	}
	entry.TrafficImports[key] = TrafficImport{AppliedAt: time.Now().Unix()}
	entry.BindHistory = append([]BindHistoryEntry(nil), state.BindHistory...)
	if err := saveAdminDB(configDir, loaded); err != nil {
		entry.DownBytes = previousDown
		entry.UpBytes = previousUp
		entry.Traffic = previousTraffic
		entry.TrafficImports = previousImports
		entry.BindHistory = previousHistory
		return adminResponse{}, err
	}
	return adminResponse{
		OK:       true,
		Message:  "Статистика и история клиента перенесены",
		Server:   buildAdminServerInfo(configDir, loaded),
		Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, strings.TrimSpace(*password), entry)),
	}, nil
}

func validateAdminClientState(state *adminClientState, password string) error {
	if state == nil || state.Version != 1 || state.Password != password {
		return errors.New("состояние клиента относится к другому паролю или версии")
	}
	if state.DownBytes < 0 || state.UpBytes < 0 {
		return errors.New("счётчики состояния клиента не могут быть отрицательными")
	}
	if len(state.Traffic) > trafficHistoryDays || len(state.BindHistory) > 50 ||
		len(state.TrafficImports) > 1024 {
		return errors.New("история состояния клиента превышает допустимый размер")
	}
	for _, bucket := range state.Traffic {
		if len(bucket.Date) != 10 || bucket.DownBytes < 0 || bucket.UpBytes < 0 {
			return errors.New("история трафика клиента повреждена")
		}
		if _, err := time.Parse("2006-01-02", bucket.Date); err != nil {
			return errors.New("история трафика клиента содержит неверную дату")
		}
	}
	for key, imported := range state.TrafficImports {
		if strings.TrimSpace(key) == "" || len(key) > 160 ||
			imported.DownBytes < 0 || imported.UpBytes < 0 || imported.AppliedAt < 0 {
			return errors.New("история учёта перенесённого трафика повреждена")
		}
	}
	return nil
}

func cloneTrafficImports(source map[string]TrafficImport) map[string]TrafficImport {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]TrafficImport, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func buildAdminPasswordInfo(loaded *Database, password string, entry *PasswordEntry) adminPasswordInfo {
	info := adminPasswordInfo{
		Password: password,
		Ports:    loaded.DefaultPorts,
		Status:   "active",
	}
	if entry == nil {
		info.Status = "broken"
		return info
	}
	if strings.TrimSpace(entry.Ports) != "" {
		info.Ports = entry.Ports
	}
	info.Label = entry.Label
	info.VkHash = entry.VkHash
	info.ExpiresAt = entry.ExpiresAt
	info.PurgeAfter = entry.PurgeAfter
	info.DownBytes = entry.DownBytes
	info.UpBytes = entry.UpBytes
	info.DeviceID = entry.DeviceID
	info.BindEventsCount = len(entry.BindHistory)
	info.Traffic = buildAdminTrafficPeriod(entry.Traffic, entry.DownBytes, entry.UpBytes)
	info.BindHistory = append([]BindHistoryEntry(nil), entry.BindHistory...)
	nowUnix := time.Now().Unix()
	if isPasswordRetainedExpiredAt(entry, nowUnix) {
		info.Status = "expired_retained"
	} else if isPasswordExpiredAt(entry, nowUnix) {
		info.Status = "expired"
	} else if entry.IsDeactivated {
		info.Status = "deactivated"
	}
	if entry.DeviceID != "" {
		if dev := loaded.Devices[entry.DeviceID]; dev != nil {
			info.DeviceName = deviceDisplayName(dev)
			info.DeviceIP = dev.IP
			info.DeviceLastSeen = dev.LastSeenAt
			deviceInfo := buildAdminDeviceInfo(dev)
			info.Device = &deviceInfo
		}
	}
	return info
}

func buildAdminDeviceInfo(dev *ClientDevice) adminDeviceInfo {
	if dev == nil {
		return adminDeviceInfo{}
	}
	return adminDeviceInfo{
		DeviceID: dev.DeviceID, IP: dev.IP, Name: deviceDisplayName(dev),
		Manufacturer: dev.Manufacturer, Brand: dev.Brand, Model: dev.Model,
		AndroidVersion: dev.AndroidVersion, SDK: dev.SDK, ABI: dev.ABI,
		AppVersion: dev.AppVersion, Locale: dev.Locale, Country: dev.Country,
		TimeZone: dev.TimeZone, RemoteIP: dev.RemoteIP, LastSeenAt: dev.LastSeenAt,
	}
}

func buildAdminTrafficPeriod(buckets []TrafficBucket, down, up int64) adminTrafficPeriod {
	period := func(days int) adminTrafficValue {
		if days <= 0 {
			return adminTrafficValue{Down: down, Up: up}
		}
		total := trafficSince(buckets, days)
		return adminTrafficValue{Down: total.Down, Up: total.Up}
	}
	return adminTrafficPeriod{Today: period(1), Week: period(7), Month: period(30), All: period(0)}
}

func buildAdminDatabaseTraffic(loaded *Database) adminTrafficPeriod {
	total := func(days int) adminTrafficValue {
		var down, up int64
		if days <= 0 {
			down, up = loaded.AdminDownBytes, loaded.AdminUpBytes
		} else {
			value := trafficSince(loaded.AdminTraffic, days)
			down, up = value.Down, value.Up
		}
		for _, entry := range loaded.Passwords {
			if entry == nil {
				continue
			}
			if days <= 0 {
				down += entry.DownBytes
				up += entry.UpBytes
			} else {
				value := trafficSince(entry.Traffic, days)
				down += value.Down
				up += value.Up
			}
		}
		return adminTrafficValue{Down: down, Up: up}
	}
	return adminTrafficPeriod{Today: total(1), Week: total(7), Month: total(30), All: total(0)}
}

func adminCreatePassword(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	days := fs.Int("days", 30, "срок действия в днях, 0 = бессрочно")
	label := fs.String("label", "", "название клиента")
	vkHash := fs.String("vk-hash", "", "VK-хеш или ссылка")
	ports := fs.String("ports", "", "DTLS,WG,TUN")
	clientPassword := fs.String("client-password", "", "заданный пароль клиента")
	expiresAt := fs.Int64("expires-at", -1, "точная дата окончания unix, 0 = бессрочно")
	purgeAfter := fs.Int64(
		"purge-after",
		0,
		"не удалять истёкшую запись до unix timestamp",
	)
	deactivated := fs.Bool("deactivated", false, "создать клиента отключённым")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	if *days < 0 || *days > 365 {
		return adminResponse{}, errors.New("days должен быть 0..365")
	}
	cleanupExpiredPasswordsAdmin(loaded)
	if len(loaded.Passwords) >= loaded.MaxPasswords {
		return adminResponse{}, newAdminCommandError("capacity_full", fmt.Sprintf("лимит клиентов: максимум %d", loaded.MaxPasswords))
	}
	normalizedPorts := loaded.DefaultPorts
	if strings.TrimSpace(*ports) != "" {
		value, err := parsePortsSpec(*ports)
		if err != nil {
			return adminResponse{}, err
		}
		normalizedPorts = value
	}
	normalizedHash := ""
	if strings.TrimSpace(*vkHash) != "" {
		value, err := normalizeVKHashesInput(*vkHash)
		if err != nil {
			return adminResponse{}, err
		}
		normalizedHash = value
	}
	password := ""
	if strings.TrimSpace(*clientPassword) != "" {
		value, err := normalizeClientPassword(*clientPassword)
		if err != nil {
			return adminResponse{}, err
		}
		if value == loaded.MainPassword {
			return adminResponse{}, errors.New("пароль клиента не должен совпадать с главным паролем")
		}
		if _, exists := loaded.Passwords[value]; exists {
			return adminResponse{}, errors.New("клиент с таким паролем уже существует")
		}
		password = value
	} else {
		for i := 0; i < 64; i++ {
			candidate := generatePassword()
			if candidate == loaded.MainPassword {
				continue
			}
			if _, exists := loaded.Passwords[candidate]; !exists {
				password = candidate
				break
			}
		}
	}
	if password == "" {
		return adminResponse{}, errors.New("не удалось создать уникальный пароль")
	}
	entry := &PasswordEntry{
		Label:         normalizePasswordLabel(*label),
		VkHash:        normalizedHash,
		Ports:         normalizedPorts,
		IsDeactivated: *deactivated,
	}
	if *expiresAt >= 0 {
		if *expiresAt > 0 && *expiresAt <= time.Now().Unix() {
			return adminResponse{}, errors.New("срок импортируемого клиента уже истёк")
		}
		entry.ExpiresAt = *expiresAt
	} else if *days > 0 {
		entry.ExpiresAt = time.Now().Add(time.Duration(*days) * 24 * time.Hour).Unix()
	}
	if err := validatePasswordRetention(entry.ExpiresAt, *purgeAfter); err != nil {
		return adminResponse{}, err
	}
	entry.PurgeAfter = *purgeAfter
	loaded.Passwords[password] = entry
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK:              true,
		Message:         "Клиент создан",
		RestartRequired: true,
		Server:          buildAdminServerInfo(configDir, loaded),
		Password:        ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, password, entry)),
	}, nil
}

func adminSetPassword(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-password", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	oldPassword := fs.String("password", "", "текущий пароль клиента")
	newPasswordRaw := fs.String("new-password", "", "новый пароль клиента")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	oldValue := strings.TrimSpace(*oldPassword)
	entry, err := requireAdminPassword(loaded, oldValue)
	if err != nil {
		return adminResponse{}, err
	}
	newValue, err := normalizeClientPassword(*newPasswordRaw)
	if err != nil {
		return adminResponse{}, err
	}
	if newValue == oldValue {
		return adminResponse{}, errors.New("новый пароль совпадает с текущим")
	}
	if newValue == loaded.MainPassword {
		return adminResponse{}, errors.New("пароль клиента не должен совпадать с главным паролем")
	}
	if _, exists := loaded.Passwords[newValue]; exists {
		return adminResponse{}, errors.New("клиент с таким паролем уже существует")
	}
	delete(loaded.Passwords, oldValue)
	loaded.Passwords[newValue] = entry
	if err := saveAdminDB(configDir, loaded); err != nil {
		delete(loaded.Passwords, newValue)
		loaded.Passwords[oldValue] = entry
		return adminResponse{}, err
	}
	return adminResponse{
		OK:              true,
		Message:         "Пароль клиента изменён",
		RestartRequired: true,
		Server:          buildAdminServerInfo(configDir, loaded),
		Password:        ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, newValue, entry)),
	}, nil
}

func adminDeletePassword(configDir string, loaded *Database, args []string) (adminResponse, error) {
	password, err := adminPasswordArg("delete", args)
	if err != nil {
		return adminResponse{}, err
	}
	entry, exists := loaded.Passwords[password]
	if !exists || entry == nil {
		return adminResponse{}, errors.New("пароль не найден")
	}
	unbindPasswordDeviceAdmin(loaded, entry)
	delete(loaded.Passwords, password)
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK:              true,
		Message:         "Клиент удалён",
		RestartRequired: true,
		Server:          buildAdminServerInfo(configDir, loaded),
	}, nil
}

func adminUnbindPassword(configDir string, loaded *Database, args []string) (adminResponse, error) {
	password, err := adminPasswordArg("unbind", args)
	if err != nil {
		return adminResponse{}, err
	}
	entry, exists := loaded.Passwords[password]
	if !exists || entry == nil {
		return adminResponse{}, errors.New("пароль не найден")
	}
	unbindPasswordDeviceAdmin(loaded, entry)
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK:              true,
		Message:         "Устройство отвязано",
		RestartRequired: true,
		Server:          buildAdminServerInfo(configDir, loaded),
		Password:        ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, password, entry)),
	}, nil
}

func adminSetPasswordActivation(configDir string, loaded *Database, args []string, deactivated bool) (adminResponse, error) {
	command := "activate"
	if deactivated {
		command = "deactivate"
	}
	password, err := adminPasswordArg(command, args)
	if err != nil {
		return adminResponse{}, err
	}
	entry, exists := loaded.Passwords[password]
	if !exists || entry == nil {
		return adminResponse{}, errors.New("пароль не найден")
	}
	if !deactivated && isPasswordExpired(entry) {
		return adminResponse{}, errors.New("срок действия клиента истёк")
	}
	entry.IsDeactivated = deactivated
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	message := "Клиент активирован"
	if deactivated {
		message = "Клиент отключён"
	}
	return adminResponse{
		OK:              true,
		Message:         message,
		RestartRequired: true,
		Server:          buildAdminServerInfo(configDir, loaded),
		Password:        ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, password, entry)),
	}, nil
}

func adminSetPasswordLabel(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-label", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	label := fs.String("label", "", "новое название")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	entry, err := requireAdminPassword(loaded, *password)
	if err != nil {
		return adminResponse{}, err
	}
	entry.Label = normalizePasswordLabel(*label)
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK:       true,
		Message:  "Название обновлено",
		Server:   buildAdminServerInfo(configDir, loaded),
		Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, *password, entry)),
	}, nil
}

func adminSetPasswordHash(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-hash", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	hash := fs.String("vk-hash", "", "новый VK-хеш или ссылка")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	entry, err := requireAdminPassword(loaded, *password)
	if err != nil {
		return adminResponse{}, err
	}
	normalized := ""
	if strings.TrimSpace(*hash) != "" {
		normalized, err = normalizeVKHashesInput(*hash)
		if err != nil {
			return adminResponse{}, err
		}
	}
	entry.VkHash = normalized
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK:       true,
		Message:  "VK-хеш обновлён",
		Server:   buildAdminServerInfo(configDir, loaded),
		Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, *password, entry)),
	}, nil
}

func adminSetPasswordExpiry(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-expiry", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	days := fs.Int("days", 30, "новый срок от текущего момента, 0 = бессрочно")
	expiresAt := fs.Int64("expires-at", -1, "точная дата окончания unix, 0 = бессрочно")
	purgeAfter := fs.Int64(
		"purge-after",
		-1,
		"не удалять истёкшую запись до unix timestamp; по умолчанию сохраняется прежний интервал",
	)
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	provided := make(map[string]bool)
	fs.Visit(func(value *flag.Flag) {
		provided[value.Name] = true
	})
	if provided["days"] && provided["expires-at"] {
		return adminResponse{}, errors.New("укажите только один из параметров: days или expires-at")
	}
	if !provided["expires-at"] && (*days < 0 || *days > 365) {
		return adminResponse{}, errors.New("days должен быть 0..365")
	}
	entry, err := requireAdminPassword(loaded, *password)
	if err != nil {
		return adminResponse{}, err
	}
	nowUnix := time.Now().Unix()
	if isPasswordPurgeableAt(entry, nowUnix) {
		return adminResponse{}, newAdminCommandError(
			"retention_expired",
			"запись уже подлежит удалению; создайте доступ заново",
		)
	}

	newExpiresAt := int64(0)
	if provided["expires-at"] {
		if *expiresAt < 0 {
			return adminResponse{}, errors.New("expires-at должен быть 0 или будущим unix timestamp")
		}
		newExpiresAt = *expiresAt
		if newExpiresAt > 0 && newExpiresAt <= nowUnix {
			return adminResponse{}, errors.New("новый срок действия уже истёк")
		}
	} else if *days > 0 {
		newExpiresAt = time.Now().Add(time.Duration(*days) * 24 * time.Hour).Unix()
	}

	newPurgeAfter := int64(0)
	if provided["purge-after"] {
		newPurgeAfter = *purgeAfter
	} else {
		oldRetentionDuration := entry.PurgeAfter - entry.ExpiresAt
		if newExpiresAt > 0 && entry.ExpiresAt > 0 && oldRetentionDuration > 0 {
			newPurgeAfter = newExpiresAt + oldRetentionDuration
			if newPurgeAfter < newExpiresAt {
				return adminResponse{}, errors.New("срок хранения выходит за допустимый диапазон")
			}
		}
	}
	if err := validatePasswordRetention(newExpiresAt, newPurgeAfter); err != nil {
		return adminResponse{}, err
	}
	entry.ExpiresAt = newExpiresAt
	entry.PurgeAfter = newPurgeAfter
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK:       true,
		Message:  "Срок обновлён",
		Server:   buildAdminServerInfo(configDir, loaded),
		Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, *password, entry)),
	}, nil
}

func validatePasswordRetention(expiresAt, purgeAfter int64) error {
	if purgeAfter < 0 {
		return errors.New("purge-after должен быть неотрицательным unix timestamp")
	}
	if expiresAt == 0 {
		if purgeAfter != 0 {
			return errors.New("для бессрочного доступа purge-after должен быть 0")
		}
		return nil
	}
	if purgeAfter > 0 && purgeAfter < expiresAt {
		return errors.New("purge-after не может быть раньше expires-at")
	}
	return nil
}

func adminSetPasswordRetention(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-retention", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	expectedExpiresAt := fs.Int64("expected-expires-at", -1, "ожидаемая дата окончания unix")
	purgeAfter := fs.Int64("purge-after", -1, "новая дата удаления истёкшей записи unix")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, newAdminCommandError("invalid", err.Error())
	}
	if fs.NArg() != 0 {
		return adminResponse{}, newAdminCommandError("invalid", "лишние аргументы set-retention")
	}
	passwordValue := strings.TrimSpace(*password)
	if passwordValue == "" {
		return adminResponse{}, newAdminCommandError("invalid", "укажите --password")
	}
	if *expectedExpiresAt <= 0 {
		return adminResponse{}, newAdminCommandError("invalid", "expected-expires-at должен быть положительным unix timestamp")
	}
	if *purgeAfter <= 0 {
		return adminResponse{}, newAdminCommandError("invalid", "purge-after должен быть положительным unix timestamp")
	}

	entry, err := requireAdminPassword(loaded, passwordValue)
	if err != nil {
		return adminResponse{}, err
	}
	nowUnix := time.Now().Unix()
	if isPasswordPurgeableAt(entry, nowUnix) {
		return adminResponse{}, newAdminCommandError("retention_expired", "истёкшая запись уже подлежит удалению")
	}
	if entry.ExpiresAt != *expectedExpiresAt {
		return adminResponse{}, newAdminCommandError("retention_conflict", "срок доступа изменился; обновите состояние перед повтором")
	}
	if entry.ExpiresAt <= 0 || entry.PurgeAfter <= 0 {
		return adminResponse{}, newAdminCommandError("invalid", "изменить можно только существующий конечный срок хранения")
	}
	if *purgeAfter < entry.ExpiresAt {
		return adminResponse{}, newAdminCommandError("invalid", "purge-after не может быть раньше expires-at")
	}
	if *purgeAfter <= entry.PurgeAfter {
		return adminResponse{}, newAdminCommandError("retention_conflict", "запись уже хранится до такого же или более позднего срока")
	}

	previousPurgeAfter := entry.PurgeAfter
	entry.PurgeAfter = *purgeAfter
	if err := saveAdminDB(configDir, loaded); err != nil {
		entry.PurgeAfter = previousPurgeAfter
		return adminResponse{}, err
	}
	return adminResponse{
		OK:       true,
		Message:  "Срок хранения обновлён",
		Server:   buildAdminServerInfo(configDir, loaded),
		Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, passwordValue, entry)),
	}, nil
}

func adminSetPasswordPorts(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-ports", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	ports := fs.String("ports", "", "DTLS,WG,TUN")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	entry, err := requireAdminPassword(loaded, *password)
	if err != nil {
		return adminResponse{}, err
	}
	normalized, err := parsePortsSpec(*ports)
	if err != nil {
		return adminResponse{}, err
	}
	entry.Ports = normalized
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Порты ссылки обновлены", Server: buildAdminServerInfo(configDir, loaded), Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, *password, entry))}, nil
}

func adminUpdateClient(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("update-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	label := fs.String("label", "", "название")
	hash := fs.String("vk-hash", "", "VK-хеш или ссылка")
	ports := fs.String("ports", "", "DTLS,WG,TUN")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	entry, err := requireAdminPassword(loaded, *password)
	if err != nil {
		return adminResponse{}, err
	}
	normalizedHash := ""
	if strings.TrimSpace(*hash) != "" {
		normalizedHash, err = normalizeVKHashesInput(*hash)
		if err != nil {
			return adminResponse{}, err
		}
	}
	normalizedPorts, err := parsePortsSpec(*ports)
	if err != nil {
		return adminResponse{}, err
	}
	entry.Label = normalizePasswordLabel(*label)
	entry.VkHash = normalizedHash
	entry.Ports = normalizedPorts
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Клиент обновлён", Server: buildAdminServerInfo(configDir, loaded), Password: ptrAdminPasswordInfo(buildAdminPasswordInfo(loaded, *password, entry))}, nil
}

func adminSetDNS(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-dns", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	value := fs.String("value", "", "DNS через запятую")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	normalized, err := normalizeDNSInput(*value)
	if err != nil {
		return adminResponse{}, err
	}
	loaded.DNS = normalized
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "DNS обновлён", Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminSetLimit(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-limit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	value := fs.Int("value", 0, "лимит клиентов")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	if *value < 1 || *value > 500 {
		return adminResponse{}, errors.New("лимит должен быть 1..500")
	}
	loaded.MaxPasswords = *value
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Лимит клиентов обновлён", Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminSetDefaultPorts(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-default-ports", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	value := fs.String("value", "", "DTLS,WG,TUN")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	normalized, err := parsePortsSpec(*value)
	if err != nil {
		return adminResponse{}, err
	}
	loaded.DefaultPorts = normalized
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Стандартные порты ссылок обновлены", Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminSetPublicIP(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("set-public-ip", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	value := fs.String("value", "", "домен, IP или автоматическое определение (`auto`)")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	normalized, err := normalizePublicAddressInput(*value)
	if err != nil {
		return adminResponse{}, err
	}
	loaded.PublicIP = normalized
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	message := "Публичный адрес обновлён"
	if normalized == "" {
		message = "Включено автоматическое определение публичного IP"
	}
	return adminResponse{OK: true, Message: message, Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminUpdateSettings(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("update-settings", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dns := fs.String("dns", "", "DNS через запятую")
	limit := fs.Int("limit", 0, "лимит клиентов")
	ports := fs.String("ports", "", "стандартные порты ссылок")
	publicHost := fs.String("public-ip", "auto", "домен, IP или автоматическое определение (`auto`)")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	normalizedDNS, err := normalizeDNSInput(*dns)
	if err != nil {
		return adminResponse{}, err
	}
	if *limit < 1 || *limit > 500 {
		return adminResponse{}, errors.New("лимит должен быть 1..500")
	}
	normalizedPorts, err := parsePortsSpec(*ports)
	if err != nil {
		return adminResponse{}, err
	}
	normalizedPublic, err := normalizePublicAddressInput(*publicHost)
	if err != nil {
		return adminResponse{}, err
	}
	loaded.DNS = normalizedDNS
	loaded.MaxPasswords = *limit
	loaded.DefaultPorts = normalizedPorts
	loaded.PublicIP = normalizedPublic
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Настройки сервера обновлены", Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminUpdateAdminProfile(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("update-admin-profile", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	vkHashes := fs.String("vk-hashes", "", "VK-хеши владельца")
	secondaryVkHash := fs.String("secondary-vk-hash", "", "резервный VK-хеш владельца")
	profileName := fs.String("profile-name", "", "название VPN-профиля владельца")
	workers := fs.Int("workers", 16, "потоков на хеш")
	protocol := fs.String("protocol", "udp", "протокол клиента")
	listenPort := fs.Int("listen-port", 0, "локальный порт клиента")
	sni := fs.String("sni", "", "SNI клиента")
	noDNS := fs.Bool("no-dns", false, "отключить DNS-перехват")
	vpnDNSSelection := fs.String("vpn-dns-selection", "", "вариант DNS внутри VPN")
	vpnDNSCustom := fs.String("vpn-dns-custom", "", "свои IPv4-адреса DNS внутри VPN")
	ports := fs.String("ports", "", "DTLS,WG,TUN")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	provided := make(map[string]bool)
	fs.Visit(func(value *flag.Flag) {
		provided[value.Name] = true
	})
	if len(provided) == 0 {
		return adminResponse{OK: true, Message: "Профиль владельца не изменён", Server: buildAdminServerInfo(configDir, loaded)}, nil
	}

	profile := normalizeAdminProfileForStorage(loaded.AdminProfile, loaded.DefaultPorts)
	if provided["vk-hashes"] {
		profile.VkHashes = ""
		if strings.TrimSpace(*vkHashes) != "" {
			normalized, err := normalizeVKHashesInput(*vkHashes)
			if err != nil {
				return adminResponse{}, err
			}
			profile.VkHashes = normalized
		}
	}
	if provided["secondary-vk-hash"] {
		profile.SecondaryVkHash = ""
		if strings.TrimSpace(*secondaryVkHash) != "" {
			normalized, err := normalizeVKHashesInput(*secondaryVkHash)
			if err != nil {
				return adminResponse{}, err
			}
			profile.SecondaryVkHash = normalized
		}
	}
	if provided["profile-name"] {
		profile.ProfileName = normalizeAdminProfileName(*profileName)
	}
	if provided["workers"] {
		if *workers < 1 || *workers > 128 {
			return adminResponse{}, errors.New("workers должен быть 1..128")
		}
		profile.WorkersPerHash = *workers
	}
	if provided["protocol"] {
		normalizedProtocol, err := normalizeAdminProfileProtocol(*protocol)
		if err != nil {
			return adminResponse{}, err
		}
		profile.Protocol = normalizedProtocol
	}
	if provided["ports"] {
		normalizedPorts, err := parsePortsSpec(*ports)
		if err != nil {
			return adminResponse{}, err
		}
		profile.Ports = normalizedPorts
	}
	if provided["listen-port"] {
		if *listenPort < 1 || *listenPort > 65535 {
			return adminResponse{}, errors.New("listen-port должен быть 1..65535")
		}
		profile.ListenPort = *listenPort
	}
	if provided["sni"] {
		profile.SNI = normalizeAdminProfileSNI(*sni)
	}
	if provided["no-dns"] {
		profile.NoDNS = *noDNS
	}
	if provided["vpn-dns-selection"] {
		profile.VpnDNSSelection = normalizeAdminProfileVpnDNSSelection(*vpnDNSSelection)
		if profile.VpnDNSSelection == "" {
			return adminResponse{}, errors.New("неизвестный вариант DNS внутри VPN")
		}
	}
	if provided["vpn-dns-custom"] {
		custom, err := normalizeAdminProfileVpnDNSCustom(*vpnDNSCustom)
		if err != nil {
			return adminResponse{}, err
		}
		profile.VpnDNSCustom = custom
	}
	if profile.VpnDNSSelection == "custom" && profile.VpnDNSCustom == "" {
		return adminResponse{}, errors.New("для своего DNS внутри VPN нужен хотя бы один IPv4-адрес")
	}
	if profile.VpnDNSSelection != "custom" {
		profile.VpnDNSCustom = ""
	}
	profile.UpdatedAt = time.Now().Unix()
	profile = normalizeAdminProfileForStorage(profile, loaded.DefaultPorts)

	loaded.AdminProfile = profile
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Профиль владельца обновлён", Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminRefreshPublicIP(configDir string, loaded *Database, live bool) (adminResponse, error) {
	if !live {
		return adminResponse{}, errors.New("повторное определение публичного IP доступно только на работающем сервере")
	}
	publicIP = ""
	value := getPublicIP()
	if value == "YOUR_SERVER_IP" {
		return adminResponse{}, errors.New("не удалось определить публичный IP")
	}
	return adminResponse{OK: true, Message: "Публичный IP сервера определён: " + value, Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminCleanupExpired(configDir string, loaded *Database, wgDev wgDevice, live bool) (adminResponse, error) {
	removed := 0
	if live {
		removed = cleanupExpiredPasswordsLocked(wgDev)
	} else {
		removed = cleanupExpiredPasswordsAdmin(loaded)
	}
	if removed > 0 {
		if err := saveAdminDB(configDir, loaded); err != nil {
			return adminResponse{}, err
		}
	}
	return adminResponse{OK: true, Message: fmt.Sprintf("Удалено истёкших клиентов: %d", removed), Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminCleanupOrphans(configDir string, loaded *Database, wgDev wgDevice, live bool) (adminResponse, error) {
	used := make(map[string]struct{})
	for _, entry := range loaded.Passwords {
		if entry != nil && entry.DeviceID != "" {
			used[entry.DeviceID] = struct{}{}
		}
	}
	for deviceID := range adminDeviceIDSet(loaded) {
		used[deviceID] = struct{}{}
	}
	removed := 0
	for deviceID, dev := range loaded.Devices {
		if _, exists := used[deviceID]; exists {
			continue
		}
		if live {
			removePeerFromWG(wgDev, dev)
		}
		delete(loaded.Devices, deviceID)
		removed++
	}
	if removed > 0 {
		if err := saveAdminDB(configDir, loaded); err != nil {
			return adminResponse{}, err
		}
	}
	return adminResponse{OK: true, Message: fmt.Sprintf("Удалено забытых устройств: %d", removed), Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminResetTraffic(configDir string, loaded *Database) (adminResponse, error) {
	loaded.AdminDownBytes = 0
	loaded.AdminUpBytes = 0
	loaded.AdminTraffic = nil
	for _, entry := range loaded.Passwords {
		if entry == nil {
			continue
		}
		entry.DownBytes = 0
		entry.UpBytes = 0
		entry.Traffic = nil
	}
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Счётчики трафика сброшены", Server: buildAdminServerInfo(configDir, loaded)}, nil
}

func adminMergeClientTraffic(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("merge-client-traffic", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	operationID := fs.String("operation-id", "", "уникальный идентификатор переноса")
	downBytes := fs.Int64("down-bytes", 0, "скачано на другом сервере")
	upBytes := fs.Int64("up-bytes", 0, "отдано на другом сервере")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	key := strings.TrimSpace(*operationID)
	if key == "" || len(key) > 160 {
		return adminResponse{}, errors.New("operation-id должен содержать 1..160 символов")
	}
	if *downBytes < 0 || *upBytes < 0 {
		return adminResponse{}, errors.New("счётчики трафика не могут быть отрицательными")
	}
	entry, err := requireAdminPassword(loaded, strings.TrimSpace(*password))
	if err != nil {
		return adminResponse{}, err
	}
	if entry.TrafficImports == nil {
		entry.TrafficImports = make(map[string]TrafficImport)
	}
	if previous, exists := entry.TrafficImports[key]; exists {
		if previous.DownBytes != *downBytes || previous.UpBytes != *upBytes {
			return adminResponse{}, errors.New("этот operation-id уже применён с другими значениями")
		}
		return adminResponse{
			OK:      true,
			Message: "Трафик уже был учтён",
			Server:  buildAdminServerInfo(configDir, loaded),
			Password: ptrAdminPasswordInfo(
				buildAdminPasswordInfo(loaded, strings.TrimSpace(*password), entry),
			),
		}, nil
	}
	entry.DownBytes += *downBytes
	entry.UpBytes += *upBytes
	entry.Traffic = addTrafficBucket(
		entry.Traffic,
		trafficDayKey(time.Now()),
		*downBytes,
		*upBytes,
	)
	entry.TrafficImports[key] = TrafficImport{
		DownBytes: *downBytes,
		UpBytes:   *upBytes,
		AppliedAt: time.Now().Unix(),
	}
	if err := saveAdminDB(configDir, loaded); err != nil {
		return adminResponse{}, err
	}
	return adminResponse{
		OK:      true,
		Message: "Трафик клиента учтён",
		Server:  buildAdminServerInfo(configDir, loaded),
		Password: ptrAdminPasswordInfo(
			buildAdminPasswordInfo(loaded, strings.TrimSpace(*password), entry),
		),
	}, nil
}

func adminPasswordArg(command string, args []string) (string, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	password := fs.String("password", "", "пароль клиента")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	value := strings.TrimSpace(*password)
	if value == "" {
		return "", errors.New("укажите --password")
	}
	return value, nil
}

func requireAdminPassword(loaded *Database, password string) (*PasswordEntry, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, errors.New("укажите --password")
	}
	entry, exists := loaded.Passwords[password]
	if !exists || entry == nil {
		return nil, newAdminCommandError("not_found", "пароль не найден")
	}
	return entry, nil
}

func cleanupExpiredPasswordsAdmin(loaded *Database) int {
	return cleanupExpiredPasswordsAdminAt(loaded, time.Now().Unix())
}

func cleanupExpiredPasswordsAdminAt(loaded *Database, nowUnix int64) int {
	removed := 0
	deviceCandidates := make(map[string]struct{})
	for password, entry := range loaded.Passwords {
		if isPasswordPurgeableAt(entry, nowUnix) {
			if entry != nil && entry.DeviceID != "" {
				markActiveBindUnbound(entry, entry.DeviceID, nowUnix)
				deviceCandidates[entry.DeviceID] = struct{}{}
			}
			delete(loaded.Passwords, password)
			removed++
		}
	}
	adminDevices := adminDeviceIDSet(loaded)
	for deviceID := range deviceCandidates {
		if _, isAdminDevice := adminDevices[deviceID]; isAdminDevice || databaseUsesDeviceID(loaded, deviceID) {
			continue
		}
		delete(loaded.Devices, deviceID)
	}
	return removed
}

func unbindPasswordDeviceAdmin(loaded *Database, entry *PasswordEntry) {
	unbindPasswordDeviceAdminAt(loaded, entry, time.Now().Unix())
}

func unbindPasswordDeviceAdminAt(loaded *Database, entry *PasswordEntry, ts int64) {
	if entry == nil || entry.DeviceID == "" {
		return
	}
	oldDeviceID := entry.DeviceID
	markActiveBindUnbound(entry, oldDeviceID, ts)
	entry.DeviceID = ""
	if _, isAdminDevice := adminDeviceIDSet(loaded)[oldDeviceID]; !isAdminDevice && !databaseUsesDeviceID(loaded, oldDeviceID) {
		delete(loaded.Devices, oldDeviceID)
	}
}

func ptrAdminPasswordInfo(value adminPasswordInfo) *adminPasswordInfo {
	return &value
}

func writeAdminJSON(response adminResponse) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(response)
}

func writeAdminError(err error) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(adminErrorResponse(err))
}

func adminAtoi(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	return strconv.Atoi(value)
}
