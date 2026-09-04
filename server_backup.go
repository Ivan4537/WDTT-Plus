package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	serverBackupFormat          = "wdtt-server-snapshot"
	serverBackupFormatVersion   = 3
	serverBackupLegacyVersion   = 1
	serverBackupPolicyVersion   = 3
	serverBackupPolicyFile      = "backup-policy.json"
	serverBackupStateFile       = "state.json"
	serverBackupSnapshotDir     = "snapshots"
	serverBackupMaxDocumentSize = 96 << 20
	serverBackupMaxFileSize     = 64 << 20
	serverBackupMaxTotalSize    = 80 << 20
	serverBackupDefaultInterval = 24
	serverBackupDefaultKeep     = 14
	serverBackupRetryDelay      = 15 * time.Minute
)

var (
	serverBackupIDPattern      = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$`)
	serverBackupVersionPattern = regexp.MustCompile(`^[0-9A-Za-z._-]{1,32}$`)
	serverBackupMu             sync.Mutex
)

type serverBackupPolicy struct {
	Enabled        bool  `json:"enabled"`
	IntervalHours  int   `json:"interval_hours"`
	RetentionCount int   `json:"retention_count"`
	UpdatedAt      int64 `json:"updated_at,omitempty"`
}

type serverBackupRuntimeState struct {
	LastAttemptAt int64  `json:"last_attempt_at,omitempty"`
	LastSuccessAt int64  `json:"last_success_at,omitempty"`
	LastBackupID  string `json:"last_backup_id,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

type serverBackupFile struct {
	Path       string `json:"path"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"data_b64"`
}

type serverBackupDocument struct {
	Format        string             `json:"format"`
	Version       int                `json:"version"`
	ID            string             `json:"id"`
	CreatedAt     int64              `json:"created_at"`
	Reason        string             `json:"reason"`
	ServerVersion string             `json:"server_version"`
	PasswordCount int                `json:"password_count"`
	DeviceCount   int                `json:"device_count"`
	Files         []serverBackupFile `json:"files"`
}

type serverBackupSummary struct {
	ID                  string `json:"id"`
	CreatedAt           int64  `json:"created_at"`
	Reason              string `json:"reason"`
	ServerVersion       string `json:"server_version"`
	PasswordCount       int    `json:"password_count"`
	DeviceCount         int    `json:"device_count"`
	SizeBytes           int64  `json:"size_bytes"`
	SHA256              string `json:"sha256,omitempty"`
	Valid               bool   `json:"valid"`
	Error               string `json:"error,omitempty"`
	ContentMetadata     bool   `json:"content_metadata,omitempty"`
	HasWireGuardKeys    bool   `json:"has_wireguard_keys,omitempty"`
	HasBackupPolicy     bool   `json:"has_backup_policy,omitempty"`
	OutboundProfileMode string `json:"outbound_profile_mode,omitempty"`
}

type serverBackupStatus struct {
	Policy      serverBackupPolicy       `json:"policy"`
	State       serverBackupRuntimeState `json:"state"`
	NextRunAt   int64                    `json:"next_run_at,omitempty"`
	BackupRoot  string                   `json:"backup_root"`
	TotalBytes  int64                    `json:"total_bytes"`
	ValidCount  int                      `json:"valid_count"`
	BrokenCount int                      `json:"broken_count"`
	Backups     []serverBackupSummary    `json:"backups"`
}

func defaultServerBackupPolicy() serverBackupPolicy {
	return serverBackupPolicy{
		IntervalHours:  serverBackupDefaultInterval,
		RetentionCount: serverBackupDefaultKeep,
	}
}

func normalizeServerBackupPolicy(policy serverBackupPolicy) (serverBackupPolicy, error) {
	if policy.IntervalHours == 0 {
		policy.IntervalHours = serverBackupDefaultInterval
	}
	if policy.RetentionCount == 0 {
		policy.RetentionCount = serverBackupDefaultKeep
	}
	if policy.IntervalHours < 6 || policy.IntervalHours > 168 {
		return serverBackupPolicy{}, errors.New("интервал резервного копирования должен быть от 6 до 168 часов")
	}
	if policy.RetentionCount < 2 || policy.RetentionCount > 90 {
		return serverBackupPolicy{}, errors.New("число хранимых резервных копий должно быть от 2 до 90")
	}
	return policy, nil
}

func serverBackupRoot(configDir string) string {
	clean := filepath.Clean(configDir)
	if clean == "/etc/wdtt" {
		return "/var/lib/wdtt-server-installer/backups/user"
	}
	return filepath.Join(filepath.Dir(clean), "wdtt-backups")
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("небезопасный каталог резервных копий: %s", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink < 2 {
		return fmt.Errorf("повреждён каталог резервных копий: %s", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("небезопасный владелец каталога резервных копий: %s", path)
	}
	return os.Chmod(path, 0700)
}

func ensureServerBackupLayout(configDir string) (string, string, error) {
	root := serverBackupRoot(configDir)
	snapshots := filepath.Join(root, serverBackupSnapshotDir)
	if filepath.Clean(configDir) == "/etc/wdtt" {
		if err := ensurePrivateDirectory(filepath.Dir(root)); err != nil {
			return "", "", err
		}
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return "", "", err
	}
	if err := ensurePrivateDirectory(snapshots); err != nil {
		return "", "", err
	}
	return root, snapshots, nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, os.FileMode, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, 0, fmt.Errorf("объект должен быть обычным файлом: %s", path)
	}
	if stat, ok := before.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return nil, 0, fmt.Errorf("жёсткие ссылки запрещены для резервируемого файла: %s", path)
	}
	if stat, ok := before.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) {
		return nil, 0, fmt.Errorf("небезопасный владелец резервируемого файла: %s", path)
	}
	if before.Size() <= 0 || before.Size() > limit {
		return nil, 0, fmt.Errorf("недопустимый размер резервируемого файла %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, 0, fmt.Errorf("файл был подменён во время подготовки копии: %s", path)
	}
	if stat, ok := after.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return nil, 0, fmt.Errorf("жёсткие ссылки запрещены для резервируемого файла: %s", path)
	}
	if stat, ok := after.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) {
		return nil, 0, fmt.Errorf("небезопасный владелец резервируемого файла: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) != after.Size() || int64(len(data)) > limit {
		return nil, 0, fmt.Errorf("файл изменился во время подготовки копии: %s", path)
	}
	final, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !os.SameFile(after, final) || final.Size() != after.Size() || !final.ModTime().Equal(after.ModTime()) {
		return nil, 0, fmt.Errorf("файл изменился во время подготовки копии: %s", path)
	}
	return data, after.Mode().Perm(), nil
}

func validateBackupWGKeys(data []byte) error {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 {
		return errors.New("wg-keys.dat должен содержать ровно четыре ключа")
	}
	for _, line := range lines {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil || len(decoded) != 32 {
			return errors.New("wg-keys.dat содержит некорректный ключ")
		}
	}
	return nil
}

func validateBackupOutboundProfile(data []byte) error {
	if !utf8.Valid(data) || strings.ContainsRune(string(data), '\x00') {
		return errors.New("outbound-profile.env содержит недопустимые данные")
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok || len(key) == 0 || len(key) > 64 {
			return errors.New("outbound-profile.env содержит некорректную строку")
		}
		for index, char := range key {
			valid := char >= 'A' && char <= 'Z'
			if index > 0 {
				valid = valid || (char >= '0' && char <= '9') || char == '_'
			}
			if !valid {
				return errors.New("outbound-profile.env содержит недопустимое имя поля")
			}
		}
	}
	return nil
}

func summarizedBackupOutboundMode(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "WDTT_OUTBOUND_MODE" {
			continue
		}
		switch value {
		case "direct", "external_proxy", "tun_interface", "warp_free", "imported_wg", "wireguard_vps":
			return value
		default:
			return "configured"
		}
	}
	return "configured"
}

func backupFileFromBytes(name string, mode os.FileMode, data []byte) serverBackupFile {
	digest := sha256.Sum256(data)
	return serverBackupFile{
		Path:       name,
		Mode:       uint32(mode.Perm()),
		Size:       int64(len(data)),
		SHA256:     hex.EncodeToString(digest[:]),
		DataBase64: base64.StdEncoding.EncodeToString(data),
	}
}

func captureServerBackupFiles(configDir string, loaded *Database) ([]serverBackupFile, int, int, error) {
	if loaded == nil {
		return nil, 0, 0, errors.New("база WDTT не загружена")
	}
	if err := persistDatabaseFile(filepath.Join(configDir, "passwords.json"), loaded); err != nil {
		return nil, 0, 0, fmt.Errorf("не удалось зафиксировать базу перед резервным копированием: %w", err)
	}

	files := make([]serverBackupFile, 0, 4)
	var total int64
	for _, item := range []struct {
		name     string
		required bool
		limit    int64
	}{
		{name: "passwords.json", required: true, limit: maxDatabaseFileBytes},
		{name: "wg-keys.dat", required: true, limit: 4096},
		{name: "outbound-profile.env", required: false, limit: 2 << 20},
	} {
		path := filepath.Join(configDir, item.name)
		data, mode, err := readBoundedRegularFile(path, item.limit)
		if err != nil {
			if os.IsNotExist(err) && !item.required {
				continue
			}
			return nil, 0, 0, err
		}
		if mode.Perm() != 0600 {
			return nil, 0, 0, fmt.Errorf("резервируемый файл должен иметь права 600: %s", path)
		}
		if item.name == "passwords.json" {
			if _, err := decodeDatabase(data); err != nil {
				return nil, 0, 0, fmt.Errorf("база не прошла проверку перед резервным копированием: %w", err)
			}
		}
		if item.name == "wg-keys.dat" {
			if err := validateBackupWGKeys(data); err != nil {
				return nil, 0, 0, err
			}
		}
		if item.name == "outbound-profile.env" {
			if err := validateBackupOutboundProfile(data); err != nil {
				return nil, 0, 0, err
			}
		}
		total += int64(len(data))
		if total > serverBackupMaxTotalSize {
			return nil, 0, 0, errors.New("общий размер важных данных превышает допустимый предел")
		}
		files = append(files, backupFileFromBytes(item.name, 0600, data))
	}
	policy, err := loadServerBackupPolicy(configDir)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("не удалось прочитать настройки резервного копирования: %w", err)
	}
	policyData, err := json.Marshal(policy)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("не удалось подготовить настройки резервного копирования: %w", err)
	}
	total += int64(len(policyData))
	if total > serverBackupMaxTotalSize {
		return nil, 0, 0, errors.New("общий размер важных данных превышает допустимый предел")
	}
	files = append(files, backupFileFromBytes(serverBackupPolicyFile, 0600, policyData))
	return files, len(loaded.Passwords), len(clientDeviceIDSet(loaded)), nil
}

func newServerBackupID(now time.Time) (string, error) {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func validateServerBackupDocument(document *serverBackupDocument) error {
	if document == nil || document.Format != serverBackupFormat ||
		document.Version < serverBackupLegacyVersion || document.Version > serverBackupFormatVersion {
		return errors.New("неподдерживаемый формат резервной копии")
	}
	if !serverBackupIDPattern.MatchString(document.ID) {
		return errors.New("некорректный идентификатор резервной копии")
	}
	if document.CreatedAt <= 0 || document.CreatedAt > time.Now().Add(5*time.Minute).Unix() {
		return errors.New("некорректное время резервной копии")
	}
	if !serverBackupVersionPattern.MatchString(document.ServerVersion) {
		return errors.New("некорректная версия сервера в резервной копии")
	}
	switch document.Reason {
	case "manual", "scheduled", "enabled", "pre_deploy", "pre_restore":
	default:
		return errors.New("некорректная причина создания резервной копии")
	}
	if document.PasswordCount < 0 || document.PasswordCount > 500 || document.DeviceCount < 0 || document.DeviceCount > 2048 {
		return errors.New("некорректные счётчики резервной копии")
	}
	allowed := map[string]int64{
		"passwords.json":       maxDatabaseFileBytes,
		"wg-keys.dat":          4096,
		"outbound-profile.env": 2 << 20,
		serverBackupPolicyFile: 64 << 10,
	}
	seen := make(map[string]bool)
	var total int64
	for _, file := range document.Files {
		limit, ok := allowed[file.Path]
		if !ok || seen[file.Path] {
			return fmt.Errorf("недопустимый файл в резервной копии: %s", file.Path)
		}
		seen[file.Path] = true
		if file.Mode != 0600 || file.Size <= 0 || file.Size > limit {
			return fmt.Errorf("некорректные атрибуты файла %s", file.Path)
		}
		if len(file.DataBase64) > int(limit*4/3+8) {
			return fmt.Errorf("закодированный файл слишком большой: %s", file.Path)
		}
		data, err := base64.StdEncoding.DecodeString(file.DataBase64)
		if err != nil || int64(len(data)) != file.Size {
			return fmt.Errorf("некорректные данные файла %s", file.Path)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != strings.ToLower(file.SHA256) {
			return fmt.Errorf("контрольная сумма файла %s не совпала", file.Path)
		}
		if file.Path == "passwords.json" {
			loaded, err := decodeDatabase(data)
			if err != nil {
				return fmt.Errorf("база в резервной копии повреждена: %w", err)
			}
			expectedDeviceCount := len(clientDeviceIDSet(loaded))
			if document.Version == serverBackupLegacyVersion {
				expectedDeviceCount = len(loaded.Devices)
			}
			if len(loaded.Passwords) != document.PasswordCount || expectedDeviceCount != document.DeviceCount {
				return errors.New("счётчики базы в резервной копии не совпали")
			}
		}
		if file.Path == "wg-keys.dat" {
			if err := validateBackupWGKeys(data); err != nil {
				return err
			}
		}
		if file.Path == "outbound-profile.env" {
			if err := validateBackupOutboundProfile(data); err != nil {
				return err
			}
		}
		if file.Path == serverBackupPolicyFile {
			var policy serverBackupPolicy
			if err := decodeSingleJSONDocument(data, &policy); err != nil {
				return fmt.Errorf("настройки резервного копирования повреждены: %w", err)
			}
			if _, err := normalizeServerBackupPolicy(policy); err != nil {
				return fmt.Errorf("настройки резервного копирования некорректны: %w", err)
			}
		}
		total += file.Size
		if total > serverBackupMaxTotalSize {
			return errors.New("резервная копия превышает допустимый размер")
		}
	}
	if !seen["passwords.json"] || !seen["wg-keys.dat"] {
		return errors.New("в резервной копии отсутствует база или WireGuard-ключи")
	}
	if document.Version >= serverBackupPolicyVersion && !seen[serverBackupPolicyFile] {
		return errors.New("в резервной копии отсутствуют настройки резервного копирования")
	}
	return nil
}

func readServerBackupDocument(path string) (*serverBackupDocument, []byte, error) {
	data, _, err := readBoundedRegularFile(path, serverBackupMaxDocumentSize)
	if err != nil {
		return nil, nil, err
	}
	var document serverBackupDocument
	if err := decodeSingleJSONDocument(data, &document); err != nil {
		return nil, nil, fmt.Errorf("некорректный документ резервной копии: %w", err)
	}
	if err := validateServerBackupDocument(&document); err != nil {
		return nil, nil, err
	}
	return &document, data, nil
}

func backupSummaryFromDocument(document *serverBackupDocument, raw []byte) serverBackupSummary {
	digest := sha256.Sum256(raw)
	deviceCount := document.DeviceCount
	hasWireGuardKeys := false
	hasBackupPolicy := false
	outboundProfileMode := ""
	for _, file := range document.Files {
		switch file.Path {
		case "passwords.json":
			if document.Version != serverBackupLegacyVersion {
				continue
			}
			data, err := base64.StdEncoding.DecodeString(file.DataBase64)
			if err != nil {
				continue
			}
			loaded, err := decodeDatabase(data)
			if err == nil {
				deviceCount = len(clientDeviceIDSet(loaded))
			}
		case "wg-keys.dat":
			hasWireGuardKeys = true
		case serverBackupPolicyFile:
			hasBackupPolicy = true
		case "outbound-profile.env":
			data, err := base64.StdEncoding.DecodeString(file.DataBase64)
			if err == nil {
				outboundProfileMode = summarizedBackupOutboundMode(data)
			}
		}
	}
	return serverBackupSummary{
		ID:                  document.ID,
		CreatedAt:           document.CreatedAt,
		Reason:              document.Reason,
		ServerVersion:       document.ServerVersion,
		PasswordCount:       document.PasswordCount,
		DeviceCount:         deviceCount,
		SizeBytes:           int64(len(raw)),
		SHA256:              hex.EncodeToString(digest[:]),
		Valid:               true,
		ContentMetadata:     true,
		HasWireGuardKeys:    hasWireGuardKeys,
		HasBackupPolicy:     hasBackupPolicy,
		OutboundProfileMode: outboundProfileMode,
	}
}

func listServerBackups(configDir string) ([]serverBackupSummary, error) {
	_, snapshots, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(snapshots)
	if err != nil {
		return nil, err
	}
	result := make([]serverBackupSummary, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".wdtt-snapshot") {
			continue
		}
		path := filepath.Join(snapshots, name)
		var size int64
		if info, statErr := os.Lstat(path); statErr == nil && info.Size() > 0 {
			size = info.Size()
		}
		id := strings.TrimSuffix(name, ".wdtt-snapshot")
		if !serverBackupIDPattern.MatchString(id) {
			result = append(result, serverBackupSummary{ID: name, SizeBytes: size, Valid: false, Error: "некорректное имя файла"})
			continue
		}
		document, raw, err := readServerBackupDocument(path)
		if err != nil {
			result = append(result, serverBackupSummary{ID: id, SizeBytes: size, Valid: false, Error: boundedBackupError(err)})
			continue
		}
		if document.ID != id {
			result = append(result, serverBackupSummary{ID: id, SizeBytes: size, Valid: false, Error: "ID внутри файла не совпадает с именем"})
			continue
		}
		result = append(result, backupSummaryFromDocument(document, raw))
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].CreatedAt == result[j].CreatedAt {
			return result[i].ID > result[j].ID
		}
		return result[i].CreatedAt > result[j].CreatedAt
	})
	return result, nil
}

func boundedBackupError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Join(strings.Fields(err.Error()), " ")
	if len([]rune(value)) > 200 {
		value = string([]rune(value)[:200])
	}
	return value
}

func loadServerBackupPolicy(configDir string) (serverBackupPolicy, error) {
	path := filepath.Join(configDir, serverBackupPolicyFile)
	data, _, err := readBoundedRegularFile(path, 64<<10)
	if os.IsNotExist(err) {
		return defaultServerBackupPolicy(), nil
	}
	if err != nil {
		return serverBackupPolicy{}, err
	}
	var policy serverBackupPolicy
	if err := decodeSingleJSONDocument(data, &policy); err != nil {
		return serverBackupPolicy{}, fmt.Errorf("повреждена политика резервного копирования: %w", err)
	}
	return normalizeServerBackupPolicy(policy)
}

func saveServerBackupPolicy(configDir string, policy serverBackupPolicy) error {
	normalized, err := normalizeServerBackupPolicy(policy)
	if err != nil {
		return err
	}
	if err := ensurePrivateDatabaseDirectory(configDir); err != nil {
		return err
	}
	normalized.UpdatedAt = time.Now().Unix()
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	return writeSyncedFileAtomically(filepath.Join(configDir, serverBackupPolicyFile), data, 0600)
}

func loadServerBackupState(configDir string) (serverBackupRuntimeState, error) {
	root, _, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return serverBackupRuntimeState{}, err
	}
	data, _, err := readBoundedRegularFile(filepath.Join(root, serverBackupStateFile), 64<<10)
	if os.IsNotExist(err) {
		return serverBackupRuntimeState{}, nil
	}
	if err != nil {
		return serverBackupRuntimeState{}, err
	}
	var state serverBackupRuntimeState
	if err := decodeSingleJSONDocument(data, &state); err != nil {
		return serverBackupRuntimeState{}, err
	}
	state.LastError = boundedBackupError(errors.New(state.LastError))
	return state, nil
}

func saveServerBackupState(configDir string, state serverBackupRuntimeState) error {
	root, _, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return err
	}
	state.LastError = boundedBackupError(errors.New(state.LastError))
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeSyncedFileAtomically(filepath.Join(root, serverBackupStateFile), data, 0600)
}

func rotateServerBackups(configDir string, keep int, protectedID string) error {
	backups, err := listServerBackups(configDir)
	if err != nil {
		return err
	}
	valid := make([]serverBackupSummary, 0, len(backups))
	for _, backup := range backups {
		if backup.Valid {
			valid = append(valid, backup)
		}
	}
	if len(valid) <= keep {
		return nil
	}
	_, snapshots, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return err
	}
	remaining := len(valid)
	for index := len(valid) - 1; index >= 0 && remaining > keep && remaining > 1; index-- {
		backup := valid[index]
		if backup.ID == protectedID {
			continue
		}
		path := filepath.Join(snapshots, backup.ID+".wdtt-snapshot")
		if err := os.Remove(path); err != nil {
			return err
		}
		remaining--
	}
	if remaining > keep {
		return errors.New("не удалось выполнить ротацию без удаления только что созданной копии")
	}
	return syncDirectory(snapshots)
}

func createServerBackup(configDir string, loaded *Database, reason string) (summary serverBackupSummary, resultErr error) {
	serverBackupMu.Lock()
	defer serverBackupMu.Unlock()
	now := time.Now()
	state, stateErr := loadServerBackupState(configDir)
	if stateErr != nil {
		return serverBackupSummary{}, fmt.Errorf("состояние резервного копирования повреждено: %w", stateErr)
	}
	state.LastAttemptAt = now.Unix()
	state.LastError = ""
	defer func() {
		if resultErr == nil {
			return
		}
		state.LastError = boundedBackupError(resultErr)
		_ = saveServerBackupState(configDir, state)
	}()
	if reason == "" {
		reason = "manual"
	}
	files, passwordCount, deviceCount, err := captureServerBackupFiles(configDir, loaded)
	if err != nil {
		return serverBackupSummary{}, err
	}
	id, err := newServerBackupID(now)
	if err != nil {
		return serverBackupSummary{}, err
	}
	document := serverBackupDocument{
		Format:        serverBackupFormat,
		Version:       serverBackupFormatVersion,
		ID:            id,
		CreatedAt:     now.Unix(),
		Reason:        reason,
		ServerVersion: wdttServerVersion,
		PasswordCount: passwordCount,
		DeviceCount:   deviceCount,
		Files:         files,
	}
	if err := validateServerBackupDocument(&document); err != nil {
		return serverBackupSummary{}, err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return serverBackupSummary{}, err
	}
	if len(raw) > serverBackupMaxDocumentSize {
		return serverBackupSummary{}, errors.New("документ резервной копии превышает допустимый размер")
	}
	_, snapshots, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return serverBackupSummary{}, err
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs(snapshots, &disk); err != nil {
		return serverBackupSummary{}, fmt.Errorf("не удалось проверить свободное место: %w", err)
	}
	available := int64(disk.Bavail) * int64(disk.Bsize)
	if available < int64(len(raw))+(64<<20) {
		return serverBackupSummary{}, errors.New("недостаточно свободного места для безопасной резервной копии")
	}
	path := filepath.Join(snapshots, id+".wdtt-snapshot")
	if err := writeSyncedFileAtomically(path, raw, 0600); err != nil {
		return serverBackupSummary{}, fmt.Errorf("не удалось атомарно сохранить резервную копию: %w", err)
	}
	verified, verifiedRaw, err := readServerBackupDocument(path)
	if err != nil {
		_ = os.Remove(path)
		return serverBackupSummary{}, fmt.Errorf("записанная резервная копия не прошла проверку: %w", err)
	}
	if verified.ID != id {
		_ = os.Remove(path)
		return serverBackupSummary{}, errors.New("записанная резервная копия получила неожиданный идентификатор")
	}
	policy, err := loadServerBackupPolicy(configDir)
	if err != nil {
		return serverBackupSummary{}, err
	}
	rotationErr := rotateServerBackups(configDir, policy.RetentionCount, id)
	state.LastSuccessAt = now.Unix()
	state.LastBackupID = id
	state.LastError = boundedBackupError(rotationErr)
	if err := saveServerBackupState(configDir, state); err != nil {
		return serverBackupSummary{}, fmt.Errorf("копия создана, но состояние не сохранено: %w", err)
	}
	return backupSummaryFromDocument(verified, verifiedRaw), nil
}

func nextServerBackupRunAt(policy serverBackupPolicy, state serverBackupRuntimeState, now int64) int64 {
	intervalSeconds := int64(policy.IntervalHours) * int64(time.Hour/time.Second)
	next := now
	if state.LastSuccessAt > 0 {
		next = state.LastSuccessAt + intervalSeconds
	}
	if state.LastError != "" && state.LastAttemptAt > state.LastSuccessAt && next <= now {
		retry := state.LastAttemptAt + int64(serverBackupRetryDelay/time.Second)
		if retry > next {
			next = retry
		}
	}
	return next
}

func serverBackupStatusFor(configDir string) (*serverBackupStatus, error) {
	policy, err := loadServerBackupPolicy(configDir)
	if err != nil {
		return nil, err
	}
	state, err := loadServerBackupState(configDir)
	if err != nil {
		return nil, err
	}
	backups, err := listServerBackups(configDir)
	if err != nil {
		return nil, err
	}
	status := &serverBackupStatus{
		Policy:     policy,
		State:      state,
		BackupRoot: serverBackupRoot(configDir),
		Backups:    backups,
	}
	for _, backup := range backups {
		status.TotalBytes += backup.SizeBytes
		if backup.Valid {
			status.ValidCount++
		} else {
			status.BrokenCount++
		}
	}
	if policy.Enabled {
		status.NextRunAt = nextServerBackupRunAt(policy, state, time.Now().Unix())
	}
	return status, nil
}

func readServerBackupByID(configDir, id string) (*serverBackupDocument, error) {
	if !serverBackupIDPattern.MatchString(id) {
		return nil, errors.New("некорректный идентификатор резервной копии")
	}
	_, snapshots, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return nil, err
	}
	document, _, err := readServerBackupDocument(filepath.Join(snapshots, id+".wdtt-snapshot"))
	if err != nil {
		return nil, err
	}
	if document.ID != id {
		return nil, errors.New("идентификатор резервной копии не совпал")
	}
	return document, nil
}

func deleteServerBackup(configDir, id string) error {
	serverBackupMu.Lock()
	defer serverBackupMu.Unlock()
	backups, err := listServerBackups(configDir)
	if err != nil {
		return err
	}
	valid := 0
	targetValid := false
	found := false
	for _, backup := range backups {
		if backup.Valid {
			valid++
		}
		if backup.ID == id {
			found = true
			targetValid = backup.Valid
		}
	}
	if !found {
		return errors.New("резервная копия не найдена")
	}
	if targetValid && valid <= 1 {
		return errors.New("нельзя удалить последнюю исправную резервную копию")
	}
	if !serverBackupIDPattern.MatchString(id) {
		return errors.New("небезопасный идентификатор резервной копии")
	}
	_, snapshots, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(snapshots, id+".wdtt-snapshot")); err != nil {
		return err
	}
	return syncDirectory(snapshots)
}

func adminBackupConfigure(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("backup-configure", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	enabledRaw := fs.String("enabled", "", "включить автоматические копии")
	interval := fs.Int("interval-hours", serverBackupDefaultInterval, "интервал в часах")
	retention := fs.Int("retention", serverBackupDefaultKeep, "число копий")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	if *enabledRaw != "true" && *enabledRaw != "false" {
		return adminResponse{}, errors.New("enabled должен быть true или false")
	}
	enabled, _ := strconv.ParseBool(*enabledRaw)
	policy, err := normalizeServerBackupPolicy(serverBackupPolicy{
		Enabled:        enabled,
		IntervalHours:  *interval,
		RetentionCount: *retention,
	})
	if err != nil {
		return adminResponse{}, err
	}
	previousPolicy, err := loadServerBackupPolicy(configDir)
	if err != nil {
		return adminResponse{}, err
	}
	if err := saveServerBackupPolicy(configDir, policy); err != nil {
		return adminResponse{}, err
	}
	status, err := serverBackupStatusFor(configDir)
	if err != nil {
		return adminResponse{}, err
	}
	if enabled && status.ValidCount == 0 {
		if _, err := createServerBackup(configDir, loaded, "enabled"); err != nil {
			if rollbackErr := saveServerBackupPolicy(configDir, previousPolicy); rollbackErr != nil {
				return adminResponse{}, fmt.Errorf("первая копия не создана: %v; прежняя политика также не восстановлена: %w", err, rollbackErr)
			}
			return adminResponse{}, fmt.Errorf("автоматическое копирование не включено, потому что первая копия не создана: %w", err)
		}
		status, err = serverBackupStatusFor(configDir)
		if err != nil {
			return adminResponse{}, err
		}
	}
	return adminResponse{OK: true, Message: "Настройки резервного копирования сохранены", BackupStatus: status}, nil
}

func adminBackupCreate(configDir string, loaded *Database, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("backup-create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "manual", "причина создания копии")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	if *reason != "manual" && *reason != "pre_deploy" && *reason != "pre_restore" {
		return adminResponse{}, errors.New("недопустимая причина резервного копирования")
	}
	created, err := createServerBackup(configDir, loaded, *reason)
	if err != nil {
		return adminResponse{}, err
	}
	status, err := serverBackupStatusFor(configDir)
	if err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Резервная копия создана и проверена", Backup: &created, BackupStatus: status}, nil
}

func adminBackupExport(configDir string, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("backup-export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "идентификатор копии")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	document, err := readServerBackupByID(configDir, strings.TrimSpace(*id))
	if err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Резервная копия проверена и подготовлена", BackupDocument: document}, nil
}

func adminBackupVerify(configDir string, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("backup-verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "идентификатор копии")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	document, err := readServerBackupByID(configDir, strings.TrimSpace(*id))
	if err != nil {
		return adminResponse{}, err
	}
	_, snapshots, err := ensureServerBackupLayout(configDir)
	if err != nil {
		return adminResponse{}, err
	}
	_, raw, err := readServerBackupDocument(filepath.Join(snapshots, document.ID+".wdtt-snapshot"))
	if err != nil {
		return adminResponse{}, err
	}
	summary := backupSummaryFromDocument(document, raw)
	return adminResponse{OK: true, Message: "Резервная копия исправна", Backup: &summary}, nil
}

func adminBackupDelete(configDir string, args []string) (adminResponse, error) {
	fs := flag.NewFlagSet("backup-delete", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id := fs.String("id", "", "идентификатор копии")
	confirm := fs.String("confirm", "", "подтверждение")
	if err := fs.Parse(args); err != nil {
		return adminResponse{}, err
	}
	if *confirm != "УДАЛИТЬ" {
		return adminResponse{}, errors.New("для удаления требуется точное подтверждение УДАЛИТЬ")
	}
	if err := deleteServerBackup(configDir, strings.TrimSpace(*id)); err != nil {
		return adminResponse{}, err
	}
	status, err := serverBackupStatusFor(configDir)
	if err != nil {
		return adminResponse{}, err
	}
	return adminResponse{OK: true, Message: "Резервная копия удалена", BackupStatus: status}, nil
}

func startServerBackupScheduler(ctx context.Context, configDir string) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				policy, err := loadServerBackupPolicy(configDir)
				if err != nil || !policy.Enabled {
					continue
				}
				state, err := loadServerBackupState(configDir)
				if err != nil {
					continue
				}
				now := time.Now().Unix()
				if now < nextServerBackupRunAt(policy, state, now) {
					continue
				}
				dbMutex.Lock()
				_, err = createServerBackup(configDir, db, "scheduled")
				dbMutex.Unlock()
				if err != nil {
					// createServerBackup records a bounded error in its state when possible.
					continue
				}
			}
		}
	}()
}
