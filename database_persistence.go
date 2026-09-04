package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	maxDatabaseFileBytes   = 64 << 20
	databasePreviousSuffix = ".previous"
)

func loadDatabaseFile(path string) (*Database, error) {
	data, err := readRegularDatabaseFile(path)
	if err != nil {
		return nil, err
	}
	return decodeDatabase(data)
}

func readRegularDatabaseFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("база WDTT должна быть обычным файлом: %s", path)
	}
	if info.Size() <= 0 {
		return nil, fmt.Errorf("база WDTT пуста: %s", path)
	}
	if info.Size() > maxDatabaseFileBytes {
		return nil, fmt.Errorf("база WDTT превышает допустимый размер %d байт", maxDatabaseFileBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDatabaseFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxDatabaseFileBytes {
		return nil, errors.New("размер базы WDTT вышел за допустимые границы")
	}
	return data, nil
}

func decodeDatabase(data []byte) (*Database, error) {
	var fields map[string]json.RawMessage
	if err := decodeSingleJSONDocument(data, &fields); err != nil {
		return nil, fmt.Errorf("некорректный JSON базы WDTT: %w", err)
	}
	for _, required := range []string{"main_password", "passwords", "devices"} {
		if _, ok := fields[required]; !ok {
			return nil, fmt.Errorf("в базе WDTT отсутствует обязательное поле %s", required)
		}
	}

	var loaded Database
	if err := decodeSingleJSONDocument(data, &loaded); err != nil {
		return nil, fmt.Errorf("не удалось разобрать базу WDTT: %w", err)
	}
	if loaded.Passwords == nil {
		return nil, errors.New("поле passwords в базе WDTT не является объектом")
	}
	if loaded.Devices == nil {
		return nil, errors.New("поле devices в базе WDTT не является объектом")
	}
	for password, entry := range loaded.Passwords {
		if password == "" || entry == nil {
			return nil, errors.New("база WDTT содержит пустую или повреждённую запись доступа")
		}
	}
	for deviceID, device := range loaded.Devices {
		if deviceID == "" || device == nil {
			return nil, errors.New("база WDTT содержит пустую или повреждённую запись устройства")
		}
	}
	return &loaded, nil
}

func decodeSingleJSONDocument(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("после JSON-документа найдены дополнительные данные")
		}
		return err
	}
	return nil
}

func persistDatabaseFile(path string, value *Database) error {
	if value == nil {
		return errors.New("нельзя сохранить пустую базу WDTT")
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("не удалось подготовить базу WDTT: %w", err)
	}
	if _, err := decodeDatabase(data); err != nil {
		return fmt.Errorf("отказ от сохранения некорректной базы WDTT: %w", err)
	}

	dir := filepath.Dir(path)
	if err := ensurePrivateDatabaseDirectory(dir); err != nil {
		return err
	}

	var previous []byte
	if _, err := os.Lstat(path); err == nil {
		previous, err = readRegularDatabaseFile(path)
		if err != nil {
			return fmt.Errorf("текущая база WDTT небезопасна, перезапись запрещена: %w", err)
		}
		if _, err := decodeDatabase(previous); err != nil {
			return fmt.Errorf("текущая база WDTT повреждена, перезапись запрещена: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if len(previous) > 0 && bytes.Equal(bytes.TrimSpace(previous), bytes.TrimSpace(data)) {
		return os.Chmod(path, 0600)
	}
	if len(previous) > 0 {
		if err := writeSyncedFileAtomically(path+databasePreviousSuffix, previous, 0600); err != nil {
			return fmt.Errorf("не удалось сохранить предыдущую копию базы WDTT: %w", err)
		}
	}
	if err := writeSyncedFileAtomically(path, data, 0600); err != nil {
		return fmt.Errorf("не удалось атомарно сохранить базу WDTT: %w", err)
	}
	return syncDirectory(dir)
}

func ensurePrivateDatabaseDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("каталог базы WDTT небезопасен: %s", dir)
	}
	return os.Chmod(dir, 0700)
}

func writeSyncedFileAtomically(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wdtt-db-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
