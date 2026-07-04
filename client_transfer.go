package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	clientTransferFormat  = "wdtt-plus-client"
	clientTransferVersion = 1
)

type clientTransferPayload struct {
	Format      string `json:"format"`
	Version     int    `json:"version"`
	CreatedAt   int64  `json:"created_at"`
	Password    string `json:"password"`
	Label       string `json:"label,omitempty"`
	VkHash      string `json:"vk_hash,omitempty"`
	ExpiresAt   int64  `json:"expires_at"`
	Deactivated bool   `json:"deactivated"`
}

func encodeClientTransfer(password string, entry *PasswordEntry) (string, error) {
	password, err := normalizeClientPassword(password)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", errors.New("данные клиента не найдены")
	}
	payload := clientTransferPayload{
		Format:      clientTransferFormat,
		Version:     clientTransferVersion,
		CreatedAt:   time.Now().UnixMilli(),
		Password:    password,
		Label:       normalizePasswordLabel(entry.Label),
		VkHash:      strings.TrimSpace(entry.VkHash),
		ExpiresAt:   entry.ExpiresAt,
		Deactivated: entry.IsDeactivated,
	}
	if payload.VkHash != "" {
		normalized, err := normalizeTransferVKHashes(payload.VkHash)
		if err != nil {
			return "", err
		}
		payload.VkHash = normalized
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeClientTransfer(value string) (clientTransferPayload, error) {
	var payload clientTransferPayload
	if err := json.Unmarshal([]byte(strings.TrimSpace(value)), &payload); err != nil {
		return payload, errors.New("данные клиента повреждены или имеют неверный формат")
	}
	if payload.Format != clientTransferFormat {
		return payload, errors.New("это не перенос клиента WDTT Plus")
	}
	if payload.Version != clientTransferVersion {
		return payload, errors.New("версия переноса клиента не поддерживается")
	}
	password, err := normalizeClientPassword(payload.Password)
	if err != nil {
		return payload, err
	}
	payload.Password = password
	payload.Label = normalizePasswordLabel(payload.Label)
	if len(payload.VkHash) > 4096 || strings.ContainsAny(payload.VkHash, "\x00\r") {
		return payload, errors.New("поле VK-хешей повреждено")
	}
	if strings.TrimSpace(payload.VkHash) != "" {
		normalized, err := normalizeTransferVKHashes(payload.VkHash)
		if err != nil {
			return payload, err
		}
		payload.VkHash = normalized
	}
	if payload.ExpiresAt < 0 {
		return payload, errors.New("в переносе указан некорректный срок")
	}
	if payload.ExpiresAt > 0 && payload.ExpiresAt <= time.Now().Unix() {
		return payload, errors.New("срок переносимого клиента уже истёк")
	}
	return payload, nil
}

func normalizeTransferVKHashes(value string) (string, error) {
	normalized, err := normalizeVKHashesInput(value)
	if err != nil {
		return "", err
	}
	for _, hash := range strings.Split(normalized, ",") {
		if len(hash) < 16 {
			return "", errors.New("VK-хеши в переносе имеют неверный формат")
		}
	}
	return normalized, nil
}
