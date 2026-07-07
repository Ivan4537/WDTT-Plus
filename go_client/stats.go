package main

import (
	"log"
	"sync/atomic"
	"time"
)

var globalActiveConnections atomic.Int32

type Stats struct {
	ActiveConnections atomic.Int32
	TotalBytesUp      atomic.Int64
	TotalBytesDown    atomic.Int64
}

func NewStats() *Stats {
	return &Stats{}
}

func (s *Stats) RunLoop(shutdown <-chan struct{}) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			active := s.ActiveConnections.Load()
			up := s.TotalBytesUp.Load()
			down := s.TotalBytesDown.Load()
			upMB := float64(up) / (1024.0 * 1024.0)
			downMB := float64(down) / (1024.0 * 1024.0)

			log.Printf("[СТАТИСТИКА] Активных: %d | ↓%.2f МБ / ↑%.2f МБ", active, downMB, upMB)
		}
	}
}
