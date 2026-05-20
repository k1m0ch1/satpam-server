package main

import (
	"sync"
	"time"
)

// MetricsPoint is a single metrics snapshot received from an agent.
type MetricsPoint struct {
	AgentID       string    `json:"agent_id"`
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemUsed       uint64    `json:"mem_used_bytes"`
	MemTotal      uint64    `json:"mem_total_bytes"`
	MemPercent    float64   `json:"mem_percent"`
	DiskUsed      uint64    `json:"disk_used_bytes"`
	DiskTotal     uint64    `json:"disk_total_bytes"`
	DiskPercent   float64   `json:"disk_percent"`
	LoadAvg1      float64   `json:"load_avg_1m,omitempty"`
	UptimeSeconds uint64    `json:"uptime_seconds,omitempty"`
}

const metricsMaxPerAgent = 576 // 48h at 5-min intervals

type metricsStore struct {
	mu   sync.RWMutex
	data map[string][]MetricsPoint // ring buffer per agent_id
}

func newMetricsStore() *metricsStore {
	return &metricsStore{data: make(map[string][]MetricsPoint)}
}

func (s *metricsStore) add(p MetricsPoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := append(s.data[p.AgentID], p)
	if len(buf) > metricsMaxPerAgent {
		buf = buf[len(buf)-metricsMaxPerAgent:]
	}
	s.data[p.AgentID] = buf
}

// query returns points for agentID newer than since (zero = all).
func (s *metricsStore) query(agentID string, since time.Time, limit int) []MetricsPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.data[agentID]
	var out []MetricsPoint
	for i := len(all) - 1; i >= 0; i-- {
		if !since.IsZero() && all[i].Timestamp.Before(since) {
			break
		}
		out = append(out, all[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	// reverse so oldest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// latest returns the most recent point for an agent (zero-value if none).
func (s *metricsStore) latest(agentID string) (MetricsPoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	buf := s.data[agentID]
	if len(buf) == 0 {
		return MetricsPoint{}, false
	}
	return buf[len(buf)-1], true
}
