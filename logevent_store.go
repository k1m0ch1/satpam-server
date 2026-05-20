package main

import (
	"sync"
	"time"
)

// LogEvent is a parsed log line from a monitored agent log file.
type LogEvent struct {
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	FilePath  string    `json:"file_path,omitempty"`
	Raw       string    `json:"raw"`
	Level     string    `json:"level,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Status    int       `json:"status,omitempty"`
}

const logEventMaxPerAgent = 2000

type logEventStore struct {
	mu   sync.RWMutex
	data map[string][]LogEvent // ring buffer per agent_id
}

func newLogEventStore() *logEventStore {
	return &logEventStore{data: make(map[string][]LogEvent)}
}

func (s *logEventStore) add(agentID string, events []LogEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := append(s.data[agentID], events...)
	if len(buf) > logEventMaxPerAgent {
		buf = buf[len(buf)-logEventMaxPerAgent:]
	}
	s.data[agentID] = buf
}

// query returns events for agentID, optionally filtered by source and level.
func (s *logEventStore) query(agentID, source, level string, limit int) []LogEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.data[agentID]
	var out []LogEvent
	for i := len(all) - 1; i >= 0; i-- {
		e := all[i]
		if source != "" && e.Source != source {
			continue
		}
		if level != "" && e.Level != level {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
