package main

import (
	"sync"
	"time"
)

const agentOfflineAfter = 10 * time.Minute

// Agent represents a known agent and its liveness state.
type Agent struct {
	AgentID  string    `json:"agent_id"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	LastSeen time.Time `json:"last_seen"`
	Online   bool      `json:"online"`
}

type agentStore struct {
	mu   sync.RWMutex
	data map[string]*Agent
}

func newAgentStore() *agentStore {
	return &agentStore{data: make(map[string]*Agent)}
}

func (s *agentStore) heartbeat(id, os, arch string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.data[id]
	if !ok {
		a = &Agent{AgentID: id}
		s.data[id] = a
	}
	a.OS = os
	a.Arch = arch
	a.LastSeen = time.Now().UTC()
}

func (s *agentStore) list() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	threshold := time.Now().Add(-agentOfflineAfter)
	out := make([]Agent, 0, len(s.data))
	for _, a := range s.data {
		copy := *a
		copy.Online = a.LastSeen.After(threshold)
		out = append(out, copy)
	}
	return out
}
