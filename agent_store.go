package main

import (
	"sync"
	"time"
)

const (
	agentOfflineAfter   = 10 * time.Minute
	maxHeartbeatHistory = 576 // 48h at 5-min interval
)

// Agent is the public representation returned by the API.
type Agent struct {
	AgentID   string    `json:"agent_id"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Hostname  string    `json:"hostname"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
}

// StatusEvent records a moment when an agent transitioned online→offline or
// was first seen. Used by the panel for a live/dead timeline.
type StatusEvent struct {
	At     time.Time `json:"at"`
	Status string    `json:"status"` // "online" | "offline"
}

// agentRecord is the internal store entry. Not exported in JSON directly.
type agentRecord struct {
	agent      Agent
	heartbeats []time.Time  // ring buffer — last maxHeartbeatHistory pings
	events     []StatusEvent // status-change log (online/offline transitions)
	wasOnline  bool          // last computed online state (for transition detection)
}

func (r *agentRecord) addHeartbeat(t time.Time) {
	if len(r.heartbeats) >= maxHeartbeatHistory {
		r.heartbeats = r.heartbeats[1:]
	}
	r.heartbeats = append(r.heartbeats, t)
}

func (r *agentRecord) addEvent(t time.Time, status string) {
	r.events = append(r.events, StatusEvent{At: t, Status: status})
	if len(r.events) > 1000 {
		r.events = r.events[1:]
	}
}

type agentStore struct {
	mu   sync.RWMutex
	data map[string]*agentRecord
}

func newAgentStore() *agentStore {
	return &agentStore{data: make(map[string]*agentRecord)}
}

// heartbeat records a ping from an agent and detects first-connect.
func (s *agentStore) heartbeat(id, agentOS, arch, hostname string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	rec, exists := s.data[id]
	if !exists {
		rec = &agentRecord{}
		rec.agent.AgentID = id
		rec.agent.FirstSeen = now
		s.data[id] = rec
		rec.addEvent(now, "online")
		rec.wasOnline = true
	}

	rec.agent.OS = agentOS
	rec.agent.Arch = arch
	if hostname != "" {
		rec.agent.Hostname = hostname
	}
	rec.agent.LastSeen = now
	rec.addHeartbeat(now)

	// Detect online restoration after a gap
	if !rec.wasOnline {
		rec.addEvent(now, "online")
		rec.wasOnline = true
	}
}

// markOffline is called by the background sweeper when an agent goes silent.
func (s *agentStore) markOffline(id string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data[id]
	if ok && rec.wasOnline {
		rec.addEvent(at, "offline")
		rec.wasOnline = false
	}
}

// list returns every agent with a computed Online field.
func (s *agentStore) list() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	threshold := time.Now().Add(-agentOfflineAfter)
	out := make([]Agent, 0, len(s.data))
	for _, rec := range s.data {
		a := rec.agent
		a.Online = a.LastSeen.After(threshold)
		out = append(out, a)
	}
	return out
}

// get returns a single agent, or nil.
func (s *agentStore) get(id string) *Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.data[id]
	if !ok {
		return nil
	}
	a := rec.agent
	a.Online = a.LastSeen.After(time.Now().Add(-agentOfflineAfter))
	return &a
}

// heartbeatHistory returns the recorded ping timestamps for one agent.
func (s *agentStore) heartbeatHistory(id string) []time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.data[id]
	if !ok {
		return nil
	}
	cp := make([]time.Time, len(rec.heartbeats))
	copy(cp, rec.heartbeats)
	return cp
}

// statusEvents returns the online/offline transition log for one agent.
func (s *agentStore) statusEvents(id string) []StatusEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.data[id]
	if !ok {
		return nil
	}
	cp := make([]StatusEvent, len(rec.events))
	copy(cp, rec.events)
	return cp
}

// ids returns all known agent IDs (used by the offline sweeper).
func (s *agentStore) ids() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.data))
	for id := range s.data {
		out = append(out, id)
	}
	return out
}

// lastSeen returns the LastSeen time for a specific agent.
func (s *agentStore) lastSeen(id string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.data[id]
	if !ok {
		return time.Time{}, false
	}
	return rec.agent.LastSeen, true
}
