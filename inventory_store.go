package main

import (
	"strings"
	"sync"
	"time"
)

// SoftwareEntry mirrors the agent's inventory.SoftwareEntry.
type SoftwareEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`   // package | service | runtime
	Source  string `json:"source"` // dpkg | rpm | brew | pip | npm | gem | cargo | systemd | ...
	Path    string `json:"path,omitempty"`
}

// InventorySnapshot is one agent's complete tech-stack snapshot.
type InventorySnapshot struct {
	AgentID     string          `json:"agent_id"`
	OS          string          `json:"os"`
	Arch        string          `json:"arch"`
	Hostname    string          `json:"hostname"`
	CollectedAt time.Time       `json:"collected_at"`
	ReceivedAt  time.Time       `json:"received_at"`
	Software    []SoftwareEntry `json:"software"`
}

// InventorySummary is the lightweight view returned when listing all agents.
type InventorySummary struct {
	AgentID       string            `json:"agent_id"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Hostname      string            `json:"hostname"`
	CollectedAt   time.Time         `json:"collected_at"`
	ReceivedAt    time.Time         `json:"received_at"`
	TotalPackages int               `json:"total_packages"`
	TotalServices int               `json:"total_services"`
	BySource      map[string]int    `json:"by_source"`
	ByType        map[string]int    `json:"by_type"`
}

type inventoryStore struct {
	mu   sync.RWMutex
	data map[string]*InventorySnapshot // keyed by agent_id
}

func newInventoryStore() *inventoryStore {
	return &inventoryStore{data: make(map[string]*InventorySnapshot)}
}

// update stores (or replaces) the latest inventory snapshot for an agent.
func (s *inventoryStore) update(snap InventorySnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap.ReceivedAt = time.Now().UTC()
	s.data[snap.AgentID] = &snap
}

// get returns the latest snapshot for a given agent, or nil.
func (s *inventoryStore) get(agentID string) *InventorySnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := s.data[agentID]
	if snap == nil {
		return nil
	}
	cp := *snap
	return &cp
}

// list returns a summary for every known agent (no full software list).
func (s *inventoryStore) list() []InventorySummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]InventorySummary, 0, len(s.data))
	for _, snap := range s.data {
		out = append(out, summarize(snap))
	}
	return out
}

// search returns entries from one agent's snapshot filtered by name/type/source.
// Empty filter strings match everything.
func (s *inventoryStore) search(agentID, nameq, typeq, sourceq string) []SoftwareEntry {
	s.mu.RLock()
	snap := s.data[agentID]
	s.mu.RUnlock()
	if snap == nil {
		return nil
	}

	nameq = strings.ToLower(nameq)
	typeq = strings.ToLower(typeq)
	sourceq = strings.ToLower(sourceq)

	var out []SoftwareEntry
	for _, e := range snap.Software {
		if nameq != "" && !strings.Contains(strings.ToLower(e.Name), nameq) {
			continue
		}
		if typeq != "" && strings.ToLower(e.Type) != typeq {
			continue
		}
		if sourceq != "" && strings.ToLower(e.Source) != sourceq {
			continue
		}
		out = append(out, e)
	}
	return out
}

func summarize(snap *InventorySnapshot) InventorySummary {
	bySource := make(map[string]int)
	byType := make(map[string]int)
	packages, services := 0, 0
	for _, e := range snap.Software {
		bySource[e.Source]++
		byType[e.Type]++
		switch e.Type {
		case "service":
			services++
		default:
			packages++
		}
	}
	return InventorySummary{
		AgentID:       snap.AgentID,
		OS:            snap.OS,
		Arch:          snap.Arch,
		Hostname:      snap.Hostname,
		CollectedAt:   snap.CollectedAt,
		ReceivedAt:    snap.ReceivedAt,
		TotalPackages: packages,
		TotalServices: services,
		BySource:      bySource,
		ByType:        byType,
	}
}
