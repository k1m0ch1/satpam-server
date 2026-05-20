package main

import "sync"

// maxFindings caps in-memory storage to prevent unbounded growth.
// Oldest findings are dropped when the limit is reached.
const maxFindings = 10_000

type findingStore struct {
	mu   sync.RWMutex
	data []Finding
}

func newFindingStore() *findingStore { return &findingStore{} }

func (s *findingStore) add(findings []Finding) {
	s.mu.Lock()
	s.data = append(s.data, findings...)
	if len(s.data) > maxFindings {
		// Slide the window: discard oldest, retain backing array to avoid reallocation.
		copy(s.data, s.data[len(s.data)-maxFindings:])
		s.data = s.data[:maxFindings]
	}
	s.mu.Unlock()
}

func (s *findingStore) list() []Finding {
	s.mu.RLock()
	out := make([]Finding, len(s.data))
	copy(out, s.data)
	s.mu.RUnlock()
	return out
}
