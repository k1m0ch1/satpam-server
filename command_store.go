package main

import (
	"fmt"
	"sync"
	"time"
)

// Command is issued by the panel and consumed by an agent.
type Command struct {
	ID       string     `json:"id"`
	AgentID  string     `json:"agent_id"` // "" = broadcast to every agent
	Type     string     `json:"type"`     // "scan"
	Status   string     `json:"status"`   // "pending" | "acked"
	IssuedAt time.Time  `json:"issued_at"`
	AckedAt  *time.Time `json:"acked_at,omitempty"`
}

type commandStore struct {
	mu   sync.RWMutex
	data []*Command
	seq  int
}

func newCommandStore() *commandStore { return &commandStore{} }

func (s *commandStore) issue(agentID, cmdType string) *Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	cmd := &Command{
		ID:       fmt.Sprintf("cmd-%04d", s.seq),
		AgentID:  agentID,
		Type:     cmdType,
		Status:   "pending",
		IssuedAt: time.Now().UTC(),
	}
	s.data = append(s.data, cmd)
	return cmd
}

// pending returns commands that this agent should execute.
func (s *commandStore) pending(agentID string) []*Command {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Command
	for _, c := range s.data {
		if c.Status == "pending" && (c.AgentID == "" || c.AgentID == agentID) {
			out = append(out, c)
		}
	}
	return out
}

func (s *commandStore) ack(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.data {
		if c.ID == id && c.Status == "pending" {
			now := time.Now().UTC()
			c.Status = "acked"
			c.AckedAt = &now
			return true
		}
	}
	return false
}

// listForAgent returns all commands targeted at an agent (for the panel history view).
func (s *commandStore) listForAgent(agentID string) []*Command {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Command
	for _, c := range s.data {
		if c.AgentID == agentID || c.AgentID == "" {
			out = append(out, c)
		}
	}
	return out
}
