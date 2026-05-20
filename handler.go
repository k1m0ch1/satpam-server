package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	rulesVersion = "1.0.0"
	cacheTTL     = time.Minute
)

type handler struct {
	rulesDir  string
	findings  *findingStore
	agents    *agentStore
	commands  *commandStore
	inventory *inventoryStore

	mu       sync.RWMutex
	cached   *RuleSet
	cachedAt time.Time
}

func newHandler(rulesDir string) *handler {
	return &handler{
		rulesDir:  rulesDir,
		findings:  newFindingStore(),
		agents:    newAgentStore(),
		commands:  newCommandStore(),
		inventory: newInventoryStore(),
	}
}

// ── Rules ─────────────────────────────────────────────────────────────────────

type RuleSet struct {
	Version    string     `json:"version"`
	UpdatedAt  time.Time  `json:"updated_at"`
	YARARules  string     `json:"yara_rules"`
	ScanConfig ScanConfig `json:"scan_config"`
}

type ScanConfig struct {
	Paths       []string `json:"paths"`
	Extensions  []string `json:"extensions"`
	MaxFileMB   int      `json:"max_file_size_mb"`
	ExcludeDirs []string `json:"exclude_dirs"`
	// SpeedMode instructs the agent to grep for keywords before full YARA scan.
	SpeedMode bool `json:"speed_mode"`
}

func (h *handler) getRules(w http.ResponseWriter, r *http.Request) {
	rs, err := h.ruleSet()
	if err != nil {
		slog.Error("load rules", "err", err)
		http.Error(w, "failed to load rules", http.StatusInternalServerError)
		return
	}
	jsonOK(w, rs)
}

func (h *handler) ruleSet() (*RuleSet, error) {
	h.mu.RLock()
	if h.cached != nil && time.Since(h.cachedAt) < cacheTTL {
		rs := h.cached
		h.mu.RUnlock()
		return rs, nil
	}
	h.mu.RUnlock()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cached != nil && time.Since(h.cachedAt) < cacheTTL {
		return h.cached, nil
	}
	yara, err := h.loadYARA()
	if err != nil {
		return nil, err
	}
	cfg, err := h.loadConfig()
	if err != nil {
		return nil, err
	}
	h.cached = &RuleSet{
		Version:    rulesVersion,
		UpdatedAt:  time.Now().UTC(),
		YARARules:  yara,
		ScanConfig: cfg,
	}
	h.cachedAt = time.Now()
	return h.cached, nil
}

func (h *handler) loadYARA() (string, error) {
	entries, err := os.ReadDir(h.rulesDir)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".yar" {
			data, err := os.ReadFile(filepath.Join(h.rulesDir, e.Name()))
			if err != nil {
				return "", err
			}
			sb.Write(data)
			sb.WriteByte('\n')
		}
	}
	return sb.String(), nil
}

func (h *handler) loadConfig() (ScanConfig, error) {
	data, err := os.ReadFile(filepath.Join(h.rulesDir, "config.json"))
	if err != nil {
		return ScanConfig{}, err
	}
	var cfg ScanConfig
	return cfg, json.Unmarshal(data, &cfg)
}

// ── Findings ──────────────────────────────────────────────────────────────────

type Finding struct {
	AgentID   string    `json:"agent_id"`
	RuleName  string    `json:"rule_name"`
	Severity  string    `json:"severity"`
	FilePath  string    `json:"file_path"`
	MatchedOn string    `json:"matched_on"`
	Snippet   string    `json:"snippet,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *handler) postFindings(w http.ResponseWriter, r *http.Request) {
	var findings []Finding
	if err := json.NewDecoder(r.Body).Decode(&findings); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	for i := range findings {
		findings[i].CreatedAt = now
	}
	h.findings.add(findings)
	slog.Info("findings received", "count", len(findings))
	w.WriteHeader(http.StatusAccepted)
}

func (h *handler) getFindings(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	all := h.findings.list()
	if agentID == "" {
		jsonOK(w, all)
		return
	}
	filtered := all[:0]
	for _, f := range all {
		if f.AgentID == agentID {
			filtered = append(filtered, f)
		}
	}
	jsonOK(w, filtered)
}

// ── Heartbeat / Agents ────────────────────────────────────────────────────────

type heartbeatPayload struct {
	AgentID string `json:"agent_id"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func (h *handler) postHeartbeat(w http.ResponseWriter, r *http.Request) {
	var p heartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.AgentID == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	h.agents.heartbeat(p.AgentID, p.OS, p.Arch)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) getAgents(w http.ResponseWriter, _ *http.Request) {
	jsonOK(w, h.agents.list())
}

// ── Commands ──────────────────────────────────────────────────────────────────

type issueCommandReq struct {
	AgentID string `json:"agent_id"` // "" = all agents
	Type    string `json:"type"`
}

// postCommand is called by the panel to issue a command.
func (h *handler) postCommand(w http.ResponseWriter, r *http.Request) {
	var req issueCommandReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		http.Error(w, "type is required", http.StatusBadRequest)
		return
	}
	cmd := h.commands.issue(req.AgentID, req.Type)
	slog.Info("command issued", "id", cmd.ID, "agent", req.AgentID, "type", req.Type)
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, cmd)
}

// getCommands is polled by agents to receive pending commands.
func (h *handler) getCommands(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}
	jsonOK(w, h.commands.pending(agentID))
}

// getCommandsForAgent is called by the panel to show command history.
func (h *handler) getCommandsForAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}
	jsonOK(w, h.commands.listForAgent(agentID))
}

// postCommandAck is called by agents to mark a command completed.
func (h *handler) postCommandAck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !h.commands.ack(id) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	slog.Info("command acked", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// ── Inventory (tech-stack discovery) ─────────────────────────────────────────

// postInventory is called by agents after a stack scan.
// POST /v1/inventory
func (h *handler) postInventory(w http.ResponseWriter, r *http.Request) {
	var snap InventorySnapshot
	if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if snap.AgentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}
	h.inventory.update(snap)
	slog.Info("inventory received",
		"agent", snap.AgentID,
		"host", snap.Hostname,
		"packages", len(snap.Software),
	)
	w.WriteHeader(http.StatusAccepted)
}

// getInventory is called by the panel.
//
//   GET /v1/inventory                       → summary list (all agents)
//   GET /v1/inventory?agent_id=foo          → full snapshot for one agent
//   GET /v1/inventory?agent_id=foo&q=nginx  → search within snapshot
//   GET /v1/inventory?agent_id=foo&type=service
//   GET /v1/inventory?agent_id=foo&source=dpkg
func (h *handler) getInventory(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")

	if agentID == "" {
		jsonOK(w, h.inventory.list())
		return
	}

	nameq   := r.URL.Query().Get("q")
	typeq   := r.URL.Query().Get("type")
	sourceq := r.URL.Query().Get("source")

	if nameq != "" || typeq != "" || sourceq != "" {
		results := h.inventory.search(agentID, nameq, typeq, sourceq)
		if results == nil {
			http.Error(w, "agent not found", http.StatusNotFound)
			return
		}
		jsonOK(w, results)
		return
	}

	snap := h.inventory.get(agentID)
	if snap == nil {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}
	jsonOK(w, snap)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("json encode", "err", err)
	}
}
