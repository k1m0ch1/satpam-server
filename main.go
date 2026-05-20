package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	addr     := flag.String("addr", ":8080", "listen address")
	rulesDir := flag.String("rules", "./rules", "directory containing .yar files and config.json")
	flag.Parse()

	h := newHandler(*rulesDir)

	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /health", healthCheck)

	// Rules (agent)
	mux.HandleFunc("GET /v1/rules", h.getRules)

	// Findings (agent → server, panel ← server)
	mux.HandleFunc("POST /v1/findings", h.postFindings)
	mux.HandleFunc("GET /v1/findings",  h.getFindings)

	// Heartbeat + agents (agent → server, panel ← server)
	mux.HandleFunc("POST /v1/heartbeat",           h.postHeartbeat)
	mux.HandleFunc("GET /v1/agents",               h.getAgents)
	mux.HandleFunc("GET /v1/agents/{id}",          h.getAgent)
	mux.HandleFunc("GET /v1/agents/{id}/heartbeats", h.getAgentHeartbeats)
	mux.HandleFunc("GET /v1/agents/{id}/events",   h.getAgentEvents)

	// Commands (panel → server → agent)
	mux.HandleFunc("POST /v1/commands",             h.postCommand)
	mux.HandleFunc("GET /v1/commands",              h.getCommands)         // agent polls
	mux.HandleFunc("GET /v1/commands/history",      h.getCommandsForAgent) // panel history
	mux.HandleFunc("POST /v1/commands/{id}/ack",    h.postCommandAck)      // agent acks

	// Inventory / tech-stack discovery (agent → server, panel ← server)
	mux.HandleFunc("POST /v1/inventory", h.postInventory)
	mux.HandleFunc("GET /v1/inventory",  h.getInventory)

	slog.Info("satpam-server starting", "addr", *addr, "rules", *rulesDir)
	if err := http.ListenAndServe(*addr, cors(mux)); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// cors wraps the mux with permissive CORS headers for the panel.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
