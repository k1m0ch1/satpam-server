# Architecture — satpam-server

## Responsibility

satpam-server has two jobs:
1. **Distribute rules** — serve a merged YARA rule block and scan config to any agent that asks
2. **Collect findings** — receive, store, and expose findings posted by agents

It holds no persistent state. A restart clears findings and rule cache.

## Request Flow

```
Agent                          satpam-server
  │                                 │
  │── GET /v1/rules ───────────────▶│
  │                           handler.getRules()
  │                           handler.ruleSet()  ← TTL cache check
  │                             if stale:
  │                               loadYARA()     ← reads *.yar from disk
  │                               loadConfig()   ← reads config.json
  │                               cache result for 60s
  │◀── { version, yara_rules, scan_config } ─────│
  │                                 │
  │  (agent scans files locally)    │
  │                                 │
  │── POST /v1/findings ───────────▶│
  │   [ { agent_id, rule_name,  handler.postFindings()
  │       severity, file_path,    stamp CreatedAt = now
  │       matched_on, snippet } ]   store.add(findings)
  │◀── 202 Accepted ───────────────│
  │                                 │
  Operator                          │
  │── GET /v1/findings ────────────▶│
  │                           handler.getFindings()
  │                             store.list()  ← snapshot copy
  │◀── [ ...all findings... ] ─────│
```

## Components

### handler.go

**`ruleSet()`** — TTL-based rule loader with double-checked locking:

```
Read lock → cache fresh? → return cached
                ↓ stale
Write lock → re-check (another goroutine may have reloaded)
           → loadYARA() + loadConfig()
           → store in h.cached, set h.cachedAt
```

`loadYARA()` concatenates every `*.yar` file in `rulesDir` in directory order. New rule files just need to be dropped in — no code change.

**`postFindings()`** — decodes a JSON array of findings, stamps `CreatedAt = time.Now().UTC()` on each entry (the server is the authoritative timestamp source, not the agent), then calls `store.add`.

### store.go

`findingStore` is a slice protected by `sync.RWMutex`:

- `add(findings)` — appends, then if `len > 10 000` it copies the last 10 000 entries in-place using a single `copy` call and reslices. No allocation on the hot path after the initial fill.
- `list()` — takes a read lock and returns a full copy so callers get a stable snapshot.

### main.go

Registers four routes on the default `http.ServeMux` using Go 1.22 method+path patterns (`GET /v1/rules`, `POST /v1/findings`, etc.) which give free method enforcement.

## Rule File Format

```
rules/
├── config.json       ← scan config for agents (parsed by loadConfig)
├── webshell.yar      ← concatenated first (alpha sort)
├── defacement.yar
└── threathunting.yar
```

Files are sorted alphabetically by `os.ReadDir` and concatenated. Each `.yar` file is self-contained — rules do not cross file boundaries.

## Operational Properties

| Property | Detail |
|----------|--------|
| Rule reload latency | ≤ 60 seconds (TTL) |
| Max findings in memory | 10 000 (oldest evicted) |
| Concurrency | Multiple agents can POST simultaneously — `store.mu` serialises writes |
| No auth | Bind to a private interface or put behind a reverse proxy with mTLS for production |
| No persistence | Findings are lost on restart — pipe `GET /v1/findings` to a SIEM for durability |
