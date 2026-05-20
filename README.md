<div align="center">

# satpam-server

**Central rule distribution and findings collection server**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen?style=flat-square)](#)

</div>

---

## Overview

satpam-server is the brain of the Satpam stack. It does two things:

- **Distributes** YARA rules and scan configuration to every agent on demand
- **Collects** findings posted by agents and makes them queryable

Rules are reloaded from disk every 60 seconds — drop a `.yar` file and agents pick it up automatically, no restart required.

---

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness check — `200 OK` |
| `GET` | `/v1/rules` | YARA rules + scan config as JSON |
| `POST` | `/v1/findings` | Accept findings batch from an agent |
| `GET` | `/v1/findings` | Query all collected findings |

---

## Quick Start

```bash
go build -o satpam-server .
./satpam-server -addr :8080 -rules ./rules
```

```bash
# verify
curl http://localhost:8080/health
curl http://localhost:8080/v1/rules | jq .version
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | TCP listen address |
| `-rules` | `./rules` | Directory with `.yar` files and `config.json` |

---

## Rule Files

```
rules/
├── config.json        ← scan paths, extensions, exclusions pushed to agents
├── webshell.yar       ← PHP/ASP webshell patterns
├── defacement.yar     ← defacement graffiti, SEO spam, hacktivist groups
└── threathunting.yar  ← C2 frameworks, lateral movement, evasion indicators
```

New `.yar` files dropped into `rules/` are automatically served to agents within 60 seconds.

---

## Files

| File | Responsibility |
|------|---------------|
| `main.go` | HTTP mux, flag parsing, health check |
| `handler.go` | Route handlers, 60s TTL rule cache with double-checked locking |
| `store.go` | Thread-safe finding store, rolling cap of 10 000 entries |

---

📖 [How to Run](how-to-run.md) · 🏗️ [Architecture](arch.md) · ⬅️ [Back to root](../README.md)
