# How to Run — satpam-server

## Prerequisites

- Go 1.22 or later

## Build

```bash
cd satpam-server
go build -o satpam-server .
```

On Windows: produces `satpam-server.exe`.

## Configure Rules

Edit `rules/config.json` to set what agents should scan:

```json
{
  "paths": ["/var/www/html", "/home"],
  "extensions": [".php", ".php3", ".php5", ".phtml", ".phar", ".js", ".html", ".htm"],
  "max_file_size_mb": 10,
  "exclude_dirs": [".git", "vendor", "node_modules", ".cache"]
}
```

| Field | Description |
|-------|-------------|
| `paths` | Root directories agents will walk recursively |
| `extensions` | File extensions to scan (case-insensitive on agents) |
| `max_file_size_mb` | Files larger than this are skipped by agents |
| `exclude_dirs` | Directory names (not full paths) skipped by agents |

Add or edit `.yar` files in `rules/` to extend detection coverage. Changes are picked up within 60 seconds without restarting.

## Start the Server

```bash
./satpam-server -addr :8080 -rules ./rules
```

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | TCP listen address |
| `-rules` | `./rules` | Directory containing `.yar` files and `config.json` |

### Verify

```bash
# Liveness
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health
# → 200

# Rules served correctly
curl -s http://localhost:8080/v1/rules | jq .version
# → "1.0.0"
```

## Query Findings

```bash
curl -s http://localhost:8080/v1/findings | jq .
```

Example output:

```json
[
  {
    "agent_id":   "web-prod-01",
    "rule_name":  "WebShell_PHP_Eval_Encoded",
    "severity":   "critical",
    "file_path":  "/var/www/html/uploads/shell.php",
    "matched_on": "$s1 = eval(base64_decode",
    "snippet":    "...eval(base64_decode($_POST['cmd']...",
    "created_at": "2026-05-19T03:00:00Z"
  }
]
```

## Run as a systemd Service (Linux)

```ini
# /etc/systemd/system/satpam-server.service
[Unit]
Description=Satpam rule server
After=network.target

[Service]
ExecStart=/usr/local/bin/satpam-server -addr :8080 -rules /etc/satpam/rules
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now satpam-server
```

## Add a New YARA Rule

1. Create or edit a `.yar` file in `rules/`:

```yara
rule My_Custom_Rule {
    meta:
        description = "detects something specific"
        severity    = "high"
    strings:
        $s1 = "suspicious string" nocase
        $r1 = /pattern_\d+/      nocase
    condition:
        any of them
}
```

2. The server reloads it within 60 seconds. No restart needed.

Supported severity values: `critical`, `high`, `medium`, `low`.
