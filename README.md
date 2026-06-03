# PyGuardDNS

PyGuardDNS is a local DNS filtering server with a web interface, blocklist management, client profiles, and encrypted upstream resolvers. It runs as a Python application, stores its configuration in SQLite, and can be used as the central DNS resolver for a home network, small lab, or individual devices.

By default, the application listens on DNS port `53` for UDP/TCP and serves the admin interface at `http://127.0.0.1:8080`.

## Features

- Local DNS resolver with filtering for block, allow, and rewrite rules
- Web dashboard with live statistics, query log, top domains, blocked requests, and client overview
- Blocklist management from remote URLs or pasted text
- Support for hosts files, Adblock/uBlock rules, wildcards, regex rules, and uMatrix lists
- Global rules and profile-specific rules per client or IP/CIDR range
- Client profiles for different protection levels, such as children, guests, default devices, or unfiltered clients
- Built-in service blocking for platforms such as YouTube, TikTok, Instagram, Facebook, Discord, Twitch, Netflix, Spotify, Steam, Roblox, and more
- SafeSearch enforcement for Google, Bing, and DuckDuckGo
- YouTube Restricted Mode through DNS rewrites
- DNS rewrites for local or custom target addresses
- DNS cache with configurable TTL and cache size
- Upstream resolver management with health checks, latency measurement, automatic pause on failures, and manual testing
- Support for multiple upstream resolver types, including classic DNS, DNS-over-TLS, and DNS-over-HTTPS
- Optional encrypted DNS server for DNS-over-TLS and DNS-over-QUIC on port `853`
- Admin login with password, sessions, CSRF protection, and login rate limiting
- API tokens for external automation
- JSON API and Prometheus-compatible metrics at `/metrics`
- Backup and restore for settings, rules, upstreams, profiles, clients, and blocklists
- Audit log for administrative actions
- Start scripts for Windows and Linux/macOS
- CLI commands for status, backup, restore, blocklist updates, and domain testing

## Requirements

- Python 3.11 or newer
- Administrator/root privileges if the DNS server should listen on port `53`
- Network access for external upstream resolvers and blocklist downloads

Python dependencies are listed in `requirements.txt`.

## Quick Start

### Windows

```bat
start-pyguarddns.bat
```

The script requests administrator privileges when needed, creates a local virtual environment in `.venv`, installs the dependencies, and starts PyGuardDNS.

### Linux/macOS

```sh
chmod +x ./start-pyguarddns.sh
sudo ./start-pyguarddns.sh
```

Port `53` usually requires root privileges. The script also creates a local virtual environment and installs the dependencies.

### Manual Start

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

On Windows:

```bat
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

After startup:

- Web UI: `http://127.0.0.1:8080`
- DNS: `0.0.0.0:53` UDP/TCP
- On first login, the admin password is created. The username is `admin`.

## Configuration

Important runtime values can be configured through environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `LOCALDNSGUARD_DB` | `localdnsguard.sqlite3` | Path to the SQLite database |
| `LOCALDNSGUARD_WEB_HOST` | `0.0.0.0` | Host/IP for the web interface |
| `LOCALDNSGUARD_WEB_PORT` | `8080` | Port for the web interface |
| `LOCALDNSGUARD_DNS_HOST` | `0.0.0.0` | Host/IP for DNS UDP/TCP |
| `LOCALDNSGUARD_DNS_PORT` | `53` | DNS port |
| `LOCALDNSGUARD_STRICT_DNS_PORT` | `0` | If set to `1`, the app exits when the DNS port is already in use |
| `LOCALDNSGUARD_MAX_DNS_WORKERS` | `48` | Maximum concurrent DNS requests |
| `LOCALDNSGUARD_MAX_UPSTREAM_WORKERS` | `64` | Maximum concurrent upstream requests |
| `LOCALDNSGUARD_ENCRYPTED_DNS_HOST` | DNS host | Host/IP for DoT/DoQ |
| `LOCALDNSGUARD_ENCRYPTED_DNS_DOMAIN` | empty | Public name for encrypted DNS |
| `LOCALDNSGUARD_DNS_TLS_PORT` | `853` | Port for DNS-over-TLS |
| `LOCALDNSGUARD_DNS_QUIC_PORT` | `853` | Port for DNS-over-QUIC |

Many settings can also be changed directly in the web interface.

## DNS Filter Rules

PyGuardDNS supports multiple rule formats:

```txt
example.com
||example.com^
*.example.com
@@allowed.example.com
/.*tracking.*/
example.local -> 192.168.1.10
0.0.0.0 ads.example.com
```

Allow rules take priority over block rules. Rewrites can map domains to custom IP addresses or forced DNS targets.

## Profiles and Clients

Clients can be assigned to a profile by IP address or CIDR range. A profile can have its own rules, blocklists, service blocks, SafeSearch settings, and YouTube Restricted Mode. This makes it possible to apply different DNS policies to specific devices or groups in the network.

## Upstream Resolvers

PyGuardDNS creates a Cloudflare DNS-over-TLS upstream by default. Additional upstreams can be added, detected, tested, enabled, or paused in the web interface. Health checks track latency, success rate, errors, and pause state.

## API and Metrics

The web interface uses the same JSON API that can also be used for automation. External clients authenticate with an API token through:

```http
Authorization: Bearer <token>
```

or:

```http
X-API-Token: <token>
```

Useful endpoints:

- `GET /api/status`
- `GET /api/dashboard`
- `GET /api/querylog`
- `GET /api/querylog.csv`
- `GET /api/rules`
- `GET /api/blocklists`
- `POST /api/blocklists/update-all`
- `GET /api/clients`
- `GET /api/profiles`
- `GET /api/upstreams`
- `POST /api/cache/clear`
- `GET /api/backup`
- `GET /api/metrics`
- `GET /metrics`

`/metrics` returns Prometheus-compatible metrics, including query counts, block rate, cache rate, active clients, upstreams, and DNS-over-TLS pool values.

## CLI

`app.py` provides additional commands:

```sh
python app.py serve
python app.py status
python app.py update-lists
python app.py backup --backup-file backup.json
python app.py restore --file backup.json
python app.py test-domain --domain example.com --query-type A --client 127.0.0.1
```

If no command is provided, `serve` is used.

## Console Commands

While the server is running, the console accepts:

```txt
status
restart
stop
cache clear
update blocklist
help
```

## Backup and Data

The application stores its data in this file by default:

```txt
localdnsguard.sqlite3
```

Backups can be exported and restored through the web interface or CLI. Backups include settings, rules, DNS rewrites, upstreams, profiles, clients, profile rules, profile blocklist mappings, and blocklist metadata. Query logs are not part of the normal backup.

## Development and Tests

Tests are located in `test_*.py` files in the project directory and can be run with `unittest`:

```sh
python -m unittest
```

Syntax check:

```sh
python -m py_compile app.py dns_engine.py blocklist_manager.py client_manager.py
```

## Security Notes

- Do not expose the web interface to the public internet without additional protection.
- For LAN usage, the allowed network range is limited to private networks by default.
- Use strong admin passwords and rotate API tokens if they have been shared.
- Ports `53` and `853` may conflict with existing DNS services.

## Project Structure

```txt
app.py                    Web UI, DNS server, API, CLI, and runtime
dns_engine.py             Filter engine for rules, rewrites, SafeSearch, and service blocks
blocklist_manager.py      Import, parsing, update, and storage of blocklists
client_manager.py         Profiles, clients, profile rules, and service blocks
requirements.txt          Python dependencies
start-pyguarddns.bat      Windows start script
start-pyguarddns.sh       Linux/macOS start script
test_*.py                 Unit tests
```

## License

This repository currently does not include a license file. Add an appropriate license before publishing if others should be allowed to use or modify the project.
