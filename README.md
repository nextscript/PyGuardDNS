<img src="https://raw.githubusercontent.com/nextscript/PyGuardDNS/refs/heads/main/example.png">

# PyGuardDNS

PyGuardDNS is a local DNS filtering server with a web interface, blocklist management, client profiles, and encrypted upstream resolvers. It runs as a Python application, stores its configuration in SQLite, and can be used as the central DNS resolver for a home network, small lab, or individual devices.

By default, the application listens on DNS port `53` for UDP/TCP and serves the admin interface at `http://127.0.0.1:8080`.

## Features

- Local DNS resolver with filtering for block, allow, and rewrite rules
- Rule explanation/debugging for allow, block, rewrite, SafeSearch, service-block, profile, and invalid-domain decisions
- CNAME blocking: allowed queries are blocked if an upstream CNAME target matches a block rule
- Web dashboard with live statistics, query log, top domains, blocked requests, and client overview
- Query-log actions for one-click global or profile allow/block rules
- Blocklist management from remote URLs or pasted text, including rollback-safe updates
- Support for hosts files, Adblock/uBlock rules, wildcards, regex rules, and uMatrix lists
- Support for plain text, `.gz`, and `.zip` blocklists
- ETag and Last-Modified support for efficient unchanged blocklist checks
- Import reporting with valid, unique, duplicate, regex, allow, and block counts
- Source tracking for duplicate rules across multiple lists
- Global rules and profile-specific rules per client or IP/CIDR range
- Client profiles for different protection levels, such as children, guests, default devices, or unfiltered clients
- Built-in service blocking for platforms such as YouTube, TikTok, Instagram, Facebook, Discord, Twitch, Netflix, Spotify, Steam, Roblox, and more
- SafeSearch enforcement for Google, Bing, and DuckDuckGo
- YouTube Restricted Mode through DNS rewrites
- DNS rewrites for local or custom target addresses
- Block response modes: zero IP, custom IP, NXDOMAIN, REFUSED, and NODATA
- DNS cache with configurable TTL and cache size
- Upstream resolver management with health checks, latency measurement, automatic pause on failures, and manual testing
- Support for multiple upstream resolver types, including classic DNS, DNS-over-TLS, and DNS-over-HTTPS
- Optional encrypted DNS server for DNS-over-TLS and DNS-over-QUIC on port `853`
- Admin login with password, sessions, CSRF protection, and login rate limiting
- API tokens for external automation
- JSON API and Prometheus-compatible metrics at `/metrics`
- Backup and restore for settings, rules, upstreams, profiles, clients, and blocklists
- SQLite RAM mode loads the database into memory for runtime reads/writes and syncs it back to disk
- Audit log for administrative actions
- Start scripts for Windows and Linux/macOS
- CLI commands for status, backup, restore, blocklist updates, and domain testing
- DNSSEC self-validation with local root trust anchor (SERVFAIL on bogus, AD flag set on valid)
- Automatic missing dependency detection and installation at startup
- Benchmark script for generated filter-engine rule sets

## Requirements

- Python 3.11 or newer
- Administrator/root privileges if the DNS server should listen on port `53`
- Network access for external upstream resolvers and blocklist downloads

Runtime dependencies are listed in `requirements.txt`. Test and development dependencies are listed in `requirements-dev.txt`.

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
| `LOCALDNSGUARD_DB_IN_MEMORY` | `1` | Load SQLite into RAM at startup and sync changes back to disk |
| `LOCALDNSGUARD_DB_MEMORY_SYNC_INTERVAL` | `5` | Seconds between RAM database syncs to disk |
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

The filter engine keeps exact, suffix, wildcard, regex, and rewrite rules separate. Suffix rules are matched through a reverse domain trie, which keeps large blocklists fast without changing rule behavior.

### Decision Explanation

The Domain Test page and `/api/explain` can show why a domain was allowed, blocked, rewritten, or refused. The explanation includes the normalized domain, client, profile, final result, reason, matched rule, matched blocklist/source, whether an allow rule won, and a step-by-step decision path.

Example:

```http
GET /api/explain?domain=doubleclick.net&client=192.168.0.80
```

### DNSSEC Self-Validation

When enabled, PyGuardDNS validates DNSSEC locally using a root trust anchor loaded from `data/root-anchors.xml` and `data/root.key`. It does not simply trust the upstream resolver's AD flag. The DO bit is set on outgoing queries, the chain of trust is verified from the root down, and signed bogus responses are returned as SERVFAIL. Unsigned delegations are allowed when the missing DS record is proven by the parent zone. Locally generated block, rewrite and SafeSearch responses are not marked as authenticated data. The client's CD (Checking Disabled) flag is respected — validation is skipped when the client sets CD.

If `dnspython` is not installed, DNSSEC validation is automatically disabled and the application continues to run normally. Metrics for secure, insecure, bogus, and indeterminate results are exported via Prometheus.

### CNAME Blocking

After an upstream response is received, PyGuardDNS extracts CNAME targets and checks them with the same profile and filtering context as the original query. If a CNAME target is blocked, the original query is blocked and logged with:

```txt
blocked_reason = cname_blocked
status = blocked
```

Corrupt or unusual DNS responses are ignored safely and do not crash the server.

### Block Modes

The `block_mode` setting controls DNS responses for blocked requests:

| Mode | Behavior |
| --- | --- |
| `zero_ip` | Return `0.0.0.0` for A and `::` for AAAA |
| `custom_ip` | Return `custom_block_ipv4` or `custom_block_ipv6` |
| `nxdomain` | Return NXDOMAIN |
| `refused` | Return REFUSED |
| `nodata` | Return a successful response with no answer |

Invalid modes fall back to `zero_ip`.

## Blocklist Updates

Remote blocklist updates are designed to keep the last working rules if the new download is bad. An update is rejected if:

- the HTTP request fails
- the content is empty
- the content looks like an HTML error page
- parsing finds no valid rules
- an existing large list shrinks suspiciously
- a compressed list is unsafe or too large

For `.zip` blocklists, PyGuardDNS reads only likely text files, rejects path traversal, and does not recursively extract nested archives.

The blocklist schema stores update metadata such as `last_successful_update`, `last_failed_update`, `last_error`, `last_rule_count`, `last_unique_rule_count`, `last_sha256`, `etag`, `last_modified`, `duplicate_rule_count`, and `import_report`.

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
- `GET /api/explain?domain=example.com&client=127.0.0.1`
- `GET /api/querylog`
- `GET /api/querylog.csv`
- `POST /api/querylog/rule-action`
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

By default, PyGuardDNS loads this SQLite file into an in-memory database at startup. Runtime reads and writes use the RAM database, and changes are synchronized back to `localdnsguard.sqlite3` every `5` seconds and again during normal shutdown. This improves database responsiveness while keeping the on-disk file as the persistent copy.

To force direct on-disk SQLite access instead, set:

```sh
LOCALDNSGUARD_DB_IN_MEMORY=0
```

The sync interval can be changed with `LOCALDNSGUARD_DB_MEMORY_SYNC_INTERVAL`. A hard power loss or process crash can lose changes made since the last sync.

Backups can be exported and restored through the web interface or CLI. Backups include settings, rules, DNS rewrites, upstreams, profiles, clients, profile rules, profile blocklist mappings, and blocklist metadata. Query logs are not part of the normal backup.

## Development and Tests

The normal start scripts install only runtime dependencies. Development dependencies such as `pytest` are installed only when requested.

The development dependency install is a startup option, not a web UI setting, because it runs before the application starts. Use one of these commands when you want the start script to install test tools:

```bat
start-pyguarddns.bat --dev-deps
```

```sh
sudo ./start-pyguarddns.sh --dev-deps
```

Install development dependencies and run tests:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest
```

Syntax check:

```sh
python -m py_compile app.py dns_engine.py blocklist_manager.py client_manager.py benchmark_filter_engine.py
```

Benchmark the filter engine with generated rules:

```sh
python benchmark_filter_engine.py --rules 100000 --samples 5000
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
dnssec_validator.py       DNSSEC chain-of-trust validation and trust anchor store
blocklist_manager.py      Import, parsing, update, and storage of blocklists
client_manager.py         Profiles, clients, profile rules, and service blocks
benchmark_filter_engine.py Synthetic filter-engine benchmark
data/root-anchors.xml     IANA root trust anchor (KSK key digests and public keys)
data/root.key             Root DNSKEYs in BIND format (optional override)
requirements.txt          Runtime Python dependencies
requirements-dev.txt      Test/development Python dependencies
start-pyguarddns.bat      Windows start script
start-pyguarddns.sh       Linux/macOS start script
tests/                    Pytest test suite
```
