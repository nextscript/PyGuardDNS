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
- Blocklist presets for common adblock/tracker lists
- Global rules and profile-specific rules per client or IP/CIDR range
- Client profiles for different protection levels, such as children, guests, default devices, or unfiltered clients
- Profile-specific blocklists attached to a profile
- Built-in service blocking for platforms such as YouTube, TikTok, Instagram, Facebook, Discord, Twitch, Netflix, Spotify, Steam, Roblox, and more
- SafeSearch enforcement for Google, Bing, and DuckDuckGo
- YouTube Restricted Mode through DNS rewrites
- DNS rewrites for local or custom target addresses, including wildcard rewrites (`*.local -> 10.0.0.1`)
- Block response modes: zero IP, custom IP, NXDOMAIN, REFUSED, and NODATA
- DNS cache with configurable TTL, min/max TTL bounds, cache size, and optimistic stale refresh
- RAM-snapshot request path: settings, client/profile data, and filter rules are read from atomically-swapped in-memory snapshots, so answering a DNS query needs no SQLite access, global locks, or synchronous query-log writes
- Asynchronous unknown-client registration with TTL-based deduplication and batched background inserts, keeping per-query database writes off the DNS hot path
- Runtime metrics for the DNS request hot path (cache hits/misses, filter decisions, upstream errors, query-log drops, queue sizes, unknown client drops) exposed via `/metrics` and `/api/runtime_metrics`
- Upstream resolver management with health checks, latency measurement, automatic pause on consecutive failures, and manual testing
- Support for multiple upstream resolver types: plain DNS (UDP/TCP), DNS-over-TLS (with connection pooling), DNS-over-HTTPS, DNS-over-HTTPS with HTTP/3 (with fallback to DoH), DNS-over-QUIC (with fallback to DoT), DNSCrypt stamps, and plain DNS stamps
- DNSCrypt with Anonymized DNSCrypt relay support and XChaCha20-Poly1305 encryption (es_version=2)
- Upstream forwarding modes: sequential, parallel fastest, and load balancing with round-robin
- Automatic fallback to hardcoded DoT resolvers (Cloudflare, Google) when all upstreams fail
- Bootstrap DNS resolution via hardcoded DoH providers to avoid recursive deadlock
- Optional encrypted DNS server for DNS-over-TLS, DNS-over-HTTPS, and DNS-over-QUIC on port `853`
- Certificate/key validation for encrypted DNS server (checks matching and server name)
- Persistent DoT/DoQ connection reuse with idle timeout and automatic reconnect
- QUIC session pooling with penalty tracking, latency recording, and idle sweep
- Admin login with password, sessions, CSRF protection, and login rate limiting
- API tokens for external automation
- JSON API and Prometheus-compatible metrics at `/metrics`
- Backup and restore for settings, rules, upstreams, profiles, clients, and blocklists
- SQLite RAM mode loads the database into memory for runtime reads/writes, with optional `/dev/shm` on Linux; syncs back to disk at configurable intervals and on shutdown
- Audit log for administrative actions
- Instance lock to prevent multiple server instances
- Automatic crash reporting with thread dumps
- Start scripts for Windows and Linux/macOS
- CLI commands for status, backup, restore, blocklist updates, and domain testing
- Interactive console command completion with Tab
- DNSSEC self-validation with local root trust anchor, RFC 5011 automatic key rollover, embedded IANA root trust anchor, NSEC/NSEC3 denial proof validation, and SERVFAIL on bogus responses
- Automatic missing dependency detection at startup

## Requirements

- Python 3.11 or newer
- Administrator/root privileges if the DNS server should listen on port `53`
- Network access for external upstream resolvers and blocklist downloads

Runtime dependencies are listed in `requirements.txt`.

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
| `LOCALDNSGUARD_DB_MEMORY_SYNC_INTERVAL` | `60` | Seconds between RAM database syncs to disk |
| `LOCALDNSGUARD_BLOCKLIST_DOWNLOAD_TIMEOUT` | `20` | Maximum seconds for one blocklist download before the import job fails |
| `LOCALDNSGUARD_WEB_HOST` | `0.0.0.0` | Host/IP for the web interface |
| `LOCALDNSGUARD_WEB_PORT` | `8080` | Port for the web interface |
| `LOCALDNSGUARD_DNS_HOST` | `0.0.0.0` | Host/IP for DNS UDP/TCP |
| `LOCALDNSGUARD_DNS_PORT` | `53` | DNS port |
| `LOCALDNSGUARD_STRICT_DNS_PORT` | `0` | If set to `1`, the app exits when the DNS port is already in use |
| `LOCALDNSGUARD_MAX_DNS_WORKERS` | `48` | Maximum concurrent DNS requests |
| `LOCALDNSGUARD_MAX_UPSTREAM_WORKERS` | `64` | Maximum concurrent upstream requests |
| `LOCALDNSGUARD_ENCRYPTED_DNS_HOST` | DNS host | Host/IP for DoT/DoH/DoQ |
| `LOCALDNSGUARD_ENCRYPTED_DNS_DOMAIN` | empty | Public name for encrypted DNS |
| `LOCALDNSGUARD_DNS_TLS_PORT` | `853` | Port for DNS-over-TLS |
| `LOCALDNSGUARD_DNS_QUIC_PORT` | `853` | Port for DNS-over-QUIC |
| `LOCALDNSGUARD_DNS_HTTPS_PORT` | `443` | Port for DNS-over-HTTPS |
| `LOCALDNSGUARD_ENABLE_EXPERIMENTAL_DOQ_UPSTREAM` | `0` | Enable experimental DoQ upstream forwarding |

Many settings can also be changed directly in the web interface.

## DNS Filter Rules

PyGuardDNS uses zwei Formate für Filterregeln: das **pgrules-Format** für benutzerdefinierte Regeln in `data/rules/user_rules.pgrules` und das **Adblock/uBlock-Format** für Blocklisten-Importe, die automatisch konvertiert werden.

### pgrules-Format (Benutzerdefinierte Regeln)

| Prefix | Typ | Bedeutung | Beispiel |
|--------|-----|-----------|----------|
| `bd::` | Block | Exakte Domain blockieren | `bd::doubleclick.net` |
| `bs::` | Block | Domain + alle Subdomains blockieren | `bs::example.com` |
| `br::` | Block | Regex-basiert blockieren | `br::/ads\..*\.com/` |
| `ad::` | Allow | Exakte Domain erlauben | `ad::trusted.com` |
| `as::` | Allow | Domain + alle Subdomains erlauben | `as::trusted.com` |
| `ar::` | Allow | Regex-basiert erlauben | `ar::/.*\.trusted\.com/` |

### Adblock/uBlock-Format (Blocklisten-Importe)

Diese Formate werden in `blocklist_manager.py` und `rules_engine.py` konvertiert. Der Import speichert sie als pgrules im Cache:

| Syntax | Bedeutung | Beispiel |
|--------|-----------|----------|
| `\|\|domain^` | Block Subdomains + Domain | `\|\|doubleclick.net^` |
| `@@\|\|domain^` | Allow Subdomains + Domain | `@@\|\|trusted.com^` |
| `/regex/` | Regex-Regel | `/ads\..*/` |
| `domain` | Exakte Domain | `example.com` |
| `\|domain` | Exakter Anfang | `\|example.com` |
| `0.0.0.0 domain` | Hosts-Datei | `0.0.0.0 example.com` |
| `127.0.0.1 domain` | Hosts-Datei | `127.0.0.1 example.com` |
| `::1 domain` | Hosts-Datei (IPv6) | `::1 example.com` |
| `address=/domain/` | Dnsmasq-Format | `address=/example.com/` |
| `server=/domain/` | Dnsmasq-Format | `server=/example.com/` |
| `domain^$badfilter` | Regel deaktivieren | `\|\|example.com^$badfilter` |
| `##.selector` | Kosmetische Regel (ignoriert) | `##.ad-banner` |
| `domain##.selector` | Kosmetische Regel (ignoriert) | `example.com##.ad` |

### Rewrite-Regeln

Domain-Umleitungen auf eine beliebige IP oder einen anderen Domain-Namen:

```
meinserver.local -> 192.168.1.100
*.local -> 10.0.0.1
```

### Verhalten und Priorität

Die Prüfreihenfolge (nach Normalisierung der Domain):

1. **Profile Allow** (profil-spezifische Allow-Regeln)
2. **Global Allow** (globale Allow-Regeln)
3. **Profile Rewrite** (profil-spezifische Rewrites)
4. **Global Rewrite** (globale Rewrites)
5. **Profile Block** (profil-spezifische Block-Regeln)
6. **Global Block** (globale Block-Regeln)
7. **SafeSearch** (profil-spezifische SafeSearch-Erzwingung)
8. **YouTube Restricted** (profil-spezifische YouTube-Einschränkung)
9. **Service Block** (profil-spezifische Dienst-Sperren)

Allow-Regeln gewinnen immer vor Block-Regeln. Sobald eine Regel matched, wird die Prüfung abgebrochen. Das bedeutet, ein Allow auf einer höheren Stufe verhindert einen Block auf einer niedrigeren Stufe.

**Match-Verhalten:**
- `bd::` / `ad::` (exact) matcht **nur** die exakte Domain, nicht Subdomains
- `bs::` / `as::` (suffix) matcht die angegebene Domain **und** alle Subdomains – `bs::example.com` blockiert `example.com`, `sub.example.com`, `deep.sub.example.com`
- `*.example.com` wird wie `bs::example.com` behandelt
- `br::` / `ar::` (regex) werden case-insensitive kompiliert und über die gesamte Domain geprüft

**Regex-Optimierung:** Regex-Regeln durchlaufen einen Literal-Index. Nur Regexes, deren erforderliche Literale in der angefragten Domain vorkommen, werden tatsächlich ausgeführt. Regexes mit Alternation (`|`) oder optionalen Gruppen (`?`) landen im Fallback-Pfad und werden bei jeder Anfrage geprüft.

**Negative Cache:** Sobald eine Domain als `ALLOW/no_match` eingestuft wurde, wird dieses Ergebnis für bis zu 50.000 Einträge zwischengespeichert und bei erneuter Anfrage sofort zurückgegeben.

### Decision Explanation

The Domain Test page and `/api/explain` can show why a domain was allowed, blocked, rewritten, or refused. The explanation includes the normalized domain, client, profile, final result, reason, matched rule, matched blocklist/source, whether an allow rule won, and a step-by-step decision path.

Example:

```http
GET /api/explain?domain=doubleclick.net&client=192.168.0.80
```

### DNSSEC Self-Validation

When enabled, PyGuardDNS validates DNSSEC locally using a root trust anchor loaded from `data/trust_anchors.json` (derived from the embedded IANA `root-anchors.xml`). It does not simply trust the upstream resolver's AD flag. The DO bit is set on outgoing queries, the chain of trust is verified from the root down, and signed bogus responses are returned as SERVFAIL. Unsigned delegations are allowed when the missing DS record is proven by the parent zone. NSEC and NSEC3 denial proofs are validated. Locally generated block, rewrite and SafeSearch responses are not marked as authenticated data. The client's CD (Checking Disabled) flag is respected — validation is skipped when the client sets CD.

The trust anchor is maintained through RFC 5011 automatic key rollover: new root KSKs are detected and promoted to active after a 30-day hold-down period, revoked keys are retired after 30 days, and retired keys are removed after 90 days.

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
| `drop` | Drop the query (no response) |

Invalid modes fall back to `zero_ip`.

## Request Path and Performance

`handle_dns_request` answers DNS queries entirely from in-memory snapshots: settings, client/profile data, and filter rules are built once and swapped in atomically whenever something changes (rule edits, profile changes, restores). This means a query never waits on a SQLite read, a global lock, or a synchronous query-log write.

Unknown clients are registered asynchronously: new IPs are deduplicated with a TTL-based set, queued, and inserted in batches by a background worker, which then triggers a snapshot rebuild. If the queue fills up, registrations are dropped and counted in `unknown_client_dropped_total` instead of blocking DNS responses.

DNS-over-TLS connections are pooled (`DotConnection`) and reused instead of performing a new TCP/TLS handshake for every query. DNS-over-QUIC sessions are pooled with idle timeout, penalty tracking after repeated failures, and automatic reconnect.

Hot-path counters (cache hits/misses, filter decisions, upstream errors, query-log drops, queue sizes, dropped client registrations) are available through `/metrics` and `/api/runtime_metrics`, and `benchmark_request_path.py` can reproduce cache-hit, clean-miss, blocked, and mixed traffic patterns, optionally with a simulated slow disk, to measure the effect of changes on this path.

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

The `From List` preset picker in the Blocklist Manager uses built-in presets. No external `adlist.txt` file is required at runtime.

## Profiles and Clients

Clients can be assigned to a profile by IP address or CIDR range. A profile can have its own rules, blocklists, service blocks, SafeSearch settings, and YouTube Restricted Mode. This makes it possible to apply different DNS policies to specific devices or groups in the network.

Client-specific filtering can be disabled per client or per profile.

## Upstream Resolvers

PyGuardDNS creates a Cloudflare DNS-over-TLS upstream by default. Additional upstreams can be added, detected, tested, enabled, or paused in the web interface. Health checks track latency, success rate, errors, and pause state. An upstream is automatically paused after five consecutive failures.

Supported upstream formats include:

- Plain DNS over UDP/TCP (IP or hostname)
- DNS-over-TLS (`tls://hostname`) with connection pooling
- DNS-over-HTTPS (`https://hostname/path`) with hostname resolution via configured upstreams or bootstrapped via hardcoded DoH providers
- DNS-over-HTTPS with HTTP/3 (`doh3://` / `h3://`) with automatic fallback to DoH
- DNS-over-QUIC (`quic://` / `doq://`) with automatic fallback to DoT (experimental, disabled by default)
- DNSCrypt `sdns://` stamps with X25519-XSalsa20Poly1305 and X25519-XChaCha20-Poly1305 encryption
- Anonymized DNSCrypt through a DNSCrypt relay upstream
- DoH, DoT, DoQ, and plain DNS `sdns://` stamps
- DNSCrypt relay stamps for use as relays on DNSCrypt upstreams

Upstream forwarding modes:

- **sequential**: try upstreams in order until one succeeds
- **parallel fastest**: query all upstreams concurrently and return the first successful response
- **load balance**: round-robin across upstreams

When all upstreams fail, PyGuardDNS falls back to hardcoded DoT resolvers (Cloudflare, Google).

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
- `GET /api/runtime_metrics`
- `GET /metrics`

`/metrics` returns Prometheus-compatible metrics, including query counts, block rate, cache rate, active clients, upstreams, DoT/DoQ pool values, runtime counters, and DNSSEC validation results. `/api/runtime_metrics` returns the same DNS hot-path counters as JSON, such as cache hits/misses, filter decisions, upstream errors, query-log drops, queue sizes, and `unknown_client_dropped_total`.

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
domain test example.com [client-ip] [qtype]
test domain example.com [client-ip] [qtype]
dnssec test
restart
stop
cache clear
update blocklist
dedupe blocklists
help
```

`domain test` uses the same decision pipeline as the web Domain Test page. The client IP defaults to `127.0.0.1` and the query type defaults to `A`.

Press `Tab` in the interactive console to cycle through matching commands.

## Backup and Data

The application stores its data in this file by default:

```txt
localdnsguard.sqlite3
```

By default, PyGuardDNS loads this SQLite file into an in-memory database at startup. On Linux, it uses `/dev/shm` for the in-memory copy when available. Runtime reads and writes use the RAM database, and changes are synchronized back to `localdnsguard.sqlite3` every `60` seconds and again during normal shutdown. Background syncs use a snapshot so normal saves are not blocked by the full disk write. This improves database responsiveness while keeping the on-disk file as the persistent copy.

To force direct on-disk SQLite access instead, set:

```sh
LOCALDNSGUARD_DB_IN_MEMORY=0
```

The sync interval can be changed with `LOCALDNSGUARD_DB_MEMORY_SYNC_INTERVAL`. A hard power loss or process crash can lose changes made since the last sync.

Upstream configuration is stored as individual JSON files in `data/upstreams/`.

Blocklist caches, cosmetic rules, unsupported rules, and original text are stored as files under `data/blocklists/`.

User rules are stored in the `.pgrules` format in `data/rules/user_rules.pgrules`, with backups in `data/rules/backups/`.

Backups can be exported and restored through the web interface or CLI. Backups include settings, rules, DNS rewrites, upstreams, profiles, clients, profile rules, profile blocklist mappings, and blocklist metadata. Query logs are not part of the normal backup.

## Development and Tests

The normal start scripts install only runtime dependencies.

Install development dependencies:

```sh
python -m pip install pytest
```

Run tests:

```sh
python -m pytest
```

Syntax check:

```sh
python -m py_compile app.py dns_engine.py blocklist_manager.py client_manager.py benchmark_filter_engine.py benchmark_request_path.py
```

Benchmark the filter engine with generated rules:

```sh
python benchmark_filter_engine.py --rules 100000 --samples 5000
```

Benchmark the DNS request hot path (`handle_dns_request`) with synthetic traffic:

```sh
python benchmark_request_path.py --mode mixed --per-thread 300 --levels 1,2,4,8,16
```

`--mode` selects the traffic pattern (`cache-hit`, `clean-miss`, `blocked`, `mixed`), and `--simulate-slow-db`/`--slow-db-delay` simulate a slow disk to verify that DNS latency stays decoupled from query-log persistence speed. The output includes p50/latency, cache-hit-ratio, and queue-size columns sourced from the runtime metrics.

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
rules_engine.py           User rule format (pgrules), blocklist conversion, and cache I/O
upstream_manager.py       Upstream resolver configuration stored as JSON files
benchmark_filter_engine.py Synthetic filter-engine benchmark
benchmark_request_path.py Synthetic benchmark for the DNS request hot path
data/root-anchors.xml     IANA root trust anchor (KSK key digests and public keys)
data/root.key             Root DNSKEYs in BIND format (optional override)
data/trust_anchors.json   RFC 5011 trust anchor state
requirements.txt          Runtime Python dependencies
start-pyguarddns.bat      Windows start script
start-pyguarddns.sh       Linux/macOS start script
```



