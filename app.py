#!/usr/bin/env python3
import base64
import csv
import faulthandler
import hashlib
import io
import ipaddress
import json
import os
import random
import re
import secrets
import signal
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import urlopen

import bcrypt

from dns_engine import FilterEngine, FilterResult
from blocklist_manager import BlocklistManager
from client_manager import ClientManager, SERVICE_DOMAINS, SAFESEARCH_REWRITES, YOUTUBE_SAFESEARCH_REWRITES, SAFESEARCH_PROFILE_COLUMNS
try:
    from dnssec_validator import DNSSECValidator, DNSSECValidationStatus, ensure_root_trust_anchor, get_dnssec_metrics
    import dns.message
    import dns.flags
    _dnssec_available = True
except ModuleNotFoundError:
    _dnssec_available = False
    DNSSECValidator = None
    DNSSECValidationStatus = None
    def ensure_root_trust_anchor(*args, **kwargs):
        return False, "dnspython DNSSEC support is not available"
    def get_dnssec_metrics():
        return {"secure": 0, "insecure": 0, "bogus": 0, "indeterminate": 0, "validation_seconds_total": 0.0}

import logging
logger = logging.getLogger("dnssec")

APP_NAME = "PyGuardDNS"
DB_PATH = os.environ.get("LOCALDNSGUARD_DB", "localdnsguard.sqlite3")
WEB_HOST = os.environ.get("LOCALDNSGUARD_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("LOCALDNSGUARD_WEB_PORT", "8080"))
DNS_HOST = os.environ.get("LOCALDNSGUARD_DNS_HOST", "0.0.0.0")
DNS_PORT = int(os.environ.get("LOCALDNSGUARD_DNS_PORT", "53"))
ENCRYPTED_DNS_HOST = os.environ.get("LOCALDNSGUARD_ENCRYPTED_DNS_HOST", DNS_HOST)
ENCRYPTED_DNS_DOMAIN = os.environ.get("LOCALDNSGUARD_ENCRYPTED_DNS_DOMAIN", "")
DNS_TLS_PORT = int(os.environ.get("LOCALDNSGUARD_DNS_TLS_PORT", "853"))
DNS_QUIC_PORT = int(os.environ.get("LOCALDNSGUARD_DNS_QUIC_PORT", "853"))
DNS_HTTPS_PORT = int(os.environ.get("LOCALDNSGUARD_DNS_HTTPS_PORT", "443"))
STRICT_DNS_PORT = os.environ.get("LOCALDNSGUARD_STRICT_DNS_PORT", "0") == "1"
DEFAULT_UPSTREAM = "tls://cloudflare-dns.com"
BOOT_TIME = time.time()
SESSION_TTL_SECONDS = 60 * 60 * 24 * 183
MAX_BACKUP_BYTES = 1_500_000_000
CSRF_COOKIE = "csrf_token"
API_TOKEN_SETTING = "api_token"

db_lock = threading.RLock()
cache_lock = threading.RLock()
rules_lock = threading.RLock()
runtime_restart_lock = threading.RLock()
dns_cache = {}
dash_cache = {"data": None, "ts": 0.0}
DASH_CACHE_TTL = 5
sessions = {}
doh_host_cache = {}
doh_connection_cache = {}
dnscrypt_cert_cache = {}
rules_cache = None
rules_cache_rebuild_running = False
dns_concurrency = threading.BoundedSemaphore(int(os.environ.get("LOCALDNSGUARD_MAX_DNS_WORKERS", "48")))
upstream_concurrency = threading.BoundedSemaphore(int(os.environ.get("LOCALDNSGUARD_MAX_UPSTREAM_WORKERS", "64")))
db_write_queue = []
db_write_lock = threading.Lock()
upstream_metric_last_write = {}
upstream_queue_wait_samples = []
upstream_queue_wait_lock = threading.Lock()
dot_pools = {}
dot_pools_lock = threading.RLock()
instance_lock_file = None
cache_bytes_used = 0
_upstream_rr_index = 0
_upstream_rr_lock = threading.Lock()

_login_attempts: dict[str, list[float]] = {}
_login_rate_limit_lock = threading.Lock()
LOGIN_RATE_LIMIT = 5
LOGIN_RATE_WINDOW = 60

_healthcheck_last_run = 0.0
_healthcheck_lock = threading.Lock()

_active_engine = FilterEngine()
_active_engine_lock = threading.RLock()
_dnssec_validator = None
_dnssec_validator_lock = threading.Lock()
blocklist_manager = None
client_manager = None
web_server = None
dns_servers = []
encrypted_dns_servers = []
server_shutdown_event = threading.Event()
dns_runtime_ready = threading.Event()
runtime_status_lock = threading.Lock()
runtime_status_message = "DNS server starting ..."
doq_metrics = {"handshakes": 0, "queries": 0, "errors": 0, "last_peer": "", "last_error": ""}
doq_metrics_lock = threading.Lock()


def build_filter_engine():
    engine = FilterEngine()
    data = rows(
        """
        SELECT action, pattern_type, pattern, target, comment
        FROM rules
        WHERE enabled=1
        ORDER BY
          CASE action WHEN 'rewrite' THEN 0 WHEN 'allow' THEN 1 WHEN 'block' THEN 2 ELSE 3 END,
          id ASC
        """
    )
    for row in data:
        action = row["action"]
        pattern = row["pattern"]
        target = row["target"]
        if action == "rewrite" and target:
            engine.add_rule(f"{pattern} -> {target}", "rewrite")
        elif action == "allow":
            engine.add_rule(f"@@{pattern}", "allow")
        else:
            engine.add_rule(pattern, "block")
    global blocklist_manager
    if blocklist_manager is not None:
        blocklist_manager.load_into_engine(engine)
    global client_manager
    if client_manager is not None:
        for profile in client_manager.get_profiles():
            pid = profile["id"]
            if not profile["filtering_enabled"]:
                continue
            client_manager.load_profile_into_engine(engine, pid)
            client_manager.load_profile_blocklists_into_engine(engine, pid, blocklist_manager)
            engines_active = []
            if profile.get("safe_search_google"):
                engines_active.append("google")
            if profile.get("safe_search_bing"):
                engines_active.append("bing")
            if profile.get("safe_search_ddg"):
                engines_active.append("ddg")
            if engines_active:
                engine.set_profile_safesearch(pid, engines_active)
            if profile.get("youtube_restricted"):
                engine.set_profile_youtube_restricted(pid, True)
            blocked_services = set(client_manager.get_profile_services(pid))
            if blocked_services:
                engine.set_profile_blocked_services(pid, blocked_services)
    return engine


def get_dnssec_validator():
    if not _dnssec_available:
        return None
    ok, err = ensure_root_trust_anchor()
    if not ok:
        logger.error("DNSSEC trust anchor bootstrap failed: %s", err)
        return None
    global _dnssec_validator
    if _dnssec_validator is None:
        with _dnssec_validator_lock:
            if _dnssec_validator is None:
                import dns.resolver
                import dns.flags
                upstream_dns = []
                for up in active_upstreams():
                    if plain_upstream_supported(up):
                        upstream_dns.append(up["address"])
                if not upstream_dns:
                    upstream_dns = ["1.1.1.1", "8.8.8.8"]
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = upstream_dns
                resolver.timeout = 3.0
                resolver.lifetime = 3.0
                resolver.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
                _dnssec_validator = DNSSECValidator(resolver)
                _dnssec_validator.reload_trust_anchor()
    return _dnssec_validator


def add_do_bit_to_query(request_bytes):
    if not _dnssec_available:
        return request_bytes
    try:
        import dns.message
        import dns.flags
        msg = dns.message.from_wire(request_bytes)
        if msg.edns != 0:
            msg.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
        return msg.to_wire()
    except Exception:
        return request_bytes


def clear_dnssec_validator():
    global _dnssec_validator
    with _dnssec_validator_lock:
        _dnssec_validator = None


def reload_filter_engine():
    global _active_engine
    new_engine = build_filter_engine()
    with _active_engine_lock:
        _active_engine = new_engine


def get_filter_engine():
    with _active_engine_lock:
        return _active_engine


def crash_filename():
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"crash_{stamp}.txt"


def write_crash_report(title, details=""):
    path = crash_filename()
    body = []
    body.append(f"{APP_NAME} crash report\n")
    body.append(f"timestamp: {now_iso()}\n")
    body.append(f"pid: {os.getpid()}\n")
    body.append(f"title: {title}\n\n")
    if details:
        body.append(details)
        if not details.endswith("\n"):
            body.append("\n")
    body.append("\n--- active threads ---\n")
    for thread in threading.enumerate():
        body.append(f"- {thread.name} ident={thread.ident} daemon={thread.daemon}\n")
    text = "".join(body)
    try:
        with open(path, "w", encoding="utf-8") as report:
            report.write(text)
    except Exception:
        pass
    try:
        with open("crash_timestamp.txt", "w", encoding="utf-8") as latest:
            latest.write(text)
            latest.write(f"\ncrash_file: {path}\n")
    except Exception:
        pass
    return path


def install_crash_handlers():
    try:
        fatal_log = open("fatal-python.log", "a", encoding="utf-8")
        faulthandler.enable(file=fatal_log, all_threads=True)
    except Exception:
        pass

    def excepthook(exc_type, exc, tb):
        write_crash_report("unhandled exception", "".join(traceback.format_exception(exc_type, exc, tb)))
        sys.__excepthook__(exc_type, exc, tb)

    def thread_hook(args):
        write_crash_report(
            f"thread exception: {args.thread.name}",
            "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)),
        )
        if hasattr(threading, "__excepthook__"):
            threading.__excepthook__(args)

    import sys

    sys.excepthook = excepthook
    if hasattr(threading, "excepthook"):
        threading.excepthook = thread_hook

    def signal_handler(signum, frame):
        stack = "".join(traceback.format_stack(frame)) if frame else ""
        write_crash_report(f"signal {signum}", stack)
        raise SystemExit(128 + int(signum))

    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None), getattr(signal, "SIGBREAK", None)):
        if sig is not None:
            try:
                signal.signal(sig, signal_handler)
            except Exception:
                pass


def acquire_instance_lock():
    global instance_lock_file
    lock_path = os.path.abspath("localdnsguard.lock")
    instance_lock_file = open(lock_path, "a+", encoding="utf-8")
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(instance_lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            instance_lock_file.close()
            instance_lock_file = None
            return False
    else:
        import fcntl

        try:
            fcntl.flock(instance_lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            instance_lock_file.close()
            instance_lock_file = None
            return False
    instance_lock_file.seek(0)
    instance_lock_file.truncate()
    instance_lock_file.write(str(os.getpid()))
    instance_lock_file.flush()
    return True


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


db = connect_db()


def init_db():
    with db_lock:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_tokens (
                token TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL DEFAULT 'global',
                client TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                comment TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS upstreams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 53,
                resolver TEXT NOT NULL DEFAULT '',
                resolver_type TEXT NOT NULL DEFAULT 'plain_udp',
                transport TEXT NOT NULL DEFAULT 'udp',
                enabled INTEGER NOT NULL DEFAULT 1,
                latency_ms REAL,
                last_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS query_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                normalized_domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                status TEXT NOT NULL,
                response_ips TEXT NOT NULL DEFAULT '',
                upstream TEXT NOT NULL DEFAULT '',
                connection_type TEXT NOT NULL DEFAULT '',
                matched_rule TEXT NOT NULL DEFAULT '',
                cache_status TEXT NOT NULL DEFAULT 'miss',
                blocked INTEGER NOT NULL DEFAULT 0,
                blocked_reason TEXT NOT NULL DEFAULT '',
                matched_list TEXT NOT NULL DEFAULT '',
                duration_ms REAL NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_query_timestamp ON query_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_query_domain ON query_log(normalized_domain);
            CREATE INDEX IF NOT EXISTS idx_query_client ON query_log(client_ip);
            CREATE INDEX IF NOT EXISTS idx_query_blocked ON query_log(blocked);
            CREATE INDEX IF NOT EXISTS idx_rules_comment ON rules(comment);
            CREATE INDEX IF NOT EXISTS idx_rules_enabled_action_pattern ON rules(enabled, action, pattern_type, pattern);
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
            CREATE TABLE IF NOT EXISTS upstream_health (
                upstream_id INTEGER PRIMARY KEY,
                latency_ms REAL NOT NULL DEFAULT 0,
                success_rate REAL NOT NULL DEFAULT 1.0,
                timeout_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                last_checked REAL NOT NULL DEFAULT 0,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                paused INTEGER NOT NULL DEFAULT 0,
                total_queries INTEGER NOT NULL DEFAULT 0,
                successful_queries INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE CASCADE
            );
            """
        )
        db.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (time.time(),))
        defaults = {
            "filtering_enabled": "1",
            "cache_enabled": "1",
            "cache_ttl": "300",
            "cache_size": "4194304",
            "cache_min_ttl": "0",
            "cache_max_ttl": "0",
            "cache_optimistic": "0",
            "disable_ipv6": "0",
            "upstream_mode": "sequential",
            "upstream_timeout": "2.5",
            "block_mode": "zero_ip",
            "block_response_ttl": "60",
            "custom_block_ipv4": "0.0.0.0",
            "custom_block_ipv6": "::",
            "lan_only": "1",
            "dnssec_validation_enabled": "0",
            "filter_update_interval_hours": "24",
            "allowed_networks": "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7",
            "query_log_enabled": "1",
            "admin_password_set": "0",
            "log_retention_days": "7",
            "auto_clear_query_log_hours": "0",
            "localdnsguard_web_host": WEB_HOST,
            "localdnsguard_web_port": str(WEB_PORT),
            "localdnsguard_dns_host": DNS_HOST,
            "localdnsguard_dns_port": str(DNS_PORT),
            "encrypted_dns_host": ENCRYPTED_DNS_HOST,
            "encrypted_dns_domain": ENCRYPTED_DNS_DOMAIN,
            "dns_over_tls_enabled": "0",
            "dns_over_tls_port": str(DNS_TLS_PORT),
            "dns_over_https_enabled": "0",
            "dns_over_https_port": str(DNS_HTTPS_PORT),
            "dns_over_quic_enabled": "0",
            "dns_over_quic_port": str(DNS_QUIC_PORT),
            "encrypted_dns_certificate_pem": "",
            "encrypted_dns_private_key_pem": "",
        }
        for key, value in defaults.items():
            db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, value))
        load_runtime_network_settings()
        if not db.execute("SELECT 1 FROM settings WHERE key=?", (API_TOKEN_SETTING,)).fetchone():
            token = secrets.token_urlsafe(32)
            db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (API_TOKEN_SETTING, token))
            db.execute("INSERT OR IGNORE INTO api_tokens(token,name,created_at) VALUES(?,?,?)", (token, "default", now_iso()))
        else:
            token = db.execute("SELECT value FROM settings WHERE key=?", (API_TOKEN_SETTING,)).fetchone()["value"]
            if token:
                db.execute("INSERT OR IGNORE INTO api_tokens(token,name,created_at) VALUES(?,?,?)", (token, "default", now_iso()))
        run_migrations()
        global blocklist_manager
        if blocklist_manager is None:
            blocklist_manager = BlocklistManager(db, reload_callback=reload_filter_engine)
            blocklist_manager.init_schema()
        global client_manager
        if client_manager is None:
            client_manager = ClientManager(db, reload_callback=reload_filter_engine)
            client_manager.init_schema()
        if not db.execute("SELECT 1 FROM upstreams WHERE enabled=1").fetchone():
            db.execute(
                "INSERT INTO upstreams(name,address,port,resolver,resolver_type,transport,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)",
                ("Cloudflare DoT", "1.1.1.1", 853, DEFAULT_UPSTREAM, "dot", "tls", 1, now_iso()),
            )
        for upstream in db.execute("SELECT * FROM upstreams WHERE resolver='' OR resolver IS NULL").fetchall():
            parsed = detect_upstream(upstream["address"])
            db.execute(
                "UPDATE upstreams SET resolver=?, resolver_type=?, transport=? WHERE id=?",
                (parsed["resolver"], parsed["type"], parsed["transport"], upstream["id"]),
            )
        db.execute("UPDATE upstreams SET latency_ms=NULL WHERE last_error<>'' AND latency_ms > 1000")
        backfill_clients_from_querylog()
        db.commit()


MIGRATIONS = [
    (1, "add matched_list to query_log", lambda: _ensure_column("query_log", "matched_list", "TEXT NOT NULL DEFAULT ''")),
    (2, "add resolver columns to upstreams", lambda: (
        _ensure_column("upstreams", "resolver", "TEXT NOT NULL DEFAULT ''"),
        _ensure_column("upstreams", "resolver_type", "TEXT NOT NULL DEFAULT 'plain_udp'"),
        _ensure_column("upstreams", "transport", "TEXT NOT NULL DEFAULT 'udp'"),
    )),

    (4, "normalize query_log timestamps", lambda: db.execute("""
        UPDATE query_log
        SET timestamp = REPLACE(SUBSTR(timestamp, 1, 19), 'T', ' ')
        WHERE timestamp LIKE '%T%'
    """)),
    (5, "add composite indexes for dashboard queries", lambda: db.executescript("""
        CREATE INDEX IF NOT EXISTS idx_query_ts_domain ON query_log(timestamp, normalized_domain);
        CREATE INDEX IF NOT EXISTS idx_query_ts_client ON query_log(timestamp, client_ip);
        CREATE INDEX IF NOT EXISTS idx_query_blocked_ts_domain ON query_log(blocked, timestamp, normalized_domain);
        CREATE INDEX IF NOT EXISTS idx_query_ts_blocked ON query_log(timestamp, blocked);
    """)),
    (6, "add client_name profile_name to query_log", lambda: (
        _ensure_column("query_log", "client_name", "TEXT NOT NULL DEFAULT ''"),
        _ensure_column("query_log", "profile_name", "TEXT NOT NULL DEFAULT ''"),
    )),
    (11, "add connection_type to query_log", lambda: (
        _ensure_column("query_log", "connection_type", "TEXT NOT NULL DEFAULT ''"),
        db.execute("UPDATE query_log SET connection_type='UDP' WHERE connection_type='' OR connection_type IS NULL"),
    )),
    (7, "migrate clients to profile schema", lambda: _migrate_clients_table()),
    (8, "add upstream_health columns", lambda: (
        _ensure_column("upstreams", "latency_ms", "REAL"),
        _ensure_column("upstreams", "last_error", "TEXT NOT NULL DEFAULT ''"),
        _ensure_column("upstreams", "success_rate", "REAL NOT NULL DEFAULT 1.0"),
        _ensure_column("upstreams", "timeout_count", "INTEGER NOT NULL DEFAULT 0"),
        _ensure_column("upstreams", "last_checked", "REAL NOT NULL DEFAULT 0"),
        _ensure_column("upstreams", "consecutive_failures", "INTEGER NOT NULL DEFAULT 0"),
        _ensure_column("upstreams", "total_queries", "INTEGER NOT NULL DEFAULT 0"),
        _ensure_column("upstreams", "successful_queries", "INTEGER NOT NULL DEFAULT 0"),
    )),
    (9, "create audit_log and upstream_health tables", lambda: db.executescript("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
        CREATE TABLE IF NOT EXISTS upstream_health (
            upstream_id INTEGER PRIMARY KEY,
            latency_ms REAL NOT NULL DEFAULT 0,
            success_rate REAL NOT NULL DEFAULT 1.0,
            timeout_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            last_checked REAL NOT NULL DEFAULT 0,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            paused INTEGER NOT NULL DEFAULT 0,
            total_queries INTEGER NOT NULL DEFAULT 0,
            successful_queries INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE CASCADE
        );
    """)),
    (10, "add safesearch youtube service columns to profiles", lambda: db.executescript("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            is_default INTEGER NOT NULL DEFAULT 0,
            filtering_enabled INTEGER NOT NULL DEFAULT 1,
            safe_search_google INTEGER NOT NULL DEFAULT 0,
            safe_search_bing INTEGER NOT NULL DEFAULT 0,
            safe_search_ddg INTEGER NOT NULL DEFAULT 0,
            youtube_restricted INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS profile_service_blocks (
            profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            service_name TEXT NOT NULL,
            PRIMARY KEY (profile_id, service_name)
        );
    """)),
]


def run_migrations():
    applied = {r["version"] for r in db.execute("SELECT version FROM schema_migrations").fetchall()}
    for version, name, fn in MIGRATIONS:
        if version not in applied:
            try:
                fn()
            except Exception as exc:
                print(f"Migration {version} ({name}) failed: {exc}", flush=True)
                raise
            db.execute("INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)", (version, name, now_iso()))
            print(f"Migration {version} ({name}) applied.", flush=True)


def _ensure_column(table, column, definition):
    existing = [row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in existing:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migrate_clients_table():
    existing = [row["name"] for row in db.execute("PRAGMA table_info(clients)").fetchall()]
    if "address" in existing:
        with db_lock:
            old = db.execute("SELECT * FROM clients").fetchall()
            db.execute("DROP TABLE IF EXISTS clients")
            db.commit()
        global client_manager
        if client_manager is not None:
            client_manager.init_schema()
            default = db.execute("SELECT id FROM profiles WHERE is_default=1").fetchone()
            default_id = default["id"] if default else None
            now = now_iso()
            for row in old:
                ip = row["address"]
                name = row["name"]
                db.execute(
                    "INSERT OR IGNORE INTO clients(name,ip,cidr,profile_id,filtering_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (name, ip, ip if "/" in ip else "", default_id, row.get("filtering_enabled", 1), now, now),
                )
            db.commit()


def discover_system_dns_servers():
    if os.name != "nt":
        return []
    try:
        output = subprocess.check_output(["ipconfig", "/all"], text=True, errors="ignore", timeout=3)
    except Exception:
        return []
    servers = []
    capture = False
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            capture = False
            continue
        if "DNS-Server" in stripped or "DNS Servers" in stripped:
            capture = True
            value = stripped.split(":", 1)[-1].strip()
        elif capture and re.match(r"^[0-9a-fA-F:.%]+$", stripped):
            value = stripped
        else:
            continue
        try:
            ip = ipaddress.ip_address(value.split("%", 1)[0])
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback and str(ip) not in servers:
            servers.append(str(ip))
    return servers


def get_setting(key, default=""):
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    with db_lock:
        db.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        db.commit()


def parse_port(value, default, name):
    try:
        port = int(str(value).strip())
    except ValueError:
        raise ValueError(f"{name} must be a number")
    if port < 0 or port > 65535:
        raise ValueError(f"{name} must be between 0 and 65535")
    return port


def parse_positive_float(value, default, name):
    try:
        number = float(str(value).strip())
    except ValueError:
        raise ValueError(f"{name} must be a number")
    if number <= 0:
        raise ValueError(f"{name} must be greater than 0")
    return number


def certificate_matches_name(cert, server_name):
    server_name = (server_name or "").strip().lower().rstrip(".")
    if not server_name:
        return True
    try:
        ip = ipaddress.ip_address(server_name)
    except ValueError:
        ip = None
    names = []
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if ip is not None:
            return ip in san.get_values_for_type(x509.IPAddress)
        names.extend(n.lower().rstrip(".") for n in san.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    try:
        from cryptography.x509.oid import NameOID
        names.extend(attr.value.lower().rstrip(".") for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    except Exception:
        pass
    for name in names:
        if name == server_name:
            return True
        if name.startswith("*.") and server_name.endswith(name[1:]) and server_name.count(".") == name.count("."):
            return True
    return False


def validate_certificate_pair(certificate_pem, private_key_pem, server_name=""):
    certificate_pem = (certificate_pem or "").strip()
    private_key_pem = (private_key_pem or "").strip()
    if not certificate_pem and not private_key_pem:
        return
    if not certificate_pem.startswith("-----BEGIN CERTIFICATE-----"):
        raise ValueError("Certificate must start with -----BEGIN CERTIFICATE-----")
    if not private_key_pem.startswith(("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----")):
        raise ValueError("Private key must start with -----BEGIN RSA PRIVATE KEY----- or -----BEGIN PRIVATE KEY-----")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ValueError("Certificate validation requires cryptography")
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        cert_public = cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:
        raise ValueError(f"Certificate/private key could not be loaded: {exc}")
    if cert_public != key_public:
        raise ValueError("Certificate and private key do not match")
    if server_name and not certificate_matches_name(cert, server_name):
        raise ValueError(f"Certificate is valid for the key, but not for {server_name}")


def encrypted_dns_readiness():
    domain = get_setting("encrypted_dns_domain", ENCRYPTED_DNS_DOMAIN).strip()
    cert = get_setting("encrypted_dns_certificate_pem", "")
    key = get_setting("encrypted_dns_private_key_pem", "")
    tls_enabled = get_setting("dns_over_tls_enabled", "0") == "1"
    https_enabled = get_setting("dns_over_https_enabled", "0") == "1"
    quic_enabled = get_setting("dns_over_quic_enabled", "0") == "1"
    issues = []
    if not domain:
        issues.append("Public DNS Domain is not set")
    if not cert.strip():
        issues.append("Certificate PEM is not set")
    if not key.strip():
        issues.append("Private Key PEM is not set")
    if (tls_enabled or https_enabled or quic_enabled) and cert.strip() and key.strip():
        try:
            validate_certificate_pair(cert, key, domain)
        except Exception as exc:
            issues.append(str(exc))
    return {
        "domain": domain,
        "tls_enabled": tls_enabled,
        "https_enabled": https_enabled,
        "quic_enabled": quic_enabled,
        "certificate_configured": bool(cert.strip()),
        "private_key_configured": bool(key.strip()),
        "ready": not issues,
        "issues": issues,
    }


def encrypted_dns_runtime_state():
    tls_running = False
    https_running = False
    quic_running = False
    for srv in encrypted_dns_servers:
        if isinstance(srv, DoQRuntimeServer):
            quic_running = srv.thread is not None and srv.thread.is_alive() and srv.error is None
        elif isinstance(srv, ReusableThreadingHTTPSServer):
            https_running = True
        elif isinstance(srv, ReusableThreadingTLSDNSServer):
            tls_running = True
    with doq_metrics_lock:
        metrics = dict(doq_metrics)
    return {"tls_running": tls_running, "https_running": https_running, "quic_running": quic_running, "doq_metrics": metrics}


def update_doq_metric(key, value=None):
    with doq_metrics_lock:
        if value is None:
            doq_metrics[key] = int(doq_metrics.get(key, 0)) + 1
        else:
            doq_metrics[key] = value


def log_doq_event(message):
    try:
        with open("web-error.log", "a", encoding="utf-8") as log:
            log.write(f"{now_iso()} dns-over-quic {message}\n")
    except Exception:
        pass


def write_temp_pem_files(certificate_pem, private_key_pem):
    cert_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".crt")
    key_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".key")
    try:
        cert_file.write(certificate_pem.strip() + "\n")
        key_file.write(private_key_pem.strip() + "\n")
        cert_file.close()
        key_file.close()
        return cert_file.name, key_file.name
    except Exception:
        try:
            cert_file.close()
            key_file.close()
        finally:
            for path in (cert_file.name, key_file.name):
                try:
                    os.unlink(path)
                except Exception:
                    pass
        raise


def make_encrypted_dns_ssl_context():
    cert = get_setting("encrypted_dns_certificate_pem", "")
    key = get_setting("encrypted_dns_private_key_pem", "")
    validate_certificate_pair(cert, key, get_setting("encrypted_dns_domain", ""))
    if not cert.strip() or not key.strip():
        raise ValueError("DNS-over-TLS/QUIC requires a certificate and private key")
    cert_path, key_path = write_temp_pem_files(cert, key)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        return context
    finally:
        for path in (cert_path, key_path):
            try:
                os.unlink(path)
            except Exception:
                pass


def load_runtime_network_settings():
    global WEB_HOST, WEB_PORT, DNS_HOST, DNS_PORT, ENCRYPTED_DNS_HOST, ENCRYPTED_DNS_DOMAIN, DNS_TLS_PORT, DNS_QUIC_PORT, DNS_HTTPS_PORT
    WEB_HOST = get_setting("localdnsguard_web_host", WEB_HOST).strip() or "0.0.0.0"
    WEB_PORT = parse_port(get_setting("localdnsguard_web_port", WEB_PORT), WEB_PORT, "Web port")
    DNS_HOST = get_setting("localdnsguard_dns_host", DNS_HOST).strip() or "0.0.0.0"
    DNS_PORT = parse_port(get_setting("localdnsguard_dns_port", DNS_PORT), DNS_PORT, "DNS port")
    ENCRYPTED_DNS_HOST = get_setting("encrypted_dns_host", DNS_HOST).strip() or DNS_HOST
    ENCRYPTED_DNS_DOMAIN = get_setting("encrypted_dns_domain", ENCRYPTED_DNS_DOMAIN).strip()
    DNS_TLS_PORT = parse_port(get_setting("dns_over_tls_port", DNS_TLS_PORT), DNS_TLS_PORT, "DNS-over-TLS port")
    DNS_HTTPS_PORT = parse_port(get_setting("dns_over_https_port", DNS_HTTPS_PORT), DNS_HTTPS_PORT, "DNS-over-HTTPS port")
    DNS_QUIC_PORT = parse_port(get_setting("dns_over_quic_port", DNS_QUIC_PORT), DNS_QUIC_PORT, "DNS-over-QUIC port")


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password, stored):
    try:
        return bcrypt.checkpw(password.encode(), stored.encode())
    except Exception:
        return False


def log_admin_action(username, action, details="", ip=""):
    try:
        db.execute(
            "INSERT INTO audit_log(timestamp,username,action,details,ip) VALUES(?,?,?,?,?)",
            (now_iso(), username, action, details[:500], ip or ""),
        )
        db.commit()
    except Exception:
        pass


def check_login_rate_limit(ip):
    now = time.time()
    with _login_rate_limit_lock:
        attempts = _login_attempts.setdefault(ip, [])
        attempts[:] = [t for t in attempts if now - t < LOGIN_RATE_WINDOW]
        if len(attempts) >= LOGIN_RATE_LIMIT:
            return False
        attempts.append(now)
        return True


def reset_login_rate_limit(ip):
    with _login_rate_limit_lock:
        _login_attempts.pop(ip, None)


def _ensure_upstream_health(upstream_id):
    db.execute(
        "INSERT OR IGNORE INTO upstream_health(upstream_id,consecutive_failures) VALUES(?,0)",
        (upstream_id,),
    )
    db.commit()


def update_upstream_health(upstream_id, success, latency_ms=0, error=""):
    try:
        with db_lock:
            _ensure_upstream_health(upstream_id)
            row = db.execute("SELECT * FROM upstream_health WHERE upstream_id=?", (upstream_id,)).fetchone()
            if not row:
                return
            total = row["total_queries"] + 1
            successful = row["successful_queries"] + (1 if success else 0)
            success_rate = successful / total if total > 0 else 1.0
            timeout_count = row["timeout_count"] + (1 if not success else 0)
            consecutive = (row["consecutive_failures"] + 1) if not success else 0
            if success and consecutive == 0:
                paused = 0
            elif not success and consecutive >= 5:
                paused = 1
            else:
                paused = row["paused"]
            db.execute(
                """UPDATE upstream_health SET
                    latency_ms=?, success_rate=?, timeout_count=?,
                    last_error=?, last_checked=?, consecutive_failures=?,
                    paused=?, total_queries=?, successful_queries=?
                WHERE upstream_id=?""",
                (latency_ms if success else row["latency_ms"],
                 success_rate, timeout_count,
                 error[:500] if error else "", time.time(),
                 consecutive, paused, total, successful, upstream_id),
            )
            if paused and not row["paused"]:
                log_admin_action("system", "upstream_auto_paused",
                                 f"Upstream {upstream_id} auto-paused after {consecutive} consecutive failures", "")
            db.commit()
    except Exception:
        pass


def get_upstream_health(upstream_id):
    db.execute("INSERT OR IGNORE INTO upstream_health(upstream_id,consecutive_failures) VALUES(?,0)", (upstream_id,))
    db.commit()
    return dict(db.execute("SELECT * FROM upstream_health WHERE upstream_id=?", (upstream_id,)).fetchone() or {"upstream_id": upstream_id})


def _healthcheck_worker():
    while True:
        try:
            time.sleep(60)
            _healthcheck_worker_pass()
        except Exception:
            pass


def _healthcheck_worker_pass():
    upstreams = rows("SELECT id,name,address,port,resolver,resolver_type,transport FROM upstreams WHERE enabled=1")
    if not upstreams:
        return
    _, query = build_query("google.com", 1)
    for up in upstreams:
        try:
            _ensure_upstream_health(up["id"])
            start = time.perf_counter()
            response, _ = _query_one_upstream(up, query, update_metrics=False, timeout_override=3.0)
            rtt = (time.perf_counter() - start) * 1000
            if response and len(response) >= 12:
                update_upstream_health(up["id"], True, rtt)
            else:
                update_upstream_health(up["id"], False, 0, "empty response")
        except Exception as e:
            update_upstream_health(up["id"], False, 0, str(e)[:200])
    with _healthcheck_lock:
        global _healthcheck_last_run
        _healthcheck_last_run = time.time()


def rows(query, params=()):
    return [dict(r) for r in db.execute(query, params).fetchall()]


def one(query, params=()):
    row = db.execute(query, params).fetchone()
    return dict(row) if row else None


def normalize_domain(domain):
    domain = (domain or "").strip().rstrip(".").lower()
    if not domain:
        return ""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    64: "SVCB",
    65: "HTTPS",
}
QTYPE_CODE = {v: k for k, v in QTYPE_MAP.items()}


def parse_qname(packet, offset):
    labels = []
    jumped = False
    end_offset = offset
    seen = set()
    while True:
        if offset >= len(packet):
            raise ValueError("invalid qname")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("invalid pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("recursive pointer")
            seen.add(pointer)
            if not jumped:
                end_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            if not jumped:
                end_offset = offset
            break
        labels.append(packet[offset : offset + length].decode("ascii", errors="ignore"))
        offset += length
    return ".".join(labels), end_offset


def parse_dns_question(packet):
    if len(packet) < 12:
        raise ValueError("packet too small")
    tid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if qdcount < 1:
        raise ValueError("no question")
    domain, offset = parse_qname(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("invalid question")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return {
        "id": tid,
        "flags": flags,
        "domain": domain,
        "normalized_domain": normalize_domain(domain),
        "qtype": qtype,
        "qtype_name": QTYPE_MAP.get(qtype, str(qtype)),
        "qclass": qclass,
        "question_end": offset + 4,
    }


def encode_qname(domain):
    out = b""
    for part in normalize_domain(domain).split("."):
        if part:
            raw = part.encode("ascii")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(domain, qtype):
    tid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = encode_qname(domain) + struct.pack("!HH", qtype, 1)
    return tid, header + question


def build_error_response(request, rcode):
    header = bytearray(request[:12])
    flags = struct.unpack("!H", header[2:4])[0]
    flags = 0x8000 | 0x0080 | (flags & 0x0100) | rcode
    header[2:4] = struct.pack("!H", flags)
    header[6:12] = b"\x00\x00\x00\x00\x00\x00"
    return bytes(header) + request[12:]


def build_empty_response(request):
    header = bytearray(request[:12])
    flags = struct.unpack("!H", header[2:4])[0]
    flags = 0x8000 | 0x0080 | (flags & 0x0100)
    header[2:4] = struct.pack("!H", flags)
    header[6:12] = b"\x00\x00\x00\x00\x00\x00"
    return bytes(header) + request[12:]


def dns_response_rcode(response):
    if not response or len(response) < 4:
        return None
    return response[3] & 0x0F


def build_ip_response(request, ip_text, ttl=60):
    question = parse_dns_question(request)
    qtype = question["qtype"]
    if ":" in ip_text and qtype != 28:
        return build_empty_response(request)
    if "." in ip_text and qtype != 1:
        return build_empty_response(request)
    rdata = socket.inet_pton(socket.AF_INET6 if ":" in ip_text else socket.AF_INET, ip_text)
    header = struct.pack("!HHHHHH", question["id"], 0x8180, 1, 1, 0, 0)
    question_part = request[12 : question["question_end"]]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    return header + question_part + answer


def block_response_ttl():
    try:
        return max(0, int(get_setting("block_response_ttl", "60") or "60"))
    except ValueError:
        return 60


def build_block_response(request, qtype_name=None):
    mode = get_setting("block_mode", "zero_ip")
    if mode == "refused":
        return build_error_response(request, 5)
    if mode == "nxdomain":
        return build_error_response(request, 3)
    if mode == "nodata":
        return build_empty_response(request)
    if mode == "drop":
        return None
    if mode not in ("zero_ip", "custom_ip"):
        mode = "zero_ip"
    if mode == "custom_ip":
        ip = get_setting("custom_block_ipv6", "::") if qtype_name == "AAAA" else get_setting("custom_block_ipv4", "0.0.0.0")
    else:
        ip = "::" if qtype_name == "AAAA" else "0.0.0.0"
    return build_ip_response(request, ip, ttl=block_response_ttl())


def strip_svcb_ipv6hint_rdata(packet, rdata):
    try:
        if len(rdata) < 3:
            return rdata
        priority = rdata[:2]
        offset = 2
        while offset < len(rdata):
            length = rdata[offset]
            offset += 1
            if length == 0:
                break
            if offset + length > len(rdata):
                return rdata
            offset += length
        params = rdata[offset:]
        out_params = b""
        p = 0
        while p + 4 <= len(params):
            key, value_len = struct.unpack("!HH", params[p : p + 4])
            p += 4
            value = params[p : p + value_len]
            if len(value) != value_len:
                return rdata
            p += value_len
            if key != 6:
                out_params += struct.pack("!HH", key, value_len) + value
        if p != len(params):
            return rdata
        return priority + rdata[2:offset] + out_params
    except Exception:
        return rdata


def apply_ipv6_disabled_policy(response):
    if get_setting("disable_ipv6", "0") != "1":
        return response
    try:
        question = parse_dns_question(response)
        if question["qtype_name"] == "AAAA":
            return build_empty_response(response)
        counts = list(struct.unpack("!HHHH", response[4:12]))
        total_rrs = counts[1] + counts[2] + counts[3]
        offset = question["question_end"]
        rebuilt = bytearray(response[:offset])
        changed = False
        for _ in range(total_rrs):
            rr_start = offset
            _, offset = parse_qname(response, offset)
            if offset + 10 > len(response):
                return response
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", response[offset : offset + 10])
            header_start = offset
            rdata_start = offset + 10
            rdata_end = rdata_start + rdlen
            if rdata_end > len(response):
                return response
            rdata = response[rdata_start:rdata_end]
            new_rdata = rdata
            if rtype in (QTYPE_CODE["HTTPS"], QTYPE_CODE["SVCB"]):
                new_rdata = strip_svcb_ipv6hint_rdata(response, rdata)
                changed = changed or new_rdata != rdata
            rebuilt += response[rr_start:header_start]
            rebuilt += struct.pack("!HHIH", rtype, rclass, ttl, len(new_rdata))
            rebuilt += new_rdata
            offset = rdata_end
        if offset != len(response):
            rebuilt += response[offset:]
        return bytes(rebuilt) if changed else response
    except Exception:
        return response


def is_lan_allowed(client_ip):
    if get_setting("lan_only", "1") != "1":
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
        nets = [n.strip() for n in get_setting("allowed_networks", "").split(",") if n.strip()]
        return any(ip in ipaddress.ip_network(net, strict=False) for net in nets)
    except ValueError:
        return False


def backfill_clients_from_querylog():
    known = {r["ip"] for r in db.execute("SELECT ip FROM clients").fetchall()}
    rows = db.execute("SELECT DISTINCT client_ip FROM query_log WHERE client_ip <> ''").fetchall()
    for row in rows:
        ip = row["client_ip"]
        if ip in known:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        known.add(ip)
        now = now_iso()
        db.execute(
            "INSERT OR IGNORE INTO clients(name,ip,cidr,filtering_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (ip, ip, "", 1, now, now),
        )


def ensure_client(client_ip):
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        return
    existing = one("SELECT id FROM clients WHERE ip=?", (client_ip,))
    if existing:
        return
    try:
        with db_lock:
            now = now_iso()
            db.execute(
                "INSERT OR IGNORE INTO clients(name,ip,cidr,filtering_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (client_ip, client_ip, "", 1, now, now),
            )
            db.commit()
    except Exception:
        pass


def client_filtering_enabled(client_ip):
    if client_manager is not None:
        c = client_manager.get_client_by_ip(client_ip)
        if c:
            return bool(c.get("filtering_enabled", 1))
        return True
    for client in rows("SELECT * FROM clients WHERE enabled=1"):
        address = client.get("address") or client.get("ip", "")
        try:
            if "/" in address and ipaddress.ip_address(client_ip) in ipaddress.ip_network(address, strict=False):
                return bool(client.get("filtering_enabled", 1))
            if client_ip == address:
                return bool(client.get("filtering_enabled", 1))
        except ValueError:
            pass
    return True


def pattern_matches(pattern_type, pattern, domain):
    pattern = normalize_domain(pattern)
    domain = normalize_domain(domain)
    if not pattern or not domain:
        return False
    if pattern_type == "domain":
        return domain == pattern or domain.endswith("." + pattern)
    if pattern_type == "exact":
        return domain == pattern
    if pattern_type == "wildcard":
        expr = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
        return re.match(expr, domain) is not None
    if pattern_type == "regex":
        try:
            return re.search(pattern, domain, re.IGNORECASE) is not None
        except re.error:
            return False
    return False


def invalidate_rules_cache():
    global rules_cache
    with rules_lock:
        rules_cache = None
    reload_filter_engine()
    clear_dns_cache()


def rebuild_rules_cache_background():
    # Custom-rule cache is small now, so rebuild synchronously and avoid
    # background workers that can keep the process busy after huge imports.
    global rules_cache
    with rules_lock:
        rules_cache = build_rules_cache()


def build_rules_cache():
    cache = {
        "rewrite": {"domain": {}, "exact": {}, "wildcard": [], "regex": []},
        "allow": {"domain": {}, "exact": {}, "wildcard": [], "regex": []},
        "block": {"domain": {}, "exact": {}, "wildcard": [], "regex": []},
    }
    data = rows(
        """
        SELECT id,scope,client,action,pattern_type,pattern,target,comment
        FROM rules
        WHERE enabled=1
        ORDER BY
          CASE action WHEN 'rewrite' THEN 0 WHEN 'allow' THEN 1 WHEN 'block' THEN 2 ELSE 3 END,
          id ASC
        """
    )
    for rule in data:
        action = rule["action"]
        pattern_type = rule["pattern_type"]
        if action not in cache or pattern_type not in cache[action]:
            continue
        pattern = normalize_domain(rule["pattern"])
        if not pattern:
            continue
        stored = dict(rule)
        stored["pattern"] = pattern
        if pattern_type in ("domain", "exact"):
            cache[action][pattern_type].setdefault(pattern, stored)
        elif pattern_type == "regex":
            try:
                stored["compiled"] = re.compile(rule["pattern"], re.IGNORECASE)
                cache[action]["regex"].append(stored)
            except re.error:
                continue
        else:
            cache[action][pattern_type].append(stored)
    return cache


def get_rules_cache():
    global rules_cache
    with rules_lock:
        if rules_cache is not None:
            return rules_cache
        if rules_cache_rebuild_running:
            return {
                "rewrite": {"domain": {}, "exact": {}, "wildcard": [], "regex": []},
                "allow": {"domain": {}, "exact": {}, "wildcard": [], "regex": []},
                "block": {"domain": {}, "exact": {}, "wildcard": [], "regex": []},
            }
        rules_cache = build_rules_cache()
        return rules_cache


def domain_suffixes(domain):
    parts = normalize_domain(domain).split(".")
    for i in range(len(parts)):
        yield ".".join(parts[i:])


def extract_response_addresses(response, wanted_type):
    addresses = []
    try:
        question = parse_dns_question(response)
        offset = question["question_end"]
        ancount = struct.unpack("!H", response[6:8])[0]
        family = socket.AF_INET if wanted_type == 1 else socket.AF_INET6
        rdlen_expected = 4 if wanted_type == 1 else 16
        for _ in range(ancount):
            _, offset = parse_qname(response, offset)
            rtype, _, _, rdlen = struct.unpack("!HHIH", response[offset : offset + 10])
            offset += 10
            rdata = response[offset : offset + rdlen]
            offset += rdlen
            if rtype == wanted_type and rdlen == rdlen_expected:
                addresses.append(socket.inet_ntop(family, rdata))
    except Exception:
        pass
    return addresses


def extract_cname_targets(packet: bytes) -> list[str]:
    targets = []
    try:
        question = parse_dns_question(packet)
        offset = question["question_end"]
        ancount = struct.unpack("!H", packet[6:8])[0]
        for _ in range(ancount):
            _, offset = parse_qname(packet, offset)
            if offset + 10 > len(packet):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10
            rdata_offset = offset
            offset += rdlen
            if rtype == QTYPE_CODE["CNAME"]:
                target, _ = parse_qname(packet, rdata_offset)
                normalized = normalize_domain(target)
                if normalized:
                    targets.append(normalized)
    except Exception:
        return []
    return list(dict.fromkeys(targets))


def query_plain_upstream(upstream, request, timeout=2.5):
    if upstream.get("transport") == "tcp":
        with socket.create_connection((upstream["address"], int(upstream["port"])), timeout=timeout) as s:
            s.sendall(struct.pack("!H", len(request)) + request)
            header = s.recv(2)
            if len(header) != 2:
                raise OSError("short TCP DNS length header")
            length = struct.unpack("!H", header)[0]
            chunks = []
            remaining = length
            while remaining:
                chunk = s.recv(remaining)
                if not chunk:
                    raise OSError("short TCP DNS response")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(request, (upstream["address"], int(upstream["port"])))
        response, _ = s.recvfrom(4096)
        return response


def read_http_response(conn, max_bytes=65_536):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < max_bytes:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
    header, _, body = data.partition(b"\r\n\r\n")
    header_text = header.decode("latin1", errors="ignore")
    status_line = header_text.splitlines()[0] if header_text else ""
    if " 200 " not in status_line:
        raise OSError(status_line or "DoH HTTP response failed")
    content_length = None
    for line in header_text.splitlines()[1:]:
        if line.lower().startswith("content-length:"):
            try:
                content_length = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
            break
    if content_length is not None:
        while len(body) < content_length and len(data) < max_bytes:
            chunk = conn.recv(min(65536, content_length - len(body)))
            if not chunk:
                break
            body += chunk
            data += chunk
        return body[:content_length]
    if "transfer-encoding: chunked" in header_text.lower():
        decoded = b""
        rest = body
        while len(data) < max_bytes:
            while b"\r\n" not in rest and len(data) < max_bytes:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                rest += chunk
                data += chunk
            size_line, _, rest = rest.partition(b"\r\n")
            if not size_line:
                break
            size = int(size_line.split(b";", 1)[0], 16)
            if size == 0:
                break
            while len(rest) < size + 2 and len(data) < max_bytes:
                chunk = conn.recv(min(65536, size + 2 - len(rest)))
                if not chunk:
                    break
                rest += chunk
                data += chunk
            if len(rest) < size:
                break
            decoded += rest[:size]
            rest = rest[size + 2 :]
        return decoded
    return body


def doh_authority(host, port):
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return display_host if int(port) == 443 else f"{display_host}:{int(port)}"


def doh_request_parts(resolver):
    parsed = urlparse(resolver)
    if parsed.scheme not in ("https", "doh", "doh3", "h3"):
        raise OSError("invalid DoH resolver URL")
    host = parsed.hostname
    if not host:
        raise OSError("DoH resolver host missing")
    port = parsed.port or 443
    path = parsed.path or "/dns-query"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, path


def resolve_upstream_host(host):
    if looks_like_ip(host):
        return [host]
    cached = doh_host_cache.get(host)
    if cached and cached["expires"] > time.time():
        return cached["ips"]
    ips = resolve_via_bootstrap_doh(host) or resolve_via_configured_dns(host)
    if ips:
        doh_host_cache[host] = {"ips": ips, "expires": time.time() + 3600}
        return ips
    return [host]


def query_doh_upstream(upstream, request, timeout=4.0):
    host, port, path = doh_request_parts(upstream["resolver"])
    authority = doh_authority(host, port)
    ips = resolve_upstream_host(host)
    last_error = None
    for i, ip in enumerate(ips[:4]):
        if i > 0:
            time.sleep(0.1)
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)
            with raw:
                raw.settimeout(timeout)
                context = ssl.create_default_context()
                conn = context.wrap_socket(raw, server_hostname=host)
                conn.settimeout(timeout)
                with conn:
                    http_request = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {authority}\r\n"
                        "User-Agent: PyGuardDNS/0.1\r\n"
                        "Accept: application/dns-message\r\n"
                        "Content-Type: application/dns-message\r\n"
                        f"Content-Length: {len(request)}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii") + request
                    conn.sendall(http_request)
                    response = read_http_response(conn)
                    if len(response) < 12:
                        raise OSError("short DoH DNS response")
                    return response
        except Exception as exc:
            last_error = exc
            continue
    raise OSError(str(last_error) if last_error else "DoH request failed")


def query_doh_http3_upstream(upstream, request, timeout=4.0):
    try:
        import asyncio
        from aioquic.asyncio import connect as quic_connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
    except ImportError:
        raise OSError("DoH HTTP/3 requires aioquic (pip install aioquic)")

    host, port, path = doh_request_parts(upstream["resolver"])
    server_name = host if not looks_like_ip(host) else None

    class _DoH3Protocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._h3 = H3Connection(self._quic)
            self._responses = {}
            self._done = {}

        def quic_event_received(self, event):
            for h3_event in self._h3.handle_event(event):
                stream_id = getattr(h3_event, "stream_id", None)
                if stream_id is None:
                    continue
                state = self._responses.setdefault(stream_id, {"headers": {}, "body": b""})
                if isinstance(h3_event, HeadersReceived):
                    state["headers"].update({k.decode("latin1"): v.decode("latin1") for k, v in h3_event.headers})
                    if h3_event.stream_ended and stream_id in self._done:
                        self._done[stream_id].set()
                elif isinstance(h3_event, DataReceived):
                    state["body"] += h3_event.data
                    if h3_event.stream_ended and stream_id in self._done:
                        self._done[stream_id].set()

        async def doh3_query(self, dns_request):
            import asyncio as _aio
            stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
            self._done[stream_id] = _aio.Event()
            headers = [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", host.encode("ascii")),
                (b":path", path.encode("ascii")),
                (b"user-agent", b"PyGuardDNS/0.1"),
                (b"accept", b"application/dns-message"),
                (b"content-type", b"application/dns-message"),
                (b"content-length", str(len(dns_request)).encode("ascii")),
            ]
            self._h3.send_headers(stream_id=stream_id, headers=headers)
            self._h3.send_data(stream_id=stream_id, data=dns_request, end_stream=True)
            self.transmit()
            await _aio.wait_for(self._done[stream_id].wait(), timeout=timeout)
            state = self._responses.get(stream_id, {})
            status = state.get("headers", {}).get(":status", "")
            if status != "200":
                raise OSError(f"DoH HTTP/3 response failed: {status or 'missing status'}")
            body = state.get("body", b"")
            if len(body) < 12:
                raise OSError("short DoH HTTP/3 DNS response")
            return body

    async def _run():
        cfg = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True)
        if server_name:
            cfg.server_name = server_name
        ips = resolve_upstream_host(host)
        last_err = None
        for ip in ips[:4]:
            try:
                async with quic_connect(ip, port, configuration=cfg, create_protocol=_DoH3Protocol) as proto:
                    return await proto.doh3_query(request)
            except Exception as exc:
                last_err = exc
                continue
        if last_err:
            message = str(last_err) or last_err.__class__.__name__
            raise OSError(message)
        raise OSError("DoH HTTP/3 request failed")

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_run())
    except OSError as exc:
        # Some DoH endpoints, including dns.cloudflare.com, are valid DoH hosts
        # but don't reliably answer HTTP/3. Keep the resolver usable by falling
        # back to regular DoH over TLS after an HTTP/3 failure.
        fallback = dict(upstream)
        fallback["resolver_type"] = "doh"
        try:
            return query_doh_upstream(fallback, request, timeout=timeout)
        except OSError:
            raise exc
    finally:
        loop.close()


def query_doh_stamp_upstream(upstream, request, timeout=4.0):
    parsed = parse_doh_stamp(upstream["resolver"])
    converted = dict(upstream)
    converted.update({
        "resolver": parsed["resolver"],
        "address": parsed["address"],
        "port": parsed["port"],
        "resolver_type": "doh",
        "transport": "https",
    })
    return query_doh_upstream(converted, request, timeout=timeout)


def query_dns_stamp_unknown_upstream(upstream, request, timeout=4.0):
    parsed = detect_upstream(upstream["resolver"])
    if parsed.get("type") == "dns_stamp_unknown" or not parsed.get("supported"):
        raise OSError("unsupported DNS stamp protocol")
    converted = dict(upstream)
    converted.update({
        "resolver": parsed["resolver"],
        "address": parsed["address"],
        "port": parsed["port"],
        "resolver_type": parsed["type"],
        "transport": parsed["transport"],
    })
    return _query_one_upstream(converted, request)[0]


def query_dot_upstream(upstream, request, timeout=4.0):
    return query_dot_upstream_pooled(upstream, request, timeout=timeout)


class DotConnection:
    def __init__(self, upstream, idle_timeout=60.0):
        self.upstream = dict(upstream)
        self.idle_timeout = idle_timeout
        self.conn = None
        self.lock = threading.Lock()
        self.last_used = 0.0
        self.handshake_count = 0
        self.reuse_count = 0
        self.reconnect_count = 0
        self.error_count = 0
        self._ip_index = 0

    def close(self):
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
        self.conn = None

    def _candidate_ips(self):
        host = self.upstream["address"]
        ips = resolve_via_configured_dns(host) if not looks_like_ip(host) else [host]
        if not ips:
            raise OSError("DoT resolver host did not resolve")
        return ips[:4]

    def connect(self, timeout=4.0):
        host = self.upstream["address"]
        port = int(self.upstream.get("port", 853))
        tls_name = self.upstream.get("tls_name") or self.upstream.get("hostname") or dot_tls_server_name(host)
        ips = self._candidate_ips()
        last_error = None
        start_index = self._ip_index % len(ips)
        ordered_ips = ips[start_index:] + ips[:start_index]
        for ip in ordered_ips:
            raw = None
            try:
                raw = socket.create_connection((ip, port), timeout=timeout)
                raw.settimeout(timeout)
                context = ssl.create_default_context()
                conn = context.wrap_socket(raw, server_hostname=tls_name)
                conn.settimeout(timeout)
                self.conn = conn
                self.last_used = time.time()
                self.handshake_count += 1
                self._ip_index = (ips.index(ip) + 1) % len(ips)
                return
            except Exception as exc:
                last_error = exc
                try:
                    if raw is not None:
                        raw.close()
                except Exception:
                    pass
        raise OSError(str(last_error) if last_error else "DoT connect failed")

    def query(self, request: bytes, timeout=4.0) -> bytes:
        with self.lock:
            try:
                self._ensure_connected(timeout)
                return self._send_and_receive(request, timeout)
            except Exception:
                self.error_count += 1
                self.reconnect_count += 1
                self.close()
                self.connect(timeout=timeout)
                return self._send_and_receive(request, timeout)

    def _ensure_connected(self, timeout):
        if self.conn is None or time.time() - self.last_used > self.idle_timeout:
            self.close()
            self.connect(timeout=timeout)
        else:
            self.reuse_count += 1

    def _send_and_receive(self, request: bytes, timeout=4.0) -> bytes:
        if len(request) > 65535:
            raise OSError("DoT DNS request too large")
        self.conn.settimeout(timeout)
        self.conn.sendall(struct.pack("!H", len(request)) + request)
        header = self._recv_exact(2)
        length = struct.unpack("!H", header)[0]
        if length < 12:
            raise OSError("invalid short DoT response")
        response = self._recv_exact(length)
        self.last_used = time.time()
        return response

    def _recv_exact(self, length: int) -> bytes:
        chunks = []
        remaining = length
        while remaining > 0:
            chunk = self.conn.recv(remaining)
            if not chunk:
                raise OSError("short DoT DNS response")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def metrics(self):
        return {
            "tls_handshake_count": self.handshake_count,
            "dot_reuse_count": self.reuse_count,
            "dot_reconnect_count": self.reconnect_count,
            "dot_error_count": self.error_count,
        }


def _dot_pool_key(upstream):
    resolver = upstream.get("resolver") or ""
    return f"{upstream.get('id', '')}:{resolver}:{upstream['address']}:{int(upstream.get('port', 853))}"


def query_dot_upstream_pooled(upstream, request, timeout=4.0):
    key = _dot_pool_key(upstream)
    with dot_pools_lock:
        pool = dot_pools.get(key)
        if pool is None:
            pool = DotConnection(upstream)
            dot_pools[key] = pool
    return pool.query(request, timeout=timeout)


def dot_pool_metrics():
    totals = {
        "tls_handshake_count": 0,
        "dot_reuse_count": 0,
        "dot_reconnect_count": 0,
        "dot_error_count": 0,
        "dot_pool_size": 0,
    }
    with dot_pools_lock:
        totals["dot_pool_size"] = len(dot_pools)
        pools = list(dot_pools.values())
    for pool in pools:
        with pool.lock:
            metrics = pool.metrics()
        for key, value in metrics.items():
            totals[key] += value
    return totals


def query_dot_upstream_once(upstream, request, timeout=4.0):
    host = upstream["address"]
    port = int(upstream["port"])
    ips = resolve_via_configured_dns(host) if not looks_like_ip(host) else [host]
    tls_name = upstream.get("tls_name") or upstream.get("hostname") or dot_tls_server_name(host)
    last_error = None
    for ip in ips[:4]:
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)
            with raw:
                raw.settimeout(timeout)
                context = ssl.create_default_context()
                conn = context.wrap_socket(raw, server_hostname=tls_name)
                conn.settimeout(timeout)
                with conn:
                    conn.sendall(struct.pack("!H", len(request)) + request)
                    header = conn.recv(2)
                    if len(header) != 2:
                        raise OSError("short DoT DNS length header")
                    length = struct.unpack("!H", header)[0]
                    chunks = []
                    remaining = length
                    while remaining:
                        chunk = conn.recv(remaining)
                        if not chunk:
                            raise OSError("short DoT DNS response")
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    return b"".join(chunks)
        except Exception as exc:
            last_error = exc
            continue
    raise OSError(str(last_error) if last_error else "DoT request failed")


def dot_tls_server_name(host):
    normalized = host.strip("[]").lower()
    known = {
        "1.1.1.1": "cloudflare-dns.com",
        "1.0.0.1": "cloudflare-dns.com",
        "2606:4700:4700::1111": "cloudflare-dns.com",
        "2606:4700:4700::1001": "cloudflare-dns.com",
        "8.8.8.8": "dns.google",
        "8.8.4.4": "dns.google",
        "2001:4860:4860::8888": "dns.google",
        "2001:4860:4860::8844": "dns.google",
        "9.9.9.9": "dns.quad9.net",
        "149.112.112.112": "dns.quad9.net",
        "2620:fe::fe": "dns.quad9.net",
        "2620:fe::9": "dns.quad9.net",
    }
    return known.get(normalized, normalized)


def query_doq_upstream(upstream, request, timeout=4.0):
    if os.environ.get("LOCALDNSGUARD_ENABLE_EXPERIMENTAL_DOQ_UPSTREAM", "0") != "1":
        raise OSError("DoQ upstream forwarding is experimental and disabled by default")
    try:
        import asyncio
        from aioquic.asyncio import connect as quic_connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived
    except ImportError:
        raise OSError("DoQ requires aioquic (pip install aioquic)")

    host = upstream["address"]
    port = int(upstream["port"])
    server_name = host if not looks_like_ip(host) else None

    class _DoQProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._stream_data = {}
            self._stream_done = {}

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                sid = event.stream_id
                self._stream_data[sid] = self._stream_data.get(sid, b"") + event.data
                if event.end_stream and sid in self._stream_done:
                    self._stream_done[sid].set()

        async def doq_query(self, dns_request):
            import asyncio as _aio
            sid = self._quic.get_next_available_stream_id(is_unidirectional=False)
            self._stream_done[sid] = _aio.Event()
            self._quic.send_stream_data(sid, struct.pack("!H", len(dns_request)) + dns_request, end_stream=True)
            self.transmit()
            await _aio.wait_for(self._stream_done[sid].wait(), timeout=timeout)
            data = self._stream_data.get(sid, b"")
            if len(data) < 2:
                raise OSError("DoQ: short response")
            length = struct.unpack("!H", data[:2])[0]
            response = data[2:2 + length]
            if len(response) < 12:
                raise OSError("DoQ: invalid DNS response")
            return response

    async def _run():
        cfg = QuicConfiguration(alpn_protocols=["doq"], is_client=True)
        if server_name:
            cfg.server_name = server_name
        ips = resolve_via_configured_dns(host) if not looks_like_ip(host) else [host]
        last_err = None
        for ip in ips[:4]:
            try:
                async with quic_connect(ip, port, configuration=cfg, create_protocol=_DoQProtocol) as proto:
                    return await proto.doq_query(request)
            except Exception as exc:
                last_err = exc
                continue
        raise OSError(str(last_err) if last_err else "DoQ failed")

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()


def _stamp_b64decode(payload):
    padding = "=" * ((4 - len(payload) % 4) % 4)
    return base64.urlsafe_b64decode(payload + padding)


def _read_stamp_lp(data, offset):
    if offset >= len(data):
        raise ValueError("truncated DNS stamp")
    length = data[offset]
    offset += 1
    if offset + length > len(data):
        raise ValueError("truncated DNS stamp field")
    return data[offset : offset + length], offset + length


def _read_stamp_vlp(data, offset):
    values = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS stamp")
        marker = data[offset]
        offset += 1
        more = bool(marker & 0x80)
        length = marker & 0x7F
        if offset + length > len(data):
            raise ValueError("truncated DNS stamp field")
        values.append(data[offset : offset + length])
        offset += length
        if not more:
            return values, offset


def parse_dnscrypt_stamp(stamp):
    if not stamp.startswith("sdns://"):
        raise ValueError("invalid DNSCrypt stamp")
    raw = _stamp_b64decode(stamp[7:])
    if len(raw) < 10 or raw[0] != 0x01:
        raise ValueError("not a DNSCrypt stamp")
    offset = 1 + 8
    address, offset = _read_stamp_lp(raw, offset)
    public_key, offset = _read_stamp_lp(raw, offset)
    provider_name, offset = _read_stamp_lp(raw, offset)
    if len(public_key) != 32:
        raise ValueError("DNSCrypt stamp has invalid provider public key")
    server = address.decode("utf-8", errors="ignore").strip()
    provider = provider_name.decode("utf-8", errors="ignore").strip()
    if not server or not provider:
        raise ValueError("DNSCrypt stamp is missing server address or provider name")
    host, port = split_host_port(server, 443)
    return {"address": host, "port": port, "provider_name": provider, "provider_public_key": public_key}


def parse_doh_stamp(stamp):
    if not stamp.startswith("sdns://"):
        raise ValueError("invalid DoH stamp")
    raw = _stamp_b64decode(stamp[7:])
    if len(raw) < 10 or raw[0] != 0x02:
        raise ValueError("not a DoH stamp")
    offset = 1 + 8
    address, offset = _read_stamp_lp(raw, offset)
    _, offset = _read_stamp_vlp(raw, offset)  # certificate hash pins; TLS validation is still done by ssl.
    hostname, offset = _read_stamp_lp(raw, offset)
    path, offset = _read_stamp_lp(raw, offset)
    addr = address.decode("utf-8", errors="ignore").strip()
    host_text = hostname.decode("utf-8", errors="ignore").strip()
    path_text = path.decode("utf-8", errors="ignore").strip() or "/dns-query"
    if not host_text:
        if not addr:
            raise ValueError("DoH stamp is missing hostname")
        host_text = addr
    host, port = split_host_port(host_text, 443)
    if not path_text.startswith("/"):
        path_text = "/" + path_text
    bracketed_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    resolver = f"https://{bracketed_host}{'' if port == 443 else ':' + str(port)}{path_text}"
    display_address = split_host_port(addr, port)[0] if addr else host
    return {"address": display_address, "port": port, "hostname": host, "path": path_text, "resolver": resolver}


def parse_plain_dns_stamp(stamp):
    if not stamp.startswith("sdns://"):
        raise ValueError("invalid plain DNS stamp")
    raw = _stamp_b64decode(stamp[7:])
    if len(raw) < 10 or raw[0] != 0x00:
        raise ValueError("not a plain DNS stamp")
    offset = 1 + 8
    address, offset = _read_stamp_lp(raw, offset)
    server = address.decode("utf-8", errors="ignore").strip()
    if not server:
        raise ValueError("plain DNS stamp is missing server address")
    host, port = split_host_port(server, 53)
    return {"address": host, "port": port}


def extract_txt_answers(response):
    answers = []
    try:
        question = parse_dns_question(response)
        offset = question["question_end"]
        ancount = struct.unpack("!H", response[6:8])[0]
        for _ in range(ancount):
            _, offset = parse_qname(response, offset)
            if offset + 10 > len(response):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", response[offset : offset + 10])
            offset += 10
            rdata = response[offset : offset + rdlen]
            offset += rdlen
            if rtype != QTYPE_CODE["TXT"]:
                continue
            pos = 0
            chunks = []
            while pos < len(rdata):
                length = rdata[pos]
                pos += 1
                chunks.append(rdata[pos : pos + length])
                pos += length
            answers.append(b"".join(chunks))
    except Exception:
        pass
    return answers


def fetch_dnscrypt_certificate(stamp_info, timeout=4.0):
    cache_key_value = f"{stamp_info['address']}:{stamp_info['port']}|{stamp_info['provider_name']}"
    cached = dnscrypt_cert_cache.get(cache_key_value)
    if cached and cached["expires"] > time.time():
        return cached["cert"]
    _, request = build_query(stamp_info["provider_name"], QTYPE_CODE["TXT"])
    response = query_plain_upstream(
        {"address": stamp_info["address"], "port": stamp_info["port"], "transport": "udp"},
        request,
        timeout=timeout,
    )
    now = int(time.time())
    best = None
    for txt in extract_txt_answers(response):
        try:
            cert = parse_dnscrypt_certificate(txt, stamp_info["provider_public_key"])
            if cert["not_before"] <= now <= cert["not_after"]:
                if best is None or cert["serial"] > best["serial"]:
                    best = cert
        except Exception:
            continue
    if not best:
        raise OSError("DNSCrypt certificate fetch failed")
    ttl = max(300, min(86400, best["not_after"] - now))
    dnscrypt_cert_cache[cache_key_value] = {"cert": best, "expires": time.time() + ttl}
    return best


def parse_dnscrypt_certificate(cert_data, provider_public_key):
    try:
        from nacl.signing import VerifyKey
    except ImportError:
        raise OSError("DNSCrypt requires PyNaCl (pip install pynacl)")
    if len(cert_data) < 124 or cert_data[:4] != b"DNSC":
        raise ValueError("invalid DNSCrypt certificate")
    es_version = struct.unpack("!H", cert_data[4:6])[0]
    if es_version != 1:
        raise ValueError(f"unsupported DNSCrypt encryption system: {es_version}")
    signature = cert_data[8:72]
    signed = cert_data[72:]
    VerifyKey(provider_public_key).verify(signed, signature)
    resolver_public_key = cert_data[72:104]
    client_magic = cert_data[104:112]
    serial, not_before, not_after = struct.unpack("!III", cert_data[112:124])
    return {
        "resolver_public_key": resolver_public_key,
        "client_magic": client_magic,
        "serial": serial,
        "not_before": not_before,
        "not_after": not_after,
    }


def pad_dnscrypt_query(request):
    target_len = max(256, ((len(request) + 1 + 63) // 64) * 64)
    return request + b"\x80" + (b"\x00" * (target_len - len(request) - 1))


def unpad_dnscrypt_response(response):
    pos = len(response) - 1
    while pos >= 0 and response[pos] == 0:
        pos -= 1
    if pos >= 12 and response[pos] == 0x80:
        return response[:pos]
    return response


def query_dnscrypt_upstream(upstream, request, timeout=4.0):
    try:
        from nacl.public import Box, PrivateKey, PublicKey
    except ImportError:
        raise OSError("DNSCrypt requires PyNaCl (pip install pynacl)")
    stamp_info = parse_dnscrypt_stamp(upstream["resolver"])
    cert = fetch_dnscrypt_certificate(stamp_info, timeout=timeout)
    client_key = PrivateKey.generate()
    box = Box(client_key, PublicKey(cert["resolver_public_key"]))
    client_nonce = secrets.token_bytes(12)
    nonce = client_nonce + (b"\x00" * 12)
    encrypted = box.encrypt(pad_dnscrypt_query(request), nonce).ciphertext
    packet = cert["client_magic"] + bytes(client_key.public_key) + client_nonce + encrypted
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (stamp_info["address"], int(stamp_info["port"])))
        response, _ = s.recvfrom(4096)
    if len(response) < 32:
        raise OSError("short DNSCrypt response")
    response_nonce = response[8:32]
    if not response_nonce.startswith(client_nonce):
        raise OSError("DNSCrypt response nonce mismatch")
    decrypted = box.decrypt(response[32:], response_nonce)
    decrypted = unpad_dnscrypt_response(decrypted)
    if len(decrypted) < 12:
        raise OSError("invalid DNSCrypt DNS response")
    return decrypted


def bootstrap_doh_query(provider_ip, provider_host, hostname, qtype):
    path = f"/dns-query?name={quote(hostname)}&type={quote(qtype)}"
    raw = socket.create_connection((provider_ip, 443), timeout=6)
    with raw:
        raw.settimeout(8)
        context = ssl.create_default_context()
        conn = context.wrap_socket(raw, server_hostname=provider_host)
        with conn:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {provider_host}\r\n"
                "Accept: application/dns-json\r\n"
                "User-Agent: PyGuardDNS/0.1\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            conn.sendall(request)
            data = b""
            while len(data) < 256_000:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
    _, _, body = data.partition(b"\r\n\r\n")
    payload = json.loads(body.decode("utf-8", errors="ignore"))
    return [answer["data"] for answer in payload.get("Answer", []) if answer.get("type") in (1, 28)]


def resolve_via_bootstrap_doh(hostname):
    providers = [
        ("1.1.1.1", "cloudflare-dns.com"),
        ("1.0.0.1", "cloudflare-dns.com"),
        ("8.8.8.8", "dns.google"),
        ("8.8.4.4", "dns.google"),
    ]
    addresses = []
    for qtype in ("A", "AAAA"):
        for ip, host in providers:
            try:
                addresses.extend(bootstrap_doh_query(ip, host, hostname, qtype))
                if addresses:
                    return list(dict.fromkeys(addresses))
            except Exception:
                continue
    return []


def resolve_via_configured_dns(hostname):
    # Do NOT use socket.getaddrinfo here: it goes through the OS system DNS which is likely
    # LocalDNSGuard itself, creating a recursive deadlock when resolving DoH/DoT hostnames.
    if looks_like_ip(hostname):
        return [hostname]
    addresses = []
    for qtype in (QTYPE_CODE["A"], QTYPE_CODE["AAAA"]):
        _, request = build_query(hostname, qtype)
        for upstream in active_upstreams():
            if not plain_upstream_supported(upstream):
                continue
            try:
                response = query_plain_upstream(upstream, request)
                addresses.extend(extract_response_addresses(response, qtype))
                if addresses:
                    return list(dict.fromkeys(addresses))
            except OSError:
                continue
    return resolve_via_bootstrap_doh(hostname)



def fetch_url_text(url, max_bytes=100_000_000):
    try:
        with urlopen(url, timeout=8) as response:
            return response.read(max_bytes).decode("utf-8", errors="ignore")
    except OSError as original_error:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise original_error
        ips = resolve_via_configured_dns(parsed.hostname)
        if not ips:
            raise original_error
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        last_error = original_error
        for ip in ips[:4]:
            try:
                raw = socket.create_connection((ip, port), timeout=6)
                with raw:
                    raw.settimeout(8)
                    conn = raw
                    if parsed.scheme == "https":
                        context = ssl.create_default_context()
                        conn = context.wrap_socket(raw, server_hostname=parsed.hostname)
                        conn.settimeout(8)
                    with conn:
                        request = (
                            f"GET {path} HTTP/1.1\r\n"
                            f"Host: {parsed.hostname}\r\n"
                            "User-Agent: PyGuardDNS/0.1\r\n"
                            "Accept: text/plain,*/*\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode("ascii")
                        conn.sendall(request)
                        data = b""
                        while len(data) < max_bytes + 8192:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                header, _, body = data.partition(b"\r\n\r\n")
                status_line = header.splitlines()[0].decode("latin1", errors="ignore") if header else ""
                if " 200 " not in status_line and " 301 " not in status_line and " 302 " not in status_line:
                    raise OSError(status_line or "HTTP download failed")
                return body[:max_bytes].decode("utf-8", errors="ignore")
            except OSError as exc:
                last_error = exc
                continue
        raise last_error


def split_host_port(value, default_port):
    value = value.strip()
    if value.startswith("[") and "]" in value:
        host, rest = value[1:].split("]", 1)
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return value, default_port


def looks_like_ip(value):
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def detect_dns_stamp_type(stamp):
    if not stamp.startswith("sdns://"):
        return ""
    payload = stamp[7:]
    try:
        raw = _stamp_b64decode(payload)
    except Exception:
        return "dns_stamp_unknown"
    if not raw:
        return "dns_stamp_unknown"
    protocol = raw[0]
    return {
        0x00: "plain_dns_stamp",
        0x01: "dnscrypt_stamp",
        0x02: "doh_stamp",
        0x03: "dot_stamp",
        0x04: "doq_stamp",
    }.get(protocol, "dns_stamp_unknown")


def detect_upstream(resolver):
    raw = (resolver or "").strip()
    if not raw:
        raw = DEFAULT_UPSTREAM
    lower = raw.lower()
    result = {
        "resolver": raw,
        "address": raw,
        "port": 53,
        "type": "plain_udp_host",
        "transport": "udp",
        "supported": True,
        "label": "Regular DNS over UDP (hostname)",
    }

    if lower.startswith("sdns://"):
        stamp_type = detect_dns_stamp_type(raw)
        labels = {
            "plain_dns_stamp": "DNS stamp: regular DNS resolver",
            "dnscrypt_stamp": "DNS stamp: DNSCrypt resolver",
            "doh_stamp": "DNS stamp: DNS-over-HTTPS resolver",
            "dot_stamp": "DNS stamp: DNS-over-TLS resolver",
            "doq_stamp": "DNS stamp: DNS-over-QUIC resolver",
            "dns_stamp_unknown": "DNS stamp: unknown resolver type",
        }
        if stamp_type == "dnscrypt_stamp":
            try:
                parsed_stamp = parse_dnscrypt_stamp(raw)
                result.update({
                    "address": parsed_stamp["address"],
                    "port": parsed_stamp["port"],
                    "type": stamp_type,
                    "transport": "dnscrypt",
                    "supported": True,
                    "label": labels[stamp_type],
                })
            except Exception as exc:
                result.update({"address": raw, "port": 0, "type": stamp_type, "transport": "dnscrypt", "supported": False, "label": f"{labels[stamp_type]} ({exc})"})
        elif stamp_type == "plain_dns_stamp":
            try:
                parsed_stamp = parse_plain_dns_stamp(raw)
                resolver_type = "plain_udp_host" if not looks_like_ip(parsed_stamp["address"]) else "plain_udp"
                result.update({
                    "address": parsed_stamp["address"],
                    "port": parsed_stamp["port"],
                    "type": resolver_type,
                    "transport": "udp",
                    "supported": True,
                    "label": labels[stamp_type],
                })
            except Exception as exc:
                result.update({"address": raw, "port": 0, "type": stamp_type, "transport": "udp", "supported": False, "label": f"{labels[stamp_type]} ({exc})"})
        elif stamp_type == "doh_stamp":
            try:
                parsed_stamp = parse_doh_stamp(raw)
                result.update({
                    "resolver": parsed_stamp["resolver"],
                    "address": parsed_stamp["address"],
                    "port": parsed_stamp["port"],
                    "type": "doh",
                    "transport": "https",
                    "supported": True,
                    "label": labels[stamp_type],
                })
            except Exception as exc:
                result.update({"address": raw, "port": 0, "type": stamp_type, "transport": "https", "supported": False, "label": f"{labels[stamp_type]} ({exc})"})
        else:
            result.update({"address": raw, "port": 0, "type": stamp_type, "transport": "stamp", "supported": False, "label": labels.get(stamp_type, labels["dns_stamp_unknown"])})
        return result

    schemes = [
        ("doh3://", "doh_http3", "https", 443, "Encrypted DNS-over-HTTPS with forced HTTP/3"),
        ("h3://", "doh_http3", "https", 443, "Encrypted DNS-over-HTTPS with forced HTTP/3"),
        ("https://", "doh", "https", 443, "Encrypted DNS-over-HTTPS"),
        ("tls://", "dot", "tls", 853, "Encrypted DNS-over-TLS"),
        ("quic://", "doq", "quic", 853, "Encrypted DNS-over-QUIC"),
        ("doq://", "doq", "quic", 853, "Encrypted DNS-over-QUIC"),
        ("tcp://", "plain_tcp", "tcp", 53, "Regular DNS over TCP"),
        ("udp://", "plain_udp", "udp", 53, "Regular DNS over UDP"),
    ]
    for prefix, resolver_type, transport, default_port, label in schemes:
        if lower.startswith(prefix):
            rest = raw[len(prefix) :]
            if resolver_type in ("doh", "doh_http3"):
                host_part = rest.split("/", 1)[0]
                host, port = split_host_port(host_part, default_port)
                result.update({"address": host, "port": port, "type": resolver_type, "transport": transport, "supported": True, "label": label})
            else:
                host, port = split_host_port(rest.split("/", 1)[0], default_port)
                suffix = " (with port)" if ":" in rest and not rest.startswith("[") else ""
                if not looks_like_ip(host):
                    suffix = " (hostname)"
                supported = resolver_type in ("plain_udp", "plain_tcp", "dot")
                if resolver_type == "doq":
                    label += " (experimental, disabled by default)"
                result.update({"address": host, "port": port, "type": resolver_type + ("_host" if not looks_like_ip(host) and resolver_type in ("plain_udp", "plain_tcp") else ""), "transport": transport, "supported": supported, "label": label + suffix})
            return result

    host, port = split_host_port(raw, 53)
    is_ip = looks_like_ip(host)
    has_port = port != 53 or (raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit())
    label = "Regular DNS over UDP"
    resolver_type = "plain_udp"
    transport = "udp"
    supported = True
    if has_port and port == 853:
        label = "Encrypted DNS-over-QUIC, inferred from port 853 (experimental, disabled by default)"
        resolver_type = "doq"
        transport = "quic"
        supported = False
    elif has_port:
        label = "Regular DNS over UDP, with port"
    elif not is_ip:
        label = "Regular DNS over UDP, hostname"
        resolver_type = "plain_udp_host"
    result.update({"address": host, "port": port, "type": resolver_type, "transport": transport, "supported": supported, "label": label})
    return result


def decide(domain, qtype_name, client_ip):
    normalized = normalize_domain(domain)
    if not is_lan_allowed(client_ip):
        return {"status": "refused", "action": "refuse", "rule": "access control", "reason": "client not allowed"}
    filtering_on = get_setting("filtering_enabled", "1") == "1" and client_filtering_enabled(client_ip)

    profile_id = None
    client_info = None
    if client_manager is not None:
        client_info = client_manager.get_client_by_ip(client_ip)
        if client_info:
            profile_id = client_info.get("profile_id")

    engine = get_filter_engine()
    result = engine.check(normalized, filtering_enabled=filtering_on, profile_id=profile_id)

    client_name = client_info.get("name", "") if client_info else ""
    profile_name = client_info.get("profile_name", "") if client_info else ""

    base = {
        "client_name": client_name,
        "profile_name": profile_name,
        "profile_id": profile_id,
    }

    matched_rule = result.matched_rule or result.matched_domain or result.reason
    if result.action == "REFUSED":
        base.update({"status": "refused", "action": "refuse", "rule": matched_rule, "filter_list": result.list_name or "", "reason": result.reason})
    elif result.action == "ALLOW":
        base.update({"status": "allowed", "action": "allow", "rule": matched_rule, "filter_list": result.list_name or "", "reason": result.reason})
    elif result.action == "REWRITE":
        base.update({"status": "rewritten", "action": "rewrite", "target": result.answer_ip or "", "rule": matched_rule, "filter_list": result.list_name or "", "reason": result.reason})
    elif result.action == "BLOCK":
        base.update({"status": "blocked", "action": "block", "rule": matched_rule, "filter_list": result.list_name or "", "reason": result.reason})
    else:
        base.update({"status": "allowed", "action": "allow", "rule": "", "reason": "no matching rule"})
    return base


def cache_key(domain, qtype_name):
    return f"{normalize_domain(domain)}|{qtype_name}"


def get_cached(domain, qtype_name):
    global cache_bytes_used
    if get_setting("cache_enabled", "1") != "1":
        return None
    key = cache_key(domain, qtype_name)
    with cache_lock:
        item = dns_cache.get(key)
        if not item:
            return None
        if item["expires"] > time.time():
            return item["response"]
        if get_setting("cache_optimistic", "0") == "1" and not item.get("stale_refresh"):
            item["stale_refresh"] = True
            threading.Thread(target=_refresh_stale_cache_entry, args=(domain, qtype_name, key), daemon=True).start()
            return item["response"]
        evicted = dns_cache.pop(key, None)
        if evicted:
            cache_bytes_used -= len(evicted.get("response", b""))
    return None


def _refresh_stale_cache_entry(domain, qtype_name, key):
    global cache_bytes_used
    try:
        qtype_code = QTYPE_CODE.get(qtype_name)
        if not qtype_code:
            with cache_lock:
                evicted = dns_cache.pop(key, None)
                if evicted:
                    cache_bytes_used -= len(evicted.get("response", b""))
            return
        _, request = build_query(domain, qtype_code)
        response, _ = forward_query(request)
        set_cached(domain, qtype_name, response)
    except Exception:
        with cache_lock:
            evicted = dns_cache.pop(key, None)
            if evicted:
                cache_bytes_used -= len(evicted.get("response", b""))


def set_cached(domain, qtype_name, response):
    global cache_bytes_used
    if get_setting("cache_enabled", "1") != "1":
        return
    ttl = int(get_setting("cache_ttl", "300") or "300")
    min_ttl_v = int(get_setting("cache_min_ttl", "0") or "0")
    max_ttl_v = int(get_setting("cache_max_ttl", "0") or "0")
    if min_ttl_v > 0:
        ttl = max(ttl, min_ttl_v)
    if max_ttl_v > 0:
        ttl = min(ttl, max_ttl_v)
    max_bytes = int(get_setting("cache_size", "4194304") or "4194304")
    key = cache_key(domain, qtype_name)
    entry_size = len(response)
    with cache_lock:
        old = dns_cache.pop(key, None)
        if old:
            cache_bytes_used -= len(old.get("response", b""))
        while cache_bytes_used + entry_size > max_bytes and dns_cache:
            oldest_key = next(iter(dns_cache))
            evicted = dns_cache.pop(oldest_key, None)
            if evicted:
                cache_bytes_used -= len(evicted.get("response", b""))
        dns_cache[key] = {"expires": time.time() + ttl, "response": response}
        cache_bytes_used += entry_size


def cache_stats():
    now = time.time()
    with cache_lock:
        entries = len(dns_cache)
        expired = sum(1 for item in dns_cache.values() if item.get("expires", 0) <= now)
        bytes_used = cache_bytes_used
        soonest_expiry = min((item.get("expires", 0) for item in dns_cache.values()), default=0)
    row = one("""
        SELECT
          COUNT(*) total,
          COALESCE(SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END),0) hits,
          COALESCE(SUM(CASE WHEN cache_status='miss' THEN 1 ELSE 0 END),0) misses
        FROM query_log
        WHERE timestamp >= datetime('now','localtime','-24 hours')
    """)
    total = row["total"] if row else 0
    hits = row["hits"] if row else 0
    misses = row["misses"] if row else 0
    max_bytes = int(get_setting("cache_size", "4194304") or "4194304")
    return {
        "enabled": get_setting("cache_enabled", "1") == "1",
        "entries": entries,
        "expired_entries": expired,
        "bytes_used": bytes_used,
        "max_bytes": max_bytes,
        "usage_percent": round((bytes_used / max_bytes * 100) if max_bytes else 0, 1),
        "hits_24h": hits,
        "misses_24h": misses,
        "hit_rate_24h": round((hits / total * 100) if total else 0, 1),
        "ttl_seconds": int(get_setting("cache_ttl", "300") or "300"),
        "min_ttl_seconds": int(get_setting("cache_min_ttl", "0") or "0"),
        "max_ttl_seconds": int(get_setting("cache_max_ttl", "0") or "0"),
        "next_expiry_seconds": max(0, round(soonest_expiry - now)) if soonest_expiry else None,
    }


def clear_dns_cache():
    global cache_bytes_used
    with cache_lock:
        dns_cache.clear()
        cache_bytes_used = 0
    return {"ok": True, "entries": 0, "bytes_used": 0}


def is_local_reverse_lookup(normalized, qtype_name):
    return qtype_name == "PTR" and normalized in {
        "1.0.0.127.in-addr.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    }


def is_local_nodata_query(qtype_name):
    return qtype_name in ("HTTPS", "SVCB")


def active_upstreams():
    return rows(
        """
        SELECT u.*,
               COALESCE(uh.paused,0) AS health_paused,
               uh.success_rate, uh.timeout_count, uh.consecutive_failures,
               uh.last_checked, uh.total_queries, uh.successful_queries
        FROM upstreams u
        LEFT JOIN upstream_health uh ON uh.upstream_id=u.id
        WHERE u.enabled=1 AND COALESCE(uh.paused,0)=0
        ORDER BY
          CASE WHEN u.last_error='' THEN 0 ELSE 1 END,
          CASE WHEN u.latency_ms IS NULL THEN 999999 ELSE u.latency_ms END,
          u.id ASC
        """
    )


def plain_upstream_supported(upstream):
    return upstream.get("transport") in ("udp", "tcp") and upstream.get("resolver_type") in ("plain_udp", "plain_udp_host", "plain_tcp", "plain_tcp_host")


def upstream_supported(upstream):
    return plain_upstream_supported(upstream) or upstream.get("resolver_type") in ("doh", "doh_stamp", "doh_http3", "dot", "dnscrypt_stamp", "dns_stamp_unknown", "plain_dns_stamp")


def probe_upstream(upstream):
    if not upstream_supported(upstream):
        raise OSError(f"{upstream['resolver_type']} forwarding is detected but not implemented yet")
    _, request = build_query("example.com", QTYPE_CODE["A"])
    start = time.perf_counter()
    if upstream.get("resolver_type") == "doh":
        query_doh_upstream(upstream, request, timeout=4.0)
    elif upstream.get("resolver_type") == "doh_stamp":
        query_doh_stamp_upstream(upstream, request, timeout=4.0)
    elif upstream.get("resolver_type") == "doh_http3":
        query_doh_http3_upstream(upstream, request, timeout=4.0)
    elif upstream.get("resolver_type") == "dot":
        query_dot_upstream(upstream, request, timeout=4.0)
    elif upstream.get("resolver_type") == "doq":
        raise OSError("DoQ upstream forwarding is experimental and disabled by default")
    elif upstream.get("resolver_type") == "dnscrypt_stamp":
        query_dnscrypt_upstream(upstream, request, timeout=4.0)
    elif upstream.get("resolver_type") in ("dns_stamp_unknown", "plain_dns_stamp"):
        query_dns_stamp_unknown_upstream(upstream, request, timeout=4.0)
    elif upstream.get("transport") == "tcp":
        query_plain_upstream(upstream, request, timeout=5.0)
    else:
        query_plain_upstream(upstream, request, timeout=5.0)
    return round((time.perf_counter() - start) * 1000, 2)


def test_upstream(upstream_id):
    upstream = one("SELECT * FROM upstreams WHERE id=?", (upstream_id,))
    if not upstream:
        raise ValueError("upstream not found")
    try:
        if upstream.get("resolver_type") == "doh":
            probe_upstream(upstream)
        latency = probe_upstream(upstream)
        with db_lock:
            db.execute("UPDATE upstreams SET latency_ms=?, last_error='' WHERE id=?", (latency, upstream_id))
            db.commit()
        return {"ok": True, "latency_ms": latency}
    except Exception as exc:
        with db_lock:
            db.execute("UPDATE upstreams SET latency_ms=NULL, last_error=? WHERE id=?", (str(exc), upstream_id))
            db.commit()
        return {"ok": False, "error": str(exc)}


FALLBACK_DOT_DNS = [
    {"name": "fallback", "address": "1.1.1.1", "port": 853, "transport": "tls", "resolver_type": "dot", "resolver": "tls://cloudflare-dns.com"},
    {"name": "fallback", "address": "8.8.8.8", "port": 853, "transport": "tls", "resolver_type": "dot", "resolver": "tls://dns.google"},
]


def _query_fallback_plain(request):
    for fb in FALLBACK_DOT_DNS:
        try:
            response = query_dot_upstream(fb, request, timeout=4.0)
            return response, f"fallback-dot ({fb['address']})"
        except OSError:
            continue
    raise OSError("no upstream available and all fallback resolvers failed")


def record_upstream_queue_wait(wait_seconds):
    wait_ms = max(0.0, wait_seconds * 1000)
    with upstream_queue_wait_lock:
        upstream_queue_wait_samples.append(wait_ms)
        if len(upstream_queue_wait_samples) > 2000:
            del upstream_queue_wait_samples[:1000]


def upstream_queue_wait_metrics():
    with upstream_queue_wait_lock:
        samples = list(upstream_queue_wait_samples)
    if not samples:
        return {"upstream_queue_wait_ms_avg": 0.0, "upstream_queue_wait_ms_p95": 0.0}
    samples.sort()
    avg = sum(samples) / len(samples)
    p95 = samples[min(len(samples) - 1, int(len(samples) * 0.95))]
    return {"upstream_queue_wait_ms_avg": round(avg, 3), "upstream_queue_wait_ms_p95": round(p95, 3)}


def forward_query(request):
    wait_start = time.perf_counter()
    if not upstream_concurrency.acquire(timeout=3.0):
        record_upstream_queue_wait(time.perf_counter() - wait_start)
        raise OSError("upstream busy")
    record_upstream_queue_wait(time.perf_counter() - wait_start)
    try:
        return _forward_query(request)
    finally:
        upstream_concurrency.release()


def _query_one_upstream(upstream, request, update_metrics=True, timeout_override=None):
    start = time.perf_counter()
    configured_timeout = parse_positive_float(get_setting("upstream_timeout", "2.5"), 2.5, "Upstream timeout")
    timeout = timeout_override or configured_timeout
    if upstream.get("resolver_type") == "doh":
        response = query_doh_upstream(upstream, request, timeout=timeout)
    elif upstream.get("resolver_type") == "doh_stamp":
        response = query_doh_stamp_upstream(upstream, request, timeout=timeout)
    elif upstream.get("resolver_type") == "doh_http3":
        response = query_doh_http3_upstream(upstream, request, timeout=timeout)
    elif upstream.get("resolver_type") == "dot":
        response = query_dot_upstream(upstream, request, timeout=timeout)
    elif upstream.get("resolver_type") == "doq":
        raise OSError("DoQ upstream forwarding is experimental and disabled by default")
    elif upstream.get("resolver_type") == "dnscrypt_stamp":
        response = query_dnscrypt_upstream(upstream, request, timeout=timeout)
    elif upstream.get("resolver_type") in ("dns_stamp_unknown", "plain_dns_stamp"):
        response = query_dns_stamp_unknown_upstream(upstream, request, timeout=timeout)
    else:
        response = query_plain_upstream(upstream, request, timeout=timeout)
    latency = (time.perf_counter() - start) * 1000
    if update_metrics:
        maybe_update_upstream_status(upstream, latency=latency, error="")
    label = f"{upstream.get('name', 'upstream')} ({upstream['resolver_type']} {upstream['address']}:{upstream['port']})"
    return response, label


def _forward_query(request):
    mode = get_setting("upstream_mode", "sequential")
    if mode == "parallel_fastest":
        return _forward_query_parallel(request)
    if mode == "load_balance":
        return _forward_query_loadbalance(request)
    upstreams = active_upstreams()
    last_error = ""
    for upstream in upstreams:
        if not upstream_supported(upstream):
            last_error = f"{upstream['resolver_type']} not yet supported"
            continue
        try:
            return _query_one_upstream(upstream, request)
        except OSError as exc:
            last_error = str(exc)
            maybe_update_upstream_status(upstream, latency=None, error=last_error)
    if not upstreams:
        return _query_fallback_plain(request)
    raise OSError(last_error or "no upstream available")


def _forward_query_parallel(request):
    upstreams = [u for u in active_upstreams() if upstream_supported(u)]
    if not upstreams:
        return _query_fallback_plain(request)
    first = [None]
    errors = []
    lock = threading.Lock()
    done = threading.Event()

    def try_one(upstream):
        try:
            result = _query_one_upstream(upstream, request)
            with lock:
                if first[0] is None:
                    first[0] = result
                    done.set()
        except OSError as exc:
            maybe_update_upstream_status(upstream, latency=None, error=str(exc))
            with lock:
                errors.append(str(exc))
                if len(errors) >= len(upstreams):
                    done.set()

    for u in upstreams:
        threading.Thread(target=try_one, args=(u,), daemon=True).start()
    done.wait(timeout=3.5)
    if first[0] is not None:
        return first[0]
    raise OSError(errors[-1] if errors else "all upstreams timed out")


def _forward_query_loadbalance(request):
    global _upstream_rr_index
    upstreams = [u for u in active_upstreams() if upstream_supported(u)]
    if not upstreams:
        return _query_fallback_plain(request)
    with _upstream_rr_lock:
        idx = _upstream_rr_index % len(upstreams)
        _upstream_rr_index = (_upstream_rr_index + 1) % max(1, len(upstreams))
    ordered = upstreams[idx:] + upstreams[:idx]
    last_error = ""
    for upstream in ordered:
        try:
            return _query_one_upstream(upstream, request)
        except OSError as exc:
            last_error = str(exc)
            maybe_update_upstream_status(upstream, latency=None, error=last_error)
    raise OSError(last_error or "no upstream available")


def maybe_update_upstream_status(upstream, latency=None, error=""):
    upstream_id = upstream["id"]
    now = time.time()
    if now - upstream_metric_last_write.get(upstream_id, 0) < 5:
        return
    upstream_metric_last_write[upstream_id] = now
    try:
        with db_lock:
            if error:
                db.execute("UPDATE upstreams SET latency_ms=NULL, last_error=? WHERE id=?", (error, upstream_id))
            else:
                previous = upstream.get("latency_ms")
                value = latency
                if previous is not None:
                    value = (float(previous) * 0.65) + (latency * 0.35)
                db.execute("UPDATE upstreams SET latency_ms=?, last_error='' WHERE id=?", (round(value, 2), upstream_id))
        if error:
            update_upstream_health(upstream_id, False, 0, error)
        elif latency is not None:
            update_upstream_health(upstream_id, True, latency)
    except Exception:
        pass


def extract_response_ips(response):
    ips = []
    try:
        question = parse_dns_question(response)
        offset = question["question_end"]
        ancount = struct.unpack("!H", response[6:8])[0]
        for _ in range(ancount):
            _, offset = parse_qname(response, offset)
            rtype, _, _, rdlen = struct.unpack("!HHIH", response[offset : offset + 10])
            offset += 10
            rdata = response[offset : offset + rdlen]
            offset += rdlen
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == 28 and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    except Exception:
        pass
    return ",".join(ips)


def log_query(client_ip, domain, normalized, qtype_name, status, response_ips="", upstream="", matched_rule="", cache_status="miss", blocked=0, reason="", duration_ms=0, matched_list="", client_name="", profile_name="", connection_type=""):
    if get_setting("query_log_enabled", "1") != "1":
        return
    with db_write_lock:
        if len(db_write_queue) >= 20000:
            return
        db_write_queue.append((now_iso(), client_ip or "", domain or "", normalized or "", qtype_name or "", status or "", response_ips or "", upstream or "", connection_type or "", matched_rule or "", cache_status or "miss", blocked or 0, reason or "", matched_list or "", duration_ms or 0, client_name or "", profile_name or ""))


def db_writer_loop():
    while True:
        batch = []
        with db_write_lock:
            if db_write_queue:
                batch = db_write_queue[:500]
                del db_write_queue[:500]
        if not batch:
            time.sleep(0.1)
            continue
        try:
            with db_lock:
                batch = [
                    tuple((0 if idx in (11, 14) else "") if value is None else value for idx, value in enumerate(item))
                    for item in batch
                ]
                db.executemany(
                    """
                    INSERT INTO query_log(timestamp,client_ip,domain,normalized_domain,query_type,status,response_ips,upstream,connection_type,matched_rule,cache_status,blocked,blocked_reason,matched_list,duration_ms,client_name,profile_name)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    batch,
                )
                db.commit()
        except Exception:
            with open("web-error.log", "a", encoding="utf-8") as log:
                log.write(f"{now_iso()} db_writer_loop\n{traceback.format_exc()}\n")


def start_db_writer():
    threading.Thread(target=db_writer_loop, name="db-writer", daemon=True).start()


def db_maintenance_loop():
    last_vacuum_setting = "db_last_vacuum"
    while True:
        try:
            days = int(get_setting("log_retention_days", "7") or "7")
            if days > 0:
                cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
                with db_lock:
                    db.execute("DELETE FROM query_log WHERE timestamp < ?", (cutoff,))
                    db.commit()
        except Exception:
            pass
        try:
            hours = int(get_setting("auto_clear_query_log_hours", "0") or "0")
            if hours > 0:
                last_clear = float(get_setting("query_log_last_auto_clear", "0") or "0")
                if last_clear == 0 or (time.time() - last_clear) >= hours * 3600:
                    with db_lock:
                        db.execute("DELETE FROM query_log")
                        db.commit()
                    set_setting("query_log_last_auto_clear", str(time.time()))
        except Exception:
            pass
        try:
            db.execute("PRAGMA optimize")
        except Exception:
            pass
        try:
            last_vacuum = get_setting(last_vacuum_setting, "0")
            if last_vacuum == "0" or (time.time() - float(last_vacuum)) > 86400:
                db.execute("VACUUM")
                set_setting(last_vacuum_setting, str(time.time()))
        except Exception:
            pass
        time.sleep(3600)


def log_query_sync(client_ip, domain, normalized, qtype_name, status, response_ips="", upstream="", matched_rule="", cache_status="miss", blocked=0, reason="", duration_ms=0, matched_list="", client_name="", profile_name="", connection_type=""):
    if get_setting("query_log_enabled", "1") != "1":
        return
    with db_lock:
        db.execute(
            """
            INSERT INTO query_log(timestamp,client_ip,domain,normalized_domain,query_type,status,response_ips,upstream,connection_type,matched_rule,cache_status,blocked,blocked_reason,matched_list,duration_ms,client_name,profile_name)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (now_iso(), client_ip, domain, normalized, qtype_name, status, response_ips, upstream, connection_type, matched_rule, cache_status, blocked, reason, matched_list, duration_ms, client_name, profile_name),
        )
        db.commit()


def handle_dns_request(request, client_ip, connection_type=""):
    started = time.perf_counter()
    ensure_client(client_ip)
    client_info = client_manager.get_client_by_ip(client_ip) if client_manager else None
    client_log_name = client_info.get("name", "") if client_info else ""
    client_profile_name = (client_info.get("profile_name", "") or "") if client_info else ""
    try:
        question = parse_dns_question(request)
        domain = question["domain"]
        normalized = question["normalized_domain"]
        qtype_name = question["qtype_name"]

        if get_setting("disable_ipv6", "0") == "1" and qtype_name == "AAAA":
            response = build_empty_response(request)
            log_query(client_ip, domain, normalized, qtype_name, "blocked", matched_rule="ipv6 disabled", blocked=1, reason="ipv6_disabled", duration_ms=(time.perf_counter() - started) * 1000, client_name=client_log_name, profile_name=client_profile_name, connection_type=connection_type)
            return response

        if is_local_reverse_lookup(normalized, qtype_name):
            response = build_empty_response(request)
            log_query(client_ip, domain, normalized, qtype_name, "local", matched_rule="local reverse", cache_status="local", reason="local reverse lookup", duration_ms=(time.perf_counter() - started) * 1000, client_name=client_log_name, profile_name=client_profile_name, connection_type=connection_type)
            return response

        decision = decide(normalized, qtype_name, client_ip)
        dc = decision.get("client_name", "")
        dp = decision.get("profile_name", "")

        if decision["action"] == "refuse":
            response = build_error_response(request, 5)
            log_query(client_ip, domain, normalized, qtype_name, "refused", matched_rule=decision["rule"], blocked=1, reason=decision["reason"], duration_ms=(time.perf_counter() - started) * 1000, matched_list=decision.get("filter_list", ""), client_name=dc, profile_name=dp, connection_type=connection_type)
            return response
        if decision["action"] == "block":
            response = build_block_response(request, qtype_name)
            log_query(client_ip, domain, normalized, qtype_name, "blocked", matched_rule=decision["rule"], blocked=1, reason=decision["reason"], duration_ms=(time.perf_counter() - started) * 1000, matched_list=decision.get("filter_list", ""), client_name=dc, profile_name=dp, connection_type=connection_type)
            return response
        if decision["action"] == "rewrite":
            response = build_ip_response(request, decision["target"])
            log_query(client_ip, domain, normalized, qtype_name, "rewritten", response_ips=decision["target"], matched_rule=decision["rule"], reason=decision["reason"], duration_ms=(time.perf_counter() - started) * 1000, matched_list=decision.get("filter_list", ""), client_name=dc, profile_name=dp, connection_type=connection_type)
            return response

        if is_local_nodata_query(qtype_name):
            response = build_empty_response(request)
            log_query(client_ip, domain, normalized, qtype_name, "local", matched_rule="local nodata", cache_status="local", reason="local no data", duration_ms=(time.perf_counter() - started) * 1000, client_name=dc, profile_name=dp, connection_type=connection_type)
            return response

        cached = get_cached(normalized, qtype_name)
        if cached:
            cached = request[:2] + cached[2:]
            cached = apply_ipv6_disabled_policy(cached)
            log_query(client_ip, domain, normalized, qtype_name, "cached", response_ips=extract_response_ips(cached), cache_status="hit", duration_ms=(time.perf_counter() - started) * 1000, client_name=dc, profile_name=dp, connection_type=connection_type)
            return cached

        forwarding_request = request
        if get_setting("dnssec_validation_enabled", "0") == "1":
            forwarding_request = add_do_bit_to_query(request)
        response, upstream = forward_query(forwarding_request)
        response = apply_ipv6_disabled_policy(response)
        filtering_on = get_setting("filtering_enabled", "1") == "1" and client_filtering_enabled(client_ip)
        profile_id = decision.get("profile_id")
        engine = get_filter_engine()

        client_cd_flag = bool(question.get("flags", 0) & 0x0100)

        if _dnssec_available and get_setting("dnssec_validation_enabled", "0") == "1" and not client_cd_flag:
            try:
                import dns.message
                import dns.flags
                qmsg = dns.message.from_wire(forwarding_request)
                rmsg = dns.message.from_wire(response)
                validator = get_dnssec_validator()
                if validator:
                    dnssec_result = validator.validate_response(qmsg, rmsg)
                    if dnssec_result.status in ("bogus", "indeterminate"):
                        servfail_response = build_error_response(request, 2)
                        log_query(client_ip, domain, normalized, qtype_name, "blocked",
                                  upstream=upstream, matched_rule="dnssec_bogus",
                                  blocked=1, reason=dnssec_result.reason,
                                  duration_ms=(time.perf_counter() - started) * 1000,
                                  client_name=dc, profile_name=dp, connection_type=connection_type)
                        return servfail_response
                    response_bytes = rmsg.to_wire()
                    if dnssec_result.ad_flag_allowed:
                        ad_mask = ~dns.flags.AD & 0xFFFF
                        response_bytes = bytearray(response_bytes)
                        flags = struct.unpack("!H", response_bytes[2:4])[0]
                        flags = (flags & ad_mask) | dns.flags.AD
                        response_bytes[2:4] = struct.pack("!H", flags)
                        response = bytes(response_bytes)
                    else:
                        response_bytes = bytearray(response_bytes)
                        flags = struct.unpack("!H", response_bytes[2:4])[0]
                        flags = flags & ~dns.flags.AD
                        response_bytes[2:4] = struct.pack("!H", flags)
                        response = bytes(response_bytes)
            except Exception as e:
                logger.warning("DNSSEC validation error for %s: %s", normalized, e)

        for cname in extract_cname_targets(response):
            cname_result = engine.check(cname, filtering_enabled=filtering_on, profile_id=profile_id)
            if cname_result.action == "BLOCK":
                blocked_response = build_block_response(request, qtype_name)
                matched = cname_result.matched_rule or cname_result.matched_domain or cname
                log_query(client_ip, domain, normalized, qtype_name, "blocked", upstream=upstream,
                          matched_rule=matched, blocked=1, reason="cname_blocked",
                          duration_ms=(time.perf_counter() - started) * 1000,
                          matched_list=cname_result.list_name or cname_result.matched_list or "",
                          client_name=dc, profile_name=dp, connection_type=connection_type)
                return blocked_response
        set_cached(normalized, qtype_name, response)
        log_query(client_ip, domain, normalized, qtype_name, "allowed", response_ips=extract_response_ips(response), upstream=upstream, duration_ms=(time.perf_counter() - started) * 1000, client_name=dc, profile_name=dp, connection_type=connection_type)
        return response
    except Exception as exc:
        try:
            question = parse_dns_question(request)
            log_query(client_ip, question["domain"], question["normalized_domain"], question["qtype_name"], "upstream_error", reason=str(exc), duration_ms=(time.perf_counter() - started) * 1000, client_name=client_log_name, profile_name=client_profile_name, connection_type=connection_type)
        except Exception:
            pass
        return build_error_response(request, 2)


class LimitedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False

    def process_request(self, request, client_address):
        if not dns_concurrency.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            dns_concurrency.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            dns_concurrency.release()


class ReusableThreadingUDPServer(LimitedThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class ReusableThreadingTCPServer(LimitedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class ReusableThreadingTLSDNSServer(ReusableThreadingTCPServer):
    def __init__(self, server_address, handler_class, ssl_context):
        self.ssl_context = ssl_context
        super().__init__(server_address, handler_class)

    def get_request(self):
        sock, addr = super().get_request()
        try:
            return self.ssl_context.wrap_socket(sock, server_side=True), addr
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise


class ReusableThreadingHTTPSServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, ssl_context):
        self.ssl_context = ssl_context
        super().__init__(server_address, handler_class)

    def get_request(self):
        sock, addr = super().get_request()
        try:
            return self.ssl_context.wrap_socket(sock, server_side=True), addr
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise


def send_doh_response(handler, params=None):
    try:
        if handler.command == "GET":
            dns_param = (params or {}).get("dns", [""])[0]
            if not dns_param:
                handler.send_error(400, "missing dns query parameter")
                return
            padded = dns_param + ("=" * (-len(dns_param) % 4))
            request = base64.urlsafe_b64decode(padded.encode("ascii"))
        else:
            length = int(handler.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65535:
                handler.send_error(400, "invalid DNS message length")
                return
            request = handler.rfile.read(length)
        response = handle_dns_request(request, handler.client_address[0], "HTTPS")
        if response is None:
            handler.send_error(502, "DNS query failed")
            return
        handler.send_response(200)
        handler.send_header("Content-Type", "application/dns-message")
        handler.send_header("Content-Length", str(len(response)))
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        handler.wfile.write(response)
    except Exception as exc:
        handler.send_error(400, str(exc))


class DNSHTTPSHandler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}-DoH/0.1"

    def do_GET(self):
        path = urlparse(self.path).path
        if path != "/dns-query":
            self.send_error(404)
            return
        send_doh_response(self, parse_qs(urlparse(self.path).query))

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/dns-query":
            self.send_error(404)
            return
        send_doh_response(self)

    def log_message(self, fmt, *args):
        try:
            with open("web-error.log", "a", encoding="utf-8") as log:
                log.write(f"{now_iso()} [doh] {self.address_string()} {fmt % args}\n")
        except Exception:
            pass


class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        response = handle_dns_request(data, self.client_address[0], "UDP")
        if response is not None:
            sock.sendto(response, self.client_address)


def recv_exact(conn, length):
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class DNSTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(120)
        while True:
            try:
                header = recv_exact(self.request, 2)
                if not header:
                    return
                length = struct.unpack("!H", header)[0]
                if length < 12:
                    return
                data = recv_exact(self.request, length)
                if not data:
                    return
                connection_type = "TLS" if isinstance(self.server, ReusableThreadingTLSDNSServer) else "TCP"
                response = handle_dns_request(data, self.client_address[0], connection_type)
                if response is not None:
                    self.request.sendall(struct.pack("!H", len(response)) + response)
            except socket.timeout:
                return


def _svg(inner):
    return f'<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{inner}</svg>'

def icon_home():     return _svg('<path d="M3 12L12 3l9 9"/><path d="M5 10v9h4v-5h6v5h4v-9"/>')
def icon_list():     return _svg('<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><circle cx="3" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="3" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="3" cy="18" r="1" fill="currentColor" stroke="none"/>')
def icon_filter():   return _svg('<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>')
def icon_shield():   return _svg('<path d="M12 2l8 4v6c0 5.5-3.8 10.7-8 12-4.2-1.3-8-6.5-8-12V6l8-4z"/>')
def icon_rewrite():  return _svg('<path d="M17 3a2.83 2.83 0 114 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>')
def icon_clients():  return _svg('<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>')
def icon_upstream(): return _svg('<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>')
def icon_cache():    return _svg('<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 11v6c0 1.66 4.03 3 9 3s9-1.34 9-3v-6"/>')
def icon_settings(): return _svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>')
def icon_search():   return _svg('<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>')
def icon_api():      return _svg('<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>')
def icon_profile():  return _svg('<path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>')


def template(content, title="Dashboard"):
    filtering_on = get_setting("filtering_enabled", "1") == "1"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{APP_NAME} - {title}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    :root{{
      --bg:#0b0f17;--sidebar:#0f1623;--card:#141e2e;--border:#1e2d3d;
      --text:#e2e8f0;--muted:#64748b;--muted2:#94a3b8;
      --accent:#00d4aa;--blue:#3b82f6;--red:#ef4444;--orange:#f59e0b;
      --green:#22c55e;--purple:#a78bfa;
    }}
    html,body{{height:100%;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;overflow-x:hidden}}
    a{{color:inherit;text-decoration:none}}
    h1,h2,h3,p{{margin:0}}
    .layout{{display:grid;grid-template-columns:230px 1fr;grid-template-rows:56px 1fr;min-height:100vh}}
    .topbar{{grid-column:1/-1;display:flex;align-items:center;background:#0d1421;border-bottom:1px solid var(--border);padding:0 1.4rem;gap:.9rem;position:sticky;top:0;z-index:100;height:56px}}
    .sidebar{{background:var(--sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:56px;height:calc(100vh - 56px);overflow-y:auto}}
    main{{padding:1.75rem;min-width:0;overflow:hidden}}
    .brand{{font-size:1rem;font-weight:700;display:flex;align-items:center;gap:.5rem;margin-right:auto;color:var(--text)}}
    .brand-ic{{color:var(--accent)}}
    .qc-sep{{width:1px;height:20px;background:var(--border);flex-shrink:0}}
    .qc-label{{font-size:.78rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap}}
    .qc-item{{display:flex;align-items:center;gap:.45rem;font-size:.88rem;color:var(--muted2);white-space:nowrap;cursor:default}}
    .toggle{{position:relative;width:36px;height:20px;cursor:pointer;display:inline-flex;align-items:center;flex-shrink:0}}
    .toggle input{{opacity:0;width:0;height:0;position:absolute}}
    .toggle-track{{position:absolute;inset:0;border-radius:10px;background:#252f40;transition:.2s}}
    .toggle input:checked~.toggle-track{{background:var(--accent)}}
    .toggle-thumb{{position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.2s;pointer-events:none;z-index:1}}
    .toggle input:checked~.toggle-thumb{{transform:translateX(16px)}}
    .btn-topbar{{background:transparent;border:1px solid var(--border);color:var(--muted2);font-size:.82rem;border-radius:.42rem;padding:.3rem .72rem;cursor:pointer;display:inline-flex;align-items:center}}
    .btn-topbar:hover{{border-color:var(--muted);color:var(--text)}}
    .menu-toggle{{display:none;background:transparent;border:1px solid var(--border);color:var(--text);border-radius:.42rem;width:40px;height:40px;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0}}
    .menu-toggle svg{{width:20px;height:20px}}
    .nav-backdrop{{display:none}}
    .nav-link{{display:flex;align-items:center;gap:.6rem;padding:.56rem .85rem;margin:.1rem .55rem;border-radius:.42rem;color:var(--muted2);font-weight:500;font-size:.9rem;transition:.12s}}
    .nav-link:hover{{background:#1a2740;color:var(--text)}}
    .nav-link.active{{background:#1a2740;color:var(--accent)}}
    .nav-link.active .nav-icon,.nav-link:hover .nav-icon{{opacity:1}}
    .nav-icon{{width:16px;height:16px;flex-shrink:0;opacity:.6}}
    .sys-status{{margin-top:auto;padding:.8rem 1.1rem;border-top:1px solid var(--border)}}
    .sys-row{{display:flex;align-items:center;gap:.4rem;font-size:.82rem;color:var(--muted2);margin-bottom:.25rem}}
    .dot-status{{width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0;box-shadow:0 0 5px var(--green)}}
    .setup-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}}
    .setup-card{{background:var(--card);border:1px solid var(--border);border-radius:.6rem;padding:1rem;min-width:0}}
    .setup-card-title{{font-size:.95rem;font-weight:800;margin-bottom:.25rem}}
    .setup-card-text{{font-size:.86rem;color:var(--muted2);margin-bottom:.75rem}}
    .setup-endpoint{{display:block;background:#0b1220;border:1px solid var(--border);border-radius:.45rem;padding:.55rem .7rem;margin:.45rem 0;color:var(--text);font:700 .86rem/1.35 ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;overflow-wrap:anywhere;word-break:break-word}}
    .setup-muted{{color:var(--muted2);font-size:.82rem}}
    .card-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.3rem}}
    .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:.6rem;padding:1.1rem 1.2rem .9rem}}
    .card-label{{font-size:.78rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.35rem}}
    .card-value{{font-size:1.9rem;font-weight:700;line-height:1.1;margin-bottom:.2rem;font-variant-numeric:tabular-nums}}
    .card-change{{font-size:.8rem;font-weight:600;margin-bottom:.5rem}}
    .card-change.up{{color:var(--green)}} .card-change.dn{{color:var(--red)}}
    .card-top{{display:flex;justify-content:space-between;align-items:flex-start}}
    .card-icon-box{{width:36px;height:36px;border-radius:.45rem;display:flex;align-items:center;justify-content:center;flex-shrink:0}}
    .panel{{background:var(--card);border:1px solid var(--border);border-radius:.6rem;max-width:100%}}
    .panel-head{{padding:.75rem 1.1rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}}
    .panel-title{{font-size:.92rem;font-weight:700}}
    .panel-link{{font-size:.82rem;color:var(--accent)}}
    .page-toolbar{{display:flex;align-items:center;justify-content:space-between;gap:.75rem;margin-bottom:1.05rem}}
    .three-col{{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.3rem;max-width:100%;min-width:0}}
    .three-col .panel{{width:100%;max-width:100%;min-width:0;overflow:hidden}}
    .three-col table{{table-layout:fixed}}
    .three-col th,.three-col td{{min-width:0}}
    .three-col .td-num{{width:96px}}
    .three-col th:last-child,.three-col td:last-child{{width:104px}}
    table{{width:100%;border-collapse:collapse}}
    .table{{width:100%;border-collapse:collapse;margin-bottom:0}}
    th,.table th{{font-size:.78rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:.58rem 1rem;text-align:left;border-bottom:1px solid var(--border)}}
    td,.table td{{padding:.55rem 1rem;font-size:.9rem;border-bottom:1px solid rgba(30,45,61,.5);vertical-align:middle}}
    tr:last-child td{{border-bottom:none}}
    tr:hover td{{background:rgba(26,39,64,.32)}}
    .table-responsive{{max-width:100%;overflow-x:auto;overflow-y:hidden;-webkit-overflow-scrolling:touch}}
    .table-responsive>.table,.table-responsive>table{{min-width:720px}}
    .td-num{{text-align:right;font-variant-numeric:tabular-nums}}
    .td-domain{{font-weight:500;overflow-wrap:anywhere;word-break:break-word}}
    .td-muted{{color:var(--muted2)}}
    .bar-wrap{{display:flex;align-items:center;gap:.5rem}}
    .bar-bg{{flex:1;min-width:36px;height:5px;background:#1e2d3d;border-radius:3px;overflow:hidden}}
    .bar-fill{{height:100%;border-radius:3px;background:var(--accent)}}
    .badge,.text-bg-success,.text-bg-danger,.text-bg-info,.text-bg-warning,.text-bg-secondary{{display:inline-flex;align-items:center;padding:.22rem .56rem;border-radius:.32rem;font-size:.8rem;font-weight:700}}
    .text-bg-success{{background:rgba(34,197,94,.12);color:#4ade80}}
    .text-bg-danger{{background:rgba(239,68,68,.12);color:#f87171}}
    .text-bg-info{{background:rgba(59,130,246,.12);color:#60a5fa}}
    .text-bg-warning{{background:rgba(245,158,11,.12);color:#fbbf24}}
    .text-bg-secondary{{background:rgba(100,116,139,.12);color:#94a3b8}}
    .badge-red{{background:rgba(239,68,68,.12);color:#f87171}}
    .form-control,.form-select,textarea{{background:#0b1220;border:1px solid var(--border);color:var(--text);border-radius:.45rem;padding:.58rem .82rem;font-size:.93rem;width:100%;display:block}}
    .form-control:focus,.form-select:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,170,.1)}}
    .form-label{{font-size:.88rem;font-weight:600;color:var(--muted2);margin-bottom:.38rem;display:block}}
    .password-toggle-wrap{{position:relative;display:flex;align-items:center}}
    .password-toggle-wrap .form-control{{padding-right:2.5rem}}
    .password-toggle-btn{{position:absolute;right:.5rem;top:50%;transform:translateY(-50%);background:none;border:none;padding:.35rem;cursor:pointer;color:var(--muted2);display:flex;align-items:center;justify-content:center;line-height:0;border-radius:.35rem}}
    .password-toggle-btn:hover{{color:var(--text);background:rgba(255,255,255,.05)}}
    .btn{{display:inline-flex;align-items:center;justify-content:center;border:1px solid transparent;border-radius:.45rem;padding:.54rem 1rem;font-size:.9rem;font-weight:600;cursor:pointer;text-decoration:none;vertical-align:middle;color:#fff}}
    .btn-sm{{padding:.32rem .68rem;font-size:.82rem}}
    .btn-success,.btn-primary{{background:var(--accent);color:#0a1628;border-color:var(--accent)}}
    .btn-outline-light{{background:transparent;border-color:var(--border);color:var(--muted2)}}
    .btn-outline-danger{{background:transparent;border-color:rgba(239,68,68,.35);color:#f87171}}
    .btn-danger{{background:#ef4444;color:#fff;border-color:#ef4444}}
    .btn:hover{{filter:brightness(1.1)}}
    .alert{{padding:.78rem 1.1rem;border-radius:.48rem;margin-bottom:1rem;font-size:.92rem;border:1px solid var(--border)}}
    .alert-danger{{background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.25);color:#fca5a5}}
    .alert-success{{background:rgba(34,197,94,.07);border-color:rgba(34,197,94,.25);color:#86efac}}
    .alert-warning{{background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.25);color:#fde68a}}
    .alert-secondary{{background:rgba(100,116,139,.07);color:var(--muted2)}}
    .status-dot{{display:inline-block;width:.58rem;height:.58rem;border-radius:50%;margin-right:.35rem;vertical-align:middle}}
    .dot-ok{{background:var(--green)}} .dot-bad{{background:var(--red)}} .dot-warn{{background:var(--orange)}}
    .metric{{border-left:3px solid var(--accent);min-height:80px}}
    .metric .fs-3{{line-height:1.1}}
    .row{{display:flex;flex-wrap:wrap;gap:1rem}}
    [class^="col-"],[class*=" col-"]{{width:100%;min-width:0}}
    .col-6{{flex:0 0 calc(50% - .5rem)}} .col-12{{flex:0 0 100%}}
    @media(min-width:768px){{.col-md-1{{flex:0 0 calc(8.33% - .92rem)}}.col-md-3{{flex:0 0 calc(25% - .75rem)}}.col-md-4{{flex:0 0 calc(33.33% - .67rem)}}.col-md-5{{flex:0 0 calc(41.67% - .58rem)}}.col-md-6{{flex:0 0 calc(50% - .5rem)}}}}
    @media(min-width:992px){{.col-lg-2{{flex:0 0 calc(16.67% - .83rem)}}.col-lg-10{{flex:0 0 calc(83.33% - .17rem)}}}}
    @media(min-width:1200px){{.col-xl-3{{flex:0 0 calc(25% - .75rem)}}.col-xl-4{{flex:0 0 calc(33.33% - .67rem)}}.col-xl-8{{flex:0 0 calc(66.67% - .33rem)}}}}
    .d-flex{{display:flex}} .d-block{{display:block}} .flex-wrap{{flex-wrap:wrap}} .align-items-center{{align-items:center}}
    .justify-content-between{{justify-content:space-between}} .justify-content-center{{justify-content:center}}
    .gap-1{{gap:.25rem}} .gap-2{{gap:.5rem}} .ms-auto{{margin-left:auto}}
    .p-3{{padding:1rem}} .p-4{{padding:1.5rem}} .py-2{{padding-top:.5rem;padding-bottom:.5rem}}
    .mt-3{{margin-top:1rem}} .mb-0{{margin-bottom:0}} .mb-1{{margin-bottom:.25rem}} .mb-2{{margin-bottom:.5rem}} .mb-3{{margin-bottom:1rem}} .mb-4{{margin-bottom:1.5rem}}
    .g-2{{gap:.5rem}} .g-3{{gap:1rem}}
    .g-3>[class*="col-"]{{margin-bottom:0}}
    .min-vh-100{{min-height:100vh}} .w-100{{width:100%}} .text-break{{word-break:break-word}}
    .text-secondary{{color:var(--muted2)!important}} .small{{font-size:.88rem}}
    .fs-3{{font-size:1.9rem}} .fw-semibold{{font-weight:700}} .h3{{font-size:1.15rem;font-weight:700}} .h5{{font-size:1rem;font-weight:700}}
    .rounded-2{{border-radius:.5rem!important}}
    .border{{border:1px solid var(--border)!important}} .border-bottom{{border-bottom:1px solid var(--border)!important}}
    .border-end{{border-right:1px solid var(--border)!important}} .border-secondary-subtle{{border-color:var(--border)!important}}
    .shadow{{box-shadow:0 12px 36px rgba(0,0,0,.25)}}
    .table-dark{{--bs-table-bg:transparent}}
    .table-hover tr:hover td{{background:rgba(26,39,64,.32)}}
    .table td form{{display:inline}} .table td .btn{{vertical-align:middle}}
    .table thead th{{color:var(--muted);font-size:.66rem;text-transform:uppercase;font-weight:700;text-align:left}}
    .page-title{{font-size:1.15rem;font-weight:700;margin-bottom:1.1rem}}
    .modal-overlay{{position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:1000;display:flex;align-items:center;justify-content:center;opacity:0;visibility:hidden;transition:.2s}}
    .modal-overlay.show{{opacity:1;visibility:visible}}
    .modal-box{{background:#101721;border:1px solid #223044;border-radius:.6rem;width:calc(100% - 2rem);max-width:520px;padding:1.5rem;max-height:90vh;overflow-y:auto}}
    @media(max-width:1100px){{.card-grid{{grid-template-columns:repeat(2,1fr)}}.three-col{{grid-template-columns:1fr}}}}
    @media(max-width:768px){{
      html,body{{height:auto;min-height:100%;font-size:14px}}
      .layout{{grid-template-columns:1fr;grid-template-rows:auto auto 1fr;min-height:100vh}}
      .topbar{{height:auto;min-height:56px;padding:.65rem .85rem;gap:.5rem;align-items:center;flex-wrap:wrap}}
      .menu-toggle{{display:inline-flex}}
      .brand{{flex:1 1 calc(100% - 48px);min-width:0;margin-right:0}}
      .brand-ic{{width:18px;height:18px}}
      .qc-sep,.qc-label{{display:none}}
      .qc-item{{font-size:.82rem;min-height:36px}}
      .btn-topbar{{flex:1 1 110px;min-height:36px;padding:.42rem .68rem;font-size:.8rem}}
      .sidebar{{position:fixed;top:0;left:0;width:min(82vw,310px);height:100vh;z-index:1001;transform:translateX(-105%);transition:transform .22s ease;flex-direction:column;overflow-y:auto;overflow-x:hidden;border-right:1px solid var(--border);border-bottom:0;padding:.6rem 0;background:var(--sidebar);box-shadow:18px 0 48px rgba(0,0,0,.36)}}
      .nav-open .sidebar{{transform:translateX(0)}}
      .nav-backdrop{{display:block;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:1000;opacity:0;visibility:hidden;transition:.2s}}
      .nav-open .nav-backdrop{{opacity:1;visibility:visible}}
      .sidebar>div:first-child{{height:.35rem!important;display:block}}
      .nav-link{{margin:.12rem .65rem;padding:.72rem .85rem;gap:.6rem;font-size:.94rem;white-space:nowrap}}
      .nav-icon{{width:17px;height:17px}}
      .sys-status{{display:block}}
      body.nav-open{{overflow:hidden}}
      .card-grid{{grid-template-columns:1fr 1fr}}
      .setup-grid{{grid-template-columns:1fr}}
      .three-col{{grid-template-columns:1fr;gap:.75rem;margin-bottom:1rem;width:100%}}
      .three-col table{{width:100%;max-width:100%;min-width:0}}
      .three-col .td-num{{width:82px}}
      .three-col th:last-child,.three-col td:last-child{{width:86px}}
      main{{padding:.9rem;overflow:visible}}
      .page-title{{font-size:1.05rem;margin-bottom:.8rem}}
      .page-toolbar{{align-items:flex-start;flex-wrap:wrap;margin-bottom:.85rem}}
      .page-toolbar .btn{{flex:0 0 auto}}
      .stat-card{{padding:.85rem}}
      .card-value{{font-size:1.55rem}}
      .card-label{{font-size:.68rem;letter-spacing:.04em}}
      .card-icon-box{{width:32px;height:32px}}
      .panel-head{{padding:.65rem .8rem}}
      .p-3{{padding:.8rem}}
      .p-4{{padding:1rem}}
      th,.table th{{padding:.5rem .7rem;font-size:.65rem;white-space:nowrap}}
      td,.table td{{padding:.52rem .7rem;font-size:.84rem}}
      .form-control,.form-select,textarea{{font-size:16px;padding:.62rem .78rem}}
      .d-flex.flex-wrap>.form-control,.d-flex.flex-wrap>.form-select{{max-width:none!important;min-width:0}}
      .btn{{min-height:40px;padding:.55rem .82rem}}
      .btn-sm{{min-height:34px;padding:.38rem .62rem}}
      .modal-overlay{{align-items:flex-start;padding:1rem 0}}
      .modal-box{{width:calc(100% - 1rem);max-height:calc(100vh - 2rem);padding:1rem}}
      .mobile-card-table{{min-width:0!important;border-collapse:separate;border-spacing:0 .65rem}}
      .mobile-card-table thead{{display:none}}
      .mobile-card-table tbody,.mobile-card-table tr,.mobile-card-table td{{display:block;width:100%}}
      .mobile-card-table tr{{background:#0f1726;border:1px solid var(--border);border-radius:.55rem;padding:.35rem .75rem}}
      .mobile-card-table tr:hover td{{background:transparent}}
      .mobile-card-table td{{border-bottom:1px solid rgba(30,45,61,.55);padding:.58rem 0;font-size:.88rem;overflow-wrap:anywhere;word-break:break-word}}
      .mobile-card-table td:last-child{{border-bottom:0}}
      .mobile-card-table td::before{{content:attr(data-label);display:block;margin-bottom:.18rem;color:var(--muted);font-size:.66rem;font-weight:800;text-transform:uppercase;letter-spacing:.05em}}
      .mobile-card-table td[colspan]::before{{display:none}}
      .mobile-card-table .td-num{{text-align:left}}
      .mobile-card-table td.d-flex{{display:flex;width:100%;justify-content:flex-start;flex-wrap:wrap}}
      .domain-test-table{{min-width:0!important}}
      .domain-test-table tr{{display:block;border-bottom:1px solid rgba(30,45,61,.7);padding:.62rem 0}}
      .domain-test-table tr:last-child{{border-bottom:0}}
      .domain-test-table th,.domain-test-table td{{display:block;width:100%!important;border:0!important;padding:.1rem 0!important;white-space:normal;overflow-wrap:anywhere;word-break:break-word}}
      .domain-test-table th{{color:var(--muted);font-size:.66rem;text-transform:uppercase;letter-spacing:.05em}}
      }}
    @media(max-width:520px){{
      .topbar{{gap:.45rem}}
      .qc-item{{flex:1 1 auto}}
      .btn-topbar{{flex:1 1 calc(33.33% - .45rem)}}
      .card-grid{{grid-template-columns:1fr;gap:.75rem;margin-bottom:1rem}}
      .row{{gap:.75rem}}
      .col-6{{flex:0 0 100%}}
      .table-responsive>.table,.table-responsive>table{{min-width:640px}}
      .table-responsive>.mobile-card-table{{min-width:0!important}}
      .table-responsive>.domain-test-table{{min-width:0!important}}
      .three-col .td-num{{width:70px}}
      .three-col th:last-child,.three-col td:last-child{{width:74px}}
      .d-flex.flex-wrap>.form-control,.d-flex.flex-wrap>.form-select,.d-flex.flex-wrap>.btn,.d-flex.flex-wrap>form{{flex:1 1 100%!important;max-width:none!important;width:100%}}
      .d-flex.flex-wrap>form>.btn{{width:100%}}
      #bl-type{{width:100%!important}}
      .panel>.d-flex.justify-content-between{{align-items:flex-start;flex-direction:column;gap:.65rem}}
      .panel>.d-flex.justify-content-between .btn{{width:100%}}
      .bar-wrap{{min-width:130px}}
      .page-toolbar .btn{{width:100%}}
    }}
  </style>
</head>
<body>
<div class="layout">
<header class="topbar">
  <button class="menu-toggle" type="button" onclick="toggleMobileNav(true)" aria-label="Open navigation" aria-controls="mobile-sidebar">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
  <div class="brand">
    <svg class="brand-ic" width="19" height="19" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6L12 2z"/></svg>
    {APP_NAME}
  </div>
  <div class="qc-sep"></div>
  <span class="qc-label">Quick Controls</span>
  <label class="qc-item">
    <span class="toggle">
      <input type="checkbox" id="prot-toggle" {"checked" if filtering_on else ""} onchange="toggleProtection(this)">
      <span class="toggle-track"></span><span class="toggle-thumb"></span>
    </span>
    Protection Enabled
  </label>
  <a class="btn-topbar" href="/api/backup">Backup</a>
  <button class="btn-topbar" type="button" onclick="document.getElementById('backup-import-input').click()" title="Import backup file">Import</button>
  <input id="backup-import-input" type="file" accept=".json,application/json" style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0" onchange="importBackup(this)">
  <a class="btn-topbar" href="/logout">Logout</a>
</header>
<div class="nav-backdrop" onclick="toggleMobileNav(false)"></div>
<aside class="sidebar" id="mobile-sidebar">
  <div style="height:.4rem"></div>
  {nav_item("/", "Dashboard", icon_home(), title)}
  {nav_item("/querylog", "Query Log", icon_list(), title)}
  {nav_item("/blocklists", "Blocklists", icon_filter(), title)}
  {nav_item("/rules", "Rules", icon_shield(), title)}
  {nav_item("/rewrites", "DNS Rewrites", icon_rewrite(), title)}
  {nav_item("/profiles", "Profiles", icon_profile(), title)}
  {nav_item("/clients", "Clients", icon_clients(), title)}
  {nav_item("/upstreams", "Upstreams", icon_upstream(), title)}
  {nav_item("/cache", "Cache", icon_cache(), title)}
  {nav_item("/setup-wizard", "Setup Wizard", icon_settings(), title)}
  {nav_item("/settings", "Settings", icon_settings(), title)}
  {nav_item("/api-docs", "API", icon_api(), title)}
  {nav_item("/domain-test", "Domain Test", icon_search(), title)}
  <div class="sys-status">
    <div class="sys-row"><span class="dot-status"></span>All Systems Operational</div>
    <div class="sys-row" style="color:var(--muted);font-size:.69rem">{APP_NAME} v0.1</div>
  </div>
</aside>
<main>{content}</main>
</div>
<script>
function getCookie(name) {{
  return document.cookie.split(';').map(v => v.trim()).find(v => v.startsWith(name + '='))?.slice(name.length + 1) || '';
}}
document.addEventListener('DOMContentLoaded', () => {{
  const token = decodeURIComponent(getCookie('{CSRF_COOKIE}'));
  if (!token) return;
  document.querySelectorAll('form[method="post"], form[method="POST"]').forEach(form => {{
    if (form.querySelector('input[name="csrf_token"]')) return;
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'csrf_token';
    input.value = token;
    form.appendChild(input);
  }});
}});
const nativeFetch = window.fetch.bind(window);
window.fetch = (resource, init = {{}}) => {{
  const method = (init.method || 'GET').toUpperCase();
  if (!['GET','HEAD','OPTIONS'].includes(method)) {{
    const token = decodeURIComponent(getCookie('{CSRF_COOKIE}'));
    if (token) {{
      init.headers = new Headers(init.headers || {{}});
      init.headers.set('X-CSRF-Token', token);
    }}
  }}
  return nativeFetch(resource, init);
}};
function toggleMobileNav(open) {{
  document.body.classList.toggle('nav-open', !!open);
}}
document.addEventListener('keydown', (event) => {{
  if (event.key === 'Escape') toggleMobileNav(false);
}});
document.addEventListener('DOMContentLoaded', () => {{
  document.querySelectorAll('.sidebar .nav-link').forEach(link => {{
    link.addEventListener('click', () => toggleMobileNav(false));
  }});
}});
async function toggleProtection(el) {{
  const ep = el.checked ? '/api/filtering/resume' : '/api/filtering/pause';
  try {{ const r = await fetch(ep,{{method:'POST'}}); if(!r.ok) el.checked=!el.checked; }}
  catch(e) {{ el.checked=!el.checked; }}
}}
function toggleTokenVisibility() {{
  const input = document.getElementById('api-token-input');
  const openEye = document.getElementById('token-eye-open');
  const closedEye = document.getElementById('token-eye-closed');
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  openEye.style.display = isPassword ? 'none' : '';
  closedEye.style.display = isPassword ? '' : 'none';
}}
async function importBackup(input) {{
  const file = input.files[0];
  if (!file) return;
  if (file.size === 0) {{
    input.value = '';
    alert('Invalid backup file: The file is empty. Please download a new backup with the backup button.');
    return;
  }}
  let text;
  let backup;
  let uploadBody = file;
  const browserValidateLimit = 25 * 1024 * 1024;
  if (file.size <= browserValidateLimit) {{
    try {{
      text = (await file.text()).replace(/^\\uFEFF/, '').trim();
      if (!text) throw new Error('The file does not contain JSON data.');
      backup = JSON.parse(text);
      const required = ['settings', 'rules', 'upstreams'];
      const missing = required.filter(k => !Object.prototype.hasOwnProperty.call(backup, k));
      if (!backup || typeof backup !== 'object' || Array.isArray(backup) || missing.length) {{
        throw new Error('Not a LocalDNSGuard backup. Missing fields: ' + (missing.join(', ') || 'backup object'));
      }}
      uploadBody = text;
    }}
    catch(e) {{ input.value = ''; alert('Invalid backup file: ' + e.message); return; }}
  }}
  if (!confirm('Restore backup "' + file.name + '"?\\nAll current settings (filters, rules, DNS rewrites, upstreams, settings) will be overwritten. DNS queries and clients remain unchanged.')) {{ input.value = ''; return; }}
  try {{
    const r = await fetch('/api/restore', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      credentials: 'same-origin',
      body: uploadBody
    }});
    const raw = await r.text();
    let d;
    try {{ d = JSON.parse(raw); }}
    catch(e) {{ throw new Error(raw ? raw.slice(0, 180) : ('HTTP ' + r.status)); }}
    if (d.ok) {{
      const s = d.restored;
      alert('Backup restored!\\n' +
        'Settings: ' + s.settings + '\\n' +
        'Rules: ' + s.rules + '\\n' +
        'Blocklists: ' + s.blocklists + '\\n' +
        'DNS Rewrites: ' + s.dns_rewrites + '\\n' +
        'Upstreams: ' + s.upstreams);
      location.reload();
    }} else {{
      alert('Error: ' + (d.error || ('HTTP ' + r.status)));
    }}
  }} catch(e) {{ alert('Import error: ' + e.message); }}
  finally {{ input.value = ''; }}
}}
</script>
</body>
</html>"""


def nav_item(path, label, icon="", current_title=""):
    _map = {
        "Dashboard": "/", "Query Log": "/querylog",
        "Blocklists": "/blocklists", "Rules": "/rules",
        "DNS Rewrites": "/rewrites", "Clients": "/clients", "Profiles": "/profiles", "Upstreams": "/upstreams", "Cache": "/cache",
        "Setup Wizard": "/setup-wizard", "Settings": "/settings", "API": "/api-docs", "Domain Test": "/domain-test",
    }
    active = " active" if _map.get(current_title) == path else ""
    return f'<a class="nav-link{active}" href="{path}">{icon}<span>{label}</span></a>'


def login_page(error=""):
    alert = f'<div class="alert alert-danger">{error}</div>' if error else ""
    first = get_setting("admin_password_set", "0") != "1"
    title = "Create Admin" if first else "Login"
    hint = "Set the first password. Username: admin" if first else "Sign in as admin."
    return f"""<!doctype html><html lang="en" data-bs-theme="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME} - Login</title>
<style>
*,*::before,*::after{{box-sizing:border-box}} body{{margin:0;background:#070b10;color:#e8eef7;font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}
.min-vh-100{{min-height:100vh}} .d-flex{{display:flex}} .align-items-center{{align-items:center}} .justify-content-center{{justify-content:center}} .p-4{{padding:1.5rem}} .mb-1{{margin-bottom:.25rem}} .mb-3{{margin-bottom:1rem}} .w-100{{width:100%}} .h3{{font-size:1.55rem}} .text-secondary{{color:#8d9bae}}
.login{{width:100%;max-width:420px}} .panel{{background:#101721;border:1px solid #223044;border-radius:.6rem;box-shadow:0 20px 60px rgba(0,0,0,.35)}}
.form-label{{display:block;margin-bottom:.35rem;color:#b8c4d4;font-weight:600}} .form-control{{display:block;width:100%;padding:.7rem .8rem;background:#0b111a;border:1px solid #26364e;border-radius:.5rem;color:#f3f7fb}} .form-control:focus{{outline:none;border-color:#20c997;box-shadow:0 0 0 .18rem rgba(32,201,151,.14)}}
.btn{{display:inline-flex;align-items:center;justify-content:center;border:1px solid #1eb98d;border-radius:.5rem;padding:.65rem .9rem;color:#fff;background:#168b6b;cursor:pointer;font-weight:700}} .alert{{padding:.75rem 1rem;border-radius:.5rem;background:#30161b;color:#ffd8de;border:1px solid #842029}}
</style></head><body>
<main class="min-vh-100 d-flex align-items-center justify-content-center">
<form method="post" action="/login" class="login panel p-4">
<h1 class="h3 mb-1">{title}</h1><p class="text-secondary">{hint}</p>{alert}
<input type="hidden" name="username" value="admin">
<label class="form-label">Password</label><input class="form-control mb-3" type="password" name="password" required autofocus>
<button class="btn btn-success w-100" type="submit">{title}</button>
</form></main></body></html>"""


def stats_summary():
    summary = one(
        """
        SELECT
          COUNT(*) total,
          COALESCE(SUM(blocked),0) blocked,
          COALESCE(SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END),0) cache_hits,
          COUNT(DISTINCT client_ip) clients
        FROM query_log
        """
    )
    recent_durations = rows(
        """
        SELECT duration_ms
        FROM query_log
        WHERE status IN ('allowed','cached','blocked','rewritten','local')
          AND duration_ms >= 0
          AND duration_ms < 1000
        ORDER BY id DESC
        LIMIT 1000
        """
    )
    durations = sorted(float(row["duration_ms"]) for row in recent_durations)
    if durations:
        middle = len(durations) // 2
        avg = durations[middle] if len(durations) % 2 else (durations[middle - 1] + durations[middle]) / 2
    else:
        avg = 0
    total = summary["total"]
    blocked = summary["blocked"]
    cache_hits = summary["cache_hits"]
    clients = summary["clients"]
    return {
        "total": total,
        "blocked": blocked,
        "block_rate": round((blocked / total * 100) if total else 0, 1),
        "avg_ms": round(avg or 0, 2),
        "cache_rate": round((cache_hits / total * 100) if total else 0, 1),
        "clients": clients,
        "rules": one("SELECT COUNT(*) c FROM rules WHERE enabled=1")["c"]
        + one("SELECT COALESCE(SUM(bl.rule_count),0) c FROM blocklists bl WHERE bl.enabled=1")["c"],
        "upstreams": one("SELECT COUNT(*) c FROM upstreams WHERE enabled=1")["c"],
        "uptime": int(time.time() - BOOT_TIME),
    }


def dashboard_data():
    return {
        "summary": stats_summary(),
        "latest": rows("SELECT * FROM query_log ORDER BY id DESC LIMIT 12"),
    }


def sparkline_svg(values, color="#00d4aa", width=160, height=40):
    if not values or max(values, default=0) == 0:
        return f'<svg width="{width}" height="{height}" style="display:block"></svg>'
    mx = max(values) or 1
    n = len(values)
    def pt(i, v):
        x = i / max(n - 1, 1) * width
        y = height - 3 - (v / mx) * (height - 6)
        return f"{x:.1f},{y:.1f}"
    pts = [pt(i, v) for i, v in enumerate(values)]
    path_d = "M " + " L ".join(pts)
    area_d = path_d + f" L {width},{height} L 0,{height} Z"
    gid = f"sg{abs(hash(color)) % 99999}"
    seg = width / max(n - 1, 1)
    hover = "".join(
        f'<rect x="{max(0, i/max(n-1,1)*width - seg/2):.1f}" y="0" width="{seg:.1f}" height="{height}" fill="transparent" style="cursor:pointer"><title>{v}</title></rect>'
        for i, v in enumerate(values)
    )
    circles = " ".join(
        f'<circle cx="{pts[i].split(",")[0]}" cy="{pts[i].split(",")[1]}" r="2.5" fill="{color}" opacity="0.7" style="cursor:pointer" class="spark-dot"/>'
        for i in range(len(pts))
    )
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" style="overflow:visible;display:block">'
        f'<defs><linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0%" stop-color="{color}" stop-opacity=".22"/>'
        f'<stop offset="100%" stop-color="{color}" stop-opacity="0"/>'
        f'</linearGradient></defs>'
        f'<path d="{area_d}" fill="url(#{gid})"/>'
        f'<path d="{path_d}" fill="none" stroke="{color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>'
        f'{circles}'
        f'{hover}'
        f'</svg>'
    )


def extended_dashboard_data():
    now_t = time.time()
    if now_t - dash_cache["ts"] < DASH_CACHE_TTL and dash_cache["data"] is not None:
        return dash_cache["data"]

    combined = one("""
        SELECT
          COUNT(*) total,
          COALESCE(SUM(blocked),0) blocked,
          COALESCE(AVG(CASE WHEN duration_ms<1000 THEN duration_ms END),0) avg_ms,
          COALESCE(SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END),0) cache_hits,
          COUNT(DISTINCT client_ip) clients_24h
        FROM query_log WHERE timestamp >= datetime('now','localtime','-24 hours')
    """) or {"total": 0, "blocked": 0, "avg_ms": 0, "cache_hits": 0, "clients_24h": 0}

    prev = one("""
        SELECT COUNT(*) total, COALESCE(SUM(blocked),0) blocked,
               COALESCE(AVG(CASE WHEN duration_ms<1000 THEN duration_ms END),0) avg_ms
        FROM query_log WHERE timestamp >= datetime('now','localtime','-48 hours')
          AND timestamp < datetime('now','localtime','-24 hours')
    """) or {"total": 0, "blocked": 0, "avg_ms": 0}

    def pct_change(curr, prev_v):
        if not prev_v:
            return 0
        return round((curr - prev_v) / prev_v * 100, 1)

    live_raw = rows("""
        SELECT strftime('%Y-%m-%d %H', timestamp) as hr,
               COUNT(*) as total, COALESCE(SUM(blocked),0) as blocked,
               COALESCE(SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END),0) as cache_hits,
               COALESCE(AVG(CASE WHEN duration_ms<1000 THEN duration_ms END),0) as avg_ms
        FROM query_log WHERE timestamp >= datetime('now','localtime','-24 hours')
        GROUP BY hr ORDER BY hr
    """)
    all_hrs = {}
    for r in live_raw:
        all_hrs[r["hr"]] = r
    sparkline_total, sparkline_blocked, sparkline_cache, sparkline_avgms = [], [], [], []
    overall_avg_ms = combined.get("avg_ms", 0) or 0
    for i in range(23, -1, -1):
        h = (datetime.now() - timedelta(hours=i)).strftime("%Y-%m-%d %H")
        r = all_hrs.get(h, {})
        tot = r.get("total", 0)
        sparkline_total.append(tot)
        sparkline_blocked.append(r.get("blocked", 0))
        sparkline_cache.append(round(r.get("cache_hits", 0) / tot * 100, 1) if tot else 0)
        avg = r.get("avg_ms", None)
        sparkline_avgms.append(round(avg, 1) if avg is not None else round(overall_avg_ms, 1))

    top_domains = rows("""
        SELECT normalized_domain as domain, COUNT(*) as cnt
        FROM query_log WHERE timestamp >= datetime('now','localtime','-24 hours')
          AND normalized_domain != '' AND status NOT IN ('local')
        GROUP BY normalized_domain ORDER BY cnt DESC LIMIT 8
    """)
    top_blocked = rows("""
        SELECT normalized_domain as domain, COUNT(*) as cnt
        FROM query_log WHERE blocked=1 AND timestamp >= datetime('now','localtime','-24 hours')
          AND normalized_domain != ''
        GROUP BY normalized_domain ORDER BY cnt DESC LIMIT 8
    """)
    top_clients = rows("""
        SELECT client_ip, COUNT(*) as requests, COALESCE(SUM(blocked),0) as blocked,
               MAX(timestamp) as last_seen
        FROM query_log WHERE timestamp >= datetime('now','localtime','-48 hours')
        GROUP BY client_ip ORDER BY requests DESC LIMIT 8
    """)
    result = {
        "today": combined, "prev": prev,
        "changes": {
            "total": pct_change(combined["total"], prev["total"]),
            "blocked": pct_change(combined["blocked"], prev["blocked"]),
            "avg_ms": pct_change(combined["avg_ms"], prev["avg_ms"]),
        },
        "sparklines": {"total": sparkline_total, "blocked": sparkline_blocked, "cache": sparkline_cache, "avgms": sparkline_avgms},
        "top_domains": top_domains, "top_blocked": top_blocked, "top_clients": top_clients,
        "total_q": combined["total"] or 1,
        "cache_rate": round((combined["cache_hits"] / combined["total"] * 100) if combined["total"] else 0, 1),
        "rules_count": one("SELECT COUNT(*) c FROM rules WHERE enabled=1")["c"]
        + one("SELECT COALESCE(SUM(bl.rule_count),0) c FROM blocklists bl WHERE bl.enabled=1")["c"],
        "upstreams_count": one("SELECT COUNT(*) c FROM upstreams WHERE enabled=1")["c"],
        "clients_24h": combined["clients_24h"],
    }
    dash_cache["data"] = result
    dash_cache["ts"] = now_t
    return result


def dashboard_page():
    d = extended_dashboard_data()
    today = d["today"]
    sp = d["sparklines"]
    total_q = d["total_q"]
    changes = d["changes"]
    blue = "#3b82f6"; red = "#ef4444"; orange = "#f59e0b"; purple = "#a78bfa"

    def change_span(pct, lower_is_better=False):
        if pct == 0:
            return '<span class="card-change" style="color:var(--muted)">— vs yesterday</span>'
        good = (pct < 0) if lower_is_better else (pct > 0)
        cls = "up" if good else "dn"
        arrow = "▲" if pct > 0 else "▼"
        sign = "+" if pct > 0 else ""
        return f'<span class="card-change {cls}">{arrow} {sign}{pct}% vs yesterday</span>'

    def stat_card(label, value, spark_vals, color, icon_svg, pct, lower_is_better=False, card_id=""):
        spark = sparkline_svg(spark_vals, color)
        li = "1" if lower_is_better else "0"
        return (
            f'<div class="stat-card" data-card="{card_id}" data-color="{color}" data-lower="{li}">'
            f'<div class="card-top">'
            f'<div><div class="card-label">{label}</div>'
            f'<div class="card-value">{value}</div>'
            f'{change_span(pct, lower_is_better)}</div>'
            f'<div class="card-icon-box" style="background:{color}1a">{icon_svg}</div>'
            f'</div>'
            f'<div class="card-sparkline" style="margin-top:.35rem">{spark}</div>'
            f'</div>'
        )

    ic_globe  = f'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="{blue}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>'
    ic_block  = f'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="{red}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>'
    ic_shield = f'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="{orange}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5.5-3.8 10.7-8 12-4.2-1.3-8-6.5-8-12V6l8-4z"/></svg>'
    ic_clock  = f'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="{purple}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>'
    ic_zap    = f'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="{orange}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>'

    blocked = today["blocked"]
    total   = today["total"]
    avg_ms  = round(today["avg_ms"], 1)
    cache_rate = d["cache_rate"]

    cards_html = (
        stat_card("DNS Queries",          f'{total:,}',       sp["total"],   blue,   ic_globe,  changes["total"],            card_id="total") +
        stat_card("Blocked Requests",     f'{blocked:,}',     sp["blocked"], red,    ic_block,  changes["blocked"], True,    card_id="blocked") +
        stat_card("Cache Hit Rate",       f'{cache_rate}%',   sp["cache"],   orange, ic_zap,    changes["total"],            card_id="cache") +
        stat_card("Average Response Time", f'{avg_ms} ms',    sp["avgms"],   purple, ic_clock,  changes["avg_ms"],  True,    card_id="avgms")
    )

    block_rate = round(blocked / total * 100, 1) if total else 0
    gen_rows = [
        ("DNS Queries (24h)", f'{total:,}'),
        ("Blocked Queries",   f'{blocked:,}'),
        ("Block Rate",        f'{block_rate}%'),
        ("Active Clients",    f'{d["clients_24h"]}'),
        ("Active Upstreams",  f'{d["upstreams_count"]}'),
        ("Filter Rules",      f'{d["rules_count"]:,}'),
    ]
    gen_html = "".join(f'<tr><td class="td-muted">{k}</td><td class="td-num">{v}</td></tr>' for k, v in gen_rows)

    def dom_row(r):
        pct = round(r["cnt"] / total_q * 100, 1) if total_q else 0
        return f'<tr><td class="td-domain">{r["domain"]}</td><td class="td-num">{r["cnt"]:,}</td><td class="td-num">{pct}%</td></tr>'

    top_dom_html = "".join(dom_row(r) for r in d["top_domains"]) or \
        '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No data yet</td></tr>'

    top_blk_html = "".join(
        f'<tr><td class="td-domain">{r["domain"]}</td><td class="td-num">{r["cnt"]:,}</td>'
        f'<td><span class="badge badge-red">Blocked</span></td></tr>'
        for r in d["top_blocked"]
    ) or '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No blocked domains</td></tr>'

    def client_row(r):
        req = r["requests"]; blk = r["blocked"]
        pct_blk = round(blk / req * 100, 1) if req else 0
        bar_w   = min(100, round(pct_blk))
        last    = r["last_seen"][:16] if r.get("last_seen") else "—"
        ip = r["client_ip"]
        ql_link = f'/querylog?client={ip}'
        return (
            f'<tr>'
            f'<td data-label="Client Name" class="td-domain"><a href="{ql_link}" style="color:inherit;text-decoration:none">{ip}</a></td>'
            f'<td data-label="IP Address" class="td-muted">{ip}</td>'
            f'<td data-label="Requests" class="td-num">{req:,}</td>'
            f'<td data-label="Blocked" class="td-num">{blk:,}</td>'
            f'<td data-label="% Blocked"><div class="bar-wrap"><div class="bar-bg"><div class="bar-fill" style="width:{bar_w}%"></div></div>'
            f'<span style="font-size:.72rem;color:var(--muted2);white-space:nowrap">{pct_blk}%</span></div></td>'
            f'<td data-label="Last Seen" class="td-muted">{last}</td>'
            f'</tr>'
        )

    clients_html = "".join(client_row(r) for r in d["top_clients"]) or \
        '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:1rem">No data yet</td></tr>'

    return template(f"""
<div class="page-toolbar">
  <span class="page-title" style="margin-bottom:0">Dashboard</span>
  <span style="font-size:.72rem;color:var(--muted)">Live &bull; updated <span id="last-refresh">—</span></span>
</div>
<div class="card-grid">{cards_html}</div>
<div class="three-col">
  <div class="panel">
    <div class="panel-head"><span class="panel-title">General Statistics</span></div>
    <table><tbody id="gen-stats-body">{gen_html}</tbody></table>
  </div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Top Queried Domains</span><a class="panel-link" href="/querylog">View all</a></div>
    <table><thead><tr><th>Domain</th><th class="td-num">Requests</th><th class="td-num">% of Total</th></tr></thead><tbody id="top-dom-body">{top_dom_html}</tbody></table>
  </div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Top Blocked Domains</span><a class="panel-link" href="/querylog?status=blocked">View all</a></div>
    <table><thead><tr><th>Domain</th><th class="td-num">Blocked</th><th>Status</th></tr></thead><tbody id="top-blk-body">{top_blk_html}</tbody></table>
  </div>
</div>
<div class="panel">
  <div class="panel-head">
    <span class="panel-title">Top Clients</span>
    <span class="small" style="color:var(--muted)">Last 48 hours</span>
  </div>
  <div class="table-responsive">
    <table class="mobile-card-table">
      <thead><tr><th>Client Name</th><th>IP Address</th><th class="td-num">Requests</th><th class="td-num">Blocked</th><th style="min-width:140px">% Blocked</th><th>Last Seen</th></tr></thead>
      <tbody id="dash-clients">{clients_html}</tbody>
    </table>
  </div>
</div>
<script>
function sparkJS(vals, color, w, h) {{
  if (!vals || !vals.some(v => v > 0)) return `<svg width="${{w}}" height="${{h}}" style="display:block"></svg>`;
  const mx = Math.max(...vals) || 1, n = vals.length;
  const seg = w / Math.max(n - 1, 1);
  const pts = vals.map((v,i) => `${{(i/Math.max(n-1,1)*w).toFixed(1)}},${{(h-3-(v/mx)*(h-6)).toFixed(1)}}`);
  const path = 'M '+pts.join(' L ');
  const area = path+` L ${{w}},${{h}} L 0,${{h}} Z`;
  const gid  = 'jsg'+color.replace('#','');
  const hover = vals.map((v,i) => `<rect x="${{Math.max(0,(i/Math.max(n-1,1)*w)-seg/2).toFixed(1)}}" y="0" width="${{seg.toFixed(1)}}" height="${{h}}" fill="transparent" style="cursor:pointer"><title>${{v}}</title></rect>`).join('');
  const dots = pts.map(p => `<circle cx="${{p.split(',')[0]}}" cy="${{p.split(',')[1]}}" r="2.5" fill="${{color}}" opacity="0.7" style="cursor:pointer" class="spark-dot"/>`).join('');
  return `<svg width="${{w}}" height="${{h}}" viewBox="0 0 ${{w}} ${{h}}" style="overflow:visible;display:block"><defs><linearGradient id="${{gid}}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${{color}}" stop-opacity=".22"/><stop offset="100%" stop-color="${{color}}" stop-opacity="0"/></linearGradient></defs><path d="${{area}}" fill="url(#${{gid}})"/><path d="${{path}}" fill="none" stroke="${{color}}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/><g style="cursor:pointer">${{dots}}${{hover}}</g></svg>`;
}}
function chgHTML(pct, lower) {{
  if (!pct) return `<span class="card-change" style="color:var(--muted)">— vs yesterday</span>`;
  const good = lower ? pct<0 : pct>0;
  return `<span class="card-change ${{good?'up':'dn'}}">${{pct>0?'▲':'▼'}} ${{pct>0?'+':''}}${{pct}}% vs yesterday</span>`;
}}
function esc(s) {{
  return String(s||'').replace(/[&<>"']/g,c=>({{
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }}[c]));
}}
async function refreshDash() {{
  try {{
    const r = await fetch('/api/dashboard', {{cache:'no-store'}});
    if (!r.ok) return;
    const d = await r.json();
    const t=d.today, ch=d.changes, sp=d.sparklines, tq=d.total_q||1;
    // Stat cards
    const cards = [
      {{id:'total',   val:t.total.toLocaleString(),                 pct:ch.total,   lower:false, spark:sp.total,               color:'#3b82f6'}},
      {{id:'blocked', val:t.blocked.toLocaleString(),               pct:ch.blocked, lower:true,  spark:sp.blocked,             color:'#ef4444'}},
      {{id:'cache',   val:(d.cache_rate||0)+'%',                    pct:ch.total,   lower:false, spark:sp.cache,               color:'#f59e0b'}},
      {{id:'avgms',   val:(Math.round(t.avg_ms*10)/10)+' ms',       pct:ch.avg_ms,  lower:true,  spark:sp.avgms,               color:'#a78bfa'}},
    ];
    for (const c of cards) {{
      const el = document.querySelector(`[data-card="${{c.id}}"]`);
      if (!el) continue;
      el.querySelector('.card-value').textContent = c.val;
      const chEl = el.querySelector('.card-change');
      if (chEl) chEl.outerHTML = chgHTML(c.pct, c.lower);
      const spEl = el.querySelector('.card-sparkline');
      if (spEl) spEl.innerHTML = sparkJS(c.spark, c.color, 160, 40);
    }}
    // General stats
    const br = t.total ? (t.blocked/t.total*100).toFixed(1) : 0;
    const genRows = [
      ['DNS Queries (24h)', t.total.toLocaleString()],
      ['Blocked Queries',   t.blocked.toLocaleString()],
      ['Block Rate',        br+'%'],
      ['Active Clients',    d.clients_24h],
      ['Active Upstreams',  d.upstreams_count],
      ['Filter Rules',      d.rules_count.toLocaleString()],
    ];
    const gb = document.getElementById('gen-stats-body');
    if (gb) gb.innerHTML = genRows.map(([k,v])=>`<tr><td class="td-muted">${{esc(k)}}</td><td class="td-num">${{esc(v)}}</td></tr>`).join('');
    // Top domains
    const db = document.getElementById('top-dom-body');
    if (db) db.innerHTML = d.top_domains.length
      ? d.top_domains.map(r=>`<tr><td class="td-domain">${{esc(r.domain)}}</td><td class="td-num">${{r.cnt.toLocaleString()}}</td><td class="td-num">${{(r.cnt/tq*100).toFixed(1)}}%</td></tr>`).join('')
      : `<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No data yet</td></tr>`;
    // Top blocked
    const bb = document.getElementById('top-blk-body');
    if (bb) bb.innerHTML = d.top_blocked.length
      ? d.top_blocked.map(r=>`<tr><td class="td-domain">${{esc(r.domain)}}</td><td class="td-num">${{r.cnt.toLocaleString()}}</td><td><span class="badge badge-red">Blocked</span></td></tr>`).join('')
      : `<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No blocked domains</td></tr>`;
    // Top clients
    const cb = document.getElementById('dash-clients');
    if (cb) cb.innerHTML = d.top_clients.length
      ? d.top_clients.map(r=>{{
          const pct=r.requests?(r.blocked/r.requests*100).toFixed(1):0;
          const bw=Math.min(100,Math.round(pct));
          const last=r.last_seen?r.last_seen.slice(0,16):'—';
          const ql = `/querylog?client=${{r.client_ip}}`;
          return `<tr><td data-label="Client Name" class="td-domain"><a href="${{ql}}" style="color:inherit;text-decoration:none">${{esc(r.client_ip)}}</a></td><td data-label="IP Address" class="td-muted">${{esc(r.client_ip)}}</td><td data-label="Requests" class="td-num">${{r.requests.toLocaleString()}}</td><td data-label="Blocked" class="td-num">${{r.blocked.toLocaleString()}}</td><td data-label="% Blocked"><div class="bar-wrap"><div class="bar-bg"><div class="bar-fill" style="width:${{bw}}%"></div></div><span style="font-size:.72rem;color:var(--muted2);white-space:nowrap">${{pct}}%</span></div></td><td data-label="Last Seen" class="td-muted">${{esc(last)}}</td></tr>`;
        }}).join('')
      : `<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:1rem">No data yet</td></tr>`;
    // Timestamp
    const ts = document.getElementById('last-refresh');
    if (ts) ts.textContent = new Date().toLocaleTimeString('de-DE',{{hour:'2-digit',minute:'2-digit',second:'2-digit'}});
  }} catch(e) {{}}
}}
setInterval(refreshDash, 3000);
refreshDash();
</script>
""")


def badge(status):
    cls = "success"
    if "block" in status or status in ("refused", "upstream_error"):
        cls = "danger"
    elif status in ("cached", "rewritten"):
        cls = "info"
    return f'<span class="badge text-bg-{cls}">{status}</span>'


def connection_label(value):
    labels = {
        "udp": "UDP",
        "tcp": "TCP",
        "doh": "HTTPS",
        "https": "HTTPS",
        "dot": "TLS",
        "tls": "TLS",
        "doq": "QUIC",
        "quic": "QUIC",
    }
    raw = str(value or "").strip()
    if not raw:
        return "UDP"
    return labels.get(raw.lower(), raw.upper())


def querylog_page(params):
    where, values = [], []
    if params.get("q", [""])[0]:
        where.append("normalized_domain LIKE ?")
        values.append(f"%{normalize_domain(params['q'][0])}%")
    if params.get("status", [""])[0]:
        where.append("status=?")
        values.append(params["status"][0])
    if params.get("client", [""])[0]:
        where.append("client_ip LIKE ?")
        values.append(f"%{params['client'][0]}%")
    sql = "SELECT q.*, COALESCE(NULLIF(c.name, c.ip), NULLIF(q.client_name, ''), q.client_ip) AS client_display_name FROM query_log q LEFT JOIN clients c ON c.ip = q.client_ip"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY q.id DESC LIMIT 300"
    data = rows(sql, values)
    client_val = html_escape(params.get('client', [''])[0])
    q_val = html_escape(params.get('q', [''])[0])
    status_val = params.get('status', [''])[0]
    def ql_actions(r):
        domain = html_escape(r["normalized_domain"] or r["domain"])
        client = html_escape(r["client_ip"])
        profile_name = html_escape(r.get("profile_name", ""))
        action = "allow" if r.get("blocked") else "block"
        label = "Allow" if action == "allow" else "Block"
        return (
            f"<div class='btn-group btn-group-sm' role='group'>"
            f"<button class='btn btn-outline-light' onclick=\"qlRuleAction('{domain}','{action}','global','{client}','')\">{label} Global</button>"
            f"<button class='btn btn-outline-light' onclick=\"qlRuleAction('{domain}','{action}','profile','{client}','')\" {'disabled' if not profile_name else ''}>{label} Profile</button>"
            f"</div>"
        )
    body = "".join(f"<tr><td data-label='Time'>{r['timestamp']}</td><td data-label='Client'>{r.get('client_display_name') or r['client_ip']}</td><td data-label='Connect'>{connection_label(r.get('connection_type',''))}</td><td data-label='Domain' class='td-domain'>{r['domain']}</td><td data-label='Type'>{r['query_type']}</td><td data-label='Status'>{badge(r['status'])}</td><td data-label='Upstream'>{r['upstream']}</td><td data-label='ms'>{r['duration_ms']:.1f}</td><td data-label='Actions'>{ql_actions(r)}</td></tr>" for r in data)
    return template(f"""
<h1 class="h3 mb-3">Query Log</h1>
<div class="d-flex gap-2 mb-3 flex-wrap">
  <input class="form-control" style="max-width:280px;flex:1 1 140px" id="ql-q" placeholder="Search domain" value="{q_val}">
  <input class="form-control" style="max-width:180px;flex:1 1 120px" id="ql-client" placeholder="Client-IP" value="{client_val}">
  <select class="form-select" style="max-width:160px;flex:1 1 100px" id="ql-status"><option value="">All Statuses</option>{status_options(status_val)}</select>
  <a class="btn btn-outline-light" href="/api/querylog.csv">CSV</a>
  <button class="btn btn-outline-light" onclick="qlFetch()">Refresh</button>
  <button class="btn btn-outline-light" id="ql-auto-btn" onclick="qlToggleAuto()">Auto-Refresh Off</button>
  <form method="post" action="/querylog/clear" style="margin:0"><button class="btn btn-outline-danger">Clear</button></form>
  <span class="small text-secondary" id="ql-count" style="display:flex;align-items:center">{len(data)} entries</span>
</div>
<div class="panel rounded-2 border border-secondary-subtle p-3"><div class="table-responsive"><table class="table table-dark table-hover mobile-card-table" id="ql-table"><thead><tr><th>Time</th><th>Client</th><th>Connect</th><th>Domain</th><th>Type</th><th>Status</th><th>Upstream</th><th>ms</th><th>Actions</th></tr></thead><tbody id="ql-body">{body}</tbody></table></div></div>
<script>
let qlTimer;
function esc(s) {{
  return String(s||'').replace(/[&<>"']/g,c=>({{
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }}[c]));
}}
function qlSearch() {{
  clearTimeout(qlTimer);
  qlTimer = setTimeout(() => {{
    qlFetch();
  }}, 200);
}}
let qlAutoTimer = null;
let qlAutoEnabled = false;
function qlToggleAuto() {{
  qlAutoEnabled = !qlAutoEnabled;
  localStorage.setItem('qlAutoRefresh', qlAutoEnabled ? '1' : '0');
  const btn = document.getElementById('ql-auto-btn');
  if (qlAutoEnabled) {{
    btn.textContent = 'Auto-Refresh On';
    btn.className = 'btn btn-success';
    qlFetch();
    qlAutoTimer = setInterval(() => qlFetch(), 1000);
  }} else {{
    btn.textContent = 'Auto-Refresh Off';
    btn.className = 'btn btn-outline-light';
    clearInterval(qlAutoTimer);
    qlAutoTimer = null;
  }}
}}
function qlFetch() {{
  const q = document.getElementById('ql-q').value;
  const c = document.getElementById('ql-client').value;
  const s = document.getElementById('ql-status').value;
  const p = new URLSearchParams();
  if (q) p.set('q', q);
  if (c) p.set('client', c);
  if (s) p.set('status', s);
  fetch('/api/querylog?' + p.toString(), {{cache:'no-store'}})
    .then(r => r.json())
    .then(d => {{
      const tb = document.getElementById('ql-body');
      const count = document.getElementById('ql-count');
      if (count) count.textContent = d.length + ' entries';
      const nextUrl = p.toString() ? ('/querylog?' + p.toString()) : '/querylog';
      history.replaceState(null, '', nextUrl);
      const connectLabel = (value) => {{
        const labels = {{udp:'UDP', tcp:'TCP', doh:'HTTPS', https:'HTTPS', dot:'TLS', tls:'TLS', doq:'QUIC', quic:'QUIC'}};
        const raw = String(value || '').trim();
        if (!raw) return 'UDP';
        return labels[raw.toLowerCase()] || raw.toUpperCase();
      }};
      tb.innerHTML = d.length ? d.map(r => {{
        let bc = 'success';
        if (r.status.includes('block') || r.status==='refused' || r.status==='upstream_error') bc='danger';
        else if (r.status==='cached' || r.status==='rewritten') bc='info';
        const act = r.blocked ? 'allow' : 'block';
        const label = r.blocked ? 'Allow' : 'Block';
        const domain = esc(r.normalized_domain || r.domain || '');
        const client = esc(r.client_ip || '');
        const profDisabled = r.profile_name ? '' : 'disabled';
        const actions = `<div class="btn-group btn-group-sm" role="group"><button class="btn btn-outline-light" onclick="qlRuleAction('${{domain}}','${{act}}','global','${{client}}','')">${{label}} Global</button><button class="btn btn-outline-light" onclick="qlRuleAction('${{domain}}','${{act}}','profile','${{client}}','')" ${{profDisabled}}>${{label}} Profile</button></div>`;
        return `<tr><td data-label="Time">${{r.timestamp}}</td><td data-label="Client">${{r.client_display_name || r.client_ip}}</td><td data-label="Connect">${{connectLabel(r.connection_type)}}</td><td data-label="Domain" class="td-domain">${{r.domain}}</td><td data-label="Type">${{r.query_type}}</td><td data-label="Status"><span class="badge text-bg-${{bc}}">${{r.status}}</span></td><td data-label="Upstream">${{r.upstream||''}}</td><td data-label="ms">${{r.duration_ms?.toFixed(1)||''}}</td><td data-label="Actions">${{actions}}</td></tr>`;
      }}).join('') : '<tr><td colspan="9" style="color:var(--muted);text-align:center;padding:1rem">No matching entries</td></tr>';
    }}).catch(() => {{}});
}}
function qlRuleAction(domain, action, scope, client, profileId) {{
  if (scope === 'global' && !confirm(`This will ${{action}} ${{domain}} for all clients. Continue?`)) return;
  const fd = new URLSearchParams();
  fd.set('domain', domain);
  fd.set('action', action);
  fd.set('scope', scope);
  fd.set('client', client || '');
  if (profileId) fd.set('profile_id', profileId);
  fetch('/api/querylog/rule-action', {{method:'POST', body: fd}})
    .then(r => r.json())
    .then(d => {{ if (d.error) alert(d.error); else qlFetch(); }})
    .catch(() => alert('Rule action failed'));
}}
function qlRestoreAuto() {{
  if (localStorage.getItem('qlAutoRefresh') === '1') {{
    if (!qlAutoEnabled) qlToggleAuto();
  }}
}}
document.getElementById('ql-q').addEventListener('input', qlSearch);
document.getElementById('ql-client').addEventListener('input', qlSearch);
document.getElementById('ql-status').addEventListener('change', qlSearch);
qlRestoreAuto();
</script>""", "Query Log")


def status_options(current):
    options = ["allowed", "blocked", "cached", "rewritten", "refused", "upstream_error", "local"]
    return "".join(f'<option value="{o}" {"selected" if o == current else ""}>{o}</option>' for o in options)


def rules_page(kind=None):
    rule_rows = rows("SELECT * FROM rules ORDER BY id DESC LIMIT 500")
    table = "".join(f"<tr><td data-label='ID'>{r['id']}</td><td data-label='Enabled'>{toggle(r['enabled'])}</td><td data-label='Action'>{r['action']}</td><td data-label='Type'>{r['pattern_type']}</td><td data-label='Pattern' class='td-domain'>{r['pattern']}</td><td data-label='Target' class='td-domain'>{r['target']}</td><td data-label='Comment'>{r['comment']}</td><td data-label='Actions'><form method='post' action='/rules/delete'><input type='hidden' name='id' value='{r['id']}'><button class='btn btn-sm btn-outline-danger'>Delete</button></form></td></tr>" for r in rule_rows)
    action = kind or "block"
    return template(f"""
<h1 class="h3 mb-3">Rules</h1>
<div class="alert alert-info py-2 mb-3">Rules from blocklists are managed and displayed on the <a href="/blocklists" class="alert-link">Blocklists</a> page. Only manually added rules are shown here.</div>
<div class="row g-3">
<div class="col-xl-4"><form class="panel rounded-2 border border-secondary-subtle p-3" method="post" action="/rules/add">
<h2 class="h5">Add Rule</h2>
<label class="form-label">Action</label><select class="form-select mb-2" name="action"><option {'selected' if action=='block' else ''}>block</option><option {'selected' if action=='allow' else ''}>allow</option><option {'selected' if action=='rewrite' else ''}>rewrite</option></select>
<label class="form-label">Type</label><select class="form-select mb-2" name="pattern_type"><option>domain</option><option>exact</option><option>wildcard</option><option>regex</option></select>
<label class="form-label">Pattern</label><input class="form-control mb-2" name="pattern" placeholder="ads.example.com or *.ads.com" required>
<label class="form-label">Rewrite Target</label><input class="form-control mb-2" name="target" placeholder="192.168.0.10">
<label class="form-label">Comment</label><input class="form-control mb-3" name="comment">
<button class="btn btn-success w-100">Save</button></form></div>
<div class="col-xl-8"><div class="panel rounded-2 border border-secondary-subtle p-3"><div class="table-responsive"><table class="table table-dark table-hover mobile-card-table"><thead><tr><th>ID</th><th>Enabled</th><th>Action</th><th>Type</th><th>Pattern</th><th>Target</th><th>Comment</th><th></th></tr></thead><tbody>{table}</tbody></table></div></div></div>
</div>""", "Rules")


def blocklists_page(error="", selected_type="block", success=""):
    global blocklist_manager
    lists = blocklist_manager.get_all() if blocklist_manager else []
    notification = ""
    if success:
        notification = (
            "<div id='bl-notification' class='alert alert-success shadow' "
            "style='position:fixed;right:1rem;top:4.5rem;z-index:1100;max-width:min(360px,calc(100vw - 2rem));"
            "border-color:rgba(34,197,94,.5);background:#11251a;color:#bbf7d0'>"
            f"<strong>Success</strong><br>{html_escape(success)}</div>"
        )
    elif error:
        notification = (
            "<div id='bl-notification' class='alert alert-danger shadow' "
            "style='position:fixed;right:1rem;top:4.5rem;z-index:1100;max-width:min(360px,calc(100vw - 2rem));"
            "border-color:rgba(239,68,68,.55);background:#2a1217;color:#fecdd3'>"
            f"<strong>Fail</strong><br>{html_escape(error)}</div>"
        )
    block_rows = [bl for bl in lists if bl.get("list_type") != "allow"]
    allow_rows = [bl for bl in lists if bl.get("list_type") == "allow"]
    selected_type = "allow" if selected_type == "allow" else "block"

    bl_edit_modals = ""

    def bl_table(rows):
        nonlocal bl_edit_modals
        if not rows:
            return '<div style="color:var(--muted);padding:1rem;text-align:center">No entries</div>'
        rows_html = ""
        def bl_enabled_toggle(bl):
            checked = "checked" if bl.get("enabled", 1) else ""
            next_enabled = "0" if bl.get("enabled", 1) else "1"
            label = "Active" if bl.get("enabled", 1) else "Inactive"
            return (
                f"<form method='post' action='/blocklists/toggle' class='m-0'>"
                f"<input type='hidden' name='id' value='{bl['id']}'>"
                f"<input type='hidden' name='enabled' value='{next_enabled}'>"
                f"<label class='form-check form-switch m-0 d-flex align-items-center gap-2'>"
                f"<input class='form-check-input' type='checkbox' role='switch' {checked} onchange='this.form.submit()'>"
                f"<span class='small text-secondary'>{label}</span>"
                f"</label></form>"
            )
        for bl in rows:
            eid = f"blEdit-{bl['id']}"
            rows_html += (
                f"<tr><td data-label='Activate'>{bl_enabled_toggle(bl)}</td><td data-label='Name'>{html_escape(bl['name'])}</td><td data-label='URL' class='text-break' style='max-width:300px'>{html_escape(bl['url'] or '-')}</td>"
                f"<td data-label='Rules'>{bl['rule_count']}</td><td data-label='Updated'>{bl['last_update'] or '—'}</td>"
                f"<td data-label='Error' style='color:var(--danger)'>{html_escape(bl['last_error'] or '')}</td>"
                f"<td data-label='Actions'><button class='btn btn-sm btn-outline-light' onclick=\"document.getElementById('{eid}').classList.add('show')\">&#x270E;</button>"
                f"<form method='post' action='/blocklists/update' class='d-inline ms-2'><input type='hidden' name='id' value='{bl['id']}'>"
                f"<button class='btn btn-sm btn-outline-light' title='Update'>&#x21bb;</button></form>"
                f"<form method='post' action='/blocklists/delete' class='d-inline ms-2'><input type='hidden' name='id' value='{bl['id']}'>"
                f"<button class='btn btn-sm btn-outline-danger' title='Delete'>&#x2716;</button></form></td></tr>"
            )
            bl_edit_modals += f"""
<div id="{eid}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 class="h5" style="margin:0">Edit {html_escape(bl['name'])}</h2>
      <button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{eid}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
    </div>
    <form method="post" action="/blocklists/edit">
      <input type="hidden" name="id" value="{bl['id']}">
      <label class="form-label">Name</label><input class="form-control mb-2" name="name" value="{html_escape(bl['name'])}" required>
      <label class="form-label">List Type</label><select class="form-select mb-2" name="list_type"><option value="block" {"selected" if bl.get("list_type") != "allow" else ""}>Blocklist</option><option value="allow" {"selected" if bl.get("list_type") == "allow" else ""}>Allowlist</option></select>
      <label class="form-label">URL</label><input class="form-control mb-2" name="url" value="{html_escape(bl['url'] or '')}" placeholder="https://raw.githubusercontent.com/...">
      <button class="btn btn-success w-100" type="submit">Save</button>
    </form>
  </div>
</div>"""
        return "<div class='table-responsive'><table class='table table-dark table-hover mobile-card-table'><thead><tr><th>Activate</th><th>Name</th><th>URL</th><th>Rules</th><th>Updated</th><th>Error</th><th></th></tr></thead><tbody>" + rows_html + "</tbody></table></div>"

    block_html = bl_table(block_rows)
    allow_html = bl_table(allow_rows)
    block_style = "display:none" if selected_type == "allow" else ""
    allow_style = "display:none" if selected_type == "block" else ""

    return template(f"""
<div class="page-toolbar">
  <span class="page-title" style="margin-bottom:0">Blocklist Manager</span>
  <button class="btn btn-success" onclick="openBlocklistModal()">+ Add</button>
</div>{notification}
<div class="panel rounded-2 border border-secondary-subtle p-3">
  <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:.75rem;flex-wrap:wrap">
    <select id="bl-type" class="form-select" style="width:auto;min-width:160px" onchange="blSwitch()">
      <option value="block" {"selected" if selected_type == "block" else ""}>Blocklists ({len(block_rows)})</option>
      <option value="allow" {"selected" if selected_type == "allow" else ""}>Allowlists ({len(allow_rows)})</option>
    </select>
  </div>
  <div id="bl-block" style="{block_style}">{block_html}</div>
  <div id="bl-allow" style="{allow_style}">{allow_html}</div>
</div>
{bl_edit_modals}
<script>
function blSwitch() {{
  var t = document.getElementById('bl-type').value;
  document.getElementById('bl-block').style.display = t === 'block' ? '' : 'none';
  document.getElementById('bl-allow').style.display = t === 'allow' ? '' : 'none';
  var addType = document.getElementById('bl-add-type');
  if (addType) addType.value = t;
}}
function openBlocklistModal() {{
  var addType = document.getElementById('bl-add-type');
  var selected = document.getElementById('bl-type');
  if (addType && selected) addType.value = selected.value;
  document.getElementById('bl-modal').classList.add('show');
}}
setTimeout(function() {{
  var n = document.getElementById('bl-notification');
  if (!n) return;
  n.style.transition = 'opacity .25s ease, transform .25s ease';
  n.style.opacity = '0';
  n.style.transform = 'translateY(-8px)';
  setTimeout(function() {{ n.remove(); }}, 280);
}}, 3500);
</script>
<div id="bl-modal" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 class="h5" style="margin:0">Add Blocklist</h2>
      <button class="btn btn-sm btn-outline-light" onclick="document.getElementById('bl-modal').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
    </div>
    <form method="post" action="/blocklists/add">
      <label class="form-label">Name</label><input class="form-control mb-2" name="name" placeholder="HaGeZi" required>
      <label class="form-label">List Type</label><select id="bl-add-type" class="form-select mb-2" name="list_type"><option value="block" {"selected" if selected_type == "block" else ""}>Blocklist</option><option value="allow" {"selected" if selected_type == "allow" else ""}>Allowlist</option></select>
      <label class="form-label">URL</label><input class="form-control mb-2" name="url" placeholder="https://raw.githubusercontent.com/...">
      <label class="form-label">Or paste list content</label><textarea class="form-control mb-3" name="content" rows="6" placeholder="0.0.0.0 ads.example.com&#10;||tracker.com^"></textarea>
      <button class="btn btn-success w-100" type="submit">Add</button>
    </form>
  </div>
</div>""", "Blocklists")


def rewrites_page():
    rewrites = rows("SELECT * FROM rules WHERE action = 'rewrite' ORDER BY id DESC LIMIT 500")
    table = "".join(
        f"<tr><td data-label='ID'>{r['id']}</td><td data-label='Enabled'>{toggle(r['enabled'])}</td>"
        f"<td data-label='Type'>{r['pattern_type']}</td><td data-label='Domain' class='td-domain'>{r['pattern']}</td>"
        f"<td data-label='Target' class='td-domain'>{r['target']}</td><td data-label='Comment'>{r['comment']}</td>"
        f"<td data-label='Actions'><form method='post' action='/rewrites/delete'><input type='hidden' name='id' value='{r['id']}'>"
        f"<button class='btn btn-sm btn-outline-danger'>Delete</button></form></td></tr>"
        for r in rewrites
    )
    return template(f"""
<h1 class="h3 mb-3">DNS Rewrites</h1>
<div class="row g-3">
<div class="col-xl-4"><form class="panel rounded-2 border border-secondary-subtle p-3" method="post" action="/rewrites/add">
<h2 class="h5">Add Rewrite</h2>
<label class="form-label">Type</label><select class="form-select mb-2" name="pattern_type"><option>domain</option><option>wildcard</option><option>regex</option></select>
<label class="form-label">Domain</label><input class="form-control mb-2" name="pattern" placeholder="nas.local or *.dev.local" required>
<label class="form-label">Target (IP or CNAME)</label><input class="form-control mb-2" name="target" placeholder="192.168.0.10" required>
<label class="form-label">Comment</label><input class="form-control mb-3" name="comment">
<button class="btn btn-success w-100">Save</button></form></div>
<div class="col-xl-8"><div class="panel rounded-2 border border-secondary-subtle p-3"><div class="table-responsive"><table class="table table-dark table-hover mobile-card-table"><thead><tr><th>ID</th><th>Enabled</th><th>Type</th><th>Domain</th><th>Target</th><th>Comment</th><th></th></tr></thead><tbody>{table}</tbody></table></div></div></div>
</div>""", "DNS Rewrites")


def clients_page():
    data = client_manager.get_clients() if client_manager else []
    profiles = client_manager.get_profiles() if client_manager else []
    profile_opts = "".join(f"<option value='{p['id']}'>{p['name']}</option>" for p in profiles)
    table = ""
    edit_modals = ""
    for r in data:
        rid = int(r["id"])
        edit_id = f"clientEdit-{rid}"
        cidr_or_ip = r.get("cidr") or r.get("ip") or ""
        edit_profile_opts = "".join(
            f"<option value='{p['id']}' {'selected' if str(p['id']) == str(r.get('profile_id') or '') else ''}>{html_escape(p['name'])}</option>"
            for p in profiles
        )
        filter_checked = "checked" if r.get("filtering_enabled") else ""
        table += (
            f"<tr><td data-label='Name'>{html_escape(r['name'])}</td><td data-label='IP'>{html_escape(r['ip'])}</td><td data-label='CIDR'>{html_escape(r.get('cidr',''))}</td>"
            f"<td data-label='Profile'>{html_escape(r.get('profile_name','Default') or 'Default')}</td>"
            f"<td data-label='Filter'>{toggle(r['filtering_enabled'])}</td>"
            f"<td data-label='Actions'><button class='btn btn-sm btn-outline-light' type='button' onclick=\"document.getElementById('{edit_id}').classList.add('show')\">Edit</button>"
            f"<form method='post' action='/clients/delete' style='display:inline;margin-left:.35rem'><input type='hidden' name='id' value='{rid}'>"
            f"<button class='btn btn-sm btn-outline-danger'>Delete</button></form></td></tr>"
        )
        edit_modals += f"""
<div id="{edit_id}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 class="h5" style="margin:0">Edit {html_escape(r['name'] or r['ip'])}</h2>
      <button class="btn btn-sm btn-outline-light" type="button" onclick="document.getElementById('{edit_id}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
    </div>
    <form method="post" action="/clients/edit">
      <input type="hidden" name="id" value="{rid}">
      <label class="form-label">Name</label><input class="form-control mb-2" name="name" value="{html_escape(r['name'])}" required>
      <label class="form-label">IP or CIDR</label><input class="form-control mb-2" name="address" value="{html_escape(cidr_or_ip)}" required>
      <label class="form-label">Profile</label><select class="form-select mb-2" name="profile_id">
        <option value="">-- Select Profile --</option>
        {edit_profile_opts}
      </select>
      <label class="settings-switch mb-3" for="client-filter-{rid}">
        <span><span class="settings-label">Filtering Enabled</span><span class="settings-help">Apply filtering rules to this client.</span></span>
        <input type="hidden" name="filtering_enabled" value="0">
        <span class="toggle settings-toggle">
          <input id="client-filter-{rid}" type="checkbox" role="switch" name="filtering_enabled" value="1" {filter_checked}>
          <span class="toggle-track"></span><span class="toggle-thumb"></span>
        </span>
      </label>
      <button class="btn btn-success w-100" type="submit">Save</button>
    </form>
  </div>
</div>"""
    return template(f"""
<h1 class="h3 mb-3">Clients</h1><div class="row g-3">
<div class="col-xl-4"><form class="panel rounded-2 border border-secondary-subtle p-3" method="post" action="/clients/add">
<h2 class="h5">Add Client</h2>
<input class="form-control mb-2" name="name" placeholder="Name" required>
<input class="form-control mb-2" name="address" placeholder="IP or CIDR" required>
<select class="form-select mb-2" name="profile_id">
<option value=''>-- Select Profile --</option>
{profile_opts}
</select>
<button class="btn btn-success w-100">Save</button></form></div>
<div class="col-xl-8"><div class="panel rounded-2 border border-secondary-subtle p-3"><div class="table-responsive"><table class="table table-dark table-hover mobile-card-table"><thead><tr><th>Name</th><th>IP</th><th>CIDR</th><th>Profile</th><th>Filter</th><th></th></tr></thead><tbody>{table}</tbody></table></div></div></div></div>{edit_modals}""", "Clients")


def profiles_page():
    data = client_manager.get_profiles() if client_manager else []
    blists = (blocklist_manager.get_all() if blocklist_manager else [])
    blist_opts = "".join(f"<option value='{b['id']}'>{b['name']}</option>" for b in blists)
    services = client_manager.get_services() if client_manager else []
    cards = ""
    for p in data:
        rules = client_manager.get_profile_rules(p["id"]) if client_manager else []
        pbl = client_manager.get_profile_blocklists(p["id"]) if client_manager else []
        pservices = client_manager.get_profile_services(p["id"]) if client_manager else []
        service_opts = "".join(
            f"<option value='{html_escape(s)}'>{html_escape(s)}</option>"
            for s in services
            if s not in pservices
        )
        rule_rows = "".join(
            f"<tr><td data-label='Action'>{r['action']}</td><td data-label='Type'>{r['pattern_type']}</td><td data-label='Pattern' class='td-domain'><code>{r['pattern']}</code></td>"
            f"<td data-label='Actions'><form method='post' action='/profiles/rule-delete' style='display:inline'>"
            f"<input type='hidden' name='rule_id' value='{r['id']}'>"
            f"<input type='hidden' name='profile_id' value='{p['id']}'>"
            f"<button class='btn btn-sm btn-outline-danger'>x</button></form></td></tr>"
            for r in rules
        )
        bl_rows = "".join(
            f"<tr><td data-label='Name'>{pb['name']}</td>"
            f"<td data-label='Actions'><form method='post' action='/profiles/blocklist-remove' style='display:inline'>"
            f"<input type='hidden' name='profile_id' value='{p['id']}'>"
            f"<input type='hidden' name='blocklist_id' value='{pb['blocklist_id']}'>"
            f"<button class='btn btn-sm btn-outline-danger'>x</button></form></td></tr>"
            for pb in pbl
        )
        service_rows = "".join(
            f"<tr><td data-label='Service'>{html_escape(svc)}</td>"
            f"<td data-label='Actions'><form method='post' action='/profiles/service-remove' style='display:inline'>"
            f"<input type='hidden' name='profile_id' value='{p['id']}'>"
            f"<input type='hidden' name='service_name' value='{html_escape(svc)}'>"
            f"<button class='btn btn-sm btn-outline-danger'>x</button></form></td></tr>"
            for svc in pservices
        )
        badges = ""
        if p["is_default"]:
            badges += "<span class='badge bg-info me-1'>default</span>"
        badges += "<span class='badge bg-secondary me-1'>Filtering: " + ("on" if p['filtering_enabled'] else "off") + "</span>"
        eid = f"editModal-{p['id']}"
        did = f"delModal-{p['id']}"
        rid = f"ruleModal-{p['id']}"
        bid = f"blModal-{p['id']}"
        sid = f"svcModal-{p['id']}"
        del_btn = ""
        if not p['is_default']:
            del_btn = '<button class="btn btn-sm btn-outline-danger" onclick="document.getElementById(\'' + did + '\').classList.add(\'show\')">Delete</button>'
        cards += f"""<div class="panel rounded-2 border border-secondary-subtle p-3 mb-3">
<div class="d-flex align-items-center justify-content-between mb-2">
<h5 class="mb-0">{p['name']}</h5>
<div>{badges}</div>
</div>
<p class="text-muted small mb-3">{p.get('description','') or 'No description'}</p>
<div class="d-flex gap-2 mb-2">
<button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{eid}').classList.add('show')">Edit</button>
{del_btn}
</div>
<div class="row g-3">
<div class="col-md-6">
<h6 class="d-flex align-items-center gap-2">Custom Rules<button class="btn btn-sm btn-success" onclick="document.getElementById('{rid}').classList.add('show')">+</button></h6>
<div class="table-responsive"><table class="table table-dark table-sm mobile-card-table"><thead><tr><th>Action</th><th>Type</th><th>Pattern</th><th></th></tr></thead><tbody>{rule_rows or '<tr><td colspan=4 class=text-muted>No custom rules</td></tr>'}</tbody></table></div>
</div>
<div class="col-md-6">
<h6 class="d-flex align-items-center gap-2">Blocklists<button class="btn btn-sm btn-success" onclick="document.getElementById('{bid}').classList.add('show')">+</button></h6>
<div class="table-responsive"><table class="table table-dark table-sm mobile-card-table"><thead><tr><th>Name</th><th></th></tr></thead><tbody>{bl_rows or '<tr><td colspan=2 class=text-muted>No blocklists attached</td></tr>'}</tbody></table></div>
</div>
<div class="col-md-6">
<h6 class="d-flex align-items-center gap-2">Service Blocks<button class="btn btn-sm btn-success" onclick="document.getElementById('{sid}').classList.add('show')">+</button></h6>
<div class="table-responsive"><table class="table table-dark table-sm mobile-card-table"><thead><tr><th>Service</th><th></th></tr></thead><tbody>{service_rows or '<tr><td colspan=2 class=text-muted>No services blocked</td></tr>'}</tbody></table></div>
</div>
</div>
</div>
<!-- Rule modal -->
<div id="{rid}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
<div class="modal-box">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
<h2 class="h5" style="margin:0">Add Rule to {p['name']}</h2>
<button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{rid}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
</div>
<form method="post" action="/profiles/rule-add">
<input type="hidden" name="profile_id" value="{p['id']}">
<label class="form-label">Action</label>
<select class="form-select mb-2" name="action"><option value="block">Block</option><option value="allow">Allow</option></select>
<label class="form-label">Type</label>
<select class="form-select mb-2" name="pattern_type"><option value="domain">Domain</option><option value="wildcard">Wildcard</option><option value="regex">Regex</option></select>
<label class="form-label">Pattern</label>
<input class="form-control mb-2" name="pattern" placeholder="e.g. bad.example.com" required>
<button class="btn btn-success w-100 mt-3" type="submit">Add Rule</button>
</form>
</div>
</div>
<!-- Blocklist modal -->
<div id="{bid}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
<div class="modal-box">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
<h2 class="h5" style="margin:0">Add Blocklist to {p['name']}</h2>
<button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{bid}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
</div>
<form method="post" action="/profiles/blocklist-add">
<input type="hidden" name="profile_id" value="{p['id']}">
<label class="form-label">Blocklist</label>
<select class="form-select mb-2" name="blocklist_id">
{blist_opts}
</select>
<button class="btn btn-success w-100 mt-3" type="submit">Add</button>
</form>
</div>
</div>
<!-- Service modal -->
<div id="{sid}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
<div class="modal-box">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
<h2 class="h5" style="margin:0">Add Service Block to {p['name']}</h2>
<button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{sid}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
</div>
<form method="post" action="/profiles/service-add">
<input type="hidden" name="profile_id" value="{p['id']}">
<label class="form-label">Service</label>
<select class="form-select mb-2" name="service_name" required>
{service_opts or '<option value="">All services are already blocked</option>'}
</select>
<button class="btn btn-success w-100 mt-3" type="submit" {"disabled" if not service_opts else ""}>Add</button>
</form>
</div>
</div>
<!-- Edit modal -->
<div id="{eid}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
<div class="modal-box">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
<h2 class="h5" style="margin:0">Edit {p['name']}</h2>
<button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{eid}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
</div>
<form method="post" action="/profiles/edit">
<input type="hidden" name="profile_id" value="{p['id']}">
<label class="form-label">Name</label>
<input class="form-control mb-2" name="name" value="{p['name']}" required>
<label class="form-label">Description</label>
<input class="form-control mb-2" name="description" value="{p.get('description','')}">
<label class="form-label">Filtering Enabled</label>
<select class="form-select mb-2" name="filtering_enabled">
<option value="1" {"selected" if p['filtering_enabled'] else ""}>On</option>
<option value="0" {"selected" if not p['filtering_enabled'] else ""}>Off</option>
</select>
<label class="form-label">SafeSearch Google</label>
<select class="form-select mb-2" name="safe_search_google">
<option value="1" {"selected" if p.get('safe_search_google') else ""}>On</option>
<option value="0" {"selected" if not p.get('safe_search_google') else ""}>Off</option>
</select>
<label class="form-label">SafeSearch Bing</label>
<select class="form-select mb-2" name="safe_search_bing">
<option value="1" {"selected" if p.get('safe_search_bing') else ""}>On</option>
<option value="0" {"selected" if not p.get('safe_search_bing') else ""}>Off</option>
</select>
<label class="form-label">SafeSearch DuckDuckGo</label>
<select class="form-select mb-2" name="safe_search_ddg">
<option value="1" {"selected" if p.get('safe_search_ddg') else ""}>On</option>
<option value="0" {"selected" if not p.get('safe_search_ddg') else ""}>Off</option>
</select>
<label class="form-label">YouTube Restricted</label>
<select class="form-select mb-2" name="youtube_restricted">
<option value="1" {"selected" if p.get('youtube_restricted') else ""}>On</option>
<option value="0" {"selected" if not p.get('youtube_restricted') else ""}>Off</option>
</select>
<button class="btn btn-success w-100 mt-3" type="submit">Save Changes</button>
</form>
</div>
</div>
"""
        if not p['is_default']:
            cards += f"""
<div id="{did}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
<div class="modal-box">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
<h2 class="h5" style="margin:0">Delete {p['name']}?</h2>
<button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{did}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
</div>
<p class="mb-3">Clients using this profile will be reassigned to the Default profile.</p>
<form method="post" action="/profiles/delete">
<input type="hidden" name="profile_id" value="{p['id']}">
<button class="btn btn-danger w-100" type="submit">Delete</button>
</form>
</div>
</div>"""
    return template(f"""
<div class="d-flex align-items-center justify-content-between mb-3">
<h1 class="h3 mb-0">Profiles</h1>
<button class="btn btn-success" type="button" onclick="document.getElementById('profile-create-modal').classList.add('show')">+ New Profile</button>
</div>
{cards}
<div id="profile-create-modal" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
<div class="modal-box">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
<h2 class="h5" style="margin:0">New Profile</h2>
<button class="btn btn-sm btn-outline-light" type="button" onclick="document.getElementById('profile-create-modal').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
</div>
<form method="post" action="/profiles/add">
<label class="form-label">Name</label>
<input class="form-control mb-2" name="name" placeholder="Profile name" required>
<label class="form-label">Description</label>
<input class="form-control mb-2" name="description" placeholder="Description">
<button class="btn btn-success w-100 mt-3" type="submit">Create</button>
</form>
</div>
</div>""", "Profiles")

def cache_page():
    s = cache_stats()
    rows_html = "".join(
        f"<tr><td data-label='Metric' class='td-muted'>{label}</td><td data-label='Value' class='td-num'>{value}</td></tr>"
        for label, value in [
            ("Status", "Enabled" if s["enabled"] else "Disabled"),
            ("Entries", s["entries"]),
            ("Expired Entries", s["expired_entries"]),
            ("Storage", f"{s['bytes_used']:,} / {s['max_bytes']:,} Bytes ({s['usage_percent']}%)"),
            ("Hits 24h", s["hits_24h"]),
            ("Misses 24h", s["misses_24h"]),
            ("Hit Rate 24h", f"{s['hit_rate_24h']}%"),
            ("TTL", f"{s['ttl_seconds']}s"),
            ("Min TTL", f"{s['min_ttl_seconds']}s"),
            ("Max TTL", f"{s['max_ttl_seconds']}s"),
            ("Next Expiry", "-" if s["next_expiry_seconds"] is None else f"{s['next_expiry_seconds']}s"),
        ]
    )
    return template(f"""
<h1 class="h3 mb-3">Cache</h1>
<div class="panel rounded-2 border border-secondary-subtle p-3">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h2 class="h5 m-0">DNS Cache Status</h2>
    <button class="btn btn-outline-danger btn-sm" onclick="clearCache(this)">Clear Cache</button>
  </div>
  <div class="table-responsive"><table class="table table-dark table-hover mobile-card-table"><tbody id="cache-stats">{rows_html}</tbody></table></div>
</div>
<script>
async function clearCache(btn) {{
  if (!confirm('Really clear DNS cache?')) return;
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Clearing...';
  try {{
    const r = await fetch('/api/cache/clear', {{method:'POST'}});
    const d = await r.json();
    if (!d.ok) throw new Error(d.error || 'Cache could not be cleared');
    location.reload();
  }} catch(e) {{
    alert(e.message);
    btn.disabled = false;
    btn.textContent = old;
  }}
}}
</script>""", "Cache")


def upstreams_page():
    current_mode = get_setting("upstream_mode", "sequential")
    data = rows("SELECT * FROM upstreams ORDER BY id ASC")
    def upstream_toggle(r):
        rid = r["id"]
        checked = "checked" if r["enabled"] else ""
        next_enabled = "0" if r["enabled"] else "1"
        label = "Enabled" if r["enabled"] else "Disabled"
        return (
            f"<form method='post' action='/upstreams/toggle' class='m-0'>"
            f"<input type='hidden' name='id' value='{rid}'>"
            f"<input type='hidden' name='enabled' value='{next_enabled}'>"
            f"<label class='form-check form-switch m-0 d-flex align-items-center gap-2'>"
            f"<input class='form-check-input' type='checkbox' role='switch' {checked} onchange='this.form.submit()'>"
            f"<span class='small text-secondary'>{label}</span>"
            f"</label></form>"
        )
    def upstream_row(r):
        rid = r['id']
        return (
            f"<tr id='upstream-row-{rid}'>"
            f"<td data-label='Name'>{html_escape(r['name'])}</td>"
            f"<td data-label='Resolver' class='text-break'>{html_escape(r['resolver'] or (r['address'] + ':' + str(r['port'])))}</td>"
            f"<td data-label='Type'><span class='badge text-bg-secondary'>{html_escape(r['resolver_type'])}</span></td>"
            f"<td data-label='Transport'>{html_escape(r['transport'])}</td>"
            f"<td data-label='Enabled'>{upstream_toggle(r)}</td>"
            f"<td data-label='Latency ms' id='upstream-latency-{rid}'>{latency_badge(r)}</td>"
            f"<td data-label='Error' class='text-secondary' id='upstream-error-{rid}'>{html_escape(r['last_error'])}</td>"
            f"<td data-label='Actions' class='d-flex gap-2'>"
            f"<button class='btn btn-sm btn-outline-light' onclick='testUpstream({rid},this)'>Test</button>"
            f"<form method='post' action='/upstreams/delete'><input type='hidden' name='id' value='{rid}'><button class='btn btn-sm btn-outline-danger'>Delete</button></form>"
            f"</td></tr>"
        )
    table = "".join(upstream_row(r) for r in data)
    mode_options = select_options([
        ("sequential",       "Sequential - try upstreams one after another"),
        ("load_balance",     "Load balancing - query one upstream server at a time"),
        ("parallel_fastest", "Parallel fastest - query all upstream servers at once"),
    ], current_mode)
    mode_desc = {
        "sequential":       "Upstreams are queried in order. If one fails, the next one is tried.",
        "load_balance":     "One upstream server is queried at a time. Requests are distributed across all active upstreams with round-robin.",
        "parallel_fastest": "Parallel queries speed up resolution by querying all upstream servers at the same time. The fastest response wins.",
    }.get(current_mode, "")
    return template(f"""
<h1 class="h3 mb-3">Upstreams</h1>
<div class="panel rounded-2 border border-secondary-subtle p-3 mb-3">
  <h2 class="h5 mb-3">Upstream Mode</h2>
  <form method="post" action="/upstreams/mode" class="row g-3">
    <div class="col-md-8"><select class="form-select" name="upstream_mode">{mode_options}</select></div>
    <div class="col-md-4"><button class="btn btn-success w-100">Save</button></div>
    <div class="col-12"><div class="alert alert-secondary py-2 small">{html_escape(mode_desc)}</div></div>
  </form>
</div>
<div class="row g-3">
<div class="col-xl-4"><form class="panel rounded-2 border border-secondary-subtle p-3" method="post" action="/upstreams/add">
<h2 class="h5">Add Upstream</h2>
<label class="form-label">Name</label><input class="form-control mb-2" name="name" placeholder="Cloudflare" required>
<label class="form-label">Resolver</label><input class="form-control mb-2" id="resolver-input" name="resolver" placeholder="https://dns.google/dns-query" required>
<div class="alert alert-secondary py-2" id="resolver-detect">Type is detected automatically.</div>
<div class="small text-secondary mb-3">Use <code>https://domain/dns-query</code> for DNS-over-HTTPS, <code>h3://domain/dns-query</code> for DNS-over-HTTPS over QUIC/HTTP3, or <code>tls://domain</code> for pooled DNS-over-TLS. Native <code>quic://domain</code> upstreams are experimental and disabled by default.</div>
<button class="btn btn-success w-100">Save</button></form></div>
<div class="col-xl-8"><div class="panel rounded-2 border border-secondary-subtle p-3"><div class="table-responsive"><table class="table table-dark table-hover mobile-card-table"><thead><tr><th>Name</th><th>Resolver</th><th>Type</th><th>Transport</th><th>Enabled</th><th>Latency ms</th><th>Error</th><th></th></tr></thead><tbody>{table}</tbody></table></div></div></div></div>
<script>
async function testUpstream(id, btn) {{
  const origText = btn.textContent;
  btn.textContent = '…';
  btn.disabled = true;
  const latCell  = document.getElementById('upstream-latency-' + id);
  const errCell  = document.getElementById('upstream-error-'   + id);
  try {{
    const fd = new FormData();
    fd.append('id', id);
    const r = await fetch('/api/upstreams/test', {{method:'POST', body: new URLSearchParams(fd)}});
    const d = await r.json();
    if (d.ok) {{
      const ms = d.latency_ms;
      const cls = ms < 80 ? 'success' : ms < 180 ? 'warning' : 'danger';
      latCell.innerHTML = `<span class="badge text-bg-${{cls}}">${{ms.toFixed(1)}} ms</span>`;
      errCell.textContent = '';
    }} else {{
      latCell.innerHTML = '<span class="badge text-bg-danger">Error</span>';
      errCell.textContent = d.error || 'Timeout';
    }}
  }} catch(e) {{
    latCell.innerHTML = '<span class="badge text-bg-danger">Error</span>';
    errCell.textContent = e.message;
  }}
  btn.textContent = origText;
  btn.disabled = false;
}}
const resolverInput = document.getElementById('resolver-input');
const resolverDetect = document.getElementById('resolver-detect');
async function detectResolver() {{
  const resolver = resolverInput.value.trim();
  if (!resolver) {{
    resolverDetect.textContent = 'Type is detected automatically.';
    resolverDetect.className = 'alert alert-secondary py-2';
    return;
  }}
  try {{
    const response = await fetch('/api/upstreams/detect?resolver=' + encodeURIComponent(resolver), {{cache:'no-store'}});
    const data = await response.json();
    resolverDetect.textContent = data.label + (data.supported ? ' - forwarding active.' : ' - detected, forwarding is not implemented yet.');
    resolverDetect.className = 'alert py-2 ' + (data.supported ? 'alert-success' : 'alert-warning');
  }} catch (error) {{}}
}}
resolverInput.addEventListener('input', detectResolver);
</script>""", "Upstreams")


def settings_page(message="", is_error=False, values=None):
    values = values or {}
    def value(name, default=""):
        return values.get(name, get_setting(name, default))

    def switch(name, label, description="", default="1"):
        checked = "checked" if value(name, default) == "1" else ""
        desc = f'<div class="settings-help">{html_escape(description)}</div>' if description else ""
        return (
            f'<label class="settings-switch" for="{name}">'
            f'<span><span class="settings-label">{label}</span>{desc}</span>'
            f'<input type="hidden" name="{name}" value="0">'
            f'<span class="toggle settings-toggle">'
            f'<input id="{name}" type="checkbox" role="switch" name="{name}" value="1" {checked}>'
            f'<span class="toggle-track"></span><span class="toggle-thumb"></span>'
            f'</span></label>'
        )

    def radio_group(name, options, default):
        current = value(name, default)
        out = ""
        for opt_value, label, description in options:
            checked = "checked" if str(current) == str(opt_value) else ""
            out += (
                f'<label class="settings-radio">'
                f'<input type="radio" name="{html_escape(name)}" value="{html_escape(opt_value)}" {checked}>'
                f'<span><span class="settings-label">{html_escape(label)}</span>'
                f'<span class="settings-help">{html_escape(description)}</span></span>'
                f'</label>'
            )
        return out

    encrypted_status = encrypted_dns_readiness()
    encrypted_alert = ""
    if encrypted_status["issues"]:
        encrypted_alert = (
            '<div class="alert alert-warning py-2">'
            'Encrypted DNS is not ready: '
            + html_escape("; ".join(encrypted_status["issues"]))
            + '</div>'
        )

    return template(f"""
<style>
.settings-shell{{display:flex;flex-direction:column;gap:1rem}}
.settings-header{{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:.2rem}}
.settings-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}}
.settings-section{{background:var(--card);border:1px solid var(--border);border-radius:.6rem;overflow:hidden}}
.settings-section-wide{{grid-column:1/-1}}
.settings-section-head{{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;padding:1rem 1.1rem;border-bottom:1px solid var(--border);background:rgba(11,18,32,.38)}}
.settings-section-title{{font-size:.94rem;font-weight:800}}
.settings-section-subtitle{{font-size:.82rem;color:var(--muted2);margin-top:.12rem}}
.settings-section-body{{padding:1rem 1.1rem}}
.settings-stack{{display:grid;gap:.75rem}}
.settings-field-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.9rem}}
.settings-field-grid.two{{grid-template-columns:repeat(2,minmax(0,1fr))}}
.settings-switch{{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.78rem .85rem;border:1px solid rgba(30,45,61,.7);border-radius:.5rem;background:#0b1220;cursor:pointer;min-height:64px}}
.settings-switch:hover{{border-color:#2f455e;background:#0d1626}}
.settings-radio{{display:flex;align-items:flex-start;gap:.7rem;padding:.78rem .85rem;border:1px solid rgba(30,45,61,.7);border-radius:.5rem;background:#0b1220;cursor:pointer;min-height:78px}}
.settings-radio:hover{{border-color:#2f455e;background:#0d1626}}
.settings-radio input{{margin-top:.2rem;accent-color:var(--accent);flex-shrink:0}}
.settings-label{{display:block;font-size:.9rem;font-weight:700;color:var(--text)}}
.settings-help{{font-size:.78rem;color:var(--muted2);margin-top:.12rem}}
.settings-toggle{{margin-left:auto}}
.settings-actions{{display:flex;justify-content:flex-end;gap:.65rem;margin-top:.1rem}}
.settings-textarea{{min-height:150px;font-family:ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace;font-size:.8rem;line-height:1.35;resize:vertical}}
@media(max-width:980px){{.settings-grid,.settings-field-grid,.settings-field-grid.two{{grid-template-columns:1fr}}}}
@media(max-width:640px){{
.settings-header,.settings-section-head,.settings-switch{{align-items:flex-start;flex-direction:column}}
.settings-section-body{{padding:.85rem}}
.settings-section-head{{padding:.85rem}}
.settings-switch{{gap:.65rem;min-height:0}}
.settings-switch .toggle{{align-self:flex-start}}
}}
.modal-result{{padding:.6rem .8rem;border-radius:.4rem;margin-bottom:.4rem;font-size:.88rem;border:1px solid transparent}}
.modal-result.ok{{background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.2);color:#4ade80}}
.modal-result.err{{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2);color:#f87171}}
.modal-result.pending{{background:rgba(100,116,139,.08);border-color:rgba(100,116,139,.2);color:var(--muted2)}}
</style>
<form class="settings-shell" method="post" action="/settings">
  <div class="settings-header">
    <div>
      <h1 class="page-title" style="margin-bottom:.15rem">Settings</h1>
      <div class="small text-secondary">Core DNS, cache, access, and response behavior.</div>
    </div>
    <button class="btn btn-success">Save Changes</button>
  </div>
  {f'<div class="alert {"alert-danger" if is_error else "alert-success"}">{html_escape(message)}</div>' if message else ''}

  <div class="settings-grid">
    <section class="settings-section settings-section-wide">
      <div class="settings-section-head">
        <div>
          <div class="settings-section-title">Runtime Network</div>
          <div class="settings-section-subtitle">Web UI, DNS listener, and encrypted DNS endpoints.</div>
        </div>
      </div>
      <div class="settings-section-body settings-stack">
        {encrypted_alert}
        <div class="settings-field-grid">
          <div><label class="form-label">LOCALDNSGUARD_WEB_HOST</label><input class="form-control" name="localdnsguard_web_host" value="{html_escape(value('localdnsguard_web_host', WEB_HOST))}"></div>
          <div><label class="form-label">LOCALDNSGUARD_WEB_PORT</label><input class="form-control" name="localdnsguard_web_port" type="number" min="0" max="65535" value="{html_escape(value('localdnsguard_web_port', WEB_PORT))}"></div>
          <div><label class="form-label">Encrypted DNS Listen Host</label><input class="form-control" name="encrypted_dns_host" value="{html_escape(value('encrypted_dns_host', DNS_HOST))}"></div>
        </div>
        <div class="settings-field-grid">
          <div><label class="form-label">LOCALDNSGUARD_DNS_HOST</label><input class="form-control" name="localdnsguard_dns_host" value="{html_escape(value('localdnsguard_dns_host', DNS_HOST))}"></div>
          <div><label class="form-label">LOCALDNSGUARD_DNS_PORT</label><input class="form-control" name="localdnsguard_dns_port" type="number" min="0" max="65535" value="{html_escape(value('localdnsguard_dns_port', DNS_PORT))}"></div>
          <div><label class="form-label">Public DNS Domain</label><input class="form-control" name="encrypted_dns_domain" placeholder="dns.example.com" value="{html_escape(value('encrypted_dns_domain', ENCRYPTED_DNS_DOMAIN))}"></div>
        </div>
        <div class="settings-field-grid">
          <div><label class="form-label">Upstream Timeout</label><input class="form-control" name="upstream_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('upstream_timeout', '2.5'))}"></div>
          <div class="settings-help" style="display:flex;align-items:center;grid-column:span 2">Number of seconds to wait for a response from the upstream server.</div>
        </div>
        <div class="settings-field-grid two">
          {switch("dns_over_tls_enabled", "DNS over TLS", "Accept encrypted DNS over TCP/TLS. Default port is 853.", "0")}
          {switch("dns_over_https_enabled", "DNS over HTTPS", "Accept DNS-over-HTTPS on /dns-query. Default port is 443.", "0")}
          {switch("dns_over_quic_enabled", "DNS over QUIC (experimental)", "Accept encrypted DNS over QUIC. Disabled by default while upstream QUIC pooling is experimental.", "0")}
        </div>
        <div class="settings-field-grid">
          <div><label class="form-label">DNS-over-TLS Port</label><input class="form-control" name="dns_over_tls_port" type="number" min="0" max="65535" value="{html_escape(value('dns_over_tls_port', '853'))}"></div>
          <div><label class="form-label">DNS-over-HTTPS Port</label><input class="form-control" name="dns_over_https_port" type="number" min="0" max="65535" value="{html_escape(value('dns_over_https_port', '443'))}"></div>
          <div><label class="form-label">DNS-over-QUIC Port</label><input class="form-control" name="dns_over_quic_port" type="number" min="0" max="65535" value="{html_escape(value('dns_over_quic_port', '853'))}"></div>
        </div>
        <div class="settings-field-grid two">
          <div>
            <label class="form-label">Certificate PEM</label>
            <textarea class="form-control settings-textarea" name="encrypted_dns_certificate_pem" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">{html_escape(value('encrypted_dns_certificate_pem', ''))}</textarea>
          </div>
          <div>
            <label class="form-label">RSA Private Key PEM</label>
            <textarea class="form-control settings-textarea" name="encrypted_dns_private_key_pem" spellcheck="false" placeholder="-----BEGIN RSA PRIVATE KEY-----">{html_escape(value('encrypted_dns_private_key_pem', ''))}</textarea>
          </div>
        </div>
        <div class="settings-help">Clients connect with <code>tls://{html_escape(value('encrypted_dns_domain', 'panel.ts3x.cc') or 'panel.ts3x.cc')}</code> for DNS-over-TLS and <code>https://{html_escape(value('encrypted_dns_domain', 'panel.ts3x.cc') or 'panel.ts3x.cc')}/dns-query</code> for DNS-over-HTTPS. The listen host is the local bind address, usually <code>0.0.0.0</code>. Public DNS Domain must be the exact hostname clients use, and the certificate must include that hostname.</div>
      </div>
    </section>

    <section class="settings-section">
      <div class="settings-section-head">
        <div>
          <div class="settings-section-title">Filtering & Validation</div>
          <div class="settings-section-subtitle">Global DNS filtering controls.</div>
        </div>
      </div>
      <div class="settings-section-body settings-stack">
        {switch("filtering_enabled", "Filtering", "Apply rules, rewrites, and blocklists.", "1")}
        {switch("dnssec_validation_enabled", "DNSSEC Self-Validation", "Validate DNSSEC signatures locally using a root trust anchor. Bogus signed responses are returned as SERVFAIL.", "0")}
        {switch("query_log_enabled", "Query Log", "Store DNS query history for the dashboard and log view.", "1")}
        <div>
          <label class="form-label">Log Retention (days)</label>
          <input class="form-control" name="log_retention_days" type="number" min="1" max="365" value="{html_escape(get_setting('log_retention_days', '7'))}">
        </div>
        <div>
          <label class="form-label">Auto Clear Query Log (hours)</label>
          <input class="form-control" name="auto_clear_query_log_hours" type="number" min="0" max="8760" value="{html_escape(get_setting('auto_clear_query_log_hours', '0'))}">
          <div class="settings-help">Set to 0 to disable. When enabled, the entire query log is automatically deleted at this interval.</div>
        </div>
      </div>
    </section>

    <section class="settings-section">
      <div class="settings-section-head">
        <div>
          <div class="settings-section-title">Access Control</div>
          <div class="settings-section-subtitle">Default resolver exposure limits.</div>
        </div>
      </div>
      <div class="settings-section-body settings-stack">
        {switch("lan_only", "LAN Only", "Restrict DNS service to private/local networks.", "1")}
        <div>
          <label class="form-label">Allowed Networks</label>
          <input class="form-control" name="allowed_networks" value="{html_escape(get_setting('allowed_networks'))}">
        </div>
      </div>
    </section>

    <section class="settings-section">
      <div class="settings-section-head">
        <div>
          <div class="settings-section-title">API Access</div>
          <div class="settings-section-subtitle">Use this token as a Bearer token for REST clients.</div>
        </div>
      </div>
      <div class="settings-section-body">
        <label class="form-label">API Token</label>
        <div class="password-toggle-wrap">
          <input class="form-control" id="api-token-input" type="password" readonly value="{html_escape(get_setting(API_TOKEN_SETTING, ''))}">
          <button class="password-toggle-btn" type="button" onclick="toggleTokenVisibility()" title="Show/hide token" aria-label="Show/hide token">
            <svg id="token-eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg id="token-eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
        </div>
        <div class="settings-help">Web requests use the admin session. External clients must send <code>Authorization: Bearer ...</code> or <code>X-API-Token</code>.</div>
      </div>
    </section>

    <section class="settings-section">
      <div class="settings-section-head">
        <div>
          <div class="settings-section-title">Blocklist Updates</div>
          <div class="settings-section-subtitle">Background updates for enabled remote blocklists.</div>
        </div>
      </div>
      <div class="settings-section-body">
        <label class="form-label">Update Interval (hours)</label>
        <div style="display:flex;gap:.65rem;align-items:center">
          <input class="form-control" name="filter_update_interval_hours" type="number" min="0" value="{get_setting('filter_update_interval_hours','24')}" style="width:auto;flex:1">
          <button class="btn btn-success" type="button" onclick="updateFilterLists()" style="white-space:nowrap">Update Now</button>
        </div>
        <div class="settings-help" style="margin-top:.12rem">Set to 0 to disable automatic updates.</div>
      </div>
    </section>

    <section class="settings-section settings-section-wide">
      <div class="settings-section-head">
        <div>
          <div class="settings-section-title">Cache</div>
          <div class="settings-section-subtitle">TTL limits and memory budget.</div>
        </div>
      </div>
      <div class="settings-section-body settings-stack">
        <div class="settings-field-grid">
          <div><label class="form-label">Default TTL (sec.)</label><input class="form-control" name="cache_ttl" type="number" min="0" value="{get_setting('cache_ttl')}"></div>
          <div><label class="form-label">Cache Size (Bytes)</label><input class="form-control" name="cache_size" type="number" min="65536" value="{get_setting('cache_size','4194304')}"></div>
          {switch("cache_enabled", "Cache Enabled", "Use cached DNS answers when valid.", "1")}
        </div>
        <div class="settings-field-grid">
          <div><label class="form-label">Minimum TTL Override</label><input class="form-control" name="cache_min_ttl" type="number" min="0" value="{get_setting('cache_min_ttl','0')}"></div>
          <div><label class="form-label">Maximum TTL Override</label><input class="form-control" name="cache_max_ttl" type="number" min="0" value="{get_setting('cache_max_ttl','0')}"></div>
          {switch("cache_optimistic", "Optimistic Caching", "Serve expired entries while refreshing them in the background.", "0")}
        </div>
      </div>
    </section>

    <section class="settings-section settings-section-wide">
      <div class="settings-section-head">
        <div>
          <div class="settings-section-title">Block Response</div>
          <div class="settings-section-subtitle">Block mode, IPv6 policy, and TTL for filtered answers.</div>
        </div>
      </div>
      <div class="settings-section-body settings-stack">
        {switch("disable_ipv6", "Disable IPv6", "Discard all DNS queries for IPv6 addresses (type AAAA) and remove IPv6 hints from HTTPS/SVCB answers.", "0")}
        <div>
          <label class="form-label">Block Mode</label>
          <div class="settings-field-grid two">
            {radio_group("block_mode", [
                ("zero_ip", "Default / Null IP", "Reply with a null IP address (0.0.0.0 for A; :: for AAAA). Hosts-style rules with their own IP are still answered as rewrites."),
                ("refused", "REFUSED", "Reply with the REFUSED response code."),
                ("nxdomain", "NXDOMAIN", "Reply with the NXDOMAIN response code."),
                ("custom_ip", "Custom IP", "Reply with a manually configured IPv4 or IPv6 address."),
            ], "zero_ip")}
          </div>
        </div>
        <div class="settings-field-grid two">
          <div><label class="form-label">Custom Block IPv4</label><input class="form-control" name="custom_block_ipv4" value="{get_setting('custom_block_ipv4')}"></div>
          <div><label class="form-label">Custom Block IPv6</label><input class="form-control" name="custom_block_ipv6" value="{get_setting('custom_block_ipv6')}"></div>
        </div>
        <div class="settings-field-grid two">
          <div><label class="form-label">Blocked Response TTL</label><input class="form-control" name="block_response_ttl" type="number" min="0" value="{get_setting('block_response_ttl','60')}"></div>
          <div class="settings-help" style="display:flex;align-items:center">Number of seconds clients should cache a filtered response.</div>
        </div>
      </div>
    </section>
  </div>

  <div class="settings-actions">
    <button class="btn btn-success">Save Changes</button>
  </div>
</form>

<div id="fl-update-modal" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 class="h5" style="margin:0">Filter List Updates</h2>
      <button class="btn btn-sm btn-outline-light" onclick="document.getElementById('fl-update-modal').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
    </div>
    <div id="fl-update-status" style="margin-bottom:.8rem;font-size:.9rem;color:var(--muted2)">Click "Update Now" to start.</div>
    <div id="fl-update-results"></div>
  </div>
</div>

<script>
let flUpdatePollTimer = null;

function flEsc(value) {{
  return String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
}}

function renderFilterListUpdateStatus(d) {{
  const status = document.getElementById('fl-update-status');
  const results = document.getElementById('fl-update-results');
  const total = d.total || 0;
  const idx = d.current_index || 0;
  const current = d.current_name || '';
  if (d.running) {{
    status.textContent = current
      ? `Updating ${{idx}}/${{total}}: ${{current}}`
      : `Preparing ${{total}} filter list update${{total === 1 ? '' : 's'}}...`;
  }} else if (d.status === 'done') {{
    status.textContent = `Finished. Updated ${{d.results?.length || 0}}/${{total}} filter list${{total === 1 ? '' : 's'}}.`;
  }} else if (d.status === 'no_lists') {{
    status.textContent = 'No remote filter lists found.';
  }} else {{
    status.textContent = 'Update status: ' + (d.status || 'idle');
  }}
  const rows = (d.results || []).map(item => {{
    const cls = item.status === 'error' ? 'err' : 'ok';
    const msg = item.status === 'error'
      ? `${{flEsc(item.name)}}: ${{flEsc(item.error || 'failed')}}`
      : `${{flEsc(item.name)}}: updated (${{item.rules || 0}} rules)`;
    return `<div class="modal-result ${{cls}}">${{msg}}</div>`;
  }}).join('');
  const pending = d.running && current ? `<div class="modal-result pending">Now: ${{flEsc(current)}}</div>` : '';
  results.innerHTML = pending + rows;
}}

async function pollFilterListUpdateStatus() {{
  try {{
    const r = await fetch('/api/blocklists/update-status', {{cache:'no-store'}});
    const d = await r.json();
    renderFilterListUpdateStatus(d);
    if (d.running) {{
      flUpdatePollTimer = setTimeout(pollFilterListUpdateStatus, 900);
    }} else {{
      flUpdatePollTimer = null;
    }}
  }} catch(e) {{
    document.getElementById('fl-update-status').textContent = 'Error: ' + e.message;
    flUpdatePollTimer = null;
  }}
}}

async function updateFilterLists() {{
  const modal = document.getElementById('fl-update-modal');
  const status = document.getElementById('fl-update-status');
  const results = document.getElementById('fl-update-results');
  modal.classList.add('show');
  status.textContent = 'Starting...';
  results.innerHTML = '';
  if (flUpdatePollTimer) {{
    clearTimeout(flUpdatePollTimer);
    flUpdatePollTimer = null;
  }}
  try {{
    const r = await fetch('/api/blocklists/update-all', {{method:'POST'}});
    const d = await r.json();
    if (d.status === 'already_running') {{
      status.textContent = 'Update is already running.';
    }} else if (d.status === 'started') {{
      status.textContent = `Starting ${{d.count || 0}} filter list update${{d.count === 1 ? '' : 's'}}...`;
    }} else {{
      status.textContent = d.status || 'Finished.';
    }}
    pollFilterListUpdateStatus();
  }} catch(e) {{
    status.textContent = 'Error: ' + e.message;
  }}
}}
</script>""", "Settings")


def api_docs_page():
    base = f"http://&lt;host&gt;:{WEB_PORT}"
    sections = [
        ("Status & Dashboard", [
            ("GET", "/api/status", "System status, DNS and web port, statistics summary.",
             None,
             '{\n  "app": "PyGuardDNS",\n  "dns": {"host": "0.0.0.0", "port": 53},\n  "web": {"host": "0.0.0.0", "port": 8080},\n  "summary": { "total": 1024, "blocked": 312, ... }\n}'),
            ("GET", "/api/dashboard", "Live dashboard data: statistics for the last 24 h, sparklines, top domains, top clients.",
             None,
             '{\n  "today": {"total": 1024, "blocked": 312, "avg_ms": 14.2},\n  "sparklines": {"total": [...24 values...], "blocked": [...24 values...]},\n  "top_domains": [{"domain": "example.com", "cnt": 45}],\n  "top_blocked": [...],\n  "top_clients": [...]\n}'),
            ("GET", "/api/stats/summary", "Short statistics: total requests, blocked requests, cache rate, clients, uptime.",
             None,
             '{\n  "total": 1024, "blocked": 312, "block_rate": 30.5,\n  "avg_ms": 14.2, "cache_rate": 18.3,\n  "clients": 5, "rules": 87432, "upstreams": 2, "uptime": 3600\n}'),
        ]),
        ("Query Log", [
            ("GET", "/api/querylog", "All retained DNS requests as a JSON array. Supports q, client, and status filters.",
             None,
             '[{\n  "id": 1, "timestamp": "2026-05-31T12:00:00+02:00",\n  "client_ip": "192.168.0.10", "domain": "example.com",\n  "query_type": "A", "status": "allowed",\n  "duration_ms": 12.4, "matched_rule": "", "upstream": "Cloudflare"\n}]'),
            ("GET", "/api/querylog.csv", "Download the retained query log as a CSV file. Browser starts the download.",
             None, None),
        ]),
        ("Filtering", [
            ("POST", "/api/filtering/pause", "Disable filtering (Protection Enabled -> off).",
             None, '{"ok": true}'),
            ("POST", "/api/filtering/resume", "Enable filtering (Protection Enabled -> on).",
             None, '{"ok": true}'),
            ("POST", "/api/domain-test", "Test a domain through the decision pipeline.",
             '{\n  "domain": "ads.example.com",\n  "query_type": "A",\n  "client": "192.168.0.10"\n}',
             '{\n  "status": "blocked", "action": "block",\n  "rule": "block:ads.example.com",\n  "reason": "block rule",\n  "domain": "ads.example.com"\n}'),
        ]),
        ("Rules", [
            ("GET", "/api/rules", "All custom rules.",
             None,
             '[{"id":1,"action":"block","pattern_type":"domain","pattern":"ads.example.com","enabled":1}]'),
        ]),
        ("Blocklists", [
            ("GET", "/api/blocklists", "All configured blocklists.",
             None,
             '[{"id":1,"name":"StevenBlack","url":"https://...","rule_count":120000,"last_update":"..."}]'),
            ("POST", "/api/blocklists/add", "Add a blocklist by URL or paste content.",
             '{"name":"MyList","url":"https://...","list_type":"block"}',
             '{"ok":true,"name":"MyList","rules":120000}'),
            ("POST", "/api/blocklists/update", "Re-download and reload one blocklist.",
             '{"id":1}',
             '{"ok":true}'),
            ("POST", "/api/blocklists/delete", "Delete a blocklist.",
             '{"id":1}',
             '{"ok":true}'),
            ("POST", "/api/blocklists/update-all", "Update all remote blocklists.",
             None, '{"ok": true, "results": [...]}'),
        ]),
        ("Clients", [
            ("GET", "/api/clients", "All saved clients with profile info.",
             None,
             '[{"id":1,"name":"PC-1","ip":"192.168.0.10","profile_id":1,"profile_name":"Default"}]'),
            ("POST", "/api/clients", "Create or update a client.",
             '{"ip":"192.168.0.10","name":"PC-1","cidr":"","profile_id":1,"filtering_enabled":1}',
             '{"ok":true,"id":1}'),
            ("PUT", "/api/clients/{id}", "Update a client.",
             '{"name":"PC-1","cidr":"","profile_id":1,"filtering_enabled":1}',
             '{"ok":true}'),
            ("DELETE", "/api/clients/{id}", "Delete a client.",
             None, '{"ok":true}'),
        ]),
        ("Profiles", [
            ("GET", "/api/profiles", "All profiles.",
             None,
             '[{"id":1,"name":"Default","description":"...","is_default":1,"filtering_enabled":1}]'),
            ("POST", "/api/profiles", "Create a profile.",
             '{"name":"Kids","description":"Restricted profile","filtering_enabled":1}',
             '{"ok":true,"id":1}'),
            ("PUT", "/api/profiles/{id}", "Update a profile.",
             '{"name":"Kids","filtering_enabled":1}',
             '{"ok":true}'),
            ("DELETE", "/api/profiles/{id}", "Delete a profile (reassigns clients to Default).",
             None, '{"ok":true}'),
            ("GET", "/api/profiles/{id}/rules", "Custom rules for a profile.",
             None,
             '[{"id":1,"action":"block","pattern_type":"domain","pattern":"ads.example.com"}]'),
            ("POST", "/api/profiles/{id}/rules", "Add a custom rule to a profile.",
             '{"action":"block","pattern_type":"domain","pattern":"bad.example.com"}',
             '{"ok":true}'),
            ("DELETE", "/api/profiles/{id}/rules/{rule_id}", "Delete a profile custom rule.",
             None, '{"ok":true}'),
            ("GET", "/api/profiles/{id}/blocklists", "Blocklists attached to a profile.",
             None,
             '[{"blocklist_id":1,"name":"HaGeZi"}]'),
            ("POST", "/api/profiles/{id}/blocklists", "Attach a blocklist to a profile.",
             '{"blocklist_id":1}',
             '{"ok":true}'),
            ("DELETE", "/api/profiles/{id}/blocklists/{bl_id}", "Detach a blocklist from a profile.",
             None, '{"ok":true}'),
        ]),
        ("Upstreams", [
            ("GET", "/api/upstreams", "All configured upstream resolvers with latency and status.",
             None,
             '[{"id":1,"name":"Cloudflare","address":"1.1.1.1","port":53,"resolver_type":"plain_udp","latency_ms":12.4,"last_error":""}]'),
            ("GET", "/api/upstreams/detect?resolver=...", "Detect upstream type automatically.",
             None,
             '{"resolver":"1.1.1.1","type":"plain_udp","transport":"udp","supported":true,"label":"Regular DNS over UDP"}'),
            ("POST", "/api/upstreams/test", "Test upstream and measure latency.",
             '{"id": "1"}',
             '{"ok": true, "latency_ms": 12.4}'),
        ]),
        ("Cache", [
            ("POST", "/api/cache/clear", "Clear the whole DNS cache.",
             None, '{"ok": true}'),
        ]),
        ("Blocklists", [
            ("GET", "/api/blocklists", "All configured blocklists.",
             None,
             '[{"id":1,"name":"HaGeZi","url":"https://...","rule_count":85000,"last_update":"..."}]'),
            ("POST", "/api/blocklists/add", "Add a blocklist by URL or paste content.",
             '{"name":"MyList","url":"https://...","list_type":"block"}',
             '{"ok": true, "name": "MyList", "rules": 120000}'),
            ("POST", "/api/blocklists/update", "Re-download and reload one blocklist.",
             '{"id": "1"}',
             '{"status": "started", "id": 1}'),
            ("POST", "/api/blocklists/update-all", "Update all remote blocklists.",
             None,
             '{"status": "started", "count": 3}'),
            ("GET", "/api/blocklists/update-status", "Current background blocklist update progress.",
             None,
             '{"running": true, "current_name": "HaGeZi", "current_index": 1, "total": 3, "results": []}'),
            ("POST", "/api/blocklists/delete", "Delete a blocklist and its entries.",
             '{"id": "1"}',
             '{"ok": true}'),
        ]),
        ("Backup", [
            ("GET", "/api/backup", "Download settings backup as a JSON file (settings, blocklists, rules, DNS rewrites, upstreams; without DNS queries).",
             None,
             '{\n  "settings": [...],\n  "blocklists": [...],\n  "rules": [...],\n  "dns_rewrites": [...],\n  "upstreams": [...]\n}'),
        ]),
    ]

    def method_badge(m):
        color = {"GET": "#22c55e", "POST": "#3b82f6", "DELETE": "#ef4444", "PUT": "#f59e0b"}.get(m, "#94a3b8")
        return f'<span style="background:{color}22;color:{color};font-size:.75rem;font-weight:700;padding:.18rem .52rem;border-radius:.3rem;font-family:monospace;flex-shrink:0">{m}</span>'

    rows_html = ""
    for section_title, endpoints in sections:
        rows_html += f'<div style="font-size:.72rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.08em;padding:.9rem 1.1rem .4rem">{section_title}</div>'
        for method, path, desc, req_body, resp_body in endpoints:
            req_html = f'<div style="margin-top:.6rem"><div style="font-size:.75rem;color:var(--muted);margin-bottom:.25rem">Request Body</div><pre style="background:#0a1018;border:1px solid var(--border);border-radius:.4rem;padding:.65rem .85rem;font-size:.78rem;color:#94a3b8;overflow-x:auto;margin:0">{req_body}</pre></div>' if req_body else ""
            resp_html = f'<div style="margin-top:.6rem"><div style="font-size:.75rem;color:var(--muted);margin-bottom:.25rem">Response</div><pre style="background:#0a1018;border:1px solid var(--border);border-radius:.4rem;padding:.65rem .85rem;font-size:.78rem;color:#86efac;overflow-x:auto;margin:0">{resp_body}</pre></div>' if resp_body else ""
            rows_html += f'''<div style="border-bottom:1px solid var(--border);padding:.85rem 1.1rem">
  <div style="display:flex;align-items:center;gap:.65rem;margin-bottom:.35rem">
    {method_badge(method)}
    <code style="font-size:.85rem;color:var(--text);font-family:monospace">{path}</code>
  </div>
  <div style="font-size:.88rem;color:var(--muted2)">{desc}</div>
  {req_html}{resp_html}
</div>'''

    return template(f"""
<div class="page-title">API Documentation</div>
<div style="margin-bottom:1rem" class="alert alert-secondary">
  Base URL: <code style="font-family:monospace">{base}</code> &nbsp;·&nbsp;
  All endpoints return <strong>JSON</strong> (except CSV and backup downloads) &nbsp;·&nbsp;
  Authentication: admin session cookie or Bearer/API token
</div>
<div class="panel">{rows_html}</div>
""", "API")


def domain_test_result_html(result):
    if not result:
        return ""
    steps = result.get("steps") or []
    steps_html = ""
    if steps:
        step_rows = ""
        for item in steps:
            detail = ", ".join(f"{html_escape(str(k))}: {html_escape(str(v))}" for k, v in item.items() if k != "step")
            step_rows += f"<tr><td>{html_escape(str(item.get('step', '')))}</td><td>{detail or '-'}</td></tr>"
        steps_html = f"""
  <div class="table-responsive mt-3">
    <table class="table table-dark table-striped align-middle mb-0 domain-test-table">
      <thead><tr><th>Step</th><th>Result</th></tr></thead>
      <tbody>{step_rows}</tbody>
    </table>
  </div>"""

    action = str(result.get("action", "") or "").upper()
    badge_cls = {
        "ALLOW": "success",
        "BLOCK": "danger",
        "REWRITE": "warning",
    }.get(action, "secondary")
    fields = [
        ("Domain", result.get("domain", "")),
        ("Query Type", result.get("query_type", "")),
        ("Client IP", result.get("client", "")),
        ("Action", f"<span class='badge text-bg-{badge_cls}'>{html_escape(action or '-')}</span>", True),
        ("Reason", result.get("reason", "")),
        ("Matched Rule", result.get("matched_rule", "")),
        ("Matched Domain", result.get("matched_domain", "")),
        ("Blocklist", result.get("list_name", "")),
        ("Client Name", result.get("client_name", "")),
        ("Profile", result.get("profile_name", "") or result.get("profile_id", "")),
    ]
    if result.get("target"):
        fields.append(("Rewrite Target", result.get("target", "")))

    rows_html = ""
    for label, value, *raw in fields:
        if value is None or value == "":
            value = "-"
        value_html = str(value) if raw else html_escape(str(value))
        rows_html += f"<tr><th scope='row' style='width:180px'>{html_escape(label)}</th><td>{value_html}</td></tr>"

    return f"""
<div class="panel rounded-2 border border-secondary-subtle p-3">
  <div class="panel-head px-0 pt-0"><span class="panel-title">Test Result</span></div>
  <div class="table-responsive">
    <table class="table table-dark table-striped align-middle mb-0 domain-test-table">
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>{steps_html}"""


def domain_test_page(result=None):
    result_html = domain_test_result_html(result)
    domain_value = html_escape(result.get("domain", "") if result else "")
    query_type_value = result.get("query_type", "A") if result else "A"
    client_value = html_escape(result.get("client", "127.0.0.1") if result else "127.0.0.1")
    return template(f"""
<h1 class="h3 mb-3">Domain Test</h1>
<form class="panel rounded-2 border border-secondary-subtle p-3 mb-3" method="post" action="/domain-test">
<div class="row g-2"><div class="col-md-5"><input class="form-control" name="domain" value="{domain_value}" placeholder="example.com" required></div><div class="col-md-3"><select class="form-select" name="query_type">{select_options(['A','AAAA','CNAME','MX','TXT','HTTPS','SVCB'], query_type_value)}</select></div><div class="col-md-3"><input class="form-control" name="client" value="{client_value}"></div><div class="col-md-1"><button class="btn btn-success w-100">Test</button></div></div>
</form>{result_html}""", "Domain Test")


def run_domain_test(form):
    domain = normalize_domain(form.get("domain", ""))
    query_type = (form.get("query_type", "A") or "A").upper()
    client = form.get("client", "127.0.0.1") or "127.0.0.1"
    if not domain:
        raise ValueError("Domain is missing")
    if query_type not in QTYPE_CODE:
        raise ValueError("Invalid query type")
    try:
        ipaddress.ip_address(client)
    except ValueError:
        raise ValueError("Client must be an IP address")
    engine = get_filter_engine()
    filtering_on = get_setting("filtering_enabled", "1") == "1" and client_filtering_enabled(client)
    profile_id = None
    client_info = None
    if client_manager is not None:
        client_info = client_manager.get_client_by_ip(client)
        if client_info:
            profile_id = client_info.get("profile_id")
    explanation = engine.explain(domain, filtering_enabled=filtering_on, profile_id=profile_id)
    base = {
        "domain": domain, "query_type": query_type, "client": client,
        "action": explanation["result"], "reason": explanation["reason"],
        "matched_rule": explanation.get("matched_rule", ""), "matched_domain": explanation.get("matched_domain", ""),
        "list_name": explanation.get("matched_list", ""),
        "profile_id": profile_id,
        "profile_name": client_info.get("profile_name", "") if client_info else "",
        "client_name": client_info.get("name", "") if client_info else "",
        "steps": explanation.get("steps", []),
        "allow_rule_won": explanation.get("allow_rule_won", False),
        "rewrite_applied": explanation.get("rewrite_applied", False),
        "safesearch_applied": explanation.get("safesearch_applied", False),
        "service_block_applied": explanation.get("service_block_applied", False),
    }
    if explanation.get("target"):
        base["target"] = explanation["target"]
    return base


def explain_decision(domain: str, client_ip: str = "") -> dict:
    client = client_ip or "127.0.0.1"
    normalized = normalize_domain(domain)
    filtering_on = get_setting("filtering_enabled", "1") == "1" and client_filtering_enabled(client)
    profile_id = None
    client_info = None
    if client_manager is not None:
        client_info = client_manager.get_client_by_ip(client)
        if client_info:
            profile_id = client_info.get("profile_id")
    explanation = get_filter_engine().explain(normalized or domain, filtering_enabled=filtering_on, profile_id=profile_id)
    explanation.update({
        "client_ip": client,
        "client_name": client_info.get("name", client) if client_info else client,
        "profile_id": profile_id,
        "profile_name": client_info.get("profile_name", "") if client_info else "",
        "filtering_enabled": filtering_on,
    })
    return explanation


def create_rule_from_querylog(form) -> dict:
    domain = normalize_domain(form.get("domain", ""))
    action = "allow" if form.get("action") == "allow" else "block"
    scope = form.get("scope", "global")
    client_ip = form.get("client", "").strip()
    profile_id = form.get("profile_id")
    if not domain:
        raise ValueError("domain required")
    now = now_iso()
    if scope == "global":
        with db_lock:
            db.execute(
                "INSERT INTO rules(scope,client,action,pattern_type,pattern,target,enabled,comment,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("global", "", action, "domain", domain, "", 1, "created from query log", now),
            )
            db.commit()
        invalidate_rules_cache()
        return {"ok": True, "scope": "global", "action": action, "pattern": domain}
    if scope == "profile":
        if client_manager is None:
            raise ValueError("profiles are not available")
        if not profile_id and client_ip:
            client_info = client_manager.get_client_by_ip(client_ip)
            profile_id = client_info.get("profile_id") if client_info else None
        if not profile_id:
            raise ValueError("profile_id required")
        rule = client_manager.add_profile_rule(int(profile_id), action, "domain", domain)
        if not rule:
            raise ValueError("profile not found")
        return {"ok": True, "scope": "profile", "profile_id": int(profile_id), "action": action, "pattern": domain}
    if scope == "client":
        raise ValueError("client-specific rules are not supported by the current filter engine")
    raise ValueError("invalid scope")


def handle_restore_data(data):
    global blocklist_manager, client_manager
    required = {"settings", "rules", "upstreams"}
    list_fields = required | {"blocklists", "dns_rewrites"}
    if not isinstance(data, dict):
        raise ValueError("Invalid backup format: JSON root must be an object")
    missing = sorted(required - set(data))
    if missing:
        raise ValueError(f"Invalid backup format: required fields are missing: {', '.join(missing)}")
    for key in list_fields:
        if key in data and not isinstance(data.get(key), list):
            raise ValueError(f"Invalid backup format: {key} must be a list")
    skip_settings = {"admin_password_set"}
    counts = {}
    with db_lock:
        settings_rows = [r for r in data.get("settings", []) if r.get("key") not in skip_settings]
        for row in settings_rows:
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (row["key"], row["value"]))
        counts["settings"] = len(settings_rows)
        db.execute("DELETE FROM rules")
        rule_rows = [row for row in data.get("rules", []) if row.get("action") != "rewrite"]
        for row in rule_rows:
            db.execute("INSERT INTO rules(action,pattern_type,pattern,target,scope,client,enabled,comment,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (row.get("action","block"), row.get("pattern_type","domain"), row.get("pattern",""), row.get("target",""),
                        row.get("scope","global"), row.get("client",""), int(row.get("enabled",1)), row.get("comment",""), row.get("created_at", now_iso())))
        counts["rules"] = len(rule_rows)
        rewrite_rows = data.get("dns_rewrites", [])
        for row in rewrite_rows:
            db.execute("INSERT INTO rules(action,pattern_type,pattern,target,scope,client,enabled,comment,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       ("rewrite", row.get("pattern_type","domain"), row.get("pattern",""), row.get("target",""),
                        row.get("scope","global"), row.get("client",""), int(row.get("enabled",1)), row.get("comment",""), row.get("created_at", now_iso())))
        counts["dns_rewrites"] = len(rewrite_rows)
        db.execute("DELETE FROM blocklists")
        db.execute("DELETE FROM blocklist_entries")
        from blocklist_manager import parse_filter_list
        restored_blocklists = 0
        for row in data.get("blocklists", []):
            name = row.get("name", "") or "unknown"
            url = row.get("url", row.get("source", ""))
            list_type = "allow" if row.get("list_type") == "allow" else "block"
            enabled = int(row.get("enabled", 1))
            last_update = row.get("last_update", "")
            last_error = ""
            entries = []
            content = row.get("content", "")
            if not content and str(url).startswith(("http://", "https://")):
                try:
                    content = fetch_url_text(url)
                    last_update = now_iso()
                except Exception as exc:
                    last_error = f"Restore update failed: {exc}"
            if content:
                entries = parse_filter_list(content)
                if not entries and not last_error:
                    last_error = "Restore update succeeded, but no valid filter rules were found"
            elif not last_error and str(url).startswith(("http://", "https://")):
                last_error = "Restore update returned no filter-list data"
            db.execute(
                "INSERT INTO blocklists(name,url,list_type,enabled,rule_count,last_update,last_error,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (name, url, list_type, enabled, len(entries), last_update, last_error or row.get("last_error", ""), row.get("created_at", now_iso())),
            )
            bl_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            if entries:
                created = now_iso()
                db.executemany(
                    "INSERT INTO blocklist_entries(blocklist_id,action,pattern_type,pattern,created_at) VALUES(?,?,?,?,?)",
                    [(bl_id, action, pt, pattern, created) for action, pt, pattern in entries],
                )
            restored_blocklists += 1
        counts["blocklists"] = restored_blocklists
        db.execute("DELETE FROM upstreams")
        for row in data.get("upstreams", []):
            db.execute("INSERT INTO upstreams(name,address,port,resolver,resolver_type,transport,enabled,latency_ms,last_error,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (row.get("name",""), row.get("address","1.1.1.1"), int(row.get("port",53)), row.get("resolver",""),
                        row.get("resolver_type","plain_udp"), row.get("transport","udp"), int(row.get("enabled",1)),
                        row.get("latency_ms"), row.get("last_error",""), row.get("created_at", now_iso())))
        counts["upstreams"] = len(data.get("upstreams", []))
        if client_manager and "profiles" in data:
            for row in data["profiles"]:
                name = row.get("name", "Default")
                description = row.get("description", "")
                is_default = int(row.get("is_default", 0))
                existing = db.execute("SELECT id FROM profiles WHERE name=? AND is_default=?", (name, is_default)).fetchone()
                if existing:
                    db.execute("UPDATE profiles SET description=?, is_default=? WHERE id=?", (description, is_default, existing["id"]))
                else:
                    db.execute("INSERT INTO profiles(name,description,is_default,created_at) VALUES(?,?,?,?)", (name, description, is_default, row.get("created_at", now_iso())))
            counts["profiles"] = len(data["profiles"])
        if client_manager and "clients" in data:
            for row in data["clients"]:
                name = row.get("name", "unknown")
                ip = row.get("ip", "")
                cidr_v = row.get("cidr", "")
                mac = row.get("mac", "")
                profile_id = row.get("profile_id")
                filtering_enabled = int(row.get("filtering_enabled", 1))
                existing = db.execute("SELECT id FROM clients WHERE name=? AND ip=?", (name, ip)).fetchone()
                if existing:
                    db.execute("UPDATE clients SET cidr=?,mac=?,profile_id=?,filtering_enabled=?,updated_at=? WHERE id=?", (cidr_v, mac, profile_id, filtering_enabled, now_iso(), existing["id"]))
                else:
                    db.execute("INSERT INTO clients(name,ip,cidr,mac,profile_id,filtering_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (name, ip, cidr_v, mac, profile_id, filtering_enabled, row.get("created_at", now_iso()), now_iso()))
            counts["clients"] = len(data["clients"])
        if client_manager and "profile_custom_rules" in data:
            for row in data["profile_custom_rules"]:
                db.execute("INSERT INTO profile_custom_rules(profile_id,action,pattern_type,pattern,enabled,comment,created_at) VALUES(?,?,?,?,?,?,?)",
                           (row.get("profile_id", 1), row.get("action", "block"), row.get("pattern_type", "domain"),
                            row.get("pattern", ""), int(row.get("enabled", 1)), row.get("comment", ""), row.get("created_at", now_iso())))
            counts["profile_custom_rules"] = len(data["profile_custom_rules"])
        if client_manager and "profile_blocklists" in data:
            for row in data["profile_blocklists"]:
                db.execute("INSERT OR IGNORE INTO profile_blocklists(profile_id,blocklist_id) VALUES(?,?)", (row.get("profile_id", 1), row.get("blocklist_id", 0)))
            counts["profile_blocklists"] = len(data["profile_blocklists"])
        if blocklist_manager and "blocklists" in data:
            for row in data["blocklists"]:
                existing = db.execute("SELECT id FROM blocklists WHERE name=? AND source=?", (row.get("name", ""), row.get("source", ""))).fetchone()
                if not existing:
                    db.execute("INSERT INTO blocklists(name,source,list_type,enabled,rule_count,last_update,last_error,created_at) VALUES(?,?,?,?,?,?,?,?)",
                               (row.get("name", ""), row.get("source", ""), row.get("list_type", "block"), int(row.get("enabled", 1)),
                                int(row.get("rule_count", 0)), row.get("last_update", ""), row.get("last_error", ""), row.get("created_at", now_iso())))
            counts["blocklists"] = len(data["blocklists"])
        db.commit()
    invalidate_rules_cache()
    return counts


def collect_metrics():
    summary = stats_summary()
    cache_stats_data = cache_stats()
    dot_metrics = dot_pool_metrics()
    queue_metrics = upstream_queue_wait_metrics()
    dnssec_metrics = get_dnssec_metrics()
    validator = get_dnssec_validator()
    dnssec_cache = validator.cache_stats() if validator else {}
    return {
        "total_queries": summary.get("total", 0),
        "blocked_queries": summary.get("blocked", 0),
        "block_rate": summary.get("block_rate", 0.0),
        "avg_response_ms": summary.get("avg_ms", 0.0),
        "cache_rate": summary.get("cache_rate", 0.0),
        "active_clients": summary.get("clients", 0),
        "filter_rules": summary.get("rules", 0),
        "active_upstreams": summary.get("upstreams", 0),
        "cache_entries": cache_stats_data.get("entries", 0),
        "cache_bytes": cache_stats_data.get("bytes_used", 0),
        "dnssec_secure": dnssec_metrics.get("secure", 0),
        "dnssec_insecure": dnssec_metrics.get("insecure", 0),
        "dnssec_bogus": dnssec_metrics.get("bogus", 0),
        "dnssec_indeterminate": dnssec_metrics.get("indeterminate", 0),
        "dnssec_validation_seconds": dnssec_metrics.get("validation_seconds_total", 0.0),
        "dnssec_dnskey_cache_entries": dnssec_cache.get("dnskey_cache_entries", 0),
        **dot_metrics,
        **queue_metrics,
    }


def toggle(value):
    return '<span class="status-dot dot-ok"></span>Yes' if value else '<span class="status-dot dot-bad"></span>No'


def latency_badge(row):
    if row["last_error"]:
        return '<span class="badge text-bg-danger">Timeout</span>'
    if row["latency_ms"] is None:
        return '<span class="text-secondary">-</span>'
    latency = float(row["latency_ms"])
    cls = "success" if latency < 80 else "warning" if latency < 180 else "danger"
    return f'<span class="badge text-bg-{cls}">{latency:.1f} ms</span>'


def bool_options(current):
    return select_options([("1", "Enabled"), ("0", "Disabled")], current)


def select_options(options, current):
    out = ""
    for opt in options:
        value, label = opt if isinstance(opt, tuple) else (opt, opt)
        out += f'<option value="{value}" {"selected" if str(value) == str(current) else ""}>{label}</option>'
    return out


def html_escape(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def bracket_host_for_url(host):
    host = str(host or "").strip()
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def local_dns_connection_hosts():
    hosts = []

    def add(host):
        host = str(host or "").strip()
        if not host or host in {"0.0.0.0", "::"}:
            return
        if host not in hosts:
            hosts.append(host)

    add("127.0.0.1")
    if DNS_HOST in {"0.0.0.0", "::"}:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("1.1.1.1", 53))
                add(s.getsockname()[0])
        except Exception:
            pass
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                if not ip.startswith("127."):
                    add(ip)
        except Exception:
            pass
    else:
        add(DNS_HOST)

    domain = get_setting("encrypted_dns_domain", ENCRYPTED_DNS_DOMAIN).strip()
    add(domain)
    return hosts


def dns_connection_endpoints():
    dns_port = int(DNS_PORT)
    tls_port = int(DNS_TLS_PORT)
    quic_port = int(DNS_QUIC_PORT)
    web_port = int(WEB_PORT)
    hosts = local_dns_connection_hosts()[:4]
    if not hosts:
        hosts = ["127.0.0.1"]

    endpoints = {
        "plain": [],
        "dot": [],
        "doq": [],
        "doh": [],
        "notes": [],
    }
    for host in hosts:
        display_host = bracket_host_for_url(host)
        plain_value = host if dns_port == 53 else f"{display_host}:{dns_port}"
        endpoints["plain"].append(plain_value)

    encrypted_status = encrypted_dns_readiness()
    public_name = encrypted_status.get("domain") or get_setting("encrypted_dns_domain", "").strip()
    if public_name:
        public_host = bracket_host_for_url(public_name)
        https_port = int(DNS_HTTPS_PORT)
        https_port_part = "" if https_port == 443 else f":{https_port}"
        endpoints["doh"].append(f"https://{public_host}{https_port_part}/dns-query")
        if get_setting("dns_over_tls_enabled", "0") == "1":
            endpoints["dot"].append(f"tls://{public_host}:{tls_port}")
        if get_setting("dns_over_quic_enabled", "0") == "1":
            endpoints["doq"].append(f"quic://{public_host}:{quic_port}")
    else:
        endpoints["notes"].append("Set Public DNS Domain in Settings to show public encrypted DNS URLs.")

    for host in hosts[:2]:
        display_host = bracket_host_for_url(host)
        scheme = "http"
        port_part = "" if web_port in (80, 443) else f":{web_port}"
        endpoints["doh"].append(f"{scheme}://{display_host}{port_part}/dns-query")

    if public_name and not encrypted_status.get("ready"):
        endpoints["notes"].extend(encrypted_status.get("issues", []))
    endpoints["notes"].append("DoH uses the web endpoint /dns-query. For https://domain/dns-query, publish the web service through HTTPS or a reverse proxy.")
    return endpoints


def endpoint_codes(values):
    if not values:
        return '<div class="setup-muted">Not configured or disabled.</div>'
    return "".join(f'<code class="setup-endpoint">{html_escape(value)}</code>' for value in values)


def setup_wizard_page():
    endpoints = dns_connection_endpoints()
    notes = "".join(f"<li>{html_escape(note)}</li>" for note in endpoints["notes"])
    body = f"""
<div class="page-toolbar">
  <div>
    <h1 class="h3 mb-1">Setup Wizard</h1>
    <div class="small text-secondary">Use these addresses to connect devices, routers, and encrypted DNS clients to this server.</div>
  </div>
</div>
<div class="setup-grid mb-3">
  <section class="setup-card">
    <div class="setup-card-title">DNS UDP/TCP</div>
    <div class="setup-card-text">For router DHCP DNS settings, Windows, Android private network DNS fields that accept an IP, and local clients.</div>
    {endpoint_codes(endpoints["plain"])}
  </section>
  <section class="setup-card">
    <div class="setup-card-title">DNS-over-HTTPS</div>
    <div class="setup-card-text">For clients that support DoH URLs.</div>
    {endpoint_codes(endpoints["doh"])}
  </section>
  <section class="setup-card">
    <div class="setup-card-title">DNS-over-TLS</div>
    <div class="setup-card-text">For Android Private DNS, routers, and clients that support DoT.</div>
    {endpoint_codes(endpoints["dot"])}
  </section>
  <section class="setup-card">
    <div class="setup-card-title">DNS-over-QUIC</div>
    <div class="setup-card-text">Experimental encrypted DNS endpoint.</div>
    {endpoint_codes(endpoints["doq"])}
  </section>
</div>
<section class="panel p-3">
  <h2 class="h5 mb-2">Notes</h2>
  <ul class="setup-muted" style="padding-left:1.1rem">{notes}</ul>
</section>
"""
    return template(body, "Setup Wizard")


def set_runtime_status(message, ready=None):
    global runtime_status_message
    with runtime_status_lock:
        runtime_status_message = message
    if ready is True:
        dns_runtime_ready.set()
    elif ready is False:
        dns_runtime_ready.clear()


def get_runtime_status():
    with runtime_status_lock:
        return runtime_status_message


def startup_page(message=None):
    msg = html_escape(message or get_runtime_status() or "DNS server starting ...")
    return f"""<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="2">
<title>{APP_NAME} - Starting</title>
<style>
*,*::before,*::after{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;background:#070b10;color:#e8eef7;font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}
.startup-shell{{min-height:100vh;display:grid;place-items:center;padding:1.5rem}}
.startup-panel{{display:flex;flex-direction:column;align-items:center;gap:.9rem;text-align:center}}
.startup-spinner{{width:2.2rem;height:2.2rem;border-radius:50%;border:3px solid #26364e;border-top-color:#20c997;animation:spin .8s linear infinite}}
.startup-title{{font-size:1.15rem;font-weight:800;letter-spacing:0}}
.startup-subtitle{{color:#8d9bae;font-size:.9rem}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style>
</head>
<body>
<main class="startup-shell">
  <section class="startup-panel" aria-live="polite">
    <div class="startup-spinner" aria-hidden="true"></div>
    <div class="startup-title">{msg}</div>
    <div class="startup-subtitle">The WebGUI will continue automatically.</div>
  </section>
</main>
</body>
</html>"""


def log_web_exception(path):
    with open("web-error.log", "a", encoding="utf-8") as log:
        log.write(f"{now_iso()} {path}\n")
        log.write(traceback.format_exc())
        log.write("\n")


class WebHandler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/0.1"

    def do_GET(self):
        try:
            self._do_GET()
        except Exception:
            log_web_exception(self.path)
            try:
                self.send_html(template("<div class='alert alert-danger'>Internal error. Details are in web-error.log.</div>", "Error"), 500)
            except Exception:
                pass

    def _do_GET(self):
        path = urlparse(self.path).path
        params = parse_qs(urlparse(self.path).query)
        if path == "/dns-query":
            self.handle_doh_query(params=params)
            return
        if path == "/metrics":
            self.send_prometheus_metrics()
            return
        if path.startswith("/api/"):
            if not self.api_auth_mode():
                self.send_json({"error": "unauthorized"}, 401)
                return
            self.api_get(path, params)
            return
        if not dns_runtime_ready.is_set():
            self.send_html(startup_page())
            return
        if path == "/login":
            self.send_html(login_page())
            return
        if path == "/logout":
            self.logout()
            return
        if not self.authed():
            self.redirect("/login")
            return
        pages = {
            "/": dashboard_page,
            "/querylog": lambda: querylog_page(params),
            "/blocklists": lambda: blocklists_page(params.get("error", [""])[0], params.get("type", ["block"])[0], params.get("success", [""])[0]),
            "/rules": rules_page,
            "/rewrites": rewrites_page,
            "/clients": clients_page,
            "/profiles": profiles_page,
            "/cache": cache_page,
            "/setup-wizard": setup_wizard_page,
            "/upstreams": upstreams_page,
            "/settings": settings_page,
            "/api-docs": api_docs_page,
            "/domain-test": domain_test_page,
        }
        if path in pages:
            self.send_html(pages[path]())
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            self._do_POST()
        except Exception:
            log_web_exception(self.path)
            if self.path.startswith("/api/"):
                try:
                    self.send_json({"error": "internal error", "log": "web-error.log"}, 500)
                except Exception:
                    pass
            else:
                try:
                    self.send_html(template("<div class='alert alert-danger'>Internal error. Details are in web-error.log.</div>", "Error"), 500)
                except Exception:
                    pass

    def do_DELETE(self):
        try:
            self._do_DELETE()
        except Exception:
            log_web_exception(self.path)
            if self.path.startswith("/api/"):
                try:
                    self.send_json({"error": "internal error", "log": "web-error.log"}, 500)
                except Exception:
                    pass

    def _do_DELETE(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self.send_json({"error": "not found"}, 404)
            return
        mode = self.api_auth_mode()
        if not mode:
            self.send_json({"error": "unauthorized"}, 401)
            return
        if re.search(r"/api/clients/\d+$", path):
            cid = int(path.strip("/").split("/")[2])
            if client_manager and client_manager.delete_client(cid):
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager and client_manager.delete_profile(pid):
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+/rules/\d+$", path):
            parts = path.strip("/").split("/")
            rule_id = int(parts[4])
            if client_manager and client_manager.delete_profile_rule(rule_id):
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+/blocklists/\d+$", path):
            parts = path.strip("/").split("/")
            pid = int(parts[2])
            bl_id = int(parts[4])
            if client_manager and client_manager.remove_blocklist_from_profile(pid, bl_id):
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+/services/\w+$", path):
            parts = path.strip("/").split("/")
            pid = int(parts[2])
            svc = parts[4]
            if client_manager is not None:
                client_manager.remove_profile_service(pid, svc)
                invalidate_rules_cache()
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "not available"}, 500)
        else:
            self.send_json({"error": "not found"}, 404)

    def _do_POST(self):
        path = urlparse(self.path).path
        if path == "/dns-query":
            self.handle_doh_query()
            return
        if path == "/api/restore":
            mode = self.api_auth_mode()
            if not mode:
                self.send_json({"error": "unauthorized"}, 401)
                return
            if mode == "session" and not self.valid_csrf({}):
                self.send_json({"error": "invalid csrf token"}, 403)
                return
            self.handle_restore()
            return
        if path == "/api/restore-preview":
            mode = self.api_auth_mode()
            if not mode:
                self.send_json({"error": "unauthorized"}, 401)
                return
            self.handle_restore_preview()
            return
        form = self.read_form()
        if path == "/login":
            self.login(form)
            return
        if path.startswith("/api/"):
            mode = self.api_auth_mode()
            if not mode:
                self.send_json({"error": "unauthorized"}, 401)
                return
            if mode == "session" and not self.valid_csrf(form):
                self.send_json({"error": "invalid csrf token"}, 403)
                return
            self.api_post(path, form)
            return
        if not self.authed():
            self.redirect("/login")
            return
        if not self.valid_csrf(form):
            self.send_html(template("<div class='alert alert-danger'>Invalid CSRF token. Reload the page and try again.</div>", "Security"), 403)
            return
        if path == "/rules/add":
            with db_lock:
                db.execute(
                    "INSERT INTO rules(action,pattern_type,pattern,target,comment,created_at) VALUES(?,?,?,?,?,?)",
                    (form.get("action", "block"), form.get("pattern_type", "domain"), normalize_domain(form.get("pattern", "")), form.get("target", ""), form.get("comment", ""), now_iso()),
                )
                db.commit()
            invalidate_rules_cache()
            self.redirect("/rules")
        elif path == "/blocklists/add":
            global blocklist_manager
            name = form.get("name", "").strip()
            url = form.get("url", "").strip()
            list_type = "allow" if form.get("list_type") == "allow" else "block"
            content = form.get("content", "")
            try:
                if url:
                    blocklist_manager.add_from_url(name, url, list_type)
                elif content.strip():
                    blocklist_manager.add_from_text(name, content, list_type)
                else:
                    raise ValueError("Provide URL or paste content")
                self.redirect(f"/blocklists?type={list_type}&success={quote('List added successfully')}")
            except Exception as exc:
                self.redirect(f"/blocklists?type={list_type}&error={quote(str(exc))}")
        elif path == "/blocklists/update":
            blocklist_manager.update(form.get("id"))
            self.redirect("/blocklists")
        elif path == "/blocklists/toggle":
            bl_id = int(form.get("id"))
            enabled = form.get("enabled") == "1"
            blocklist_manager.set_enabled(bl_id, enabled)
            self.redirect("/blocklists")
        elif path == "/blocklists/delete":
            blocklist_manager.delete(form.get("id"))
            self.redirect("/blocklists")
        elif path == "/blocklists/edit":
            bl_id = int(form.get("id"))
            name = form.get("name", "").strip()
            url = form.get("url", "").strip()
            list_type = form.get("list_type", "block")
            if name:
                blocklist_manager.update_metadata(bl_id, name, url, list_type)
            self.redirect("/blocklists")
        elif path == "/rules/delete":
            with db_lock:
                db.execute("DELETE FROM rules WHERE id=?", (form.get("id"),))
                db.commit()
            invalidate_rules_cache()
            self.redirect("/rules")
        elif path == "/rewrites/add":
            with db_lock:
                db.execute(
                    "INSERT INTO rules(action,pattern_type,pattern,target,comment,created_at) VALUES(?,?,?,?,?,?)",
                    ("rewrite", form.get("pattern_type", "domain"), normalize_domain(form.get("pattern", "")), form.get("target", ""), form.get("comment", ""), now_iso()),
                )
                db.commit()
            invalidate_rules_cache()
            self.redirect("/rewrites")
        elif path == "/rewrites/delete":
            with db_lock:
                db.execute("DELETE FROM rules WHERE id=?", (form.get("id"),))
                db.commit()
            invalidate_rules_cache()
            self.redirect("/rewrites")
        elif path == "/clients/add":
            if client_manager is not None:
                name = form.get("name", "").strip()
                address = form.get("address", "").strip()
                profile_id = form.get("profile_id")
                if profile_id:
                    profile_id = int(profile_id)
                else:
                    profile_id = None
                client_manager.create_client(address, name, profile_id=profile_id)
            else:
                with db_lock:
                    db.execute("INSERT INTO clients(name,address,created_at) VALUES(?,?,?)", (form.get("name", ""), form.get("address", ""), now_iso()))
                    db.commit()
            self.redirect("/clients")
        elif path == "/clients/edit":
            if client_manager is not None:
                cid = int(form.get("id"))
                name = form.get("name", "").strip()
                address = form.get("address", "").strip()
                profile_id = form.get("profile_id")
                profile_id = int(profile_id) if profile_id else None
                filtering_enabled = form.get("filtering_enabled") == "1"
                ip = address
                cidr = address if "/" in address else ""
                if "/" in address:
                    ip = address.split("/", 1)[0].strip()
                    ipaddress.ip_network(address, strict=False)
                else:
                    ipaddress.ip_address(address)
                client_manager.update_client(
                    cid,
                    name=name or address,
                    ip=ip,
                    cidr=cidr,
                    profile_id=profile_id,
                    filtering_enabled=filtering_enabled,
                )
            self.redirect("/clients")
        elif path == "/clients/delete":
            if client_manager is not None:
                client_manager.delete_client(int(form.get("id")))
            else:
                with db_lock:
                    db.execute("DELETE FROM clients WHERE id=?", (form.get("id"),))
                    db.commit()
            self.redirect("/clients")
        elif path == "/profiles/add":
            if client_manager is not None:
                name = form.get("name", "").strip()
                desc = form.get("description", "").strip()
                if name:
                    client_manager.create_profile(name, desc)
            self.redirect("/profiles")
        elif path == "/profiles/rule-add":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                action = form.get("action", "block")
                pt = form.get("pattern_type", "domain")
                pattern = form.get("pattern", "").strip()
                if pattern:
                    client_manager.add_profile_rule(pid, action, pt, pattern)
            self.redirect("/profiles")
        elif path == "/profiles/rule-delete":
            if client_manager is not None:
                rule_id = int(form.get("rule_id"))
                client_manager.delete_profile_rule(rule_id)
            self.redirect("/profiles")
        elif path == "/profiles/blocklist-add":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                bl_id = int(form.get("blocklist_id"))
                client_manager.add_blocklist_to_profile(pid, bl_id)
            self.redirect("/profiles")
        elif path == "/profiles/blocklist-remove":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                bl_id = int(form.get("blocklist_id"))
                client_manager.remove_blocklist_from_profile(pid, bl_id)
            self.redirect("/profiles")
        elif path == "/profiles/service-add":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                svc = form.get("service_name", "").strip()
                if svc:
                    client_manager.add_profile_service(pid, svc)
                    invalidate_rules_cache()
            self.redirect("/profiles")
        elif path == "/profiles/service-remove":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                svc = form.get("service_name", "").strip()
                if svc:
                    client_manager.remove_profile_service(pid, svc)
                    invalidate_rules_cache()
            self.redirect("/profiles")
        elif path == "/profiles/edit":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                name = form.get("name", "").strip()
                if name:
                    client_manager.update_profile(pid,
                        name=name,
                        description=form.get("description", "").strip(),
                        filtering_enabled=form.get("filtering_enabled") == "1",
                        safe_search_google=form.get("safe_search_google") == "1",
                        safe_search_bing=form.get("safe_search_bing") == "1",
                        safe_search_ddg=form.get("safe_search_ddg") == "1",
                        youtube_restricted=form.get("youtube_restricted") == "1",
                    )
            self.redirect("/profiles")
        elif path == "/profiles/delete":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                client_manager.delete_profile(pid)
            self.redirect("/profiles")
        elif path == "/upstreams/add":
            parsed = detect_upstream(form.get("resolver", form.get("address", "")))
            with db_lock:
                db.execute(
                    "INSERT INTO upstreams(name,address,port,resolver,resolver_type,transport,created_at) VALUES(?,?,?,?,?,?,?)",
                    (form.get("name", ""), parsed["address"], int(parsed["port"]), parsed["resolver"], parsed["type"], parsed["transport"], now_iso()),
                )
                db.commit()
            self.redirect("/upstreams")
        elif path == "/upstreams/mode":
            set_setting("upstream_mode", form.get("upstream_mode", "sequential"))
            self.redirect("/upstreams")
        elif path == "/upstreams/toggle":
            enabled = 1 if form.get("enabled") == "1" else 0
            with db_lock:
                db.execute("UPDATE upstreams SET enabled=? WHERE id=?", (enabled, form.get("id")))
                db.commit()
            self.redirect("/upstreams")
        elif path == "/upstreams/delete":
            with db_lock:
                db.execute("DELETE FROM upstreams WHERE id=?", (form.get("id"),))
                db.commit()
            self.redirect("/upstreams")
        elif path == "/upstreams/test":
            test_upstream(form.get("id"))
            self.redirect("/upstreams")
        elif path == "/settings":
            settings_keys = [
                "filtering_enabled", "cache_enabled", "query_log_enabled", "lan_only", "dnssec_validation_enabled",
                "block_mode", "block_response_ttl", "disable_ipv6", "cache_ttl", "cache_size", "cache_min_ttl", "cache_max_ttl", "cache_optimistic",
                "filter_update_interval_hours", "allowed_networks", "custom_block_ipv4", "custom_block_ipv6",
                "log_retention_days", "auto_clear_query_log_hours", "localdnsguard_web_host", "localdnsguard_web_port",
                "localdnsguard_dns_host", "localdnsguard_dns_port", "encrypted_dns_host", "encrypted_dns_domain",
                "upstream_timeout",
                "dns_over_tls_enabled", "dns_over_tls_port", "dns_over_https_enabled", "dns_over_https_port",
                "dns_over_quic_enabled", "dns_over_quic_port",
                "encrypted_dns_certificate_pem", "encrypted_dns_private_key_pem",
            ]
            try:
                parse_port(form.get("localdnsguard_web_port", WEB_PORT), WEB_PORT, "LOCALDNSGUARD_WEB_PORT")
                parse_port(form.get("localdnsguard_dns_port", DNS_PORT), DNS_PORT, "LOCALDNSGUARD_DNS_PORT")
                parse_positive_float(form.get("upstream_timeout", "2.5"), 2.5, "Upstream timeout")
                parse_port(form.get("dns_over_tls_port", DNS_TLS_PORT), DNS_TLS_PORT, "DNS-over-TLS port")
                parse_port(form.get("dns_over_https_port", DNS_HTTPS_PORT), DNS_HTTPS_PORT, "DNS-over-HTTPS port")
                parse_port(form.get("dns_over_quic_port", DNS_QUIC_PORT), DNS_QUIC_PORT, "DNS-over-QUIC port")
                if form.get("block_mode", "zero_ip") not in {"zero_ip", "refused", "nxdomain", "custom_ip", "nodata", "drop"}:
                    raise ValueError("Invalid block mode")
                if int(form.get("block_response_ttl", "60") or "0") < 0:
                    raise ValueError("Blocked response TTL must be 0 or higher")
                encrypted_enabled = (
                    form.get("dns_over_tls_enabled") == "1"
                    or form.get("dns_over_https_enabled") == "1"
                    or form.get("dns_over_quic_enabled") == "1"
                )
                existing_cert = get_setting("encrypted_dns_certificate_pem", "")
                existing_key = get_setting("encrypted_dns_private_key_pem", "")
                existing_domain = get_setting("encrypted_dns_domain", "")
                cert = form.get("encrypted_dns_certificate_pem", "")
                key = form.get("encrypted_dns_private_key_pem", "")
                domain = form.get("encrypted_dns_domain", "").strip()
                if not cert.strip() and existing_cert.strip():
                    cert = existing_cert
                    form["encrypted_dns_certificate_pem"] = existing_cert
                if not key.strip() and existing_key.strip():
                    key = existing_key
                    form["encrypted_dns_private_key_pem"] = existing_key
                if not domain and existing_domain.strip():
                    domain = existing_domain.strip()
                    form["encrypted_dns_domain"] = domain
                if encrypted_enabled or cert.strip() or key.strip():
                    if encrypted_enabled and not domain:
                        raise ValueError("DNS-over-TLS/QUIC requires Public DNS Domain, for example panel.ts3x.cc")
                    validate_certificate_pair(cert, key, domain)
                    if encrypted_enabled and (not cert.strip() or not key.strip()):
                        raise ValueError("DNS-over-TLS/QUIC requires both certificate and private key")
                dnssec_was_enabled = get_setting("dnssec_validation_enabled", "0") == "1"
                dnssec_will_be_enabled = form.get("dnssec_validation_enabled") == "1"
                if dnssec_will_be_enabled:
                    if not _dnssec_available:
                        raise ValueError("DNSSEC Self-Validation requires dnspython with DNSSEC support")
                    ok, err = ensure_root_trust_anchor()
                    if not ok:
                        raise ValueError(f"DNSSEC trust anchor bootstrap failed: {err}")
            except ValueError as exc:
                self.send_html(settings_page(str(exc), True, form), 400)
                return
            for key in settings_keys:
                set_setting(key, form.get(key, ""))
            if dnssec_will_be_enabled or dnssec_was_enabled:
                clear_dnssec_validator()
            load_runtime_network_settings()
            set_runtime_status("Reboot DNS ...", ready=False)
            schedule_dns_runtime_restart()
            self.send_html(startup_page("Reboot DNS ..."))
        elif path == "/domain-test":
            try:
                result = run_domain_test(form)
            except Exception as exc:
                result = {"status": "error", "error": str(exc)}
            self.send_html(domain_test_page(result))
        elif path == "/querylog/clear":
            with db_lock:
                db.execute("DELETE FROM query_log")
                db.commit()
            self.redirect("/querylog")
        else:
            self.send_error(404)

    def login(self, form):
        client_ip = self.client_address[0]
        password = form.get("password", "")
        if not check_login_rate_limit(client_ip):
            log_admin_action("system", "login_rate_limited", f"Rate limited login from {client_ip}", client_ip)
            self.send_html(login_page("Too many login attempts. Please wait 60 seconds."), 429)
            return
        with db_lock:
            user = db.execute("SELECT * FROM users WHERE username='admin'").fetchone()
            if not user:
                db.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)", ("admin", hash_password(password), now_iso()))
                db.execute("UPDATE settings SET value='1' WHERE key='admin_password_set'")
                db.commit()
                user = db.execute("SELECT * FROM users WHERE username='admin'").fetchone()
            if user and verify_password(password, user["password_hash"]):
                reset_login_rate_limit(client_ip)
                token = secrets.token_urlsafe(32)
                csrf = secrets.token_urlsafe(32)
                expires = time.time() + SESSION_TTL_SECONDS
                sessions[token] = {"user": "admin", "expires": expires, "csrf": csrf}
                db.execute(
                    "INSERT OR REPLACE INTO auth_sessions(token,username,expires_at,created_at) VALUES(?,?,?,?)",
                    (token, "admin", expires, now_iso()),
                )
                db.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (time.time(),))
                db.commit()
                log_admin_action("admin", "login", f"Logged in from {client_ip}", client_ip)
                self.send_response(302)
                self.send_header("Set-Cookie", f"session={token}; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Set-Cookie", f"{CSRF_COOKIE}={csrf}; Max-Age={SESSION_TTL_SECONDS}; SameSite=Lax; Path=/")
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self.send_html(login_page("Password is incorrect"), 403)

    def logout(self):
        token = self.cookie("session")
        sessions.pop(token, None)
        if token:
            with db_lock:
                db.execute("DELETE FROM auth_sessions WHERE token=?", (token,))
                db.commit()
        self.send_response(302)
        self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/")
        self.send_header("Set-Cookie", f"{CSRF_COOKIE}=; Max-Age=0; Path=/")
        self.send_header("Location", "/login")
        self.end_headers()

    def handle_doh_query(self, params=None):
        send_doh_response(self, params)

    def current_session(self):
        token = self.cookie("session")
        if not token:
            return None
        session = sessions.get(token)
        now = time.time()
        if session and session["expires"] > now:
            if not session.get("csrf"):
                session["csrf"] = secrets.token_urlsafe(32)
            return session
        with db_lock:
            row = db.execute("SELECT username,expires_at FROM auth_sessions WHERE token=?", (token,)).fetchone()
            if not row:
                return None
            if row["expires_at"] <= now:
                db.execute("DELETE FROM auth_sessions WHERE token=?", (token,))
                db.commit()
                sessions.pop(token, None)
                return None
            sessions[token] = {"user": row["username"], "expires": row["expires_at"], "csrf": secrets.token_urlsafe(32)}
            return sessions[token]

    def authed(self):
        return self.current_session() is not None

    def session_user(self):
        session = self.current_session()
        return session.get("user", "unknown") if session else "unknown"

    def api_auth_mode(self):
        auth = self.headers.get("Authorization", "")
        token = ""
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
        token = token or self.headers.get("X-API-Token", "").strip()
        configured = get_setting(API_TOKEN_SETTING, "")
        if token and configured and secrets.compare_digest(token, configured):
            return "token"
        if token:
            with db_lock:
                for row in db.execute("SELECT token FROM api_tokens").fetchall():
                    if secrets.compare_digest(token, row["token"]):
                        db.execute("UPDATE api_tokens SET last_used=? WHERE token=?", (now_iso(), row["token"]))
                        db.commit()
                        return "token"
        return "session" if self.authed() else ""

    def csrf_token(self):
        session = self.current_session()
        return session.get("csrf", "") if session else ""

    def valid_csrf(self, form):
        expected = self.csrf_token()
        sent = form.get("csrf_token", "") or self.headers.get("X-CSRF-Token", "")
        return bool(expected and sent and secrets.compare_digest(expected, sent))

    def cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return v
        return ""

    def read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        data = self.rfile.read(length).decode()
        parsed = parse_qs(data)
        return {k: v[-1] for k, v in parsed.items()}

    def handle_restore(self):
        global blocklist_manager, client_manager
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self.send_json({"error": "Empty backup file"}, 400)
            return
        if length > 50_000_000:
            self.send_json({"error": "File is too large (max 50 MB)"}, 400)
            return
        raw = self.rfile.read(length)
        if not raw.strip():
            self.send_json({"error": "Empty backup file"}, 400)
            return
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except UnicodeDecodeError:
            self.send_json({"error": "Backup file is not UTF-8 encoded"}, 400)
            return
        except json.JSONDecodeError as exc:
            self.send_json({"error": f"Invalid JSON on line {exc.lineno}, column {exc.colno}: {exc.msg}"}, 400)
            return
        required = {"settings", "rules", "upstreams"}
        list_fields = required | {"blocklists", "dns_rewrites"}
        if not isinstance(data, dict):
            self.send_json({"error": "Invalid backup format: JSON root must be an object"}, 400)
            return
        missing = sorted(required - set(data))
        if missing:
            self.send_json({"error": "Invalid backup format: required fields are missing: " + ", ".join(missing)}, 400)
            return
        for key in list_fields:
            if key in data and not isinstance(data.get(key), list):
                self.send_json({"error": f"Invalid backup format: {key} must be a list"}, 400)
                return
        skip_settings = {"admin_password_set"}
        counts = {}
        with db_lock:
            settings_rows = [r for r in data.get("settings", []) if r.get("key") not in skip_settings]
            for row in settings_rows:
                db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (row["key"], row["value"]))
            counts["settings"] = len(settings_rows)

            db.execute("DELETE FROM rules")
            rule_rows = [
                row for row in data.get("rules", [])
                if row.get("action") != "rewrite"
            ]
            for row in rule_rows:
                db.execute(
                    "INSERT INTO rules(action,pattern_type,pattern,target,scope,client,enabled,comment,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (row.get("action","block"), row.get("pattern_type","domain"),
                     row.get("pattern",""), row.get("target",""),
                     row.get("scope","global"), row.get("client",""),
                     int(row.get("enabled",1)), row.get("comment",""), row.get("created_at", now_iso()))
                )
            counts["rules"] = len(rule_rows)

            rewrite_rows = data.get("dns_rewrites", [])
            for row in rewrite_rows:
                db.execute(
                    "INSERT INTO rules(action,pattern_type,pattern,target,scope,client,enabled,comment,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("rewrite", row.get("pattern_type","domain"),
                     row.get("pattern",""), row.get("target",""),
                     row.get("scope","global"), row.get("client",""),
                     int(row.get("enabled",1)), row.get("comment",""), row.get("created_at", now_iso()))
                )
            counts["dns_rewrites"] = len(rewrite_rows)

            db.execute("DELETE FROM blocklists")
            db.execute("DELETE FROM blocklist_entries")
            from blocklist_manager import parse_filter_list
            restored_blocklists = 0
            for row in data.get("blocklists", []):
                name = row.get("name", "") or "unknown"
                url = row.get("url", row.get("source", ""))
                list_type = "allow" if row.get("list_type") == "allow" else "block"
                enabled = int(row.get("enabled", 1))
                last_update = row.get("last_update", "")
                last_error = ""
                entries = []
                content = row.get("content", "")
                if not content and str(url).startswith(("http://", "https://")):
                    try:
                        content = fetch_url_text(url)
                        last_update = now_iso()
                    except Exception as exc:
                        last_error = f"Restore update failed: {exc}"
                if content:
                    entries = parse_filter_list(content)
                    if not entries and not last_error:
                        last_error = "Restore update succeeded, but no valid filter rules were found"
                elif not last_error and str(url).startswith(("http://", "https://")):
                    last_error = "Restore update returned no filter-list data"
                db.execute(
                    "INSERT INTO blocklists(name,url,list_type,enabled,rule_count,last_update,last_error,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (name, url, list_type, enabled, len(entries), last_update, last_error or row.get("last_error", ""), row.get("created_at", now_iso())),
                )
                bl_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                if entries:
                    created = now_iso()
                    db.executemany(
                        "INSERT INTO blocklist_entries(blocklist_id,action,pattern_type,pattern,created_at) VALUES(?,?,?,?,?)",
                        [(bl_id, action, pt, pattern, created) for action, pt, pattern in entries],
                    )
                restored_blocklists += 1
            counts["blocklists"] = restored_blocklists

            db.execute("DELETE FROM upstreams")
            upstream_rows = data.get("upstreams", [])
            for row in upstream_rows:
                db.execute(
                    "INSERT INTO upstreams(name,address,port,resolver,resolver_type,transport,enabled,latency_ms,last_error,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (row.get("name",""), row.get("address","1.1.1.1"), int(row.get("port",53)),
                     row.get("resolver",""), row.get("resolver_type","plain_udp"),
                     row.get("transport","udp"), int(row.get("enabled",1)),
                     row.get("latency_ms"), row.get("last_error",""),
                     row.get("created_at", now_iso()))
                )
            counts["upstreams"] = len(upstream_rows)

            if client_manager and "profiles" in data:
                for row in data["profiles"]:
                    name = row.get("name", "Default")
                    description = row.get("description", "")
                    is_default = int(row.get("is_default", 0))
                    existing = db.execute("SELECT id FROM profiles WHERE name=? AND is_default=?", (name, is_default)).fetchone()
                    if existing:
                        db.execute("UPDATE profiles SET description=?, is_default=? WHERE id=?", (description, is_default, existing["id"]))
                    else:
                        db.execute("INSERT INTO profiles(name,description,is_default,created_at) VALUES(?,?,?,?)", (name, description, is_default, row.get("created_at", now_iso())))
                counts["profiles"] = len(data["profiles"])

            if client_manager and "clients" in data:
                for row in data["clients"]:
                    name = row.get("name", "unknown")
                    ip = row.get("ip", "")
                    cidr = row.get("cidr", "")
                    mac = row.get("mac", "")
                    profile_id = row.get("profile_id")
                    filtering_enabled = int(row.get("filtering_enabled", 1))
                    tags = row.get("tags", "")
                    existing = db.execute("SELECT id FROM clients WHERE name=? AND ip=?", (name, ip)).fetchone()
                    if existing:
                        db.execute("UPDATE clients SET cidr=?,mac=?,profile_id=?,filtering_enabled=?,tags=?,updated_at=? WHERE id=?", (cidr, mac, profile_id, filtering_enabled, tags, now_iso(), existing["id"]))
                    else:
                        db.execute("INSERT INTO clients(name,ip,cidr,mac,profile_id,filtering_enabled,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (name, ip, cidr, mac, profile_id, filtering_enabled, tags, row.get("created_at", now_iso()), now_iso()))
                counts["clients"] = len(data["clients"])

            if client_manager and "profile_custom_rules" in data:
                for row in data["profile_custom_rules"]:
                    db.execute(
                        "INSERT INTO profile_custom_rules(profile_id,action,pattern_type,pattern,enabled,comment,created_at) VALUES(?,?,?,?,?,?,?)",
                        (row.get("profile_id", 1), row.get("action", "block"), row.get("pattern_type", "domain"),
                         row.get("pattern", ""), int(row.get("enabled", 1)), row.get("comment", ""), row.get("created_at", now_iso())),
                    )
                counts["profile_custom_rules"] = len(data["profile_custom_rules"])

            if client_manager and "profile_blocklists" in data:
                for row in data["profile_blocklists"]:
                    db.execute(
                        "INSERT OR IGNORE INTO profile_blocklists(profile_id,blocklist_id) VALUES(?,?)",
                        (row.get("profile_id", 1), row.get("blocklist_id", 0)),
                    )
                counts["profile_blocklists"] = len(data["profile_blocklists"])

            if blocklist_manager and "blocklists" in data:
                for row in data["blocklists"]:
                    existing = db.execute("SELECT id FROM blocklists WHERE name=? AND source=?", (row.get("name", ""), row.get("source", ""))).fetchone()
                    if not existing:
                        db.execute(
                            "INSERT INTO blocklists(name,source,list_type,enabled,rule_count,last_update,last_error,created_at) VALUES(?,?,?,?,?,?,?,?)",
                            (row.get("name", ""), row.get("source", ""), row.get("list_type", "block"),
                             int(row.get("enabled", 1)), int(row.get("rule_count", 0)),
                             row.get("last_update", ""), row.get("last_error", ""), row.get("created_at", now_iso())),
                        )
                counts["blocklists"] = len(data["blocklists"])

            db.commit()
        invalidate_rules_cache()
        log_admin_action(self.session_user(), "restore", f"Restored: {counts}", self.client_address[0])
        self.send_json({"ok": True, "restored": counts})

    def handle_restore_preview(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self.send_json({"error": "Empty backup file"}, 400)
            return
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8-sig"))
        except Exception as exc:
            self.send_json({"error": str(exc)}, 400)
            return
        required = {"settings", "rules", "upstreams"}
        if not isinstance(data, dict):
            self.send_json({"error": "Invalid format"}, 400)
            return
        missing = sorted(required - set(data))
        if missing:
            self.send_json({"error": "Missing fields: " + ", ".join(missing)}, 400)
            return
        preview = {
            "settings": len(data.get("settings", [])),
            "rules": len(data.get("rules", [])),
            "dns_rewrites": len(data.get("dns_rewrites", [])),
            "upstreams": len(data.get("upstreams", [])),
            "profiles": len(data.get("profiles", [])),
            "clients": len(data.get("clients", [])),
            "profile_custom_rules": len(data.get("profile_custom_rules", [])),
            "profile_blocklists": len(data.get("profile_blocklists", [])),
            "blocklists": len(data.get("blocklists", [])),
        }
        self.send_json({"ok": True, "preview": preview})

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        csrf = self.csrf_token()
        if csrf:
            self.send_header("Set-Cookie", f"{CSRF_COOKIE}={csrf}; Max-Age={SESSION_TTL_SECONDS}; SameSite=Lax; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_prometheus_metrics(self):
        m = collect_metrics()
        lines = [
            "# HELP localdnsguard_total_queries Total DNS queries processed",
            "# TYPE localdnsguard_total_queries counter",
            f"localdnsguard_total_queries {m['total_queries']}",
            "",
            "# HELP localdnsguard_blocked_queries Blocked DNS queries",
            "# TYPE localdnsguard_blocked_queries counter",
            f"localdnsguard_blocked_queries {m['blocked_queries']}",
            "",
            "# HELP localdnsguard_block_rate Block rate percentage",
            "# TYPE localdnsguard_block_rate gauge",
            f"localdnsguard_block_rate {m['block_rate']}",
            "",
            "# HELP localdnsguard_avg_response_ms Average DNS response time in ms",
            "# TYPE localdnsguard_avg_response_ms gauge",
            f"localdnsguard_avg_response_ms {m['avg_response_ms']}",
            "",
            "# HELP localdnsguard_cache_rate Cache hit rate percentage",
            "# TYPE localdnsguard_cache_rate gauge",
            f"localdnsguard_cache_rate {m['cache_rate']}",
            "",
            "# HELP localdnsguard_active_clients Active unique clients",
            "# TYPE localdnsguard_active_clients gauge",
            f"localdnsguard_active_clients {m['active_clients']}",
            "",
            "# HELP localdnsguard_filter_rules Total filter rules loaded",
            "# TYPE localdnsguard_filter_rules gauge",
            f"localdnsguard_filter_rules {m['filter_rules']}",
            "",
            "# HELP localdnsguard_active_upstreams Healthy upstream resolvers",
            "# TYPE localdnsguard_active_upstreams gauge",
            f"localdnsguard_active_upstreams {m['active_upstreams']}",
            "",
            "# HELP localdnsguard_cache_entries DNS cache entries count",
            "# TYPE localdnsguard_cache_entries gauge",
            f"localdnsguard_cache_entries {m['cache_entries']}",
            "",
            "# HELP localdnsguard_cache_bytes DNS cache bytes used",
            "# TYPE localdnsguard_cache_bytes gauge",
            f"localdnsguard_cache_bytes {m['cache_bytes']}",
            "",
            "# HELP pyguarddns_dot_tls_handshakes_total DNS-over-TLS upstream TLS handshakes",
            "# TYPE pyguarddns_dot_tls_handshakes_total counter",
            f"pyguarddns_dot_tls_handshakes_total {m['tls_handshake_count']}",
            "",
            "# HELP pyguarddns_dot_reuse_total DNS-over-TLS upstream connection reuses",
            "# TYPE pyguarddns_dot_reuse_total counter",
            f"pyguarddns_dot_reuse_total {m['dot_reuse_count']}",
            "",
            "# HELP pyguarddns_dot_reconnects_total DNS-over-TLS upstream reconnects",
            "# TYPE pyguarddns_dot_reconnects_total counter",
            f"pyguarddns_dot_reconnects_total {m['dot_reconnect_count']}",
            "",
            "# HELP pyguarddns_dot_errors_total DNS-over-TLS upstream errors",
            "# TYPE pyguarddns_dot_errors_total counter",
            f"pyguarddns_dot_errors_total {m['dot_error_count']}",
            "",
            "# HELP pyguarddns_dot_pool_size DNS-over-TLS upstream connection pool size",
            "# TYPE pyguarddns_dot_pool_size gauge",
            f"pyguarddns_dot_pool_size {m['dot_pool_size']}",
            "",
            "# HELP pyguarddns_upstream_queue_wait_seconds Upstream worker queue wait time",
            "# TYPE pyguarddns_upstream_queue_wait_seconds gauge",
            f"pyguarddns_upstream_queue_wait_seconds {m['upstream_queue_wait_ms_avg'] / 1000}",
        ]
        lines += [
            "",
            "# HELP pyguarddns_dnssec_secure_total DNSSEC secure validations",
            "# TYPE pyguarddns_dnssec_secure_total counter",
            f"pyguarddns_dnssec_secure_total {m['dnssec_secure']}",
            "",
            "# HELP pyguarddns_dnssec_insecure_total DNSSEC insecure results",
            "# TYPE pyguarddns_dnssec_insecure_total counter",
            f"pyguarddns_dnssec_insecure_total {m['dnssec_insecure']}",
            "",
            "# HELP pyguarddns_dnssec_bogus_total DNSSEC bogus results",
            "# TYPE pyguarddns_dnssec_bogus_total counter",
            f"pyguarddns_dnssec_bogus_total {m['dnssec_bogus']}",
            "",
            "# HELP pyguarddns_dnssec_indeterminate_total DNSSEC indeterminate results",
            "# TYPE pyguarddns_dnssec_indeterminate_total counter",
            f"pyguarddns_dnssec_indeterminate_total {m['dnssec_indeterminate']}",
            "",
            "# HELP pyguarddns_dnssec_validation_seconds Total seconds spent on DNSSEC validation",
            "# TYPE pyguarddns_dnssec_validation_seconds counter",
            f"pyguarddns_dnssec_validation_seconds {m['dnssec_validation_seconds']}",
            "",
            "# HELP pyguarddns_dnssec_dnskey_cache_entries DNSKEY cache entries",
            "# TYPE pyguarddns_dnssec_dnskey_cache_entries gauge",
            f"pyguarddns_dnssec_dnskey_cache_entries {m['dnssec_dnskey_cache_entries']}",
        ]
        body = "\n".join(lines).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_get(self, path, params):
        if path == "/api/status":
            with _healthcheck_lock:
                hc_last = _healthcheck_last_run
            encrypted_status = encrypted_dns_readiness()
            encrypted_runtime = encrypted_dns_runtime_state()
            upstream_health = rows(
                "SELECT u.id,u.name,u.address,u.port,u.resolver_type,uh.success_rate,uh.latency_ms,uh.consecutive_failures,uh.paused,uh.last_checked "
                "FROM upstreams u LEFT JOIN upstream_health uh ON uh.upstream_id=u.id "
                "ORDER BY u.id ASC"
            )
            self.send_json({
                "app": APP_NAME, "dns": {"host": DNS_HOST, "port": DNS_PORT},
                "web": {"host": WEB_HOST, "port": WEB_PORT},
                "encrypted_dns": {
                    "host": ENCRYPTED_DNS_HOST,
                    "domain": encrypted_status["domain"],
                    "ready": encrypted_status["ready"],
                    "issues": encrypted_status["issues"],
                    "tls": {
                        "enabled": get_setting("dns_over_tls_enabled", "0") == "1",
                        "running": encrypted_runtime["tls_running"],
                        "port": DNS_TLS_PORT,
                    },
                    "https": {
                        "enabled": get_setting("dns_over_https_enabled", "0") == "1",
                        "running": encrypted_runtime["https_running"],
                        "port": DNS_HTTPS_PORT,
                        "connect_url": f"https://{encrypted_status['domain']}{'' if DNS_HTTPS_PORT == 443 else ':' + str(DNS_HTTPS_PORT)}/dns-query" if encrypted_status["domain"] else "",
                    },
                    "quic": {
                        "enabled": get_setting("dns_over_quic_enabled", "0") == "1",
                        "running": encrypted_runtime["quic_running"],
                        "port": DNS_QUIC_PORT,
                        "experimental": True,
                        "metrics": encrypted_runtime["doq_metrics"],
                        "connect_url": f"quic://{encrypted_status['domain']}:{DNS_QUIC_PORT}" if encrypted_status["domain"] else "",
                        "upstream_disabled_reason": "DoQ upstream forwarding needs persistent QUIC pooling before it can be enabled by default",
                    },
                },
                "summary": stats_summary(),
                "upstream_health": upstream_health,
                "healthcheck_last_run": hc_last,
            })
        elif path == "/api/dashboard":
            self.send_json(extended_dashboard_data())
        elif path == "/api/stats/summary":
            self.send_json(stats_summary())
        elif path == "/api/stats/cache":
            self.send_json(cache_stats())
        elif path == "/api/querylog":
            w, v = [], []
            if params.get("q", [""])[0]:
                w.append("normalized_domain LIKE ?"); v.append(f"%{normalize_domain(params['q'][0])}%")
            if params.get("client", [""])[0]:
                w.append("client_ip LIKE ?"); v.append(f"%{params['client'][0]}%")
            if params.get("status", [""])[0]:
                w.append("status=?"); v.append(params["status"][0])
            sql = "SELECT q.*, COALESCE(NULLIF(c.name, c.ip), NULLIF(q.client_name, ''), q.client_ip) AS client_display_name FROM query_log q LEFT JOIN clients c ON c.ip = q.client_ip"
            if w: sql += " WHERE " + " AND ".join(w)
            sql += " ORDER BY q.id DESC LIMIT 300"
            self.send_json(rows(sql, v))
        elif path == "/api/explain":
            domain = params.get("domain", [""])[0]
            client = params.get("client", ["127.0.0.1"])[0]
            if not domain:
                self.send_json({"error": "domain required"}, 400)
            else:
                self.send_json(explain_decision(domain, client))
        elif path == "/api/querylog.csv":
            data = rows("SELECT * FROM query_log ORDER BY id DESC")
            data = [{k: v for k, v in row.items() if k != "matched_rule"} for row in data]
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=data[0].keys() if data else ["id"])
            writer.writeheader()
            writer.writerows(data)
            body = output.getvalue().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=querylog.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/rules":
            self.send_json(rows("SELECT * FROM rules ORDER BY id DESC"))
        elif path == "/api/blocklists":
            self.send_json(blocklist_manager.get_all() if blocklist_manager else [])
        elif path == "/api/blocklists/stats":
            self.send_json(blocklist_manager.get_stats() if blocklist_manager else [])
        elif path == "/api/blocklists/update-status":
            self.send_json(blocklist_manager.update_status() if blocklist_manager else {"running": False, "status": "not_available"})
        elif path == "/api/clients":
            if client_manager is not None:
                self.send_json(client_manager.get_clients())
            else:
                self.send_json([])
        elif path.startswith("/api/clients/") and re.search(r"/api/clients/\d+$", path):
            cid = int(path.strip("/").split("/")[2])
            if client_manager is not None:
                c = client_manager.get_client(cid)
                if c:
                    self.send_json(c)
                else:
                    self.send_json({"error": "not found"}, 404)
            else:
                self.send_json({"error": "not available"}, 500)
        elif path == "/api/profiles":
            if client_manager is not None:
                self.send_json(client_manager.get_profiles())
            else:
                self.send_json([])
        elif re.search(r"/api/profiles/\d+$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager is not None:
                p = client_manager.get_profile(pid)
                if p:
                    self.send_json(p)
                else:
                    self.send_json({"error": "not found"}, 404)
            else:
                self.send_json({"error": "not available"}, 500)
        elif re.search(r"/api/profiles/\d+/rules$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager is not None:
                self.send_json(client_manager.get_profile_rules(pid))
            else:
                self.send_json([])
        elif re.search(r"/api/profiles/\d+/blocklists$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager is not None:
                self.send_json(client_manager.get_profile_blocklists(pid))
            else:
                self.send_json([])
        elif path == "/api/upstreams":
            self.send_json(rows("SELECT * FROM upstreams ORDER BY id ASC"))
        elif path == "/api/upstreams/detect":
            self.send_json(detect_upstream(params.get("resolver", [""])[0]))
        elif path == "/api/upstreams/health":
            all_health = rows(
                "SELECT u.id,u.name,u.address,u.port,u.resolver_type,uh.* "
                "FROM upstreams u LEFT JOIN upstream_health uh ON uh.upstream_id=u.id "
                "ORDER BY u.id ASC"
            )
            self.send_json(all_health)
        elif path == "/api/audit-log":
            limit = int(params.get("limit", ["100"])[0])
            offset = int(params.get("offset", ["0"])[0])
            items = rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (min(limit, 1000), offset))
            total = db.execute("SELECT COUNT(*) as cnt FROM audit_log").fetchone()["cnt"]
            self.send_json({"items": items, "total": total})
        elif path == "/api/api-tokens":
            self.send_json(rows("SELECT token,name,created_at,last_used FROM api_tokens ORDER BY created_at ASC"))
        elif path == "/api/backup":
            sensitive_keys = {"admin_password_set", "api_token", "encrypted_dns_private_key_pem"}
            data = {
                "version": 2,
                "settings": [r for r in rows("SELECT * FROM settings") if r["key"] not in sensitive_keys],
                "blocklists": rows("SELECT * FROM blocklists ORDER BY id ASC"),
                "rules": rows("SELECT * FROM rules WHERE action <> 'rewrite' ORDER BY id ASC"),
                "dns_rewrites": rows("SELECT * FROM rules WHERE action = 'rewrite' ORDER BY id ASC"),
                "upstreams": rows("SELECT * FROM upstreams"),
                "profiles": rows("SELECT * FROM profiles") if client_manager else [],
                "clients": rows("SELECT * FROM clients") if client_manager else [],
                "profile_custom_rules": rows("SELECT * FROM profile_custom_rules") if client_manager else [],
                "profile_blocklists": rows("SELECT * FROM profile_blocklists") if client_manager else [],
                "blocklists": rows("SELECT * FROM blocklists") if blocklist_manager else [],
            }
            log_admin_action(self.session_user(), "backup_export", f"Backup exported with {len(data['settings'])} settings, {len(data['rules'])} rules, {len(data['upstreams'])} upstreams", self.client_address[0])
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="localdnsguard_backup_{stamp}.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/services":
            self.send_json(sorted(SERVICE_DOMAINS.keys()))
        elif re.search(r"/api/profiles/\d+/services$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager is not None:
                self.send_json(client_manager.get_profile_services(pid))
            else:
                self.send_json([])
        elif path == "/api/metrics":
            self.send_json(collect_metrics())
        else:
            self.send_json({"error": "not found"}, 404)

    def api_post(self, path, form):
        if path == "/api/domain-test":
            try:
                self.send_json(run_domain_test(form))
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
        elif path == "/api/cache/clear":
            result = clear_dns_cache()
            log_admin_action(self.session_user(), "cache_clear", "DNS cache cleared", self.client_address[0])
            self.send_json(result)
        elif path == "/api/upstreams/test":
            result = test_upstream(form.get("id"))
            log_admin_action(self.session_user(), "upstream_test", f"Tested upstream {form.get('id')}", self.client_address[0])
            self.send_json(result)
        elif path == "/api/filtering/pause":
            set_setting("filtering_enabled", "0")
            log_admin_action(self.session_user(), "filtering_pause", "Filtering paused", self.client_address[0])
            self.send_json({"ok": True})
        elif path == "/api/filtering/resume":
            set_setting("filtering_enabled", "1")
            log_admin_action(self.session_user(), "filtering_resume", "Filtering resumed", self.client_address[0])
            self.send_json({"ok": True})
        elif path == "/api/blocklists/add":
            global blocklist_manager
            name = form.get("name", "").strip()
            url = form.get("url", "").strip()
            list_type = "allow" if form.get("list_type") == "allow" else "block"
            content = form.get("content", "")
            try:
                if url:
                    count = blocklist_manager.add_from_url(name, url, list_type)
                elif content.strip():
                    count = blocklist_manager.add_from_text(name, content, list_type)
                else:
                    raise ValueError("Provide URL or paste content")
                self.send_json({"ok": True, "name": name, "rules": count})
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
        elif path == "/api/blocklists/delete":
            bl_name = form.get("name", form.get("id", ""))
            blocklist_manager.delete(form.get("id"))
            log_admin_action(self.session_user(), "blocklist_delete", f"Deleted blocklist {bl_name}", self.client_address[0])
            self.send_json({"ok": True})
        elif path == "/api/blocklists/update":
            blocklist_manager.update(form.get("id"))
            log_admin_action(self.session_user(), "blocklist_update", f"Updated blocklist {form.get('id')}", self.client_address[0])
            self.send_json({"ok": True})
        elif path == "/api/blocklists/update-all":
            result = blocklist_manager.update_all()
            log_admin_action(self.session_user(), "blocklist_update_all", "Updated all blocklists", self.client_address[0])
            self.send_json(result)
        elif path == "/api/querylog/rule-action":
            try:
                result = create_rule_from_querylog(form)
                log_admin_action(self.session_user(), "querylog_rule_action", f"{result['action']} {result['pattern']} scope={result['scope']}", self.client_address[0])
                self.send_json(result)
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
        elif path == "/api/clients":
            if client_manager is None:
                self.send_json({"error": "not available"}, 500)
            else:
                ip = form.get("ip", "").strip()
                if not ip:
                    self.send_json({"error": "ip required"}, 400)
                else:
                    name = form.get("name", "").strip()
                    cidr = form.get("cidr", "").strip()
                    profile_id = form.get("profile_id")
                    if profile_id is not None:
                        profile_id = int(profile_id)
                    filtering_enabled = int(form.get("filtering_enabled", "1"))
                    c = client_manager.create_client(ip, name, cidr, profile_id)
                    log_admin_action(self.session_user(), "client_create", f"Created client {name} ({ip})", self.client_address[0])
                    self.send_json({"ok": True, "id": c["id"] if c else None})
        elif re.search(r"/api/clients/\d+$", path):
            cid = int(path.strip("/").split("/")[2])
            if client_manager is None:
                self.send_json({"error": "not available"}, 500)
            else:
                kwargs = {}
                for key in ("name", "cidr", "profile_id", "filtering_enabled"):
                    if key in form:
                        val = form[key]
                        if key == "profile_id":
                            val = int(val) if val else None
                        elif key == "filtering_enabled":
                            val = int(val)
                        kwargs[key] = val
                c = client_manager.update_client(cid, **kwargs)
                if c:
                    log_admin_action(self.session_user(), "client_update", f"Updated client {cid}", self.client_address[0])
                    self.send_json({"ok": True})
                else:
                    self.send_json({"error": "not found"}, 404)
        elif path == "/api/profiles":
            if client_manager is None:
                self.send_json({"error": "not available"}, 500)
            else:
                name = form.get("name", "").strip()
                if not name:
                    self.send_json({"error": "name required"}, 400)
                else:
                    desc = form.get("description", "")
                    fe = int(form.get("filtering_enabled", "1"))
                    p = client_manager.create_profile(name, desc, bool(fe))
                    log_admin_action(self.session_user(), "profile_create", f"Created profile {name}", self.client_address[0])
                    self.send_json({"ok": True, "id": p["id"]})
        elif re.search(r"/api/profiles/\d+$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager is None:
                self.send_json({"error": "not available"}, 500)
            else:
                kwargs = {}
                for key in ("name", "description", "filtering_enabled", "safe_search_google", "safe_search_bing", "safe_search_ddg", "youtube_restricted"):
                    if key in form:
                        val = form[key]
                        if key in ("filtering_enabled", "safe_search_google", "safe_search_bing", "safe_search_ddg", "youtube_restricted"):
                            val = int(val)
                        kwargs[key] = val
                p = client_manager.update_profile(pid, **kwargs)
                if p:
                    log_admin_action(self.session_user(), "profile_update", f"Updated profile {pid}", self.client_address[0])
                    invalidate_rules_cache()
                    self.send_json({"ok": True})
                else:
                    self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+/rules$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager is None:
                self.send_json({"error": "not available"}, 500)
            else:
                action = form.get("action", "block")
                pattern_type = form.get("pattern_type", "domain")
                pattern = form.get("pattern", "").strip()
                if not pattern:
                    self.send_json({"error": "pattern required"}, 400)
                else:
                    r = client_manager.add_profile_rule(pid, action, pattern_type, pattern)
                    log_admin_action(self.session_user(), "profile_rule_add", f"Added rule {action} {pattern} to profile {pid}", self.client_address[0])
                    self.send_json({"ok": True, "id": r["id"]} if r else {"error": "profile not found"}, 400 if not r else 200)
        elif re.search(r"/api/profiles/\d+/blocklists$", path):
            pid = int(path.strip("/").split("/")[2])
            if client_manager is None:
                self.send_json({"error": "not available"}, 500)
            else:
                bl_id = form.get("blocklist_id")
                if bl_id is None:
                    self.send_json({"error": "blocklist_id required"}, 400)
                else:
                    ok = client_manager.add_blocklist_to_profile(pid, int(bl_id))
                    log_admin_action(self.session_user(), "profile_blocklist_add", f"Added blocklist {bl_id} to profile {pid}", self.client_address[0])
                    self.send_json({"ok": ok})
        elif re.search(r"/api/profiles/\d+/services/add$", path):
            pid = int(path.strip("/").split("/")[2])
            svc = form.get("service_name", "").strip()
            if client_manager is not None and client_manager.add_profile_service(pid, svc):
                log_admin_action(self.session_user(), "profile_service_add", f"Added service block {svc} to profile {pid}", self.client_address[0])
                invalidate_rules_cache()
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "failed"}, 400)
        elif re.search(r"/api/profiles/\d+/services/remove$", path):
            pid = int(path.strip("/").split("/")[2])
            svc = form.get("service_name", "").strip()
            if client_manager is not None:
                client_manager.remove_profile_service(pid, svc)
                log_admin_action(self.session_user(), "profile_service_remove", f"Removed service block {svc} from profile {pid}", self.client_address[0])
                invalidate_rules_cache()
                self.send_json({"ok": True})
        elif path == "/api/upstreams/health/pause":
            up_id = form.get("id")
            if not up_id:
                self.send_json({"error": "id required"}, 400)
            else:
                with db_lock:
                    h = get_upstream_health(int(up_id))
                    new_paused = 0 if h.get("paused") else 1
                    db.execute("UPDATE upstream_health SET paused=? WHERE upstream_id=?", (new_paused, int(up_id)))
                    db.commit()
                log_admin_action(self.session_user(), "upstream_pause_toggle", f"{'Paused' if new_paused else 'Unpaused'} upstream {up_id}", self.client_address[0])
                self.send_json({"ok": True, "paused": bool(new_paused)})
        elif path == "/api/api-tokens":
            action = form.get("action", "")
            if action == "create":
                name = form.get("name", "token").strip()
                token = secrets.token_urlsafe(32)
                db.execute("INSERT INTO api_tokens(token,name,created_at) VALUES(?,?,?)", (token, name, now_iso()))
                db.commit()
                log_admin_action(self.session_user(), "api_token_create", f"Created API token {name}", self.client_address[0])
                self.send_json({"ok": True, "token": token, "name": name})
            elif action == "delete":
                token = form.get("token", "").strip()
                db.execute("DELETE FROM api_tokens WHERE token=?", (token,))
                db.commit()
                log_admin_action(self.session_user(), "api_token_delete", "Deleted API token", self.client_address[0])
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "unknown action"}, 400)
        elif path == "/api/audit-log/clear":
            with db_lock:
                db.execute("DELETE FROM audit_log")
                db.commit()
            log_admin_action(self.session_user(), "audit_log_clear", "Audit log cleared", self.client_address[0])
            self.send_json({"ok": True})
        else:
            self.send_json({"error": "not found"}, 404)

    def log_message(self, fmt, *args):
        try:
            with open("server.out.log", "a", encoding="utf-8") as log:
                log.write(f"{now_iso()} [web] {self.address_string()} {fmt % args}\n")
        except Exception:
            pass


def start_dns_servers():
    global DNS_PORT
    last_error = None
    requested = DNS_PORT
    ports = [requested] if STRICT_DNS_PORT else range(requested, requested + 20)
    for port in ports:
        udp = None
        try:
            udp = ReusableThreadingUDPServer((DNS_HOST, port), DNSUDPHandler)
            tcp = ReusableThreadingTCPServer((DNS_HOST, port), DNSTCPHandler)
            DNS_PORT = port
            break
        except OSError as exc:
            last_error = exc
            if udp is not None:
                try:
                    udp.server_close()
                except Exception:
                    pass
            try:
                tcp.server_close()
            except Exception:
                pass
            continue
    else:
        raise last_error or OSError("could not bind DNS server")
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    return udp, tcp


class DoQRuntimeServer:
    def __init__(self, host, port, ssl_context):
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.loop = None
        self.server = None
        self.thread = None
        self.ready = threading.Event()
        self.error = None

    def start(self):
        self.thread = threading.Thread(target=self._run, name="dns-over-quic-server", daemon=True)
        self.thread.start()
        if not self.ready.wait(timeout=5.0):
            raise OSError("DNS-over-QUIC startup timed out")
        if self.error:
            raise self.error

    def _run(self):
        try:
            import asyncio
            from aioquic.asyncio import serve as quic_serve
            from aioquic.asyncio.protocol import QuicConnectionProtocol
            from aioquic.quic.configuration import QuicConfiguration
            from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, ProtocolNegotiated, StreamDataReceived

            class _DoQServerProtocol(QuicConnectionProtocol):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self._buffers = {}
                    self._responded = set()

                def quic_event_received(self, event):
                    if isinstance(event, ProtocolNegotiated):
                        peer = self._quic._network_paths[0].addr[0] if self._quic._network_paths else ""
                        update_doq_metric("last_peer", peer)
                        log_doq_event(f"protocol negotiated peer={peer} alpn={event.alpn_protocol}")
                        return
                    if isinstance(event, HandshakeCompleted):
                        peer = self._quic._network_paths[0].addr[0] if self._quic._network_paths else ""
                        update_doq_metric("handshakes")
                        update_doq_metric("last_peer", peer)
                        log_doq_event(f"handshake completed peer={peer}")
                        return
                    if isinstance(event, ConnectionTerminated):
                        if event.error_code:
                            update_doq_metric("last_error", f"connection terminated code={event.error_code} reason={event.reason_phrase}")
                            log_doq_event(f"connection terminated code={event.error_code} reason={event.reason_phrase}")
                        return
                    if not isinstance(event, StreamDataReceived):
                        return
                    sid = event.stream_id
                    data = self._buffers.get(sid, b"") + event.data
                    if not event.end_stream:
                        self._buffers[sid] = data
                        return
                    self._buffers.pop(sid, None)
                    try:
                        if len(data) < 2:
                            raise OSError("short DoQ query")
                        length = struct.unpack("!H", data[:2])[0]
                        request = data[2:2 + length]
                        if len(request) != length:
                            raise OSError("truncated DoQ query")
                        peer = self._quic._network_paths[0].addr[0] if self._quic._network_paths else ""
                        update_doq_metric("queries")
                        update_doq_metric("last_peer", peer)
                        response = handle_dns_request(request, peer, "QUIC")
                        payload = b"" if response is None else struct.pack("!H", len(response)) + response
                        try:
                            question = parse_dns_question(request)
                            rcode = dns_response_rcode(response)
                            if rcode and rcode != 0:
                                with open("web-error.log", "a", encoding="utf-8") as log:
                                    log.write(f"{now_iso()} dns-over-quic response peer={peer} domain={question['domain']} type={question['qtype_name']} rcode={rcode}\n")
                        except Exception:
                            pass
                    except Exception as exc:
                        update_doq_metric("errors")
                        update_doq_metric("last_error", str(exc))
                        log_doq_event(f"handler: {exc}")
                        payload = b""
                    if sid in self._responded:
                        return
                    self._quic.send_stream_data(sid, payload, end_stream=True)
                    self._responded.add(sid)
                    self.transmit()

            cert = get_setting("encrypted_dns_certificate_pem", "")
            key = get_setting("encrypted_dns_private_key_pem", "")
            validate_certificate_pair(cert, key, get_setting("encrypted_dns_domain", ""))
            cert_path, key_path = write_temp_pem_files(cert, key)
            try:
                config = QuicConfiguration(alpn_protocols=["doq", "doq-i11", "doq-i10", "doq-i02"], is_client=False)
                config.load_cert_chain(cert_path, key_path)
            finally:
                for path in (cert_path, key_path):
                    try:
                        os.unlink(path)
                    except Exception:
                        pass

            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.server = self.loop.run_until_complete(
                quic_serve(self.host, self.port, configuration=config, create_protocol=_DoQServerProtocol)
            )
            self.ready.set()
            self.loop.run_forever()
        except Exception as exc:
            self.error = exc
            self.ready.set()
        finally:
            try:
                if self.server is not None:
                    self.server.close()
            except Exception:
                pass
            try:
                if self.loop is not None:
                    self.loop.close()
            except Exception:
                pass

    def shutdown(self):
        if self.loop is not None and self.loop.is_running():
            try:
                closed = threading.Event()
                def _close():
                    try:
                        if self.server is not None:
                            self.server.close()
                    finally:
                        closed.set()
                self.loop.call_soon_threadsafe(_close)
                closed.wait(timeout=1.0)
                self.loop.call_soon_threadsafe(self.loop.stop)
            except Exception:
                pass
        if self.thread is not None:
            self.thread.join(timeout=3.0)

    def server_close(self):
        self.shutdown()


def start_encrypted_dns_servers():
    servers = []
    context = None
    def ssl_context():
        nonlocal context
        if context is None:
            context = make_encrypted_dns_ssl_context()
        return context
    if get_setting("dns_over_tls_enabled", "0") == "1":
        try:
            dot = ReusableThreadingTLSDNSServer((ENCRYPTED_DNS_HOST, DNS_TLS_PORT), DNSTCPHandler, ssl_context())
            threading.Thread(target=dot.serve_forever, name="dns-over-tls-server", daemon=True).start()
            servers.append(dot)
        except Exception as exc:
            print(f"Failed to start DoT server: {exc}", flush=True)
    if get_setting("dns_over_https_enabled", "0") == "1":
        try:
            doh = ReusableThreadingHTTPSServer((ENCRYPTED_DNS_HOST, DNS_HTTPS_PORT), DNSHTTPSHandler, ssl_context())
            threading.Thread(target=doh.serve_forever, name="dns-over-https-server", daemon=True).start()
            servers.append(doh)
        except Exception as exc:
            print(f"Failed to start DoH server: {exc}", flush=True)
    if get_setting("dns_over_quic_enabled", "0") == "1":
        try:
            doq = DoQRuntimeServer(ENCRYPTED_DNS_HOST, DNS_QUIC_PORT, make_encrypted_dns_ssl_context())
            doq.start()
            servers.append(doq)
        except Exception as exc:
            print(f"Failed to start DoQ server: {exc}", flush=True)
    return servers


def start_web_server():
    global web_server
    if web_server is not None:
        return web_server
    web_server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), WebHandler)
    threading.Thread(target=web_server.serve_forever, name="web-server", daemon=True).start()
    return web_server


def shutdown_runtime_servers():
    global web_server, dns_servers, encrypted_dns_servers
    if web_server is not None:
        try:
            web_server.shutdown()
            web_server.server_close()
        except Exception as exc:
            print(f"Web shutdown error: {exc}", flush=True)
        web_server = None
    shutdown_dns_runtime_servers()


def shutdown_dns_runtime_servers():
    global dns_servers, encrypted_dns_servers
    for srv in dns_servers:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception as exc:
            print(f"DNS shutdown error: {exc}", flush=True)
    dns_servers = []
    for srv in encrypted_dns_servers:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception as exc:
            print(f"Encrypted DNS shutdown error: {exc}", flush=True)
    encrypted_dns_servers = []


def restart_runtime_servers():
    global dns_servers, encrypted_dns_servers
    with runtime_restart_lock:
        set_runtime_status("Reboot DNS ...", ready=False)
        shutdown_dns_runtime_servers()
        time.sleep(0.15)
        load_runtime_network_settings()
        clear_dns_cache()
        invalidate_rules_cache()
        dns_servers = list(start_dns_servers())
        encrypted_dns_servers = list(start_encrypted_dns_servers())
        start_web_server()
        set_runtime_status("DNS server ready", ready=True)


def restart_dns_runtime_servers():
    global dns_servers, encrypted_dns_servers
    with runtime_restart_lock:
        set_runtime_status("Reboot DNS ...", ready=False)
        shutdown_dns_runtime_servers()
        time.sleep(0.15)
        load_runtime_network_settings()
        clear_dns_cache()
        invalidate_rules_cache()
        dns_servers = list(start_dns_servers())
        encrypted_dns_servers = list(start_encrypted_dns_servers())
        set_runtime_status("DNS server ready", ready=True)


def safe_restart_dns_runtime_servers():
    try:
        restart_dns_runtime_servers()
    except Exception as exc:
        try:
            with open("startup.log", "a", encoding="utf-8") as log:
                log.write(f"{now_iso()} dns restart failed: {type(exc).__name__}: {exc}\n")
        except Exception:
            pass
        print(f"DNS restart failed: {exc}", flush=True)


def schedule_dns_runtime_restart(delay=0.6):
    timer = threading.Timer(delay, safe_restart_dns_runtime_servers)
    timer.daemon = True
    timer.start()


def print_console_status():
    summary = stats_summary()
    cache_info = cache_stats()
    print(f"{APP_NAME} Status", flush=True)
    print(f"  Web UI:          http://127.0.0.1:{WEB_PORT}", flush=True)
    print(f"  DNS:             {DNS_HOST}:{DNS_PORT} UDP/TCP", flush=True)
    public_name = ENCRYPTED_DNS_DOMAIN or ENCRYPTED_DNS_HOST
    print(f"  Encrypted DNS:   tls://{public_name}:{DNS_TLS_PORT}, https://{public_name}{'' if DNS_HTTPS_PORT == 443 else ':' + str(DNS_HTTPS_PORT)}/dns-query, quic://{public_name}:{DNS_QUIC_PORT}", flush=True)
    print(f"  Total queries:   {summary.get('total', 0)}", flush=True)
    print(f"  Blocked queries: {summary.get('blocked', 0)}", flush=True)
    print(f"  Block rate:      {summary.get('block_rate', 0.0):.1f}%", flush=True)
    print(f"  Avg response:    {summary.get('avg_ms', 0.0):.1f} ms", flush=True)
    print(f"  Active clients:  {summary.get('clients', 0)}", flush=True)
    print(f"  Filter rules:    {summary.get('rules', 0)}", flush=True)
    print(f"  Cache entries:   {cache_info.get('entries', 0)}", flush=True)


def run_dnssec_self_validation_test(server_host=None, server_port=None, timeout=4.0):
    server_host = server_host or "127.0.0.1"
    server_port = int(server_port or DNS_PORT)
    tests = [
        {
            "name": "valid signed domain",
            "domain": "cloudflare.com.",
            "qtype": "A",
            "expected_rcode": "NOERROR",
            "expect_ad": True,
        },
        {
            "name": "broken DNSSEC domain",
            "domain": "dnssec-failed.org.",
            "qtype": "A",
            "expected_rcode": "SERVFAIL",
            "expect_ad": False,
        },
    ]
    results = []
    if not _dnssec_available:
        return {
            "server": f"{server_host}:{server_port}",
            "enabled": False,
            "overall": "fail",
            "error": "DNSSEC support is not available in this Python environment",
            "tests": [],
        }

    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rdatatype

    dnssec_enabled = get_setting("dnssec_validation_enabled", "0") == "1"
    overall_ok = dnssec_enabled

    for item in tests:
        started = time.perf_counter()
        result = {
            "name": item["name"],
            "domain": item["domain"].rstrip("."),
            "qtype": item["qtype"],
            "expected_rcode": item["expected_rcode"],
            "ok": False,
            "rcode": "",
            "ad": False,
            "duration_ms": 0.0,
            "error": "",
        }
        try:
            query = dns.message.make_query(
                item["domain"],
                dns.rdatatype.from_text(item["qtype"]),
                want_dnssec=True,
            )
            query.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
            wire = query.to_wire()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(wire, (server_host, server_port))
                response_wire, _ = sock.recvfrom(4096)
            response = dns.message.from_wire(response_wire)
            rcode_text = dns.rcode.to_text(response.rcode())
            ad_flag = bool(response.flags & dns.flags.AD)
            result["rcode"] = rcode_text
            result["ad"] = ad_flag
            result["ok"] = (
                rcode_text == item["expected_rcode"]
                and (not item["expect_ad"] or ad_flag)
                and (item["expect_ad"] or not ad_flag)
            )
        except Exception as exc:
            result["error"] = str(exc)
        finally:
            result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        overall_ok = overall_ok and result["ok"]
        results.append(result)

    return {
        "server": f"{server_host}:{server_port}",
        "enabled": dnssec_enabled,
        "overall": "pass" if overall_ok else "fail",
        "tests": results,
    }


def print_dnssec_self_validation_test():
    result = run_dnssec_self_validation_test()
    print(f"DNSSEC Self-Validation test against {result['server']}", flush=True)
    if not result.get("enabled"):
        print("  WARNING: dnssec_validation_enabled is off.", flush=True)
    if result.get("error"):
        print(f"  ERROR: {result['error']}", flush=True)
    for item in result.get("tests", []):
        status = "OK" if item["ok"] else "FAIL"
        ad_text = "AD" if item["ad"] else "no AD"
        details = item["error"] or f"rcode={item['rcode']} {ad_text} expected={item['expected_rcode']}"
        print(f"  [{status}] {item['domain']} {item['qtype']} - {details} ({item['duration_ms']} ms)", flush=True)
    print(f"  Overall: {result['overall'].upper()}", flush=True)


def run_console_command(command):
    global dns_servers
    command = command.replace(chr(0xFEFF), "")
    cleaned = "".join(ch for ch in command if ch.isprintable())
    cmd = " ".join(cleaned.strip().lower().split())
    if not cmd:
        return True
    if cmd in {"help", "?"}:
        print("Commands: restart, stop, status, dnssec test, cache clear, update blocklist, help", flush=True)
        return True
    if cmd == "status":
        print_console_status()
        return True
    if cmd in {"dnssec test", "test dnssec", "dnssec"}:
        print_dnssec_self_validation_test()
        return True
    if cmd == "cache clear":
        result = clear_dns_cache()
        print(f"Cache cleared: {result['entries']} entries, {result['bytes_used']} bytes", flush=True)
        return True
    if cmd in {"update blocklist", "update blocklists"}:
        if blocklist_manager is None:
            print("Blocklist manager is not available.", flush=True)
        else:
            lists = [
                bl for bl in blocklist_manager.get_all()
                if bl.get("url", "").startswith(("http://", "https://"))
            ]
            if not lists:
                print("No remote blocklists found.", flush=True)
                return True
            total = len(lists)
            for idx, bl in enumerate(lists, 1):
                name = bl.get("name") or f"ID {bl.get('id')}"
                print(f"[{idx}/{total}] Updating {name}...", flush=True)
                try:
                    blocklist_manager.update(bl["id"], background=False)
                    updated = blocklist_manager.get_by_id(bl["id"]) or {}
                    if updated.get("last_error"):
                        print(f"[{idx}/{total}] {name}: ERROR - {updated['last_error']}", flush=True)
                    else:
                        print(f"[{idx}/{total}] {name}: updated ({updated.get('rule_count', 0)} rules)", flush=True)
                except Exception as exc:
                    print(f"[{idx}/{total}] {name}: ERROR - {exc}", flush=True)
            print("All Blocklist Updated", flush=True)
        return True
    if cmd == "restart":
        print("Restarting runtime servers...", flush=True)
        try:
            restart_runtime_servers()
            print(f"Runtime restarted. Web UI: http://127.0.0.1:{WEB_PORT} | DNS: {DNS_HOST}:{DNS_PORT}", flush=True)
        except Exception as exc:
            print(f"Runtime restart failed: {exc}", flush=True)
            try:
                with open("startup.log", "a", encoding="utf-8") as log:
                    log.write(f"{now_iso()} runtime restart failed: {type(exc).__name__}: {exc}\n")
            except Exception:
                pass
        return True
    if cmd == "stop":
        print("Stopping server...", flush=True)
        server_shutdown_event.set()
        shutdown_runtime_servers()
        return False
    print(f"Unknown command: {command}. Type 'help'.", flush=True)
    return True


def console_loop():
    print("Console commands: restart, stop, status, dnssec test, cache clear, update blocklist, help", flush=True)
    while not server_shutdown_event.is_set():
        try:
            command = input("pyguarddns> ")
        except EOFError:
            time.sleep(0.5)
            continue
        except KeyboardInterrupt:
            command = "stop"
        if not run_console_command(command):
            break


def ensure_requirements():
    try:
        import subprocess, json, sys
        req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
        if not os.path.exists(req_path):
            return
        with open(req_path) as f:
            required = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    required.append(line)
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
            capture_output=True, text=True, timeout=30
        )
        installed = {pkg["name"].lower(): pkg["version"] for pkg in json.loads(result.stdout)}
        to_install = []
        for req in required:
            name = req.split(">=")[0].split("==")[0].split("<")[0].split("~=")[0].split("!=")[0].strip().lower()
            if name == "pip":
                continue
            if name not in installed:
                to_install.append(req)
        if not to_install:
            return
        print(f"Missing packages: {', '.join(to_install)} — installing...", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install"] + to_install,
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print(f"pip install failed (exit {result.returncode}):\n{result.stdout}\n{result.stderr}", flush=True)
        else:
            print("Done.", flush=True)
    except Exception as e:
        print(f"Warning: could not verify requirements: {e}", flush=True)


def main():
    global dns_servers, encrypted_dns_servers
    ensure_requirements()
    install_crash_handlers()
    if not acquire_instance_lock():
        print(f"{APP_NAME} is already running. Please do not start a second window.", flush=True)
        return
    server_shutdown_event.clear()
    set_runtime_status("DNS server starting ...", ready=False)
    with open("startup.log", "a", encoding="utf-8") as log:
        log.write(f"{now_iso()} starting {APP_NAME}\n")
        log.flush()
        init_db()
        log.write(f"{now_iso()} database ready\n")
        log.flush()
        start_web_server()
        log.write(f"{now_iso()} web ready on {WEB_HOST}:{WEB_PORT}\n")
        log.flush()
        start_db_writer()
        log.write(f"{now_iso()} db writer ready\n")
        log.flush()
        threading.Thread(target=db_maintenance_loop, name="db-maintenance", daemon=True).start()
        log.write(f"{now_iso()} db maintenance ready\n")
        log.flush()
        threading.Thread(target=_healthcheck_worker, name="healthcheck", daemon=True).start()
        log.write(f"{now_iso()} healthcheck worker ready\n")
        log.flush()
        invalidate_rules_cache()
        log.write(f"{now_iso()} custom rule cache lazy\n")
        log.flush()
        dns_servers = list(start_dns_servers())
        log.write(f"{now_iso()} dns ready on {DNS_HOST}:{DNS_PORT}\n")
        log.flush()
        encrypted_dns_servers = list(start_encrypted_dns_servers())
        encrypted_state = encrypted_dns_runtime_state()
        if encrypted_dns_servers:
            log.write(
                f"{now_iso()} encrypted dns ready on {ENCRYPTED_DNS_HOST}:{DNS_TLS_PORT}/tls "
                f"{ENCRYPTED_DNS_HOST}:{DNS_HTTPS_PORT}/https "
                f"{ENCRYPTED_DNS_HOST}:{DNS_QUIC_PORT}/quic "
                f"tls_running={encrypted_state['tls_running']} https_running={encrypted_state['https_running']} quic_running={encrypted_state['quic_running']}\n"
            )
        else:
            log.write(f"{now_iso()} encrypted dns disabled\n")
        log.flush()
        set_runtime_status("DNS server ready", ready=True)
        public_dns_name = ENCRYPTED_DNS_DOMAIN or ENCRYPTED_DNS_HOST
        print(f"{APP_NAME} Web UI: http://127.0.0.1:{WEB_PORT}", flush=True)
        print(f"{APP_NAME} DNS UDP/TCP: {DNS_HOST}:{DNS_PORT}", flush=True)
        if encrypted_dns_servers:
            print(f"{APP_NAME} encrypted DNS: tls://{public_dns_name}:{DNS_TLS_PORT} | https://{public_dns_name}{'' if DNS_HTTPS_PORT == 443 else ':' + str(DNS_HTTPS_PORT)}/dns-query | quic://{public_dns_name}:{DNS_QUIC_PORT}", flush=True)
    try:
        console_loop()
    finally:
        shutdown_runtime_servers()


def cli_main():
    import argparse
    parser = argparse.ArgumentParser(prog=APP_NAME, description="LocalDNSGuard DNS filtering server")
    parser.add_argument("command", nargs="?", default="serve",
                        help="Command: serve, status, reload, update-lists, backup, restore, test-domain, dnssec-test")
    parser.add_argument("--domain", help="Domain for test-domain command")
    parser.add_argument("--query-type", default="A", help="Query type for test-domain (default: A)")
    parser.add_argument("--client", default="127.0.0.1", help="Client IP for test-domain (default: 127.0.0.1)")
    parser.add_argument("--file", help="Backup file path for restore command")
    parser.add_argument("--backup-file", help="Output path for backup command")
    args = parser.parse_args()

    cmd = args.command

    if cmd == "serve":
        main()
        return

    init_db()
    start_db_writer()

    if cmd == "status":
        summary = stats_summary()
        cache_info = cache_stats()
        print(f"{APP_NAME} Status")
        print(f"  Total queries:   {summary.get('total', 0)}")
        print(f"  Blocked queries: {summary.get('blocked', 0)}")
        print(f"  Block rate:      {summary.get('block_rate', 0.0):.1f}%")
        print(f"  Avg response:    {summary.get('avg_ms', 0.0):.1f} ms")
        print(f"  Cache rate:      {summary.get('cache_rate', 0.0):.1f}%")
        print(f"  Active clients:  {summary.get('clients', 0)}")
        print(f"  Filter rules:    {summary.get('rules', 0)}")
        print(f"  Upstreams:       {summary.get('upstreams', 0)}")
        print(f"  Cache entries:   {cache_info.get('entries', 0)}")
        print(f"  Cache bytes:     {cache_info.get('bytes_used', 0)}")

    elif cmd == "reload":
        invalidate_rules_cache()
        print("Rules cache invalidated.")

    elif cmd == "update-lists":
        if blocklist_manager is not None:
            result = blocklist_manager.update_all()
            print(f"Updated blocklists: {result}")
        else:
            print("No blocklist manager available.")

    elif cmd == "backup":
        sensitive_keys = {"admin_password_set", "api_token", "encrypted_dns_private_key_pem"}
        data = {
            "version": 2,
            "settings": [r for r in rows("SELECT * FROM settings") if r["key"] not in sensitive_keys],
            "rules": rows("SELECT * FROM rules WHERE action <> 'rewrite' ORDER BY id ASC"),
            "dns_rewrites": rows("SELECT * FROM rules WHERE action = 'rewrite' ORDER BY id ASC"),
            "upstreams": rows("SELECT * FROM upstreams"),
            "profiles": rows("SELECT * FROM profiles") if client_manager else [],
            "clients": rows("SELECT * FROM clients") if client_manager else [],
            "profile_custom_rules": rows("SELECT * FROM profile_custom_rules") if client_manager else [],
            "profile_blocklists": rows("SELECT * FROM profile_blocklists") if client_manager else [],
            "blocklists": rows("SELECT * FROM blocklists") if blocklist_manager else [],
        }
        body = json.dumps(data, ensure_ascii=False, indent=2)
        backup_path = args.backup_file or f"localdnsguard_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_path, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"Backup written to {backup_path}")

    elif cmd == "restore":
        if not args.file:
            print("Error: --file argument required for restore command", file=sys.stderr)
            return
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                data = json.load(f)
            handle_restore_data(data)
            print(f"Restore from {args.file} completed.")
        except Exception as exc:
            print(f"Restore failed: {exc}", file=sys.stderr)

    elif cmd == "test-domain":
        if not args.domain:
            print("Error: --domain argument required for test-domain command", file=sys.stderr)
            return
        try:
            result = run_domain_test({"domain": args.domain, "query_type": args.query_type, "client": args.client})
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except Exception as exc:
            print(f"Domain test failed: {exc}", file=sys.stderr)

    elif cmd == "dnssec-test":
        print_dnssec_self_validation_test()

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        parser.print_help()


if __name__ == "__main__":
    try:
        cli_main()
    except Exception as exc:
        write_crash_report("fatal main exception", traceback.format_exc())
        with open("startup.log", "a", encoding="utf-8") as log:
            log.write(f"{now_iso()} fatal: {type(exc).__name__}: {exc}\n")
        raise
