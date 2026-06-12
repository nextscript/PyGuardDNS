#!/usr/bin/env python3
import base64
import csv
import atexit
import faulthandler
import hashlib
import hmac
import io
import ipaddress
import json
import os
import queue
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
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import MappingProxyType
from urllib.parse import parse_qs, quote, urlparse
import urllib.request

import bcrypt

from dns_engine import FilterEngine, FilterResult
from blocklist_manager import BlocklistManager, fetch_url_text as fetch_blocklist_url_text, parse_filter_list, set_dns_resolver as _set_blocklist_dns_resolver
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
from rules_engine import (
    parse_rule_line,
    read_rules,
    write_rules,
    validate_rules,
    count_rules,
    load_rules_into_engine,
    migration_needed,
    run_migration,
    load_blocklist_cache,
    save_blocklist_cache,
    convert_blocklist_text,
    save_cosmetic_rules,
    save_unsupported_rules,
    save_original_text,
)
import upstream_manager as um
logger = logging.getLogger("dnssec")


class FormData(dict):
    def __init__(self, parsed):
        super().__init__((key, values[-1]) for key, values in parsed.items())
        self._all = parsed

    def get_all(self, key):
        return list(self._all.get(key, []))


class TTLSet:
    """Thread-safe "seen recently" set with a fixed TTL per entry.

    Used to dedupe unknown-client events so a single noisy IP queues at most
    one registration event per TTL window, instead of one per DNS query.
    """

    def __init__(self, ttl_seconds, max_entries=20000):
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._expires = {}
        self._lock = threading.Lock()

    def add_if_absent(self, item):
        """Record `item` and return True, unless it was already seen within the TTL (then False)."""
        now = time.monotonic()
        with self._lock:
            expires_at = self._expires.get(item)
            if expires_at is not None and expires_at > now:
                return False
            self._expires[item] = now + self._ttl
            if len(self._expires) > self._max_entries:
                self._expires = {k: v for k, v in self._expires.items() if v > now}
            return True


memory_db_dirty = threading.Event()
memory_db_generation = 0
memory_db_generation_lock = threading.Lock()
memory_db_sync_stop = threading.Event()
memory_db_sync_started = False


class PyGuardConnection(sqlite3.Connection):
    def commit(self):
        global memory_db_generation
        result = super().commit()
        if DB_IN_MEMORY:
            with memory_db_generation_lock:
                memory_db_generation += 1
                memory_db_dirty.set()
        return result


APP_NAME = "PyGuardDNS"
DB_PATH = os.environ.get("LOCALDNSGUARD_DB", "localdnsguard.sqlite3")
DB_IN_MEMORY = os.environ.get("LOCALDNSGUARD_DB_IN_MEMORY", "1") == "1"
DB_MEMORY_SYNC_INTERVAL = float(os.environ.get("LOCALDNSGUARD_DB_MEMORY_SYNC_INTERVAL", "60"))


def _get_ram_db_path():
    if not DB_IN_MEMORY:
        return None
    if sys.platform != "linux":
        return None
    if not os.path.isdir("/dev/shm"):
        return None
    return os.path.join("/dev/shm", os.path.basename(DB_PATH))


RAM_DB_PATH = _get_ram_db_path()
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
rules_lock = threading.RLock()
runtime_restart_lock = threading.RLock()

# DNS response cache and negative-response cache are sharded across N
# independent dict+lock pairs (shard = hash(cache_key) % CACHE_SHARDS), so
# concurrent lookups for different domains don't serialize on one global
# lock. Each dns_cache shard tracks its own byte usage.
CACHE_SHARDS = 32
dns_cache_shards = [{} for _ in range(CACHE_SHARDS)]
cache_locks = [threading.RLock() for _ in range(CACHE_SHARDS)]
negative_cache_shards = [{} for _ in range(CACHE_SHARDS)]
negative_cache_locks = [threading.RLock() for _ in range(CACHE_SHARDS)]
NEGATIVE_CACHE_MAX_ENTRIES = 10000
NEGATIVE_CACHE_SHARD_MAX = max(1, NEGATIVE_CACHE_MAX_ENTRIES // CACHE_SHARDS)
prefetch_hits = {}
prefetch_hits_lock = threading.RLock()
prefetch_in_progress = set()
prefetch_in_progress_lock = threading.Lock()
dash_cache = {"data": None, "ts": 0.0}
DASH_CACHE_TTL = 5
sessions = {}
doh_host_cache = {}
doh_connection_cache = {}
dnscrypt_cert_cache = {}
rules_cache = None
shutdown_signal_received = False
dns_concurrency = threading.BoundedSemaphore(int(os.environ.get("LOCALDNSGUARD_MAX_DNS_WORKERS", "48")))
upstream_concurrency = threading.BoundedSemaphore(int(os.environ.get("LOCALDNSGUARD_MAX_UPSTREAM_WORKERS", "64")))
db_write_queue = []
db_write_lock = threading.Lock()
upstream_metric_last_write = {}
upstream_queue_wait_samples = []
upstream_queue_wait_lock = threading.Lock()
DOT_POOL_SIZE = max(1, int(os.environ.get("LOCALDNSGUARD_DOT_POOL_SIZE", "4")))
dot_pools = {}
dot_pool_counters = {}
dot_pools_lock = threading.RLock()
doh_pools = {}
doh_pools_lock = threading.RLock()
quic_sessions = {}
quic_sessions_lock = threading.RLock()
_quic_loop = None
_quic_loop_thread = None
_quic_loop_lock = threading.Lock()
QUIC_IDLE_TIMEOUT = 45.0
MAX_QUIC_FAILURES_BEFORE_PENALTY = 3
QUIC_PENALTY_COOLDOWN_SECONDS = 120.0
instance_lock_file = None
cache_bytes_used = [0] * CACHE_SHARDS
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

# RAM snapshot of clients/profiles for the DNS hot path (see build_client_snapshot).
# Replaced wholesale (atomic reference swap) after client/profile changes -
# readers never block on a rebuild and never touch SQLite directly.
_empty_client_snapshot = {"by_ip": MappingProxyType({}), "networks": (), "default_profile": None}
_client_snapshot = _empty_client_snapshot
_client_snapshot_lock = threading.RLock()
_client_snapshot_generation = 0

# Async unknown-client registration: the DNS hot path only enqueues an IP
# (deduped via TTL, at most one event per IP per window) - a background
# worker performs the actual SQLite insert and triggers a snapshot reload.
unknown_client_queue = queue.Queue(maxsize=10000)
unknown_client_seen = TTLSet(ttl_seconds=300)
unknown_client_dropped_total = 0
unknown_client_dropped_lock = threading.Lock()

# Lightweight DNS hot-path runtime counters (see get_runtime_metrics / spec
# task 8). Plain dict + lock - increments are rare-contention single-key
# updates, not a bottleneck compared to the DNS work itself.
_filter_engine_generation = 0
dns_runtime_metrics_lock = threading.Lock()
dns_runtime_metrics = {
    "dns_requests_total": 0,
    "dns_cache_hits_total": 0,
    "dns_cache_misses_total": 0,
    "dns_filter_blocks_total": 0,
    "dns_filter_allows_total": 0,
    "dns_upstream_errors_total": 0,
    "query_log_dropped_total": 0,
}


def bump_runtime_metric(name, amount=1):
    with dns_runtime_metrics_lock:
        dns_runtime_metrics[name] = dns_runtime_metrics.get(name, 0) + amount


def get_runtime_metrics():
    """Snapshot of all spec-required runtime/queue/generation metrics for
    /metrics and /api/runtime_metrics."""
    with dns_runtime_metrics_lock:
        snapshot = dict(dns_runtime_metrics)
    with db_write_lock:
        snapshot["query_log_queue_size"] = len(db_write_queue)
    snapshot["unknown_client_queue_size"] = unknown_client_queue.qsize()
    with unknown_client_dropped_lock:
        snapshot["unknown_client_dropped_total"] = unknown_client_dropped_total
    snapshot["runtime_snapshot_generation"] = client_snapshot_generation()
    with _active_engine_lock:
        snapshot["filter_engine_generation"] = _filter_engine_generation
    return snapshot
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
blocklist_import_queue = []
blocklist_import_lock = threading.Lock()
blocklist_import_running = False
blocklist_import_status = {
    "running": False,
    "queued": 0,
    "total": 0,
    "done": 0,
    "failed": 0,
    "current": "",
    "last_error": "",
    "started_at": "",
    "finished_at": "",
}
blocklist_delete_queue = []
blocklist_delete_lock = threading.Lock()
blocklist_delete_running = False
blocklist_delete_status = {
    "running": False,
    "queued": 0,
    "total": 0,
    "done": 0,
    "failed": 0,
    "current_id": None,
    "current": "",
    "last_error": "",
    "started_at": "",
    "finished_at": "",
}
blocklist_toggle_lock = threading.Lock()
blocklist_toggle_running = False
blocklist_toggle_pending = 0
blocklist_toggle_status = {
    "running": False,
    "queued": 0,
    "total": 0,
    "done": 0,
    "failed": 0,
    "current": "",
    "last_error": "",
    "started_at": "",
    "finished_at": "",
}
rules_reload_lock = threading.Lock()
rules_reload_running = False
rules_reload_pending = 0


def build_filter_engine():
    engine = FilterEngine()
    load_rules_into_engine(engine)
    for rewrite in rows("SELECT pattern, target, pattern_type FROM rules WHERE action = 'rewrite' AND enabled = 1"):
        pattern = rewrite["pattern"]
        target = rewrite["target"]
        if pattern and target:
            engine.add_rule(f"{pattern} -> {target}", "rewrite", "rewrite_rules")
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
                def dnssec_fetch(request_wire):
                    dnssec_timeout = get_timeout_setting("dnssec_validation_timeout", 3.0)
                    response_wire, _ = forward_query(request_wire, timeout_override=dnssec_timeout)
                    return response_wire

                _dnssec_validator = DNSSECValidator(
                    timeout=get_timeout_setting("dnssec_validation_timeout", 3.0),
                    query_func=dnssec_fetch,
                )
                _dnssec_validator.reload_trust_anchor()
    return _dnssec_validator


def process_dnssec_trust_anchor_startup():
    if not _dnssec_available:
        logger.warning("DNSSEC startup trust-anchor processing skipped: dnspython is not available")
        return False, "dnspython DNSSEC support is not available"
    ok, err = ensure_root_trust_anchor()
    if not ok:
        logger.error("DNSSEC startup trust-anchor bootstrap failed: %s", err)
        return False, err
    validator = DNSSECValidator()
    changed = validator.process_rfc5011_state()
    ok, err = validator.reload_trust_anchor()
    if not ok:
        logger.error("DNSSEC startup trust-anchor reload failed: %s", err)
        return False, err
    if changed:
        logger.warning("DNSSEC startup RFC5011 trust-anchor state promoted")
    return True, "promoted" if changed else "unchanged"


def add_do_bit_to_query(request_bytes):
    if not _dnssec_available:
        return request_bytes
    try:
        import dns.message
        import dns.flags
        msg = dns.message.from_wire(request_bytes)
        msg.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
        return msg.to_wire()
    except Exception:
        return request_bytes


def clear_dnssec_validator():
    global _dnssec_validator
    with _dnssec_validator_lock:
        _dnssec_validator = None


def reload_filter_engine():
    global _active_engine, _filter_engine_generation
    try:
        new_engine = build_filter_engine()
    except Exception as exc:
        with open("startup.log", "a", encoding="utf-8") as log:
            log.write(f"{now_iso()} FILTER ENGINE BUILD FAILED: {exc}\n")
        raise
    with _active_engine_lock:
        _active_engine = new_engine
        _filter_engine_generation += 1
    with open("startup.log", "a", encoding="utf-8") as log:
        log.write(f"{now_iso()} filter engine reloaded (gen={_filter_engine_generation}, suffix_blocks={len(new_engine.suffix_block)})\n")


def get_filter_engine():
    # Lock-free read: reading a module global is a single, GIL-atomic
    # name lookup, and reload_filter_engine() always swaps in a fully
    # built engine - readers see either the old or the new engine, never
    # a half-built one. The lock is only needed by the writer to keep the
    # engine swap and generation-counter bump consistent.
    return _active_engine


def build_client_snapshot():
    """Build an immutable RAM snapshot of clients/profiles for the DNS hot path.

    Mirrors ClientManager.get_client_by_ip's exact-IP-or-CIDR matching, but
    precomputed offline (no lock held, no SQLite access from readers): exact
    IP entries land in an O(1) dict, CIDR entries in an ordered tuple that's
    scanned only on a dict miss.
    """
    by_ip = {}
    networks = []
    default_profile = None
    if client_manager is not None:
        try:
            for row in client_manager.get_clients_full():
                cidr_str = (row.get("cidr") or row.get("ip") or "").strip()
                if not cidr_str:
                    continue
                if "/" in cidr_str:
                    try:
                        net = ipaddress.ip_network(cidr_str, strict=False)
                    except ValueError:
                        continue
                    networks.append((net, row))
                else:
                    by_ip.setdefault(cidr_str, row)
        except Exception:
            pass
        try:
            for profile in client_manager.get_profiles():
                if profile.get("is_default"):
                    default_profile = profile
                    break
        except Exception:
            pass
    return {
        "by_ip": MappingProxyType(by_ip),
        "networks": tuple(networks),
        "default_profile": default_profile,
    }


def reload_client_snapshot():
    global _client_snapshot, _client_snapshot_generation
    new_snapshot = build_client_snapshot()
    with _client_snapshot_lock:
        _client_snapshot = new_snapshot
        _client_snapshot_generation += 1


def get_client_snapshot():
    # Lock-free read - see get_filter_engine() for the rationale.
    return _client_snapshot


def client_snapshot_generation():
    return _client_snapshot_generation


def lookup_client_snapshot(client_ip):
    """O(1) exact-IP lookup with CIDR fallback - reads only the RAM snapshot,
    never SQLite. This is what the DNS hot path should call instead of
    client_manager.get_client_by_ip()."""
    snapshot = get_client_snapshot()
    info = snapshot["by_ip"].get(client_ip)
    if info is not None:
        return info
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return None
    for net, row in snapshot["networks"]:
        if ip_obj in net:
            return row
    return None


def reload_client_state():
    """Rebuild the filter engine and the client/profile RAM snapshot together -
    used as ClientManager's reload_callback so client/profile edits propagate
    to both atomically-swapped caches."""
    reload_filter_engine()
    reload_client_snapshot()


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
        global shutdown_signal_received
        if shutdown_signal_received:
            raise SystemExit(128 + int(signum))
        shutdown_signal_received = True
        try:
            name = signal.Signals(signum).name
        except Exception:
            name = f"signal {signum}"
        try:
            console_event("info", "Shutdown signal received", name)
            server_shutdown_event.set()
            shutdown_runtime_servers()
        except Exception:
            pass
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
    if RAM_DB_PATH:
        conn = sqlite3.connect(RAM_DB_PATH, check_same_thread=False, factory=PyGuardConnection)
        conn.row_factory = sqlite3.Row
        if os.path.exists(DB_PATH):
            source = sqlite3.connect(DB_PATH)
            try:
                source.backup(conn)
            finally:
                source.close()
        conn.execute("PRAGMA journal_mode=WAL")
    elif DB_IN_MEMORY:
        conn = sqlite3.connect(":memory:", check_same_thread=False, factory=PyGuardConnection)
        conn.row_factory = sqlite3.Row
        if os.path.exists(DB_PATH):
            source = sqlite3.connect(DB_PATH)
            try:
                source.backup(conn)
            finally:
                source.close()
        conn.execute("PRAGMA journal_mode=MEMORY")
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, factory=PyGuardConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


db = connect_db()


def sync_memory_db_to_disk(force=False):
    if not DB_IN_MEMORY:
        return
    if not memory_db_dirty.is_set():
        return
    temp_path = f"{DB_PATH}.ramtmp"
    snapshot = None
    snapshot_generation = 0
    lock_acquired = db_lock.acquire(blocking=force)
    if not lock_acquired:
        return
    try:
        if not memory_db_dirty.is_set():
            return
        with memory_db_generation_lock:
            snapshot_generation = memory_db_generation
        if RAM_DB_PATH:
            dest = sqlite3.connect(temp_path)
            try:
                db.backup(dest)
                dest.commit()
            finally:
                dest.close()
        elif hasattr(db, "serialize"):
            snapshot = db.serialize()
        else:
            dest = sqlite3.connect(temp_path)
            try:
                db.backup(dest)
                dest.commit()
            finally:
                dest.close()
    finally:
        db_lock.release()
    if snapshot is not None:
        with open(temp_path, "wb") as fh:
            fh.write(snapshot)
    try:
        os.replace(temp_path, DB_PATH)
    except PermissionError:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass
        raise
    for suffix in ("-wal", "-shm"):
        aux_path = f"{DB_PATH}{suffix}"
        try:
            if os.path.exists(aux_path):
                os.remove(aux_path)
        except OSError:
            pass
    with memory_db_generation_lock:
        if memory_db_generation == snapshot_generation:
            memory_db_dirty.clear()


def memory_db_sync_loop():
    while not memory_db_sync_stop.wait(DB_MEMORY_SYNC_INTERVAL):
        try:
            sync_memory_db_to_disk()
        except Exception:
            with open("web-error.log", "a", encoding="utf-8") as log:
                log.write(f"{now_iso()} memory_db_sync_loop\n{traceback.format_exc()}\n")


def start_memory_db_sync():
    global memory_db_sync_started
    if not DB_IN_MEMORY or memory_db_sync_started:
        return
    memory_db_sync_started = True
    threading.Thread(target=memory_db_sync_loop, name="memory-db-sync", daemon=True).start()


def stop_memory_db_sync():
    if not DB_IN_MEMORY:
        return
    memory_db_sync_stop.set()
    if memory_db_dirty.is_set():
        sync_memory_db_to_disk(force=True)


atexit.register(stop_memory_db_sync)


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
                dnscrypt_relay TEXT NOT NULL DEFAULT '',
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
            "negative_cache_enabled": "1",
            "negative_cache_max_ttl": "300",
            "negative_cache_min_ttl": "30",
            "prefetch_enabled": "1",
            "prefetch_min_hits": "3",
            "prefetch_ttl_percentage": "20",
            "serve_stale_enabled": "0",
            "serve_stale_max_age": "86400",
            "optimistic_cache_enabled": "0",
            "dnssec_cache_enabled": "1",
            "dnssec_cache_max_ttl": "86400",
            "disable_ipv6": "0",
            "upstream_mode": "sequential",
            "upstream_timeout": "2.5",
            "tcp_connect_timeout": "3.0",
            "tls_handshake_timeout": "4.0",
            "dns_query_timeout": "2.5",
            "dnssec_validation_timeout": "3.0",
            "doq_total_timeout": "1.8",
            "doh3_total_timeout": "2.2",
            "block_mode": "zero_ip",
            "block_response_ttl": "60",
            "custom_block_ipv4": "0.0.0.0",
            "custom_block_ipv6": "::",
            "lan_only": "1",
            "dnssec_validation_enabled": "1",
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
        _invalidate_settings_cache()
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
            _set_blocklist_dns_resolver(resolve_via_configured_dns)
            reload_filter_engine()
        if migration_needed():
            run_migration()
        global client_manager
        if client_manager is None:
            client_manager = ClientManager(db, reload_callback=reload_client_state, db_lock=db_lock)
            client_manager.init_schema()
            reload_client_snapshot()
        um.load_all()
        if not um.get_all():
            um.migrate_from_sqlite(db)
        existing = um.get_all()
        if not existing:
            um.create("Cloudflare DoT", "1.1.1.1", 853, DEFAULT_UPSTREAM, "dot", "tls", enabled=True)
            existing = um.get_all()
        for up in existing:
            if not up.get("resolver"):
                parsed = detect_upstream(up["address"])
                um.update(up["id"], resolver=parsed["resolver"], resolver_type=parsed["type"], transport=parsed["transport"])
        normalize_dnscrypt_relay_upstreams()
        for up in um.get_all():
            if up.get("last_error") and up.get("latency_ms") is not None and up["latency_ms"] > 1000:
                um.update(up["id"], latency_ms=None)
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
    (12, "add DNSCrypt relay column to upstreams", lambda: (
        _ensure_column("upstreams", "dnscrypt_relay", "TEXT NOT NULL DEFAULT ''"),
    )),
    (13, "drop legacy blocklist_entries table", lambda: db.executescript("""
        DROP TABLE IF EXISTS blocklist_entries;
    """)),
    (14, "add performance metrics to query_log", lambda: (
        _ensure_column("query_log", "upstream_protocol", "TEXT NOT NULL DEFAULT ''"),
        _ensure_column("query_log", "response_time_ms", "REAL NOT NULL DEFAULT 0"),
        _ensure_column("query_log", "connect_time_ms", "REAL NOT NULL DEFAULT 0"),
        _ensure_column("query_log", "handshake_time_ms", "REAL NOT NULL DEFAULT 0"),
        _ensure_column("query_log", "upstream_query_time_ms", "REAL NOT NULL DEFAULT 0"),
        _ensure_column("query_log", "dnssec_status", "TEXT NOT NULL DEFAULT ''"),
        _ensure_column("query_log", "pool_reused", "INTEGER NOT NULL DEFAULT 0"),
        _ensure_column("query_log", "served_stale", "INTEGER NOT NULL DEFAULT 0"),
        _ensure_column("query_log", "prefetch_triggered", "INTEGER NOT NULL DEFAULT 0"),
        _ensure_column("query_log", "resolver_mode", "TEXT NOT NULL DEFAULT ''"),
    )),
]


def run_migrations():
    applied = {r["version"] for r in db.execute("SELECT version FROM schema_migrations").fetchall()}
    for version, name, fn in MIGRATIONS:
        if version not in applied:
            try:
                fn()
            except Exception as exc:
                console_event("error", f"Migration {version} ({name}) failed", exc)
                raise
            db.execute("INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)", (version, name, now_iso()))
            console_event("ok", f"Migration {version} ({name}) applied")


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


_settings_cache = {}
_settings_cache_lock = threading.RLock()
_SETTING_MISSING = object()


def _invalidate_settings_cache(key=None):
    with _settings_cache_lock:
        if key is None:
            _settings_cache.clear()
        else:
            _settings_cache.pop(key, None)


def get_setting(key, default=""):
    # Lock-free read: dict.get() is GIL-atomic, and concurrent writers
    # (set_setting/_invalidate_settings_cache) only ever replace/remove a
    # key, never leave the dict in a torn state. The lock is only needed
    # for the write-back below and for actual writes.
    cached = _settings_cache.get(key, _SETTING_MISSING)
    if cached is not _SETTING_MISSING:
        return cached
    with db_lock:
        row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is None:
        return default
    value = row["value"]
    with _settings_cache_lock:
        _settings_cache[key] = value
    return value


def set_setting(key, value):
    value = str(value)
    with db_lock:
        db.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        db.commit()
    with _settings_cache_lock:
        _settings_cache[key] = value


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


def get_timeout_setting(key, fallback):
    try:
        raw = get_setting(key, str(fallback))
    except sqlite3.Error:
        return fallback
    try:
        return parse_positive_float(raw, fallback, key)
    except ValueError:
        return fallback


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
    pass


def update_upstream_health(upstream_id, success, latency_ms=0, error=""):
    try:
        newly_paused = um.update_health(upstream_id, success, latency_ms, error)
        if newly_paused:
            log_admin_action("system", "upstream_auto_paused",
                             f"Upstream {upstream_id} auto-paused after repeated failures", "")
    except Exception:
        pass


def get_upstream_health(upstream_id):
    return um.get_health(upstream_id)


def _healthcheck_worker():
    while True:
        try:
            time.sleep(60)
            _healthcheck_worker_pass()
        except Exception:
            pass


def _healthcheck_worker_pass():
    upstreams = [u for u in um.get_all() if u.get("enabled") and u.get("resolver_type") != "dnscrypt_relay"]
    if not upstreams:
        return
    _, query = build_query("google.com", 1)
    for up in upstreams:
        try:
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
    domain = (domain or "").strip()
    if "://" in domain:
        from urllib.parse import urlparse
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    domain = domain.rstrip(".").lower()
    if not domain:
        return ""
    if domain.isascii():
        # IDNA encoding of an already-ASCII domain is a no-op (and on
        # UnicodeError we'd fall back to `domain` anyway) - skip the
        # stringprep-based codec entirely for the common case.
        return domain
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


def dns_response_truncated(response):
    if not response or len(response) < 4:
        return False
    return bool(response[2] & 0x02)


def build_ip_response(request, ip_text, ttl=60, question=None):
    if question is None:
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


def build_block_response(request, qtype_name=None, question=None):
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
    return build_ip_response(request, ip, ttl=block_response_ttl(), question=question)


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
        default_profile = db.execute("SELECT id FROM profiles WHERE is_default=1").fetchone()
        default_id = default_profile["id"] if default_profile else None
        db.execute(
            "INSERT OR IGNORE INTO clients(name,ip,cidr,profile_id,filtering_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (ip, ip, "", default_id, 1, now, now),
        )


def ensure_client(client_ip):
    """Register a previously-unseen client IP - asynchronously.

    The DNS hot path must never block on SQLite, so this only does an O(1)
    RAM-snapshot lookup plus a TTL-deduped queue push. A background worker
    (unknown_client_worker) performs the actual insert and triggers a
    snapshot reload so the new client gets picked up.
    """
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        return
    if lookup_client_snapshot(client_ip) is not None:
        return
    if not unknown_client_seen.add_if_absent(client_ip):
        return
    try:
        unknown_client_queue.put_nowait(client_ip)
    except queue.Full:
        global unknown_client_dropped_total
        with unknown_client_dropped_lock:
            unknown_client_dropped_total += 1


def unknown_client_worker():
    """Background worker: batches queued unknown-client IPs into SQLite
    inserts and reloads the client/profile RAM snapshot when new rows land."""
    while not server_shutdown_event.is_set():
        try:
            ip = unknown_client_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        batch = [ip]
        while len(batch) < 200:
            try:
                batch.append(unknown_client_queue.get_nowait())
            except queue.Empty:
                break
        inserted = False
        try:
            now = now_iso()
            with db_lock:
                default_profile = db.execute("SELECT id FROM profiles WHERE is_default=1").fetchone()
                default_id = default_profile["id"] if default_profile else None
                for client_ip in batch:
                    try:
                        existing = db.execute("SELECT id FROM clients WHERE ip=?", (client_ip,)).fetchone()
                        if existing:
                            continue
                        db.execute(
                            "INSERT OR IGNORE INTO clients(name,ip,cidr,profile_id,filtering_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                            (client_ip, client_ip, "", default_id, 1, now, now),
                        )
                        inserted = True
                    except sqlite3.IntegrityError:
                        # UNIQUE(ip) race: another writer (or a previous batch
                        # entry for the same IP) already inserted this client.
                        pass
                db.commit()
        except Exception:
            with open("web-error.log", "a", encoding="utf-8") as log:
                log.write(f"{now_iso()} unknown_client_worker\n{traceback.format_exc()}\n")
            continue
        if inserted:
            try:
                reload_client_snapshot()
            except Exception:
                pass


def start_unknown_client_worker():
    threading.Thread(target=unknown_client_worker, name="unknown-client-worker", daemon=True).start()


def client_filtering_enabled(client_ip, client_info=None):
    if client_manager is not None:
        c = client_info if client_info is not None else lookup_client_snapshot(client_ip)
        if c:
            client_enabled = bool(c.get("filtering_enabled", 1))
            profile_enabled = bool(c.get("profile_filtering", 1))
            return client_enabled and profile_enabled
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


def invalidate_rules_cache(reload_now: bool = True):
    if reload_now:
        reload_filter_engine()
        reload_client_snapshot()
        clear_dns_cache()


def enqueue_rules_reload(reason: str = "Rule changes"):
    global rules_reload_running, rules_reload_pending
    with rules_reload_lock:
        rules_reload_pending += 1
        if rules_reload_running:
            return
        rules_reload_running = True
    threading.Thread(target=rules_reload_worker, args=(reason,), name="rules-reload", daemon=True).start()


def rules_reload_worker(reason: str = "Rule changes"):
    global rules_reload_running, rules_reload_pending
    try:
        while True:
            with rules_reload_lock:
                seen_pending = rules_reload_pending
            time.sleep(1.0)
            with rules_reload_lock:
                if rules_reload_pending != seen_pending:
                    continue
            try:
                console_event("work", "Reloading filter engine", reason)
                reload_filter_engine()
                clear_dns_cache()
                console_event("ok", "Filter engine reloaded", reason)
            except Exception as exc:
                console_event("error", "Rule reload failed", exc)
            with rules_reload_lock:
                if rules_reload_pending == seen_pending:
                    rules_reload_pending = 0
                    rules_reload_running = False
                    return
                rules_reload_pending = max(0, rules_reload_pending - seen_pending)
    finally:
        with rules_reload_lock:
            if not rules_reload_pending:
                rules_reload_running = False


def rebuild_rules_cache_background():
    pass


def build_rules_cache():
    return {"rules": read_rules()}


def get_rules_cache():
    return build_rules_cache()


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
    connect_timeout = get_timeout_setting("tcp_connect_timeout", timeout)
    query_timeout = get_timeout_setting("dns_query_timeout", timeout)
    if upstream.get("transport") == "tcp":
        with socket.create_connection((upstream["address"], int(upstream["port"])), timeout=connect_timeout) as s:
            s.settimeout(query_timeout)
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
    with socket.socket(socket_family_for_host(upstream["address"]), socket.SOCK_DGRAM) as s:
        s.settimeout(query_timeout)
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
    return query_doh_upstream_pooled(upstream, request, timeout=timeout)


def query_doh_upstream_once(upstream, request, timeout=4.0):
    connect_timeout = get_timeout_setting("tcp_connect_timeout", timeout)
    tls_timeout = get_timeout_setting("tls_handshake_timeout", timeout)
    query_timeout = get_timeout_setting("dns_query_timeout", timeout)
    host, port, path = doh_request_parts(upstream["resolver"])
    authority = doh_authority(host, port)
    ips = resolve_upstream_host(host)
    last_error = None
    for i, ip in enumerate(ips[:4]):
        if i > 0:
            time.sleep(0.1)
        try:
            raw = socket.create_connection((ip, port), timeout=connect_timeout)
            with raw:
                raw.settimeout(tls_timeout)
                context = ssl.create_default_context()
                conn = context.wrap_socket(raw, server_hostname=host)
                conn.settimeout(query_timeout)
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


def _quic_session_key(protocol_name, upstream):
    resolver = upstream.get("resolver") or ""
    return f"{protocol_name}:{upstream.get('id', '')}:{resolver}:{upstream['address']}:{int(upstream.get('port', 0))}"


class _QuicSession:
    def __init__(self, protocol_name, upstream):
        self.protocol_name = protocol_name
        self.upstream = dict(upstream)
        self.lock = None
        self.ctx = None
        self.proto = None
        self.last_used = 0.0
        self.handshake_count = 0
        self.reuse_count = 0
        self.reconnect_count = 0
        self.error_count = 0
        self.consecutive_failures = 0
        self.penalized_until = 0.0
        self.latencies_ms = []
        self.ever_connected = False

    def record_latency(self, latency_ms):
        self.latencies_ms.append(latency_ms)
        if len(self.latencies_ms) > 50:
            self.latencies_ms = self.latencies_ms[-25:]

    def is_penalized(self):
        return self.penalized_until > time.time()

    def record_success(self, latency_ms):
        self.record_latency(latency_ms)
        self.consecutive_failures = 0
        self.penalized_until = 0.0

    def record_failure(self):
        self.error_count += 1
        self.consecutive_failures += 1
        if self.consecutive_failures >= MAX_QUIC_FAILURES_BEFORE_PENALTY:
            self.penalized_until = time.time() + QUIC_PENALTY_COOLDOWN_SECONDS

    def avg_latency_ms(self):
        if not self.latencies_ms:
            return None
        return sum(self.latencies_ms) / len(self.latencies_ms)

    def metrics(self):
        return {
            "quic_handshake_count": self.handshake_count,
            "quic_reuse_count": self.reuse_count,
            "quic_reconnect_count": self.reconnect_count,
            "quic_error_count": self.error_count,
        }


def _get_quic_loop():
    global _quic_loop, _quic_loop_thread
    with _quic_loop_lock:
        if _quic_loop is None or _quic_loop.is_closed():
            import asyncio
            _quic_loop = asyncio.new_event_loop()
            _quic_loop_thread = threading.Thread(target=_quic_loop.run_forever, name="quic-pool-loop", daemon=True)
            _quic_loop_thread.start()
            asyncio.run_coroutine_threadsafe(_quic_idle_sweep(), _quic_loop)
        return _quic_loop


async def _quic_idle_sweep():
    import asyncio as _aio
    while True:
        await _aio.sleep(15.0)
        now = time.time()
        with quic_sessions_lock:
            sessions = list(quic_sessions.values())
        for session in sessions:
            if session.proto is not None and now - session.last_used > QUIC_IDLE_TIMEOUT:
                await _quic_session_reset(session)


async def _quic_session_reset(session):
    ctx = session.ctx
    session.ctx = None
    session.proto = None
    if ctx is not None:
        try:
            await ctx.__aexit__(None, None, None)
        except Exception:
            pass


async def _quic_session_attempt(session, request, cfg, ips, make_protocol, run_query, quic_connect):
    port = int(session.upstream.get("port", 0))
    needs_connect = (
        session.proto is None
        or session.ctx is None
        or time.time() - session.last_used > QUIC_IDLE_TIMEOUT
    )
    if needs_connect:
        await _quic_session_reset(session)
        last_err = None
        for ip in ips[:4]:
            try:
                ctx = quic_connect(ip, port, configuration=cfg, create_protocol=make_protocol)
                proto = await ctx.__aenter__()
                session.ctx = ctx
                session.proto = proto
                session.handshake_count += 1
                if session.ever_connected:
                    session.reconnect_count += 1
                session.ever_connected = True
                last_err = None
                break
            except Exception as exc:
                last_err = exc
                continue
        if session.proto is None:
            raise OSError(str(last_err) if last_err else f"{session.protocol_name} connect failed")
    else:
        session.reuse_count += 1

    start = time.perf_counter()
    try:
        result = await run_query(session.proto, request)
    except Exception:
        await _quic_session_reset(session)
        session.record_failure()
        raise
    latency_ms = (time.perf_counter() - start) * 1000.0
    session.last_used = time.time()
    session.record_success(latency_ms)
    return result


async def _quic_session_query(session, request, total_timeout, cfg, ips, make_protocol, run_query):
    import asyncio as _aio
    from aioquic.asyncio import connect as quic_connect
    if session.lock is None:
        session.lock = _aio.Lock()
    async with session.lock:
        try:
            return await _aio.wait_for(
                _quic_session_attempt(session, request, cfg, ips, make_protocol, run_query, quic_connect),
                timeout=total_timeout,
            )
        except _aio.TimeoutError:
            session.record_failure()
            await _quic_session_reset(session)
            raise OSError(f"{session.protocol_name} query timed out")


def _quic_pooled_query(protocol_name, upstream, request, total_timeout, cfg, ips, make_protocol, run_query):
    import asyncio
    import concurrent.futures

    key = _quic_session_key(protocol_name, upstream)
    with quic_sessions_lock:
        session = quic_sessions.get(key)
        if session is None:
            session = _QuicSession(protocol_name, upstream)
            quic_sessions[key] = session

    if session.is_penalized():
        raise OSError(f"{protocol_name} upstream temporarily disabled after repeated failures")

    loop = _get_quic_loop()
    future = asyncio.run_coroutine_threadsafe(
        _quic_session_query(session, request, total_timeout, cfg, ips, make_protocol, run_query),
        loop,
    )
    try:
        return future.result(total_timeout + 2.0)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise OSError(f"{protocol_name} query timed out")


def quic_pool_metrics():
    totals = {
        "quic_handshake_count": 0,
        "quic_reuse_count": 0,
        "quic_reconnect_count": 0,
        "quic_error_count": 0,
        "quic_pool_size": 0,
        "quic_penalized_count": 0,
    }
    with quic_sessions_lock:
        sessions = list(quic_sessions.values())
    totals["quic_pool_size"] = len(sessions)
    for session in sessions:
        for key, value in session.metrics().items():
            totals[key] += value
        if session.is_penalized():
            totals["quic_penalized_count"] += 1
    return totals


def query_doh_http3_upstream(upstream, request, timeout=4.0):
    try:
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
    except ImportError:
        raise OSError("DoH HTTP/3 requires aioquic (pip install aioquic)")

    host, port, path = doh_request_parts(upstream["resolver"])
    server_name = host if not looks_like_ip(host) else None
    total_timeout = get_timeout_setting("doh3_total_timeout", timeout)

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
            await self._done[stream_id].wait()
            state = self._responses.pop(stream_id, {})
            self._done.pop(stream_id, None)
            status = state.get("headers", {}).get(":status", "")
            if status != "200":
                raise OSError(f"DoH HTTP/3 response failed: {status or 'missing status'}")
            body = state.get("body", b"")
            if len(body) < 12:
                raise OSError("short DoH HTTP/3 DNS response")
            return body

    async def _run_query(proto, dns_request):
        return await proto.doh3_query(dns_request)

    cfg = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True)
    if server_name:
        cfg.server_name = server_name
    ips = resolve_upstream_host(host)

    try:
        return _quic_pooled_query("doh3", upstream, request, total_timeout, cfg, ips, _DoH3Protocol, _run_query)
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


def query_dot_stamp_upstream(upstream, request, timeout=4.0):
    parsed = parse_dot_stamp(upstream["resolver"])
    converted = dict(upstream)
    converted.update({
        "resolver": f"tls://{parsed['address']}",
        "address": parsed["address"],
        "port": parsed["port"],
        "resolver_type": "dot",
        "transport": "tls",
    })
    return query_dot_upstream(converted, request, timeout=timeout)


def query_doq_stamp_upstream(upstream, request, timeout=4.0):
    parsed = parse_doq_stamp(upstream["resolver"])
    converted = dict(upstream)
    converted.update({
        "resolver": f"quic://{parsed['address']}",
        "address": parsed["address"],
        "port": parsed["port"],
        "resolver_type": "doq",
        "transport": "quic",
    })
    return query_doq_upstream(converted, request, timeout=timeout)


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
        connect_timeout = get_timeout_setting("tcp_connect_timeout", timeout)
        tls_timeout = get_timeout_setting("tls_handshake_timeout", timeout)
        query_timeout = get_timeout_setting("dns_query_timeout", timeout)
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
                raw = socket.create_connection((ip, port), timeout=connect_timeout)
                raw.settimeout(tls_timeout)
                context = ssl.create_default_context()
                conn = context.wrap_socket(raw, server_hostname=tls_name)
                conn.settimeout(query_timeout)
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
        self.conn.settimeout(get_timeout_setting("dns_query_timeout", timeout))
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
            pool = [DotConnection(upstream) for _ in range(DOT_POOL_SIZE)]
            dot_pools[key] = pool
            dot_pool_counters[key] = 0
        idx = dot_pool_counters[key] % len(pool)
        dot_pool_counters[key] = idx + 1
        conn = pool[idx]
    return conn.query(request, timeout=timeout)


def dot_pool_metrics():
    totals = {
        "tls_handshake_count": 0,
        "dot_reuse_count": 0,
        "dot_reconnect_count": 0,
        "dot_error_count": 0,
        "dot_pool_size": 0,
    }
    with dot_pools_lock:
        totals["dot_pool_size"] = sum(len(pool) for pool in dot_pools.values())
        connections = [conn for pool in dot_pools.values() for conn in pool]
    for conn in connections:
        with conn.lock:
            metrics = conn.metrics()
        for key, value in metrics.items():
            totals[key] += value
    return totals


class DohConnection:
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
        host, port, path = doh_request_parts(self.upstream["resolver"])
        ips = resolve_upstream_host(host)
        if not ips:
            raise OSError("DoH resolver host did not resolve")
        return ips[:4]

    def connect(self, timeout=4.0):
        connect_timeout = get_timeout_setting("tcp_connect_timeout", timeout)
        tls_timeout = get_timeout_setting("tls_handshake_timeout", timeout)
        query_timeout = get_timeout_setting("dns_query_timeout", timeout)
        host, port, path = doh_request_parts(self.upstream["resolver"])
        ips = self._candidate_ips()
        last_error = None
        start_index = self._ip_index % len(ips)
        ordered_ips = ips[start_index:] + ips[:start_index]
        for ip in ordered_ips:
            raw = None
            try:
                raw = socket.create_connection((ip, port), timeout=connect_timeout)
                raw.settimeout(tls_timeout)
                context = ssl.create_default_context()
                conn = context.wrap_socket(raw, server_hostname=host)
                conn.settimeout(query_timeout)
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
        raise OSError(str(last_error) if last_error else "DoH connect failed")

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
        host, port, path = doh_request_parts(self.upstream["resolver"])
        authority = doh_authority(host, port)
        query_timeout = get_timeout_setting("dns_query_timeout", timeout)
        self.conn.settimeout(query_timeout)
        http_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: PyGuardDNS/0.1\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(request)}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii") + request
        self.conn.sendall(http_request)
        response = read_http_response(self.conn)
        if len(response) < 12:
            raise OSError("short DoH DNS response")
        self.last_used = time.time()
        return response

    def metrics(self):
        return {
            "tls_handshake_count": self.handshake_count,
            "doh_reuse_count": self.reuse_count,
            "doh_reconnect_count": self.reconnect_count,
            "doh_error_count": self.error_count,
        }


def _doh_pool_key(upstream):
    resolver = upstream.get("resolver") or ""
    return f"{upstream.get('id', '')}:{resolver}:{upstream['address']}:{int(upstream.get('port', 443))}"


def query_doh_upstream_pooled(upstream, request, timeout=4.0):
    key = _doh_pool_key(upstream)
    with doh_pools_lock:
        pool = doh_pools.get(key)
        if pool is None:
            pool = DohConnection(upstream)
            doh_pools[key] = pool
    return pool.query(request, timeout=timeout)


def doh_pool_metrics():
    totals = {
        "tls_handshake_count": 0,
        "doh_reuse_count": 0,
        "doh_reconnect_count": 0,
        "doh_error_count": 0,
        "doh_pool_size": 0,
    }
    with doh_pools_lock:
        totals["doh_pool_size"] = len(doh_pools)
        pools = list(doh_pools.values())
    for pool in pools:
        with pool.lock:
            metrics = pool.metrics()
        for key, value in metrics.items():
            totals[key] += value
    return totals


def query_dot_upstream_once(upstream, request, timeout=4.0):
    connect_timeout = get_timeout_setting("tcp_connect_timeout", timeout)
    tls_timeout = get_timeout_setting("tls_handshake_timeout", timeout)
    query_timeout = get_timeout_setting("dns_query_timeout", timeout)
    host = upstream["address"]
    port = int(upstream["port"])
    ips = resolve_via_configured_dns(host) if not looks_like_ip(host) else [host]
    tls_name = upstream.get("tls_name") or upstream.get("hostname") or dot_tls_server_name(host)
    last_error = None
    for ip in ips[:4]:
        try:
            raw = socket.create_connection((ip, port), timeout=connect_timeout)
            with raw:
                raw.settimeout(tls_timeout)
                context = ssl.create_default_context()
                conn = context.wrap_socket(raw, server_hostname=tls_name)
                conn.settimeout(query_timeout)
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
    try:
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived
    except ImportError:
        raise OSError("DoQ requires aioquic (pip install aioquic)")

    host = upstream["address"]
    port = int(upstream["port"])
    server_name = host if not looks_like_ip(host) else None
    total_timeout = get_timeout_setting("doq_total_timeout", timeout)

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
            await self._stream_done[sid].wait()
            data = self._stream_data.pop(sid, b"")
            self._stream_done.pop(sid, None)
            if len(data) < 2:
                raise OSError("DoQ: short response")
            length = struct.unpack("!H", data[:2])[0]
            response = data[2:2 + length]
            if len(response) < 12:
                raise OSError("DoQ: invalid DNS response")
            return response

    async def _run_query(proto, dns_request):
        return await proto.doq_query(dns_request)

    cfg = QuicConfiguration(alpn_protocols=["doq"], is_client=True)
    if server_name:
        cfg.server_name = server_name
    ips = resolve_via_configured_dns(host) if not looks_like_ip(host) else [host]

    try:
        return _quic_pooled_query("doq", upstream, request, total_timeout, cfg, ips, _DoQProtocol, _run_query)
    except OSError as exc:
        fallback = dict(upstream)
        fallback["resolver_type"] = "dot"
        try:
            return query_dot_upstream(fallback, request, timeout=timeout)
        except OSError:
            raise exc


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


def parse_dnscrypt_relay_stamp(stamp):
    if not stamp.startswith("sdns://"):
        raise ValueError("invalid DNSCrypt relay stamp")
    raw = _stamp_b64decode(stamp[7:])
    if len(raw) < 3 or raw[0] != 0x81:
        raise ValueError("not a DNSCrypt relay stamp")
    address, offset = _read_stamp_lp(raw, 1)
    server = address.decode("utf-8", errors="ignore").strip()
    if not server:
        raise ValueError("DNSCrypt relay stamp is missing server address")
    host, port = split_host_port(server, 443)
    return {"address": host, "port": port}


def parse_dot_stamp(stamp):
    if not stamp.startswith("sdns://"):
        raise ValueError("invalid DoT stamp")
    raw = _stamp_b64decode(stamp[7:])
    if len(raw) < 3 or raw[0] != 0x03:
        raise ValueError("not a DoT stamp")
    offset = 1 + 8
    address, offset = _read_stamp_lp(raw, offset)
    port_bytes, offset = _read_stamp_lp(raw, offset)
    provider_name, offset = _read_stamp_lp(raw, offset)
    addr = address.decode("utf-8", errors="ignore").strip()
    port_str = port_bytes.decode("utf-8", errors="ignore").strip()
    provider = provider_name.decode("utf-8", errors="ignore").strip()
    port = int(port_str) if port_str else 853
    host, _ = split_host_port(addr, port)
    return {"address": host, "port": port, "provider_name": provider}

def parse_doq_stamp(stamp):
    if not stamp.startswith("sdns://"):
        raise ValueError("invalid DoQ stamp")
    raw = _stamp_b64decode(stamp[7:])
    if len(raw) < 3 or raw[0] != 0x04:
        raise ValueError("not a DoQ stamp")
    offset = 1 + 8
    address, offset = _read_stamp_lp(raw, offset)
    port_bytes, offset = _read_stamp_lp(raw, offset)
    provider_name, offset = _read_stamp_lp(raw, offset)
    addr = address.decode("utf-8", errors="ignore").strip()
    port_str = port_bytes.decode("utf-8", errors="ignore").strip()
    provider = provider_name.decode("utf-8", errors="ignore").strip()
    port = int(port_str) if port_str else 853
    host, _ = split_host_port(addr, port)
    return {"address": host, "port": port, "provider_name": provider}


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
                if pos + length > len(rdata):
                    raise ValueError("truncated TXT answer")
                chunks.append(rdata[pos : pos + length])
                pos += length
            answers.append(b"".join(chunks))
    except Exception:
        pass
    return answers


ANON_DNSCRYPT_MAGIC = b"\xff" * 8 + b"\x00\x00"


def anonymized_dnscrypt_target_header(stamp_info):
    try:
        target_ip = ipaddress.ip_address(stamp_info["address"].strip("[]"))
    except ValueError:
        raise OSError("Anonymized DNSCrypt relay forwarding requires a resolver stamp with an IP address")
    if target_ip.version == 4:
        target_bytes = b"\x00" * 10 + b"\xff\xff" + target_ip.packed
    else:
        target_bytes = target_ip.packed
    return ANON_DNSCRYPT_MAGIC + target_bytes + struct.pack("!H", int(stamp_info["port"]))


def wrap_anonymized_dnscrypt_packet(stamp_info, packet):
    if packet.startswith(ANON_DNSCRYPT_MAGIC):
        raise OSError("refusing nested Anonymized DNSCrypt packet")
    return anonymized_dnscrypt_target_header(stamp_info) + packet


def send_anonymized_dnscrypt_packet(stamp_info, relay_info, packet, timeout=4.0, transport="udp"):
    connect_timeout = get_timeout_setting("tcp_connect_timeout", timeout)
    query_timeout = get_timeout_setting("dns_query_timeout", timeout)
    relay_packet = wrap_anonymized_dnscrypt_packet(stamp_info, packet)
    relay_target = {"address": relay_info["address"], "port": relay_info["port"]}
    if transport == "tcp":
        with socket.create_connection((relay_target["address"], int(relay_target["port"])), timeout=connect_timeout) as s:
            s.settimeout(query_timeout)
            s.sendall(struct.pack("!H", len(relay_packet)) + relay_packet)
            return _read_dnscrypt_tcp_response(s)
    with socket.socket(socket_family_for_host(relay_target["address"]), socket.SOCK_DGRAM) as s:
        s.settimeout(query_timeout)
        s.sendto(relay_packet, (relay_target["address"], int(relay_target["port"])))
        response, _ = s.recvfrom(4096)
        return response


def _dnscrypt_certificate_response_candidates(stamp_info, request, timeout, relay_info=None):
    base = {"address": stamp_info["address"], "port": stamp_info["port"]}
    udp_response = None
    last_error = None
    try:
        if relay_info:
            udp_response = send_anonymized_dnscrypt_packet(stamp_info, relay_info, request, timeout=timeout, transport="udp")
        else:
            udp_response = query_plain_upstream({**base, "transport": "udp"}, request, timeout=timeout)
    except OSError:
        last_error = sys.exc_info()[1]
        udp_response = None
    if udp_response is not None and not dns_response_truncated(udp_response):
        yield udp_response
    if udp_response is not None and not dns_response_truncated(udp_response) and extract_txt_answers(udp_response):
        return
    try:
        if relay_info:
            yield send_anonymized_dnscrypt_packet(stamp_info, relay_info, request, timeout=timeout, transport="tcp")
        else:
            yield query_plain_upstream({**base, "transport": "tcp"}, request, timeout=timeout)
        return
    except OSError:
        last_error = sys.exc_info()[1]
    if udp_response is None and last_error is not None:
        raise OSError(f"DNSCrypt certificate transport failed: {last_error}") from last_error


def fetch_dnscrypt_certificate(stamp_info, timeout=4.0, relay_info=None):
    relay_key = f"|relay={relay_info['address']}:{relay_info['port']}" if relay_info else ""
    cache_key_value = f"{stamp_info['address']}:{stamp_info['port']}|{stamp_info['provider_name']}{relay_key}"
    cached = dnscrypt_cert_cache.get(cache_key_value)
    if cached and cached["expires"] > time.time():
        return cached["cert"]
    _, request = build_query(stamp_info["provider_name"], QTYPE_CODE["TXT"])
    now = int(time.time())
    best = None
    for response in _dnscrypt_certificate_response_candidates(stamp_info, request, timeout, relay_info=relay_info):
        for txt in extract_txt_answers(response):
            try:
                cert = parse_dnscrypt_certificate(txt, stamp_info["provider_public_key"])
                if cert["not_before"] <= now <= cert["not_after"]:
                    if best is None or cert["serial"] > best["serial"]:
                        best = cert
            except Exception:
                continue
        if best:
            break
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
    if es_version not in (1, 2):
        raise ValueError(f"unsupported DNSCrypt encryption system: {es_version}")
    signature = cert_data[8:72]
    signed = cert_data[72:]
    VerifyKey(provider_public_key).verify(signed, signature)
    resolver_public_key = cert_data[72:104]
    client_magic = cert_data[104:112]
    serial, not_before, not_after = struct.unpack("!III", cert_data[112:124])
    return {
        "es_version": es_version,
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


def _rotl32(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _chacha20_quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def hchacha20(key, nonce16):
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("HChaCha20 requires a 32-byte key and 16-byte nonce")
    constants = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    state = list(constants)
    state.extend(struct.unpack("<8I", key))
    state.extend(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _chacha20_quarter_round(state, 0, 4, 8, 12)
        _chacha20_quarter_round(state, 1, 5, 9, 13)
        _chacha20_quarter_round(state, 2, 6, 10, 14)
        _chacha20_quarter_round(state, 3, 7, 11, 15)
        _chacha20_quarter_round(state, 0, 5, 10, 15)
        _chacha20_quarter_round(state, 1, 6, 11, 12)
        _chacha20_quarter_round(state, 2, 7, 8, 13)
        _chacha20_quarter_round(state, 3, 4, 9, 14)
    return struct.pack("<8I", state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15])


def _chacha20_djb_block(key, counter, nonce8):
    constants = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    initial = list(constants)
    initial.extend(struct.unpack("<8I", key))
    initial.extend((counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF))
    initial.extend(struct.unpack("<2I", nonce8))
    state = initial[:]
    for _ in range(10):
        _chacha20_quarter_round(state, 0, 4, 8, 12)
        _chacha20_quarter_round(state, 1, 5, 9, 13)
        _chacha20_quarter_round(state, 2, 6, 10, 14)
        _chacha20_quarter_round(state, 3, 7, 11, 15)
        _chacha20_quarter_round(state, 0, 5, 10, 15)
        _chacha20_quarter_round(state, 1, 6, 11, 12)
        _chacha20_quarter_round(state, 2, 7, 8, 13)
        _chacha20_quarter_round(state, 3, 4, 9, 14)
    return struct.pack("<16I", *((state[i] + initial[i]) & 0xFFFFFFFF for i in range(16)))


def _xchacha20_djb_xor(key, nonce24, data, initial_counter=0, initial_skip=32):
    if len(key) != 32 or len(nonce24) != 24:
        raise ValueError("XChaCha20 requires a 32-byte key and 24-byte nonce")
    subkey = hchacha20(key, nonce24[:16])
    nonce8 = nonce24[16:]
    out = bytearray()
    counter = initial_counter
    skip = initial_skip
    offset = 0
    while offset < len(data):
        block = _chacha20_djb_block(subkey, counter, nonce8)
        if skip:
            block = block[skip:]
            skip = 0
        chunk = data[offset : offset + len(block)]
        out.extend(bytes(a ^ b for a, b in zip(chunk, block)))
        offset += len(chunk)
        counter += 1
    return bytes(out)


def dnscrypt_xchacha20poly1305_encrypt(key, nonce24, data):
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    subkey = hchacha20(key, nonce24[:16])
    poly_key = _chacha20_djb_block(subkey, 0, nonce24[16:])[:32]
    ciphertext = _xchacha20_djb_xor(key, nonce24, data)
    return Poly1305.generate_tag(poly_key, ciphertext) + ciphertext


def dnscrypt_xchacha20poly1305_decrypt(key, nonce24, data):
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    if len(data) < 16:
        raise ValueError("short XChaCha20-Poly1305 ciphertext")
    tag = data[:16]
    ciphertext = data[16:]
    subkey = hchacha20(key, nonce24[:16])
    poly_key = _chacha20_djb_block(subkey, 0, nonce24[16:])[:32]
    expected = Poly1305.generate_tag(poly_key, ciphertext)
    if not hmac.compare_digest(tag, expected):
        raise ValueError("invalid XChaCha20-Poly1305 tag")
    return _xchacha20_djb_xor(key, nonce24, ciphertext)


def dnscrypt_encrypt_query(cert, client_key, request):
    from nacl.public import Box, PublicKey

    client_nonce = secrets.token_bytes(12)
    nonce = client_nonce + (b"\x00" * 12)
    padded = pad_dnscrypt_query(request)
    if cert["es_version"] == 1:
        box = Box(client_key, PublicKey(cert["resolver_public_key"]))
        encrypted = box.encrypt(padded, nonce).ciphertext
        decrypt_response = lambda ciphertext, response_nonce: box.decrypt(ciphertext, response_nonce)
    elif cert["es_version"] == 2:
        try:
            from nacl.bindings import crypto_scalarmult
        except ImportError:
            raise OSError("DNSCrypt XChaCha20 support requires PyNaCl")
        shared_key = hchacha20(crypto_scalarmult(bytes(client_key), cert["resolver_public_key"]), b"\x00" * 16)
        encrypted = dnscrypt_xchacha20poly1305_encrypt(shared_key, nonce, padded)
        decrypt_response = lambda ciphertext, response_nonce: dnscrypt_xchacha20poly1305_decrypt(shared_key, response_nonce, ciphertext)
    else:
        raise OSError(f"unsupported DNSCrypt encryption system: {cert['es_version']}")
    packet = cert["client_magic"] + bytes(client_key.public_key) + client_nonce + encrypted
    return packet, client_nonce, decrypt_response


def _read_dnscrypt_tcp_response(conn):
    header = conn.recv(2)
    if len(header) != 2:
        raise OSError("short DNSCrypt TCP length header")
    length = struct.unpack("!H", header)[0]
    chunks = []
    remaining = length
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise OSError("short DNSCrypt TCP response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_dnscrypt_packet(stamp_info, packet, timeout=4.0, transport="udp", relay_info=None):
    if relay_info:
        return send_anonymized_dnscrypt_packet(stamp_info, relay_info, packet, timeout=timeout, transport=transport)
    connect_timeout = get_timeout_setting("tcp_connect_timeout", timeout)
    query_timeout = get_timeout_setting("dns_query_timeout", timeout)
    address = stamp_info["address"]
    port = int(stamp_info["port"])
    if transport == "tcp":
        with socket.create_connection((address, port), timeout=connect_timeout) as s:
            s.settimeout(query_timeout)
            s.sendall(struct.pack("!H", len(packet)) + packet)
            return _read_dnscrypt_tcp_response(s)
    with socket.socket(socket_family_for_host(address), socket.SOCK_DGRAM) as s:
        s.settimeout(query_timeout)
        s.sendto(packet, (address, port))
        response, _ = s.recvfrom(4096)
        return response


def decrypt_dnscrypt_response(response, client_nonce, decrypt_response):
    if len(response) < 32:
        raise OSError("short DNSCrypt response")
    response_nonce = response[8:32]
    if not response_nonce.startswith(client_nonce):
        raise OSError("DNSCrypt response nonce mismatch")
    decrypted = decrypt_response(response[32:], response_nonce)
    decrypted = unpad_dnscrypt_response(decrypted)
    if len(decrypted) < 12:
        raise OSError("invalid DNSCrypt DNS response")
    return decrypted


def query_dnscrypt_upstream(upstream, request, timeout=4.0):
    try:
        from nacl.public import PrivateKey
    except ImportError:
        raise OSError("DNSCrypt requires PyNaCl (pip install pynacl)")
    stamp_info = parse_dnscrypt_stamp(upstream["resolver"])
    relay_info = None
    relay_stamp = (upstream.get("dnscrypt_relay") or "").strip()
    if relay_stamp:
        relay_info = parse_dnscrypt_relay_stamp(relay_stamp)
    elif not upstream.get("_skip_auto_relay"):
        relay_upstream = active_dnscrypt_relay()
        if relay_upstream and relay_upstream.get("resolver"):
            relay_info = parse_dnscrypt_relay_stamp(relay_upstream["resolver"])
    cert = fetch_dnscrypt_certificate(stamp_info, timeout=timeout, relay_info=relay_info)
    client_key = PrivateKey.generate()
    packet, client_nonce, decrypt_response = dnscrypt_encrypt_query(cert, client_key, request)
    try:
        response = send_dnscrypt_packet(stamp_info, packet, timeout=timeout, transport="udp", relay_info=relay_info)
        decrypted = decrypt_dnscrypt_response(response, client_nonce, decrypt_response)
        if not dns_response_truncated(decrypted):
            return decrypted
    except OSError:
        pass
    response = send_dnscrypt_packet(stamp_info, packet, timeout=timeout, transport="tcp", relay_info=relay_info)
    return decrypt_dnscrypt_response(response, client_nonce, decrypt_response)


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
        with urllib.request.urlopen(url, timeout=8) as response:
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


def socket_family_for_host(host):
    try:
        return socket.AF_INET6 if ipaddress.ip_address(host.strip("[]")).version == 6 else socket.AF_INET
    except ValueError:
        return socket.AF_INET


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
        0x81: "dnscrypt_relay",
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
            "dnscrypt_relay": "DNS stamp: DNSCrypt relay",
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
        elif stamp_type == "dot_stamp":
            try:
                parsed_stamp = parse_dot_stamp(raw)
                result.update({
                    "resolver": f"tls://{parsed_stamp['address']}",
                    "address": parsed_stamp["address"],
                    "port": parsed_stamp["port"],
                    "type": "dot",
                    "transport": "tls",
                    "supported": True,
                    "label": labels[stamp_type],
                })
            except Exception as exc:
                result.update({"address": raw, "port": 0, "type": stamp_type, "transport": "tls", "supported": False, "label": f"{labels[stamp_type]} ({exc})"})
        elif stamp_type == "doq_stamp":
            try:
                parsed_stamp = parse_doq_stamp(raw)
                result.update({
                    "resolver": f"quic://{parsed_stamp['address']}",
                    "address": parsed_stamp["address"],
                    "port": parsed_stamp["port"],
                    "type": "doq",
                    "transport": "quic",
                    "supported": True,
                    "label": labels[stamp_type],
                })
            except Exception as exc:
                result.update({"address": raw, "port": 0, "type": stamp_type, "transport": "quic", "supported": False, "label": f"{labels[stamp_type]} ({exc})"})
        elif stamp_type == "dnscrypt_relay":
            try:
                parsed_stamp = parse_dnscrypt_relay_stamp(raw)
                result.update({
                    "address": parsed_stamp["address"],
                    "port": parsed_stamp["port"],
                    "type": stamp_type,
                    "transport": "dnscrypt-relay",
                    "supported": False,
                    "label": labels[stamp_type] + " (use as Relay on a DNSCrypt upstream)",
                })
            except Exception as exc:
                result.update({"address": raw, "port": 0, "type": stamp_type, "transport": "dnscrypt-relay", "supported": False, "label": f"{labels[stamp_type]} ({exc})"})
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
                supported = resolver_type in ("plain_udp", "plain_tcp", "dot", "doq")
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
        label = "Encrypted DNS-over-QUIC, inferred from port 853"
        resolver_type = "doq"
        transport = "quic"
        supported = True
    elif has_port:
        label = "Regular DNS over UDP, with port"
    elif not is_ip:
        label = "Regular DNS over UDP, hostname"
        resolver_type = "plain_udp_host"
    result.update({"address": host, "port": port, "type": resolver_type, "transport": transport, "supported": supported, "label": label})
    return result


_update_check_cache = {
    "result": None,
    "last_check": 0
}


GITHUB_API_URL = "https://api.github.com/repos/nextscript/PyGuardDNS/commits"
GITHUB_ZIP_URL = "https://github.com/nextscript/PyGuardDNS/archive/refs/heads/main.zip"
COMMIT_HASH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".last_commit")


def _get_local_commit_hash():
    try:
        if os.path.exists(COMMIT_HASH_FILE):
            with open(COMMIT_HASH_FILE, "r") as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def _save_local_commit_hash(commit_hash):
    try:
        with open(COMMIT_HASH_FILE, "w") as f:
            f.write(commit_hash)
    except Exception:
        pass


def check_for_updates(force=False):
    global _update_check_cache
    
    if not force and _update_check_cache["result"] is not None:
        time_since_check = time.time() - _update_check_cache["last_check"]
        if time_since_check < 21600:
            return _update_check_cache["result"]
    
    try:
        req = urllib.request.Request(GITHUB_API_URL, headers={"User-Agent": "PyGuardDNS"})
        with urllib.request.urlopen(req, timeout=30) as response:
            commits = json.loads(response.read().decode())
        
        if not commits:
            check_result = {"ok": True, "available": False, "count": 0, "commits": []}
            _update_check_cache["result"] = check_result
            _update_check_cache["last_check"] = time.time()
            return check_result
        
        latest_commit = commits[0]
        latest_hash = latest_commit["sha"]
        latest_message = latest_commit["commit"]["message"].split("\n")[0]
        
        local_hash = _get_local_commit_hash()
        
        if local_hash and local_hash != latest_hash:
            new_commits = []
            for c in commits:
                if c["sha"] == local_hash:
                    break
                new_commits.append(f"{c['sha'][:7]} {c['commit']['message'].split(chr(10))[0]}")
            
            check_result = {
                "ok": True,
                "available": True,
                "count": len(new_commits),
                "commits": new_commits
            }
        elif not local_hash:
            _save_local_commit_hash(latest_hash)
            check_result = {"ok": True, "available": False, "count": 0, "commits": []}
        else:
            check_result = {"ok": True, "available": False, "count": 0, "commits": []}
        
        _update_check_cache["result"] = check_result
        _update_check_cache["last_check"] = time.time()
        return check_result
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _update_checker_thread():
    while True:
        try:
            check_for_updates(force=True)
        except Exception:
            pass
        time.sleep(21600)


def start_update_checker():
    thread = threading.Thread(target=_update_checker_thread, daemon=True)
    thread.start()


def perform_update():
    import zipfile
    import shutil
    import tempfile
    import stat
    
    project_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = None
    
    try:
        req = urllib.request.Request(GITHUB_API_URL, headers={"User-Agent": "PyGuardDNS"})
        with urllib.request.urlopen(req, timeout=30) as response:
            commits = json.loads(response.read().decode())
        
        if not commits:
            return {"ok": False, "error": "Keine Commits gefunden"}
        
        latest_hash = commits[0]["sha"]
        
        req = urllib.request.Request(GITHUB_ZIP_URL, headers={"User-Agent": "PyGuardDNS"})
        with urllib.request.urlopen(req, timeout=120) as response:
            temp_dir = tempfile.mkdtemp()
            zip_path = os.path.join(temp_dir, "update.zip")
            with open(zip_path, "wb") as f:
                f.write(response.read())
            
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)
            
            extracted_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
            if not extracted_dirs:
                return {"ok": False, "error": "ZIP entpackt aber kein Verzeichnis gefunden"}
            
            source_dir = os.path.join(temp_dir, extracted_dirs[0])
            
            skip_items = {".git", ".last_commit", "db", "logs", "__pycache__", ".env"}
            
            for item in os.listdir(source_dir):
                if item in skip_items:
                    continue
                
                src_path = os.path.join(source_dir, item)
                dst_path = os.path.join(project_dir, item)
                
                if os.path.isdir(src_path):
                    if os.path.exists(dst_path):
                        shutil.rmtree(dst_path, ignore_errors=True)
                    shutil.copytree(src_path, dst_path, ignore=shutil.ignore_patterns(*skip_items))
                else:
                    shutil.copy2(src_path, dst_path)
                    if item.endswith(".sh"):
                        try:
                            os.chmod(dst_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                        except Exception:
                            pass
            
            for root, dirs, files in os.walk(project_dir):
                skip_dirs = {".git", "db", "logs", "__pycache__"}
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                
                for file in files:
                    if file.endswith(".sh"):
                        file_path = os.path.join(root, file)
                        try:
                            os.chmod(file_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                        except Exception:
                            pass
            
            _save_local_commit_hash(latest_hash)
            _update_check_cache["result"] = {"ok": True, "available": False, "count": 0, "commits": []}
            _update_check_cache["last_check"] = time.time()
            
            return {"ok": True, "output": f"Update erfolgreich installiert ({latest_hash[:7]})"}
    
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass


def restart_server():
    def delayed_restart():
        time.sleep(1)
        python = sys.executable
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        
        if sys.platform == "win32":
            restart_script = os.path.join(tempfile.gettempdir(), "pyguarddns_restart.bat")
            with open(restart_script, "w") as f:
                f.write("@echo off\n")
                f.write("timeout /t 2 /nobreak >nul\n")
                f.write(f'cd /d "{script_dir}"\n')
                f.write(f'cls\n')
                f.write(f'title PyGuardDNS\n')
                f.write(f'"{python}" "{script_path}"\n')
                f.write('del "%~f0"\n')
            os.execl("cmd.exe", "cmd.exe", "/c", restart_script)
        else:
            restart_script = os.path.join(tempfile.gettempdir(), "pyguarddns_restart.sh")
            with open(restart_script, "w") as f:
                f.write("#!/bin/bash\n")
                f.write("sleep 2\n")
                f.write(f'cd "{script_dir}"\n')
                f.write("clear\n")
                f.write("stty sane\n")
                f.write("stty echo\n")
                f.write(f'"{python}" "{script_path}"\n')
                f.write('rm -f "$0"\n')
            os.chmod(restart_script, 0o755)
            os.execl("/bin/bash", "/bin/bash", restart_script)
    
    threading.Thread(target=delayed_restart, daemon=True).start()
    return {"ok": True, "message": "DNS Server Update..."}


def decide(domain, qtype_name, client_ip, client_info=None):
    normalized = normalize_domain(domain)
    if not is_lan_allowed(client_ip):
        return {"status": "refused", "action": "refuse", "rule": "access control", "reason": "client not allowed"}

    profile_id = None
    if client_info is None:
        client_info = lookup_client_snapshot(client_ip)
    if client_info:
        profile_id = client_info.get("profile_id")

    filtering_on = get_setting("filtering_enabled", "1") == "1" and client_filtering_enabled(client_ip, client_info=client_info)

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


def _shard_for(key):
    return hash(key) % CACHE_SHARDS


def extract_negative_ttl(response):
    try:
        import dns.message
        msg = dns.message.from_wire(response)
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                soa_ttl = rrset.ttl
                if rrset.items:
                    soa = rrset.items[0]
                    soa_minimum = soa.minimum
                    return min(soa_ttl, soa_minimum) if soa_minimum > 0 else soa_ttl
                return soa_ttl
    except Exception:
        pass
    return None


def get_negative_cached(domain, qtype_name):
    if get_setting("negative_cache_enabled", "1") != "1":
        return None
    key = cache_key(domain, qtype_name)
    shard = _shard_for(key)
    negative_cache = negative_cache_shards[shard]
    with negative_cache_locks[shard]:
        item = negative_cache.get(key)
        if not item:
            return None
        if item["expires"] > time.time():
            return item["response"], item["type"]
        negative_cache.pop(key, None)
    return None


def set_negative_cached(domain, qtype_name, response, neg_type="nxdomain"):
    if get_setting("negative_cache_enabled", "1") != "1":
        return
    max_ttl = int(get_setting("negative_cache_max_ttl", "300") or "300")
    min_ttl = int(get_setting("negative_cache_min_ttl", "30") or "30")
    ttl = extract_negative_ttl(response)
    if ttl is None:
        ttl = min_ttl
    ttl = max(min_ttl, min(ttl, max_ttl))
    key = cache_key(domain, qtype_name)
    shard = _shard_for(key)
    negative_cache = negative_cache_shards[shard]
    with negative_cache_locks[shard]:
        if len(negative_cache) >= NEGATIVE_CACHE_SHARD_MAX:
            oldest_key = next(iter(negative_cache))
            negative_cache.pop(oldest_key, None)
        negative_cache[key] = {"expires": time.time() + ttl, "response": response, "type": neg_type}


def is_negative_response(response):
    try:
        flags = struct.unpack("!H", response[2:4])[0]
        rcode = flags & 0x000F
        ancount = struct.unpack("!H", response[6:8])[0]
        if rcode == 3:
            return "nxdomain"
        if rcode == 0 and ancount == 0:
            return "nodata"
    except Exception:
        pass
    return None


def _maybe_prefetch(domain, qtype_name, key, item):
    if get_setting("prefetch_enabled", "1") != "1":
        return
    min_hits = int(get_setting("prefetch_min_hits", "3") or "3")
    ttl_pct = int(get_setting("prefetch_ttl_percentage", "20") or "20")
    inserted_at = item.get("inserted_at", item.get("expires", 0) - 300)
    ttl_total = item["expires"] - inserted_at
    if ttl_total <= 0:
        return
    ttl_remaining = item["expires"] - time.time()
    if ttl_remaining > ttl_total * (ttl_pct / 100.0):
        return
    with prefetch_hits_lock:
        hits = prefetch_hits.get(key, 0) + 1
        prefetch_hits[key] = hits
    if hits < min_hits:
        return
    with prefetch_in_progress_lock:
        if key in prefetch_in_progress:
            return
        prefetch_in_progress.add(key)
    threading.Thread(target=_prefetch_refresh, args=(domain, qtype_name, key), daemon=True).start()


def _prefetch_refresh(domain, qtype_name, key):
    global cache_bytes_used
    try:
        qtype_code = QTYPE_CODE.get(qtype_name)
        if not qtype_code:
            return
        _, request = build_query(domain, qtype_code)
        response, _ = forward_query(request)
        set_cached(domain, qtype_name, response)
    except Exception:
        pass
    finally:
        with prefetch_in_progress_lock:
            prefetch_in_progress.discard(key)


def get_cached(domain, qtype_name):
    if get_setting("cache_enabled", "1") != "1":
        return None
    key = cache_key(domain, qtype_name)
    shard = _shard_for(key)
    dns_cache = dns_cache_shards[shard]
    with cache_locks[shard]:
        item = dns_cache.get(key)
        if not item:
            return None
        if item["expires"] > time.time():
            _maybe_prefetch(domain, qtype_name, key, item)
            return item["response"]
        stale_enabled = get_setting("serve_stale_enabled", "0") == "1"
        if stale_enabled:
            max_stale = int(get_setting("serve_stale_max_age", "86400") or "86400")
            age = time.time() - item["expires"]
            if age <= max_stale and not item.get("stale_refresh"):
                item["stale_refresh"] = True
                threading.Thread(target=_refresh_stale_cache_entry, args=(domain, qtype_name, key), daemon=True).start()
                return item["response"]
            if age > max_stale:
                evicted = dns_cache.pop(key, None)
                if evicted:
                    cache_bytes_used[shard] -= len(evicted.get("response", b""))
                return None
        if get_setting("cache_optimistic", "0") == "1" and not item.get("stale_refresh"):
            item["stale_refresh"] = True
            threading.Thread(target=_refresh_stale_cache_entry, args=(domain, qtype_name, key), daemon=True).start()
            return item["response"]
        evicted = dns_cache.pop(key, None)
        if evicted:
            cache_bytes_used[shard] -= len(evicted.get("response", b""))
    return None


def _refresh_stale_cache_entry(domain, qtype_name, key):
    try:
        qtype_code = QTYPE_CODE.get(qtype_name)
        if not qtype_code:
            return
        _, request = build_query(domain, qtype_code)
        response, _ = forward_query(request)
        set_cached(domain, qtype_name, response)
    except Exception:
        shard = _shard_for(key)
        with cache_locks[shard]:
            item = dns_cache_shards[shard].get(key)
            if item:
                item.pop("stale_refresh", None)


def set_cached(domain, qtype_name, response):
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
    max_bytes_per_shard = max(1, max_bytes // CACHE_SHARDS)
    key = cache_key(domain, qtype_name)
    shard = _shard_for(key)
    dns_cache = dns_cache_shards[shard]
    entry_size = len(response)
    with cache_locks[shard]:
        old = dns_cache.pop(key, None)
        if old:
            cache_bytes_used[shard] -= len(old.get("response", b""))
        while cache_bytes_used[shard] + entry_size > max_bytes_per_shard and dns_cache:
            oldest_key = next(iter(dns_cache))
            evicted = dns_cache.pop(oldest_key, None)
            if evicted:
                cache_bytes_used[shard] -= len(evicted.get("response", b""))
        dns_cache[key] = {"expires": time.time() + ttl, "response": response, "fresh": True, "inserted_at": time.time()}
        cache_bytes_used[shard] += entry_size


def cache_stats():
    now = time.time()
    entries = 0
    expired = 0
    stale = 0
    bytes_used = 0
    soonest_expiry = None
    for shard in range(CACHE_SHARDS):
        with cache_locks[shard]:
            shard_cache = dns_cache_shards[shard]
            entries += len(shard_cache)
            bytes_used += cache_bytes_used[shard]
            for item in shard_cache.values():
                exp = item.get("expires", 0)
                if exp <= now:
                    expired += 1
                    if item.get("stale_refresh"):
                        stale += 1
                if soonest_expiry is None or exp < soonest_expiry:
                    soonest_expiry = exp
    soonest_expiry = soonest_expiry or 0
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
        "stale_entries": stale,
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
        "serve_stale_enabled": get_setting("serve_stale_enabled", "0") == "1",
        "serve_stale_max_age": int(get_setting("serve_stale_max_age", "86400") or "86400"),
    }


def clear_dns_cache():
    for shard in range(CACHE_SHARDS):
        with cache_locks[shard]:
            dns_cache_shards[shard].clear()
            cache_bytes_used[shard] = 0
        with negative_cache_locks[shard]:
            negative_cache_shards[shard].clear()
    with prefetch_hits_lock:
        prefetch_hits.clear()
    return {"ok": True, "entries": 0, "bytes_used": 0}


def is_local_reverse_lookup(normalized, qtype_name):
    return qtype_name == "PTR" and normalized in {
        "1.0.0.127.in-addr.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    }


def is_local_nodata_query(qtype_name):
    return qtype_name in ("HTTPS", "SVCB")


def active_upstreams():
    return um.active_upstreams()


def active_dnscrypt_relay():
    relays = um.active_dnscrypt_relays()
    return relays[0] if relays else None


def normalize_dnscrypt_relay_upstreams():
    um.normalize_dnscrypt_relay()


def plain_upstream_supported(upstream):
    return upstream.get("transport") in ("udp", "tcp") and upstream.get("resolver_type") in ("plain_udp", "plain_udp_host", "plain_tcp", "plain_tcp_host")


def upstream_supported(upstream):
    return plain_upstream_supported(upstream) or upstream.get("resolver_type") in ("doh", "doh_stamp", "doh_http3", "dot", "dot_stamp", "doq", "doq_stamp", "dnscrypt_stamp", "dnscrypt_relay", "dns_stamp_unknown", "plain_dns_stamp")


def probe_upstream(upstream):
    if not upstream_supported(upstream):
        raise OSError(f"{upstream['resolver_type']} forwarding is detected but not implemented yet")
    if upstream.get("resolver_type") == "dnscrypt_relay":
        start = time.perf_counter()
        with socket.create_connection((upstream["address"], int(upstream["port"])), timeout=4.0):
            pass
        return round((time.perf_counter() - start) * 1000, 2)
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
        query_doq_upstream(upstream, request, timeout=4.0)
    elif upstream.get("resolver_type") == "dot_stamp":
        query_dot_stamp_upstream(upstream, request, timeout=4.0)
    elif upstream.get("resolver_type") == "doq_stamp":
        query_doq_stamp_upstream(upstream, request, timeout=4.0)
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
    upstream = um.get(upstream_id)
    if not upstream:
        raise ValueError("upstream not found")
    try:
        # Warm up the connection pool / cached certificate first. Otherwise the
        # measured latency includes the one-time TCP/TLS/QUIC handshake cost,
        # which inflates the result on the first test (subsequent tests reuse
        # the now-pooled connection and look "normal").
        try:
            probe_upstream(upstream)
        except Exception:
            pass
        latency = probe_upstream(upstream)
        um.update(upstream_id, latency_ms=latency, last_error="")
        return {"ok": True, "latency_ms": latency}
    except Exception as exc:
        um.update(upstream_id, latency_ms=None, last_error=str(exc))
        return {"ok": False, "error": str(exc)}


def parse_upstream_form(form):
    parsed = detect_upstream(form.get("resolver", form.get("address", "")))
    dnscrypt_relay = form.get("dnscrypt_relay", "").strip()
    if dnscrypt_relay:
        relay_detected = detect_upstream(dnscrypt_relay)
        if relay_detected.get("type") != "dnscrypt_relay":
            raise ValueError("DNSCrypt Relay must be a relay sdns:// stamp")
    return {
        "name": form.get("name", "").strip(),
        "address": parsed["address"],
        "port": int(parsed["port"]),
        "resolver": parsed["resolver"],
        "resolver_type": parsed["type"],
        "transport": parsed["transport"],
        "dnscrypt_relay": dnscrypt_relay if parsed["type"] == "dnscrypt_stamp" else "",
    }


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


def forward_query(request, timeout_override=None):
    wait_start = time.perf_counter()
    if not upstream_concurrency.acquire(timeout=3.0):
        record_upstream_queue_wait(time.perf_counter() - wait_start)
        raise OSError("upstream busy")
    record_upstream_queue_wait(time.perf_counter() - wait_start)
    try:
        return _forward_query(request, timeout_override=timeout_override)
    finally:
        upstream_concurrency.release()


def _query_one_upstream(upstream, request, update_metrics=True, timeout_override=None):
    start = time.perf_counter()
    try:
        configured_timeout = parse_positive_float(get_setting("upstream_timeout", "2.5"), 2.5, "Upstream timeout")
    except ValueError:
        configured_timeout = 2.5
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
        response = query_doq_upstream(upstream, request, timeout=timeout)
    elif upstream.get("resolver_type") == "dot_stamp":
        response = query_dot_stamp_upstream(upstream, request, timeout=timeout)
    elif upstream.get("resolver_type") == "doq_stamp":
        response = query_doq_stamp_upstream(upstream, request, timeout=timeout)
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


def _forward_query(request, timeout_override=None):
    mode = get_setting("upstream_mode", "sequential")
    if mode == "parallel_fastest":
        return _forward_query_parallel(request, timeout_override=timeout_override)
    if mode == "parallel_race":
        return _forward_query_race(request, timeout_override=timeout_override)
    if mode == "fastest_addr":
        return _forward_query_fastest(request, timeout_override=timeout_override)
    if mode == "strict_order":
        return _forward_query_strict(request, timeout_override=timeout_override)
    if mode == "load_balance":
        return _forward_query_loadbalance(request, timeout_override=timeout_override)
    upstreams = active_upstreams()
    last_error = ""
    for upstream in upstreams:
        if not upstream_supported(upstream):
            last_error = f"{upstream['resolver_type']} not yet supported"
            continue
        try:
            return _query_one_upstream(upstream, request, timeout_override=timeout_override)
        except OSError as exc:
            last_error = str(exc)
            maybe_update_upstream_status(upstream, latency=None, error=last_error)
    if not upstreams:
        return _query_fallback_plain(request)
    raise OSError(last_error or "no upstream available")


def _forward_query_race(request, timeout_override=None):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    upstreams = [u for u in active_upstreams() if upstream_supported(u)]
    if not upstreams:
        return _query_fallback_plain(request)
    if len(upstreams) == 1:
        return _query_one_upstream(upstreams[0], request, timeout_override=timeout_override)
    first = [None]
    errors = []
    lock = threading.Lock()
    done = threading.Event()

    def try_one(upstream):
        try:
            result = _query_one_upstream(upstream, request, timeout_override=timeout_override)
            with lock:
                if first[0] is None:
                    first[0] = (result, upstream)
                    done.set()
        except OSError as exc:
            maybe_update_upstream_status(upstream, latency=None, error=str(exc))
            with lock:
                errors.append(str(exc))
                if len(errors) >= len(upstreams):
                    done.set()

    with ThreadPoolExecutor(max_workers=len(upstreams)) as ex:
        futures = [ex.submit(try_one, u) for u in upstreams]
        try:
            for f in as_completed(futures, timeout=3.5):
                if first[0] is not None:
                    for ff in futures:
                        ff.cancel()
                    break
        except TimeoutError:
            pass
    if first[0] is not None:
        return first[0][0]
    raise OSError(errors[-1] if errors else "all upstreams timed out")


def _forward_query_fastest(request, timeout_override=None):
    upstreams = [u for u in active_upstreams() if upstream_supported(u)]
    if not upstreams:
        return _query_fallback_plain(request)
    ordered = sorted(upstreams, key=lambda u: (
        u.get("health", {}).get("latency_ms") or u.get("latency_ms") or 999999,
        -(u.get("health", {}).get("success_rate", 1.0)),
    ))
    last_error = ""
    for upstream in ordered:
        try:
            return _query_one_upstream(upstream, request, timeout_override=timeout_override)
        except OSError as exc:
            last_error = str(exc)
            maybe_update_upstream_status(upstream, latency=None, error=last_error)
    raise OSError(last_error or "no upstream available")


def _forward_query_strict(request, timeout_override=None):
    upstreams = [u for u in active_upstreams() if upstream_supported(u)]
    if not upstreams:
        return _query_fallback_plain(request)
    last_error = ""
    for upstream in upstreams:
        try:
            return _query_one_upstream(upstream, request, timeout_override=timeout_override)
        except OSError as exc:
            last_error = str(exc)
            maybe_update_upstream_status(upstream, latency=None, error=last_error)
    raise OSError(last_error or "no upstream available")


def _forward_query_parallel(request, timeout_override=None):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    upstreams = [u for u in active_upstreams() if upstream_supported(u)]
    if not upstreams:
        return _query_fallback_plain(request)
    try:
        race_count = max(1, int(get_setting("upstream_race_count", "2")))
    except (ValueError, TypeError):
        race_count = 2
    race_count = min(race_count, len(upstreams))
    if race_count < 2:
        ordered = sorted(upstreams, key=lambda u: u.get("latency_ms") or 999999)
        for upstream in ordered:
            try:
                return _query_one_upstream(upstream, request, timeout_override=timeout_override)
            except OSError as exc:
                maybe_update_upstream_status(upstream, latency=None, error=str(exc))
        raise OSError("all upstreams failed")
    candidates = sorted(upstreams, key=lambda u: (
        u.get("latency_ms") or 999999,
        -(u.get("health", {}).get("success_rate", 1.0)),
    ))[:race_count]
    first = [None]
    errors = []
    lock = threading.Lock()
    done = threading.Event()

    def try_one(upstream):
        try:
            result = _query_one_upstream(upstream, request, timeout_override=timeout_override)
            with lock:
                if first[0] is None:
                    first[0] = result
                    done.set()
        except OSError as exc:
            maybe_update_upstream_status(upstream, latency=None, error=str(exc))
            with lock:
                errors.append(str(exc))
                if len(errors) >= len(candidates):
                    done.set()

    with ThreadPoolExecutor(max_workers=race_count) as ex:
        futures = [ex.submit(try_one, u) for u in candidates]
        try:
            for f in as_completed(futures, timeout=3.5):
                if first[0] is not None:
                    for ff in futures:
                        ff.cancel()
                    break
        except TimeoutError:
            pass
    if first[0] is not None:
        return first[0]
    raise OSError(errors[-1] if errors else "all upstreams timed out")


def _forward_query_loadbalance(request, timeout_override=None):
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
            return _query_one_upstream(upstream, request, timeout_override=timeout_override)
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
        um.maybe_update_latency(upstream_id, latency, error)
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


def log_query(client_ip, domain, normalized, qtype_name, status, response_ips="", upstream="", matched_rule="", cache_status="miss", blocked=0, reason="", duration_ms=0, matched_list="", client_name="", profile_name="", connection_type="", upstream_protocol="", response_time_ms=0, connect_time_ms=0, handshake_time_ms=0, upstream_query_time_ms=0, dnssec_status="", pool_reused=0, served_stale=0, prefetch_triggered=0, resolver_mode=""):
    if get_setting("query_log_enabled", "1") != "1":
        return
    with db_write_lock:
        if len(db_write_queue) >= 20000:
            full = True
        else:
            full = False
            db_write_queue.append((now_iso(), client_ip or "", domain or "", normalized or "", qtype_name or "", status or "", response_ips or "", upstream or "", connection_type or "", matched_rule or "", cache_status or "miss", blocked or 0, reason or "", matched_list or "", duration_ms or 0, client_name or "", profile_name or "", upstream_protocol or "", response_time_ms or 0, connect_time_ms or 0, handshake_time_ms or 0, upstream_query_time_ms or 0, dnssec_status or "", pool_reused or 0, served_stale or 0, prefetch_triggered or 0, resolver_mode or ""))
    if full:
        bump_runtime_metric("query_log_dropped_total")


def db_writer_loop():
    while True:
        batch = []
        with db_write_lock:
            if db_write_queue:
                batch = db_write_queue[:2000]
                del db_write_queue[:2000]
        if not batch:
            time.sleep(0.05)
            continue
        try:
            with db_lock:
                batch = [
                    tuple((0 if idx in (11, 14, 18, 19, 20, 21, 23, 24, 25) else "") if value is None else value for idx, value in enumerate(item))
                    for item in batch
                ]
                db.executemany(
                    """
                    INSERT INTO query_log(timestamp,client_ip,domain,normalized_domain,query_type,status,response_ips,upstream,connection_type,matched_rule,cache_status,blocked,blocked_reason,matched_list,duration_ms,client_name,profile_name,upstream_protocol,response_time_ms,connect_time_ms,handshake_time_ms,upstream_query_time_ms,dnssec_status,pool_reused,served_stale,prefetch_triggered,resolver_mode)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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


def log_query_sync(client_ip, domain, normalized, qtype_name, status, response_ips="", upstream="", matched_rule="", cache_status="miss", blocked=0, reason="", duration_ms=0, matched_list="", client_name="", profile_name="", connection_type="", upstream_protocol="", response_time_ms=0, connect_time_ms=0, handshake_time_ms=0, upstream_query_time_ms=0, dnssec_status="", pool_reused=0, served_stale=0, prefetch_triggered=0, resolver_mode=""):
    if get_setting("query_log_enabled", "1") != "1":
        return
    with db_lock:
        db.execute(
            """
            INSERT INTO query_log(timestamp,client_ip,domain,normalized_domain,query_type,status,response_ips,upstream,connection_type,matched_rule,cache_status,blocked,blocked_reason,matched_list,duration_ms,client_name,profile_name,upstream_protocol,response_time_ms,connect_time_ms,handshake_time_ms,upstream_query_time_ms,dnssec_status,pool_reused,served_stale,prefetch_triggered,resolver_mode)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (now_iso(), client_ip, domain, normalized, qtype_name, status, response_ips, upstream, connection_type, matched_rule, cache_status, blocked, reason, matched_list, duration_ms, client_name, profile_name, upstream_protocol, response_time_ms, connect_time_ms, handshake_time_ms, upstream_query_time_ms, dnssec_status, pool_reused, served_stale, prefetch_triggered, resolver_mode),
        )
        db.commit()


def handle_dns_request(request, client_ip, connection_type=""):
    started = time.perf_counter()
    bump_runtime_metric("dns_requests_total")
    ensure_client(client_ip)
    client_info = lookup_client_snapshot(client_ip)
    client_log_name = client_info.get("name", "") if client_info else ""
    client_profile_name = (client_info.get("profile_name", "") or "") if client_info else ""
    resolver_mode = get_setting("upstream_mode", "sequential")
    try:
        question = parse_dns_question(request)
        domain = question["domain"]
        normalized = question["normalized_domain"]
        qtype_name = question["qtype_name"]

        if get_setting("disable_ipv6", "0") == "1" and qtype_name == "AAAA":
            response = build_empty_response(request)
            return response

        if is_local_reverse_lookup(normalized, qtype_name):
            response = build_empty_response(request)
            log_query(client_ip, domain, normalized, qtype_name, "local", matched_rule="local reverse", cache_status="local", reason="local reverse lookup", duration_ms=(time.perf_counter() - started) * 1000, client_name=client_log_name, profile_name=client_profile_name, connection_type=connection_type, resolver_mode=resolver_mode)
            return response

        decision = decide(normalized, qtype_name, client_ip, client_info=client_info)
        dc = decision.get("client_name", "")
        dp = decision.get("profile_name", "")

        if decision["action"] == "refuse":
            response = build_error_response(request, 5)
            log_query(client_ip, domain, normalized, qtype_name, "refused", matched_rule=decision["rule"], blocked=1, reason=decision["reason"], duration_ms=(time.perf_counter() - started) * 1000, matched_list=decision.get("filter_list", ""), client_name=dc, profile_name=dp, connection_type=connection_type, resolver_mode=resolver_mode)
            return response
        if decision["action"] == "block":
            bump_runtime_metric("dns_filter_blocks_total")
            response = build_block_response(request, qtype_name, question)
            log_query(client_ip, domain, normalized, qtype_name, "blocked", matched_rule=decision["rule"], blocked=1, reason=decision["reason"], duration_ms=(time.perf_counter() - started) * 1000, matched_list=decision.get("filter_list", ""), client_name=dc, profile_name=dp, connection_type=connection_type, resolver_mode=resolver_mode)
            return response
        if decision["action"] == "rewrite":
            response = build_ip_response(request, decision["target"], question=question)
            log_query(client_ip, domain, normalized, qtype_name, "rewritten", response_ips=decision["target"], matched_rule=decision["rule"], reason=decision["reason"], duration_ms=(time.perf_counter() - started) * 1000, matched_list=decision.get("filter_list", ""), client_name=dc, profile_name=dp, connection_type=connection_type, resolver_mode=resolver_mode)
            return response

        bump_runtime_metric("dns_filter_allows_total")

        if is_local_nodata_query(qtype_name):
            response = build_empty_response(request)
            log_query(client_ip, domain, normalized, qtype_name, "local", matched_rule="local nodata", cache_status="local", reason="local no data", duration_ms=(time.perf_counter() - started) * 1000, client_name=dc, profile_name=dp, connection_type=connection_type, resolver_mode=resolver_mode)
            return response

        cached = get_cached(normalized, qtype_name)
        if cached:
            bump_runtime_metric("dns_cache_hits_total")
            cached = request[:2] + cached[2:]
            cached = apply_ipv6_disabled_policy(cached)
            cache_hit_status = "hit"
            if isinstance(cached, tuple) and len(cached) == 2:
                cached, cache_hit_status = cached
            log_query(client_ip, domain, normalized, qtype_name, "cached", response_ips=extract_response_ips(cached), cache_status=cache_hit_status, duration_ms=(time.perf_counter() - started) * 1000, client_name=dc, profile_name=dp, connection_type=connection_type, resolver_mode=resolver_mode)
            return cached

        neg_cached = get_negative_cached(normalized, qtype_name)
        if neg_cached:
            bump_runtime_metric("dns_cache_hits_total")
            neg_response, neg_type = neg_cached
            neg_response = request[:2] + neg_response[2:]
            neg_response = apply_ipv6_disabled_policy(neg_response)
            log_query(client_ip, domain, normalized, qtype_name, "cached", response_ips="", cache_status="negative_hit", duration_ms=(time.perf_counter() - started) * 1000, client_name=dc, profile_name=dp, connection_type=connection_type, resolver_mode=resolver_mode)
            return neg_response

        bump_runtime_metric("dns_cache_misses_total")

        forwarding_request = request
        if get_setting("dnssec_validation_enabled", "0") == "1":
            forwarding_request = add_do_bit_to_query(request)
        upstream_start = time.perf_counter()
        response, upstream = forward_query(forwarding_request)
        upstream_query_time_ms = (time.perf_counter() - upstream_start) * 1000
        response = apply_ipv6_disabled_policy(response)
        filtering_on = get_setting("filtering_enabled", "1") == "1" and client_filtering_enabled(client_ip, client_info=client_info)
        profile_id = decision.get("profile_id")
        engine = get_filter_engine()

        client_cd_flag = bool(question.get("flags", 0) & 0x0100)

        dnssec_status = ""
        if _dnssec_available and get_setting("dnssec_validation_enabled", "0") == "1" and not client_cd_flag:
            try:
                import dns.message
                import dns.flags
                qmsg = dns.message.from_wire(forwarding_request)
                rmsg = dns.message.from_wire(response)
                validator = get_dnssec_validator()
                if validator:
                    dnssec_result = validator.validate_response(qmsg, rmsg)
                    dnssec_status = dnssec_result.status
                    if dnssec_result.status in ("bogus", "indeterminate"):
                        servfail_response = build_error_response(request, 2)
                        log_query(client_ip, domain, normalized, qtype_name, "blocked",
                                  upstream=upstream, matched_rule="dnssec_bogus",
                                  blocked=1, reason=dnssec_result.reason,
                                  duration_ms=(time.perf_counter() - started) * 1000,
                                  client_name=dc, profile_name=dp, connection_type=connection_type,
                                  upstream_query_time_ms=upstream_query_time_ms,
                                  dnssec_status=dnssec_status, resolver_mode=resolver_mode)
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
                bump_runtime_metric("dns_filter_blocks_total")
                blocked_response = build_block_response(request, qtype_name, question)
                matched = cname_result.matched_rule or cname_result.matched_domain or cname
                log_query(client_ip, domain, normalized, qtype_name, "blocked", upstream=upstream,
                          matched_rule=matched, blocked=1, reason="cname_blocked",
                          duration_ms=(time.perf_counter() - started) * 1000,
                          matched_list=cname_result.list_name or cname_result.matched_list or "",
                          client_name=dc, profile_name=dp, connection_type=connection_type,
                          upstream_query_time_ms=upstream_query_time_ms,
                          dnssec_status=dnssec_status, resolver_mode=resolver_mode)
                return blocked_response
        neg_type = is_negative_response(response)
        if neg_type:
            set_negative_cached(normalized, qtype_name, response, neg_type)
        else:
            set_cached(normalized, qtype_name, response)
        log_query(client_ip, domain, normalized, qtype_name, "allowed", response_ips=extract_response_ips(response), upstream=upstream, duration_ms=(time.perf_counter() - started) * 1000, client_name=dc, profile_name=dp, connection_type=connection_type, upstream_query_time_ms=upstream_query_time_ms, dnssec_status=dnssec_status, resolver_mode=resolver_mode)
        return response
    except Exception as exc:
        bump_runtime_metric("dns_upstream_errors_total")
        try:
            question = parse_dns_question(request)
            log_query(client_ip, question["domain"], question["normalized_domain"], question["qtype_name"], "upstream_error", reason=str(exc), duration_ms=(time.perf_counter() - started) * 1000, client_name=client_log_name, profile_name=client_profile_name, connection_type=connection_type, resolver_mode=resolver_mode)
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
    .three-col,.two-col{{display:grid;gap:1rem;margin-bottom:1.3rem;max-width:100%;min-width:0}}
    .three-col{{grid-template-columns:repeat(3,1fr)}}
    .two-col{{grid-template-columns:repeat(2,1fr)}}
    .three-col .panel,.two-col .panel{{width:100%;max-width:100%;min-width:0;overflow:hidden}}
    .three-col table,.two-col table{{table-layout:fixed}}
    .three-col th,.three-col td,.two-col th,.two-col td{{min-width:0}}
    .three-col .td-num,.two-col .td-num{{width:96px}}
    .three-col th:last-child,.three-col td:last-child,.two-col th:last-child,.two-col td:last-child{{width:104px}}
    table{{width:100%;border-collapse:collapse}}
    .table{{width:100%;border-collapse:collapse;margin-bottom:0}}
    th,.table th{{font-size:.78rem;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:.58rem 1rem;text-align:left;border-bottom:1px solid var(--border)}}
    td,.table td{{padding:.55rem 1rem;font-size:.9rem;border-bottom:1px solid rgba(30,45,61,.5);vertical-align:middle}}
    tr:last-child td{{border-bottom:none}}
    tr:hover td{{background:rgba(26,39,64,.32)}}
    .table-responsive{{max-width:100%;overflow-x:auto;overflow-y:hidden;-webkit-overflow-scrolling:touch}}
    .table-responsive>.table,.table-responsive>table{{min-width:720px}}
    .domain-test-list{{display:grid;gap:0;border-top:1px solid rgba(30,45,61,.5)}}
    .domain-test-row{{display:grid;grid-template-columns:180px 1fr;gap:1rem;padding:.58rem 0;border-bottom:1px solid rgba(30,45,61,.5)}}
    .domain-test-label{{color:var(--muted);font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em}}
    .domain-test-value{{overflow-wrap:anywhere;word-break:break-word}}
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
    @media(max-width:1100px){{.card-grid{{grid-template-columns:repeat(2,1fr)}}.three-col,.two-col{{grid-template-columns:1fr}}}}
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
      .three-col,.two-col{{grid-template-columns:1fr;gap:.75rem;margin-bottom:1rem;width:100%}}
      .three-col table,.two-col table{{width:100%;max-width:100%;min-width:0}}
      .three-col .td-num,.two-col .td-num{{width:82px}}
      .three-col th:last-child,.three-col td:last-child,.two-col th:last-child,.two-col td:last-child{{width:86px}}
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
      .domain-test-row{{grid-template-columns:1fr;gap:.18rem;padding:.62rem 0}}
      .domain-test-label{{font-size:.66rem}}
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
      .three-col .td-num,.two-col .td-num{{width:70px}}
      .three-col th:last-child,.three-col td:last-child,.two-col th:last-child,.two-col td:last-child{{width:74px}}
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
        "upstreams": sum(1 for u in um.get_all() if u.get("enabled")),
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
               COALESCE(AVG(CASE WHEN duration_ms<1000 THEN duration_ms END),0) avg_ms,
               COALESCE(SUM(CASE WHEN cache_status='hit' THEN 1 ELSE 0 END),0) cache_hits
        FROM query_log WHERE timestamp >= datetime('now','localtime','-48 hours')
          AND timestamp < datetime('now','localtime','-24 hours')
    """) or {"total": 0, "blocked": 0, "avg_ms": 0, "cache_hits": 0}

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
          AND normalized_domain != '' AND blocked=0 AND status NOT IN ('local')
        GROUP BY normalized_domain ORDER BY cnt DESC LIMIT 8
    """)
    top_blocked = rows("""
        SELECT normalized_domain as domain, COUNT(*) as cnt
        FROM query_log WHERE blocked=1 AND timestamp >= datetime('now','localtime','-24 hours')
          AND normalized_domain != ''
        GROUP BY normalized_domain ORDER BY cnt DESC LIMIT 8
    """)
    top_cache_domains = rows("""
        SELECT normalized_domain as domain, COUNT(*) as cnt
        FROM query_log WHERE cache_status='hit' AND timestamp >= datetime('now','localtime','-24 hours')
          AND normalized_domain != ''
        GROUP BY normalized_domain ORDER BY cnt DESC LIMIT 8
    """)
    top_upstreams = rows("""
        SELECT upstream, COUNT(*) as requests,
               COALESCE(AVG(CASE WHEN duration_ms<1000 THEN duration_ms END),0) as avg_ms
        FROM query_log WHERE timestamp >= datetime('now','localtime','-24 hours')
          AND upstream != ''
        GROUP BY upstream ORDER BY requests DESC LIMIT 8
    """)
    top_clients = rows("""
        SELECT client_ip, COUNT(*) as requests, COALESCE(SUM(blocked),0) as blocked,
               MAX(timestamp) as last_seen
        FROM query_log WHERE timestamp >= datetime('now','localtime','-48 hours')
        GROUP BY client_ip ORDER BY requests DESC LIMIT 8
    """)
    today_cache_rate = round((combined["cache_hits"] / combined["total"] * 100) if combined["total"] else 0, 1)
    prev_cache_rate = round((prev["cache_hits"] / prev["total"] * 100) if prev["total"] else 0, 1)
    result = {
        "today": combined, "prev": prev,
        "changes": {
            "total": pct_change(combined["total"], prev["total"]),
            "blocked": pct_change(combined["blocked"], prev["blocked"]),
            "avg_ms": pct_change(combined["avg_ms"], prev["avg_ms"]),
            "cache": pct_change(today_cache_rate, prev_cache_rate),
            "total_abs": combined["total"] - prev["total"],
            "blocked_abs": combined["blocked"] - prev["blocked"],
            "avg_ms_abs": round((combined["avg_ms"] or 0) - (prev["avg_ms"] or 0), 1),
        },
        "sparklines": {"total": sparkline_total, "blocked": sparkline_blocked, "cache": sparkline_cache, "avgms": sparkline_avgms},
        "top_domains": top_domains, "top_blocked": top_blocked,
        "top_cache_domains": top_cache_domains, "top_upstreams": top_upstreams,
        "top_clients": top_clients,
        "total_q": combined["total"] or 1,
        "cache_rate": round((combined["cache_hits"] / combined["total"] * 100) if combined["total"] else 0, 1),
        "total_cache_hits": combined["cache_hits"] or 1,
        "rules_count": one("SELECT COUNT(*) c FROM rules WHERE enabled=1")["c"]
        + one("SELECT COALESCE(SUM(bl.rule_count),0) c FROM blocklists bl WHERE bl.enabled=1")["c"],
        "upstreams_count": sum(1 for u in um.get_all() if u.get("enabled")),
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
    total_cache_hits = d["total_cache_hits"]
    changes = d["changes"]
    blue = "#3b82f6"; red = "#ef4444"; orange = "#f59e0b"; purple = "#a78bfa"

    def change_span(val, lower_is_better=False, fmt="pct"):
        if val == 0:
            return '<span class="card-change" style="color:var(--muted)">— vs yesterday</span>'
        good = (val < 0) if lower_is_better else (val > 0)
        cls = "up" if good else "dn"
        arrow = "▲" if val > 0 else "▼"
        sign = "+" if val > 0 else ""
        if fmt == "count":
            formatted = f'{sign}{int(val):,}'
        elif fmt == "ms":
            formatted = f'{sign}{val} ms'
        else:
            display = f'{int(val)}' if abs(val) >= 100 else f'{val}'
            formatted = f'{sign}{display}%'
        return f'<span class="card-change {cls}">{arrow} {formatted} vs yesterday</span>'

    def stat_card(label, value, spark_vals, color, icon_svg, chval, lower_is_better=False, card_id="", fmt="pct"):
        spark = sparkline_svg(spark_vals, color)
        li = "1" if lower_is_better else "0"
        return (
            f'<div class="stat-card" data-card="{card_id}" data-color="{color}" data-lower="{li}">'
            f'<div class="card-top">'
            f'<div><div class="card-label">{label}</div>'
            f'<div class="card-value">{value}</div>'
            f'{change_span(chval, lower_is_better, fmt)}</div>'
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
        stat_card("DNS Queries",           f'{total:,}',      sp["total"],   blue,   ic_globe,  changes["total_abs"],           False, card_id="total",   fmt="count") +
        stat_card("Blocked Requests",      f'{blocked:,}',    sp["blocked"], red,    ic_block,  changes["blocked_abs"],         True,  card_id="blocked", fmt="count") +
        stat_card("Cache Hit Rate",        f'{cache_rate}%',  sp["cache"],   orange, ic_zap,    changes["cache"],               False, card_id="cache",   fmt="pct") +
        stat_card("Average Response Time", f'{avg_ms} ms',    sp["avgms"],   purple, ic_clock,  changes["avg_ms_abs"],          True,  card_id="avgms",   fmt="ms")
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

    def cache_row(r):
        pct = round(r["cnt"] / total_cache_hits * 100, 1) if total_cache_hits else 0
        return f'<tr><td class="td-domain">{r["domain"]}</td><td class="td-num">{r["cnt"]:,}</td><td class="td-num">{pct}%</td></tr>'

    top_cache_html = "".join(cache_row(r) for r in d["top_cache_domains"]) or \
        '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No cache hits yet</td></tr>'

    top_upstream_html = "".join(
        f'<tr><td class="td-domain">{r["upstream"]}</td><td class="td-num">{r["requests"]:,}</td>'
        f'<td class="td-num">{round(r["avg_ms"], 1)} ms</td></tr>'
        for r in d["top_upstreams"]
    ) or '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No upstream data yet</td></tr>'

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
  <div style="display:flex;align-items:center;gap:.65rem;flex-wrap:wrap">
    <span class="page-title" style="margin-bottom:0">Dashboard</span>
    <button class="btn btn-outline-light btn-sm" type="button" id="dash-refresh-btn" onclick="manualRefreshDash()">Refresh stats</button>
  </div>
  <span style="font-size:.72rem;color:var(--muted)">Live &bull; updated <span id="last-refresh">—</span></span>
</div>
<div id="update-alert-container"></div>
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
<div class="two-col">
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Top Cache Domains</span><a class="panel-link" href="/querylog?status=cached">View cached</a></div>
    <table><thead><tr><th>Domain</th><th class="td-num">Hits</th><th class="td-num">% Cache</th></tr></thead><tbody id="top-cache-body">{top_cache_html}</tbody></table>
  </div>
  <div class="panel">
    <div class="panel-head"><span class="panel-title">Top Upstreams</span><a class="panel-link" href="/upstreams">Manage</a></div>
    <table><thead><tr><th>Upstream</th><th class="td-num">Requests</th><th class="td-num">Avg ms</th></tr></thead><tbody id="top-upstream-body">{top_upstream_html}</tbody></table>
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
function chgHTML(val, lower, fmt) {{
  if (val === 0 || val == null) return `<span class="card-change" style="color:var(--muted)">— vs yesterday</span>`;
  const good = lower ? val<0 : val>0;
  const arrow = val>0 ? '▲' : '▼';
  const sign = val>0 ? '+' : '';
  let formatted;
  if (fmt === 'count') {{
    formatted = sign + Math.round(val).toLocaleString();
  }} else if (fmt === 'ms') {{
    formatted = sign + val + ' ms';
  }} else {{
    const display = Math.abs(val) >= 100 ? Math.round(val) : val;
    formatted = sign + display + '%';
  }}
  return `<span class="card-change ${{good?'up':'dn'}}">${{arrow}} ${{formatted}} vs yesterday</span>`;
}}
function esc(s) {{
  return String(s||'').replace(/[&<>"']/g,c=>({{
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }}[c]));
}}
async function refreshDash(force=false) {{
  try {{
    const r = await fetch(force ? '/api/dashboard?refresh=1' : '/api/dashboard', {{cache:'no-store'}});
    if (!r.ok) return;
    const d = await r.json();
    const t=d.today, ch=d.changes, sp=d.sparklines, tq=d.total_q||1;
    const tch=d.total_cache_hits||1;
    // Stat cards
    const cards = [
      {{id:'total',   val:t.total.toLocaleString(),                 chval:ch.total_abs,   lower:false, fmt:'count', spark:sp.total,   color:'#3b82f6'}},
      {{id:'blocked', val:t.blocked.toLocaleString(),               chval:ch.blocked_abs, lower:true,  fmt:'count', spark:sp.blocked, color:'#ef4444'}},
      {{id:'cache',   val:(d.cache_rate||0)+'%',                    chval:ch.cache,       lower:false, fmt:'pct',   spark:sp.cache,   color:'#f59e0b'}},
      {{id:'avgms',   val:(Math.round(t.avg_ms*10)/10)+' ms',       chval:ch.avg_ms_abs,  lower:true,  fmt:'ms',    spark:sp.avgms,   color:'#a78bfa'}},
    ];
    for (const c of cards) {{
      const el = document.querySelector(`[data-card="${{c.id}}"]`);
      if (!el) continue;
      el.querySelector('.card-value').textContent = c.val;
      const chEl = el.querySelector('.card-change');
      if (chEl) chEl.outerHTML = chgHTML(c.chval, c.lower, c.fmt);
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
    // Top cache domains
    const cacheb = document.getElementById('top-cache-body');
    if (cacheb) cacheb.innerHTML = d.top_cache_domains.length
      ? d.top_cache_domains.map(r=>`<tr><td class="td-domain">${{esc(r.domain)}}</td><td class="td-num">${{r.cnt.toLocaleString()}}</td><td class="td-num">${{(r.cnt/tch*100).toFixed(1)}}%</td></tr>`).join('')
      : `<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No cache hits yet</td></tr>`;
    // Top upstreams
    const ub = document.getElementById('top-upstream-body');
    if (ub) ub.innerHTML = d.top_upstreams.length
      ? d.top_upstreams.map(r=>`<tr><td class="td-domain">${{esc(r.upstream)}}</td><td class="td-num">${{r.requests.toLocaleString()}}</td><td class="td-num">${{(Math.round((r.avg_ms||0)*10)/10)}} ms</td></tr>`).join('')
      : `<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:1rem">No upstream data yet</td></tr>`;
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
async function manualRefreshDash() {{
  const btn = document.getElementById('dash-refresh-btn');
  if (btn) {{
    btn.disabled = true;
    btn.textContent = 'Refreshing...';
  }}
  await refreshDash(true);
  if (btn) {{
    btn.disabled = false;
    btn.textContent = 'Refresh stats';
  }}
}}
setInterval(refreshDash, 3000);
refreshDash();

async function checkForUpdates() {{
  try {{
    const r = await fetch('/api/update/check', {{cache:'no-store'}});
    if (!r.ok) return;
    const d = await r.json();
    const container = document.getElementById('update-alert-container');
    if (!container) return;
    
    if (d.ok && d.available && d.count > 0) {{
      const commitList = d.commits.slice(0, 5).map(c => `<li>${{c}}</li>`).join('');
      const moreText = d.count > 5 ? `<li>...and ${{d.count - 5}} more</li>` : '';
      
      container.innerHTML = `
        <div style="background:linear-gradient(135deg,#f59e0b 0%,#f97316 100%);color:white;padding:1rem 1.5rem;border-radius:.75rem;margin-bottom:1.5rem;box-shadow:0 4px 12px rgba(245,158,11,0.3);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem">
          <div style="flex:1;min-width:200px">
            <div style="font-size:1.1rem;font-weight:600;margin-bottom:.25rem">
              <svg style="vertical-align:middle;margin-right:.5rem" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.778-7.778zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
              Update Available: ${{d.count}} new commit${{d.count > 1 ? 's' : ''}}
            </div>
            <div style="font-size:.85rem;opacity:.9">
              <ul style="margin:.5rem 0 0 0;padding-left:1.5rem">${{commitList}}${{moreText}}</ul>
            </div>
          </div>
          <button onclick="applyUpdate()" style="background:white;color:#f59e0b;border:none;padding:.75rem 1.5rem;border-radius:.5rem;font-weight:600;cursor:pointer;font-size:.95rem;white-space:nowrap;box-shadow:0 2px 8px rgba(0,0,0,0.15);transition:all .2s" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 12px rgba(0,0,0,0.2)'" onmouseout="this.style.transform='';this.style.boxShadow='0 2px 8px rgba(0,0,0,0.15)'">
            <svg style="vertical-align:middle;margin-right:.5rem" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            Update Now
          </button>
        </div>
      `;
    }}
  }} catch(e) {{
    console.error('Update check failed:', e);
  }}
}}

async function applyUpdate() {{
  if (!confirm('Apply update and restart server?')) return;
  
  const container = document.getElementById('update-alert-container');
  if (container) {{
    container.innerHTML = `
      <div style="background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);color:white;padding:1.5rem;border-radius:.75rem;margin-bottom:1.5rem;text-align:center;box-shadow:0 4px 12px rgba(59,130,246,0.3)">
        <div style="font-size:1.2rem;font-weight:600">
          <svg style="vertical-align:middle;margin-right:.5rem;animation:spin 1s linear infinite" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          DNS Server Update...
        </div>
        <div style="font-size:.9rem;opacity:.9;margin-top:.5rem">Applying updates and restarting server</div>
      </div>
      <style>@keyframes spin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}</style>
    `;
  }}
  
  try {{
    const r = await fetch('/api/update/apply', {{method:'POST'}});
    const d = await r.json();
    if (!d.ok) {{
      alert('Update failed: ' + (d.error || 'Unknown error'));
      location.reload();
    }}
  }} catch(e) {{
    console.error('Update failed:', e);
  }}
}}

checkForUpdates();
setInterval(checkForUpdates, 21600000);
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


def h(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def rules_page(kind=None):
    current_rules = read_rules()
    errs = validate_rules(current_rules)
    counts = count_rules(current_rules)
    alert_html = ""
    if errs:
        alert_html = '<div class="alert alert-danger py-2 mb-3"><strong>' + str(len(errs)) + ' rule error(s) found</strong><br>'
        for e in errs[:10]:
            alert_html += f'<code class="d-block small">Line {e["line"]}: {h(e["message"])}</code>'
        if len(errs) > 10:
            alert_html += f'<code class="d-block small text-muted">... and {len(errs) - 10} more</code>'
        alert_html += "</div>"
    return template(f"""
<h1 class="h3 mb-3">Rules</h1>
{alert_html}
<div class="alert alert-info py-2 mb-3">Use <a href="/blocklists" class="alert-link">Blocklists</a> for bulk filter lists. Custom rules on this page are stored in <code>data/rules/user_rules.pgrules</code>.</div>
<div class="panel rounded-2 border border-secondary-subtle p-3">
<form method="post" action="/rules/save">
<div class="mb-2 d-flex justify-content-between align-items-center">
<span class="text-muted small">{counts["total"]} rules ({counts["block_exact"]} bd, {counts["block_suffix"]} bs, {counts["block_regex"]} br, {counts["allow_exact"]} ad, {counts["allow_suffix"]} as, {counts["allow_regex"]} ar)</span>
</div>
<textarea class="form-control font-monospace mb-2" name="rules" rows="20" style="font-size:13px">{h(current_rules)}</textarea>
<div class="d-flex justify-content-between align-items-center">
<small class="text-muted">Syntax: <code>bd::</code> block domain, <code>bs::</code> block suffix, <code>br::</code> block regex, <code>ad::</code> allow domain, <code>as::</code> allow suffix, <code>ar::</code> allow regex. One rule per line, <code>#</code> for comments.</small>
<button class="btn btn-success" type="submit">Save Rules</button>
</div>
</form>
</div>""", "Rules")


BUILTIN_ADLIST_PRESETS = """
Blocklists

1Hosts (Lite): https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt
1Hosts (Xtra): https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt
AdGuard DNS filter: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
AdGuard DNS Popup Hosts filter: https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt
AWAvenue Ads Rule: https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt
Dan Pollock's List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt
HaGeZi's Normal Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt
HaGeZi's Pro Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt
HaGeZi's Pro++ Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt
HaGeZi's Ultimate Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt
OISD Blocklist Small: https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_small.txt
OISD Blocklist Big: https://big.oisd.nl
OISD Blocklist NSFW: https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_nsfw.txt
Peter Lowe's Blocklist: https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext
ShadowWhisperer Tracking List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_69.txt
Steven Black's List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt
Dandelion Sprout's Anti Push Notifications: https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt
Dandelion Sprout's Game Console Adblock List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt
HaGeZi's Anti-Piracy Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt
HaGeZi's Apple Tracker Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt
HaGeZi's Gambling Blocklist: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt
HaGeZi's OPPO & Realme Tracker Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt
HaGeZi's Samsung Tracker Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt
HaGeZi's Vivo Tracker Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt
HaGeZi's Windows/Office Tracker Blocklist: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt
HaGeZi's Xiaomi Tracker Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt
HaGeZi's TikTok Fingerprinting DNS Blocklist: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tiktok.txt
No Google: https://adguardteam.github.io/HostlistsRegistry/assets/filter_37.txt
Perflyst and Dandelion Sprout's Smart-TV Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt
ShadowWhisperer's Dating List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_57.txt
Ukrainian Security Filter: https://adguardteam.github.io/HostlistsRegistry/assets/filter_62.txt
Phishing URL Blocklist (PhishTank and OpenPhish): https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt
Dandelion Sprout's Anti-Malware List: https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt
HaGeZi's Badware Hoster Blocklist: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/hoster.txt
HaGeZi's Fake DNS Blocklist: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt
HaGeZi's DNS Rebind Protection: https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt
HaGeZi's DynDNS Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt
HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass: https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt
HaGeZi's The World's Most Abused TLDs: https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt
HaGeZi's Threat Intelligence Feeds: https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt
HaGeZi's URL Shortener Blocklist: https://adguardteam.github.io/HostlistsRegistry/assets/filter_68.txt
NoCoin Filter List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt
Phishing Army: https://phishing.army/download/phishing_army_blocklist.txt
Phishing Army (extended): https://phishing.army/download/phishing_army_blocklist_extended.txt
Scam Blocklist by DurableNapkin: https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt
ShadowWhisperer's Malware List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt
Stalkerware Indicators List: https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts
The Big List of Hacked Malware Web Sites: https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt
uBlock filters Badware risks: https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt
Malicious URL Blocklist (URLHaus): https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt
CHN: anti-AD: https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt
CHN: AdRules DNS List: https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt
WaLLy3K: https://v.firebog.net/hosts/static/w3kbl.txt
KADhosts: https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt
add.Spam: https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts
Matomo Referrer-spam-blacklist: https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt
Zero Hosts: https://someonewhocares.org/hosts/zero/hosts
RooneyMcNibNug SNAFU: https://raw.githubusercontent.com/RooneyMcNibNug/pihole-stuff/master/SNAFU.txt
AdAway default blocklist: https://adaway.org/hosts.txt
AdguardDNS: https://v.firebog.net/hosts/AdguardDNS.txt
Admiral: https://v.firebog.net/hosts/Admiral.txt
AnudeepND: https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt
Easylist: https://v.firebog.net/hosts/Easylist.txt
hostsVN: https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts
Easyprivacy: https://v.firebog.net/hosts/Easyprivacy.txt
Prigent-Ads: https://v.firebog.net/hosts/Prigent-Ads.txt
add.2o7Net: https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts
WindowsSpyBlocker: https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
First-party trackers host list: https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
Prigent-Crypto: https://v.firebog.net/hosts/Prigent-Crypto.txt
add.Risk: https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts
NoTrack Malware Blocklist: https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt
Spam404: https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt
abuse.ch URLhaus Host file: https://urlhaus.abuse.ch/downloads/hostfile/
CyberHost.uk Malware and Phishing Blocklist: https://lists.cyberhost.uk/malware.txt
winhelp2002hosts: https://winhelp2002.mvps.org/hosts.txt
ad-wars: https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts
d3ward: https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.txt
RPiList-Malware: https://v.firebog.net/hosts/RPiList-Malware.txt
Lightswitch05's ads-and-tracking-extended: https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt
hblock: https://hblock.molinero.dev/hosts_adblock.txt
Newly Registered Domains: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd7.txt
crypto-nl: https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt
drugs-nl: https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt
gambling-nl: https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt
phishing-nl: https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt
ransomware-nl: https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt
scam-nl: https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt
VeleSila hosts: https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts
PiHole Youtube-List: https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/youtubelist.txt
PiHole Youtube-Crowed-List: https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/crowed_list.txt

Whitelists

IceFlom adguard-whitelist: https://gitlab.com/IceFlom/adguard-whitelist/-/raw/main/whitelist.txt
hg1978's AdGuard Home Whitelist: https://raw.githubusercontent.com/hg1978/AdGuard-Home-Whitelist/master/whitelist.txt
HaGeZi's Allowlist Referral: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt
Ealenn Allow: https://raw.githubusercontent.com/Ealenn/AdGuard-Home-List/gh-pages/AdGuard-Home-List.Allow.txt
AdGuard Home Whitelist: https://raw.githubusercontent.com/hl2guide/AdGuard-Home-Whitelist/main/whitelist.txt
kristerkari: https://raw.githubusercontent.com/kristerkari/umatrix-recipes/master/README.md
"""


def load_adlist_presets():
    presets = {"block": [], "allow": []}
    section = None
    for raw_line in BUILTIN_ADLIST_PRESETS.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered == "blocklists":
            section = "block"
            continue
        if lowered == "whitelists":
            section = "allow"
            continue
        if section is None:
            continue
        match = re.match(r"^(.+?):\s*(https?://.+)$", line)
        if not match:
            continue
        name = match.group(1).strip()
        url = match.group(2).strip()
        if name and url:
            presets[section].append({"name": name, "url": url})
    return presets


def preset_exists(item, rows):
    name = str(item.get("name", "")).strip().lower()
    url = str(item.get("url", "")).strip().lower()
    for row in rows:
        row_name = str(row.get("name", "")).strip().lower()
        row_url = str(row.get("url", "")).strip().lower()
        if url and row_url and url == row_url:
            return True
        if name and row_name and name == row_name:
            return True
    return False


def normalized_list_url(url):
    return str(url or "").strip().rstrip("/").lower()


def parsed_blocklist_entry_set(text, list_type):
    list_type = "allow" if list_type == "allow" else "block"
    entries = parse_filter_list(text or "", default_action=list_type)
    if list_type == "allow":
        entries = [(action, pt, pattern) for action, pt, pattern in entries if action == "allow"]
    return frozenset(entries)


def duplicate_blocklist_by_url(url, list_type):
    wanted_url = normalized_list_url(url)
    if not wanted_url or blocklist_manager is None:
        return None
    wanted_type = "allow" if list_type == "allow" else "block"
    for row in blocklist_manager.get_all():
        row_type = "allow" if row.get("list_type") == "allow" else "block"
        if row_type == wanted_type and normalized_list_url(row.get("url")) == wanted_url:
            return row
    return None


def duplicate_blocklist_by_entries(entry_set, list_type):
    if not entry_set:
        return None
    wanted_type = "allow" if list_type == "allow" else "block"
    existing = {}
    for bl in blocklist_manager.get_all():
        if (bl.get("list_type") or "block") != wanted_type:
            continue
        cache = load_blocklist_cache(str(bl["id"]))
        if not cache:
            continue
        rules = cache.get("rules", [])
        entry_set_from_cache = frozenset(
            (r["action"], r["type"], r["pattern"])
            for raw in rules if (r := parse_rule_line(raw)) and "error" not in r
        )
        existing[bl["id"]] = {"name": bl["name"], "entries": entry_set_from_cache}
    for data in existing.values():
        if data["entries"] == entry_set:
            return data
    return None


def ensure_manual_blocklist_not_duplicate(url, text, list_type):
    duplicate = duplicate_blocklist_by_url(url, list_type)
    if duplicate:
        raise ValueError(f"List URL is already added as {duplicate.get('name', 'existing list')}")
    entry_set = parsed_blocklist_entry_set(text, list_type)
    duplicate = duplicate_blocklist_by_entries(entry_set, list_type)
    if duplicate:
        raise ValueError(f"List entries already exist as {duplicate.get('name', 'existing list')}")
    return entry_set


def enqueue_blocklist_imports(jobs):
    global blocklist_import_running
    if not jobs:
        return
    with blocklist_import_lock:
        was_running = blocklist_import_status["running"]
        blocklist_import_queue.extend(jobs)
        blocklist_import_status["queued"] = len(blocklist_import_queue)
        blocklist_import_status["total"] = blocklist_import_status["total"] + len(jobs) if was_running else len(jobs)
        if not was_running:
            blocklist_import_status.update({
                "running": True,
                "done": 0,
                "failed": 0,
                "current_id": None,
                "current": "",
                "last_error": "",
                "started_at": now_iso(),
                "finished_at": "",
            })
        if not blocklist_import_running:
            blocklist_import_running = True
            threading.Thread(target=blocklist_import_worker, name="blocklist-import", daemon=True).start()


def blocklist_import_worker():
    global blocklist_import_running
    should_reload = False
    try:
        while True:
            with blocklist_import_lock:
                if not blocklist_import_queue:
                    blocklist_import_status["running"] = False
                    blocklist_import_status["queued"] = 0
                    blocklist_import_status["current"] = ""
                    blocklist_import_status["finished_at"] = now_iso()
                    return
                job = blocklist_import_queue.pop(0)
                blocklist_import_status["queued"] = len(blocklist_import_queue)
                blocklist_import_status["current"] = job.get("name", "")
            try:
                list_type = "allow" if job.get("list_type") == "allow" else "block"
                if job.get("source") == "text":
                    console_event("work", "Blocklist import started", f"{job.get('name', '')} from pasted content")
                    with blocklist_import_lock:
                        blocklist_import_status["current"] = f"{job.get('name', '')} - checking"
                    if job.get("check_duplicates"):
                        ensure_manual_blocklist_not_duplicate("", job.get("content", ""), list_type)
                    with blocklist_import_lock:
                        blocklist_import_status["current"] = f"{job.get('name', '')} - saving"
                    count = blocklist_manager.add_from_text(
                        job.get("name", ""),
                        job.get("content", ""),
                        list_type,
                        replace_by_name=job.get("replace_by_name", True),
                        notify_reload=False,
                    )
                    if count <= 0:
                        raise ValueError("List contains no new rules")
                else:
                    url = job.get("url", "")
                    console_event("work", "Blocklist import started", f"{job.get('name', '')} from {url}")
                    with blocklist_import_lock:
                        blocklist_import_status["current"] = f"{job.get('name', '')} - checking"
                    if job.get("check_duplicates"):
                        duplicate = duplicate_blocklist_by_url(url, list_type)
                        if duplicate:
                            raise ValueError(f"List URL is already added as {duplicate.get('name', 'existing list')}")
                    with blocklist_import_lock:
                        blocklist_import_status["current"] = f"{job.get('name', '')} - downloading"
                    fetched = fetch_blocklist_url_text(url)
                    with blocklist_import_lock:
                        blocklist_import_status["current"] = f"{job.get('name', '')} - checking entries"
                    if job.get("check_duplicates"):
                        ensure_manual_blocklist_not_duplicate("", fetched["text"], list_type)
                    with blocklist_import_lock:
                        blocklist_import_status["current"] = f"{job.get('name', '')} - saving"
                    count = blocklist_manager.add_from_text(
                        job.get("name", ""),
                        fetched["text"],
                        list_type,
                        source=url,
                        sha256=fetched.get("sha256", ""),
                        etag=fetched.get("etag", ""),
                        last_modified=fetched.get("last_modified", ""),
                        replace_by_name=job.get("replace_by_name", True),
                        notify_reload=False,
                    )
                    if count <= 0:
                        raise ValueError("Downloaded list contains no new rules")
                should_reload = True
                with blocklist_import_lock:
                    blocklist_import_status["done"] += 1
                console_event("ok", "Blocklist imported", f"{job.get('name', '')} ({count} rules)")
            except Exception as exc:
                with blocklist_import_lock:
                    blocklist_import_status["failed"] += 1
                    blocklist_import_status["last_error"] = f"{job.get('name', 'List')}: {exc}"
                console_event("error", "Blocklist import failed", f"{job.get('name', 'List')}: {exc}")
            finally:
                if should_reload and not blocklist_import_queue:
                    try:
                        with blocklist_import_lock:
                            blocklist_import_status["current"] = "Reloading filter engine"
                        console_event("work", "Reloading filter engine")
                        reload_filter_engine()
                        console_event("ok", "Filter engine reloaded")
                    except Exception as exc:
                        with blocklist_import_lock:
                            blocklist_import_status["last_error"] = f"Filter reload failed: {exc}"
                    finally:
                        should_reload = False
    finally:
        with blocklist_import_lock:
            blocklist_import_running = False
            if not blocklist_import_queue:
                blocklist_import_status["running"] = False
                blocklist_import_status["queued"] = 0
                blocklist_import_status["current"] = ""
                blocklist_import_status["finished_at"] = blocklist_import_status.get("finished_at") or now_iso()


def current_blocklist_import_status():
    with blocklist_import_lock:
        return dict(blocklist_import_status)


def enqueue_blocklist_deletes(jobs):
    global blocklist_delete_running
    if not jobs:
        return
    with blocklist_delete_lock:
        was_running = blocklist_delete_status["running"]
        blocklist_delete_queue.extend(jobs)
        blocklist_delete_status["queued"] = len(blocklist_delete_queue)
        blocklist_delete_status["total"] = blocklist_delete_status["total"] + len(jobs) if was_running else len(jobs)
        if not was_running:
            blocklist_delete_status.update({
                "running": True,
                "done": 0,
                "failed": 0,
                "current": "",
                "last_error": "",
                "started_at": now_iso(),
                "finished_at": "",
            })
        if not blocklist_delete_running:
            blocklist_delete_running = True
            threading.Thread(target=blocklist_delete_worker, name="blocklist-delete", daemon=True).start()


def blocklist_delete_worker():
    global blocklist_delete_running
    should_reload = False
    try:
        while True:
            with blocklist_delete_lock:
                if not blocklist_delete_queue:
                    blocklist_delete_status["running"] = False
                    blocklist_delete_status["queued"] = 0
                    blocklist_delete_status["current"] = ""
                    blocklist_delete_status["current_id"] = None
                    blocklist_delete_status["finished_at"] = now_iso()
                    return
                job = blocklist_delete_queue.pop(0)
                job_name = job.get("name") or f"ID {job.get('id', '')}"
                blocklist_delete_status["queued"] = len(blocklist_delete_queue)
                blocklist_delete_status["current_id"] = job.get("id")
                blocklist_delete_status["current"] = job_name
            try:
                console_event("work", "Blocklist delete started", job_name)
                if blocklist_manager.delete(job.get("id"), notify_reload=False):
                    should_reload = True
                with blocklist_delete_lock:
                    blocklist_delete_status["done"] += 1
                console_event("ok", "Blocklist deleted", job_name)
            except Exception as exc:
                with blocklist_delete_lock:
                    blocklist_delete_status["failed"] += 1
                    blocklist_delete_status["last_error"] = f"{job.get('name', 'List')}: {exc}"
                console_event("error", "Blocklist delete failed", f"{job.get('name', 'List')}: {exc}")
            finally:
                if should_reload and not blocklist_delete_queue:
                    try:
                        console_event("work", "Reloading filter engine")
                        reload_filter_engine()
                        console_event("ok", "Filter engine reloaded")
                    except Exception as exc:
                        with blocklist_delete_lock:
                            blocklist_delete_status["last_error"] = f"Filter reload failed: {exc}"
                    finally:
                        should_reload = False
    finally:
        with blocklist_delete_lock:
            blocklist_delete_running = False
            if not blocklist_delete_queue:
                blocklist_delete_status["running"] = False
                blocklist_delete_status["queued"] = 0
                blocklist_delete_status["current"] = ""
                blocklist_delete_status["current_id"] = None
                blocklist_delete_status["finished_at"] = blocklist_delete_status.get("finished_at") or now_iso()


def current_blocklist_delete_status():
    with blocklist_delete_lock:
        return dict(blocklist_delete_status)


def enqueue_blocklist_toggle_reload():
    global blocklist_toggle_running, blocklist_toggle_pending
    with blocklist_toggle_lock:
        was_running = blocklist_toggle_status["running"]
        blocklist_toggle_pending += 1
        blocklist_toggle_status["queued"] = blocklist_toggle_pending
        blocklist_toggle_status["total"] = blocklist_toggle_status["total"] + 1 if was_running else 1
        if not was_running:
            blocklist_toggle_status.update({
                "running": True,
                "done": 0,
                "failed": 0,
                "current": "Waiting for more changes",
                "last_error": "",
                "started_at": now_iso(),
                "finished_at": "",
            })
        if not blocklist_toggle_running:
            blocklist_toggle_running = True
            threading.Thread(target=blocklist_toggle_reload_worker, name="blocklist-toggle-reload", daemon=True).start()


def blocklist_toggle_reload_worker():
    global blocklist_toggle_running, blocklist_toggle_pending
    try:
        while True:
            with blocklist_toggle_lock:
                seen_pending = blocklist_toggle_pending
                blocklist_toggle_status["queued"] = seen_pending
                blocklist_toggle_status["current"] = "Waiting for more changes"
            time.sleep(1.0)
            with blocklist_toggle_lock:
                if blocklist_toggle_pending != seen_pending:
                    continue
                blocklist_toggle_status["current"] = "Reloading filter engine"
            try:
                console_event("work", "Reloading filter engine", "Blocklist state changes")
                reload_filter_engine()
                console_event("ok", "Filter engine reloaded", "Blocklist state changes")
                with blocklist_toggle_lock:
                    blocklist_toggle_status["done"] += seen_pending
                    if blocklist_toggle_pending == seen_pending:
                        blocklist_toggle_pending = 0
                        blocklist_toggle_status["queued"] = 0
                        blocklist_toggle_status["running"] = False
                        blocklist_toggle_status["current"] = ""
                        blocklist_toggle_status["finished_at"] = now_iso()
                        return
                    blocklist_toggle_pending = max(0, blocklist_toggle_pending - seen_pending)
            except Exception as exc:
                with blocklist_toggle_lock:
                    blocklist_toggle_status["failed"] += seen_pending or 1
                    blocklist_toggle_status["last_error"] = f"Filter reload failed: {exc}"
                    if blocklist_toggle_pending == seen_pending:
                        blocklist_toggle_pending = 0
                        blocklist_toggle_status["queued"] = 0
                        blocklist_toggle_status["running"] = False
                        blocklist_toggle_status["current"] = ""
                        blocklist_toggle_status["finished_at"] = now_iso()
                        return
                    blocklist_toggle_pending = max(0, blocklist_toggle_pending - seen_pending)
    finally:
        with blocklist_toggle_lock:
            blocklist_toggle_running = False
            if not blocklist_toggle_pending:
                blocklist_toggle_status["running"] = False
                blocklist_toggle_status["queued"] = 0
                blocklist_toggle_status["current"] = ""
                blocklist_toggle_status["finished_at"] = blocklist_toggle_status.get("finished_at") or now_iso()


def current_blocklist_toggle_status():
    with blocklist_toggle_lock:
        return dict(blocklist_toggle_status)


def dedupe_existing_blocklist_entries():
    removed_by_list = {}
    kept_keys = set()
    for bl in blocklist_manager.get_all():
        bl_id = str(bl["id"])
        cache = load_blocklist_cache(bl_id)
        if not cache:
            continue
        list_type = "allow" if bl.get("list_type") == "allow" else "block"
        new_rules = []
        removed = 0
        for raw in cache.get("rules", []):
            result = parse_rule_line(raw)
            if result is None or "error" in result:
                new_rules.append(raw)
                continue
            key = (list_type, result["action"], result["type"], result["pattern"])
            if key in kept_keys:
                removed += 1
            else:
                kept_keys.add(key)
                new_rules.append(raw)
        if removed:
            cache["rules"] = new_rules
            cache["counts"]["converted"] = len(new_rules)
            save_blocklist_cache(bl_id, cache)
            removed_by_list[bl["id"]] = {"name": bl["name"], "removed": removed}
            with db_lock:
                db.execute("UPDATE blocklists SET rule_count=?, last_rule_count=? WHERE id=?",
                           (len(new_rules), len(new_rules), bl["id"]))
                db.commit()
    removed_total = sum(v["removed"] for v in removed_by_list.values())
    if removed_total:
        reload_filter_engine()
    return {
        "removed": removed_total,
        "lists": sorted(removed_by_list.values(), key=lambda item: item["name"].lower()),
    }


def queued_blocklist_delete_ids():
    with blocklist_delete_lock:
        ids = {int(job.get("id")) for job in blocklist_delete_queue if str(job.get("id", "")).isdigit()}
        current_id = blocklist_delete_status.get("current_id")
        if current_id is not None:
            try:
                ids.add(int(current_id))
            except (TypeError, ValueError):
                pass
        return ids


def blocklists_page(error="", selected_type="block", success=""):
    global blocklist_manager
    lists = blocklist_manager.get_all() if blocklist_manager else []
    adlist_presets = load_adlist_presets()
    block_rows = [bl for bl in lists if bl.get("list_type") != "allow"]
    allow_rows = [bl for bl in lists if bl.get("list_type") == "allow"]
    selected_type = "allow" if selected_type == "allow" else "block"

    preset_block_options = ""
    preset_allow_options = ""
    for idx, item in enumerate(adlist_presets["block"]):
        exists = preset_exists(item, block_rows)
        disabled = " disabled" if exists else ""
        extra_class = " preset-list-option-disabled" if exists else ""
        suffix = " <span class='text-secondary small'>Added</span>" if exists else ""
        preset_block_options += (
            f"<label class='preset-list-option{extra_class}'>"
            f"<input class='form-check-input bl-preset-choice' type='checkbox' name='preset_choice' value='block-{idx}'{disabled}>"
            f"<span>{html_escape(item['name'])}</span>"
            f"{suffix}"
            f"</label>"
        )
    for idx, item in enumerate(adlist_presets["allow"]):
        exists = preset_exists(item, allow_rows)
        disabled = " disabled" if exists else ""
        extra_class = " preset-list-option-disabled" if exists else ""
        suffix = " <span class='text-secondary small'>Added</span>" if exists else ""
        preset_allow_options += (
            f"<label class='preset-list-option{extra_class}'>"
            f"<input class='form-check-input bl-preset-choice' type='checkbox' name='preset_choice' value='allow-{idx}'{disabled}>"
            f"<span>{html_escape(item['name'])}</span>"
            f"{suffix}"
            f"</label>"
        )
    if not preset_block_options:
        preset_block_options = "<div class='text-secondary small py-2'>No blocklist presets found.</div>"
    if not preset_allow_options:
        preset_allow_options = "<div class='text-secondary small py-2'>No allowlist presets found.</div>"
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
    import_status = current_blocklist_import_status()
    delete_status = current_blocklist_delete_status()
    import_notice = ""
    if import_status.get("running"):
        current = import_status.get("current") or "Preparing import"
        import_notice = (
            "<div id='bl-job-status' class='alert alert-info py-2 mb-3'>"
            f"Blocklist import running: {html_escape(current)} "
            f"({import_status.get('done', 0)} done, {import_status.get('failed', 0)} failed, "
            f"{import_status.get('queued', 0)} queued)."
            "</div>"
        )
    if delete_status.get("running"):
        current = delete_status.get("current") or "Preparing delete"
        import_notice += (
            "<div id='bl-delete-status' class='alert alert-warning py-2 mb-3'>"
            f"Blocklist delete running: {html_escape(current)} "
            f"({delete_status.get('done', 0)} done, {delete_status.get('failed', 0)} failed, "
            f"{delete_status.get('queued', 0)} queued)."
            "</div>"
        )
    deleting_ids = queued_blocklist_delete_ids()
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
            deleting = bl["id"] in deleting_ids
            delete_action = (
                "<button class='btn btn-sm btn-outline-danger ms-2' disabled>Deleting</button>"
                if deleting else
                f"<form method='post' action='/blocklists/delete' class='d-inline ms-2'><input type='hidden' name='id' value='{bl['id']}'>"
                f"<button class='btn btn-sm btn-outline-danger' title='Delete'>&#x2716;</button></form>"
            )
            rows_html += (
                f"<tr><td data-label='Activate'>{bl_enabled_toggle(bl)}</td><td data-label='Name'>{html_escape(bl['name'])}</td><td data-label='URL' class='text-break' style='max-width:300px'>{html_escape(bl['url'] or '-')}</td>"
                f"<td data-label='Rules'>{bl['rule_count']}</td><td data-label='Updated'>{bl['last_update'] or '—'}</td>"
                f"<td data-label='Error' style='color:var(--danger)'>{html_escape(bl['last_error'] or '')}</td>"
                f"<td data-label='Actions'><button class='btn btn-sm btn-outline-light' onclick=\"document.getElementById('{eid}').classList.add('show')\">&#x270E;</button>"
                f"<form method='post' action='/blocklists/update' class='d-inline ms-2'><input type='hidden' name='id' value='{bl['id']}'>"
                f"<button class='btn btn-sm btn-outline-light' title='Update'>&#x21bb;</button></form>"
                f"{delete_action}</td></tr>"
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
</div>{notification}{import_notice}
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
  blPresetTypeChanged();
}}
function openBlocklistModal() {{
  var addType = document.getElementById('bl-add-type');
  var selected = document.getElementById('bl-type');
  if (addType && selected) addType.value = selected.value;
  setBlocklistAddMode('from-list');
  blPresetTypeChanged();
  document.getElementById('bl-modal').classList.add('show');
}}
function setBlocklistAddMode(mode) {{
  var fromList = mode === 'from-list';
  document.getElementById('bl-add-mode').value = mode;
  document.getElementById('bl-from-list-panel').style.display = fromList ? '' : 'none';
  document.getElementById('bl-manual-panel').style.display = fromList ? 'none' : '';
  document.getElementById('bl-mode-from-list').classList.toggle('active', fromList);
  document.getElementById('bl-mode-manual').classList.toggle('active', !fromList);
  document.getElementById('bl-manual-name').disabled = fromList;
  document.getElementById('bl-manual-url').disabled = fromList;
  document.getElementById('bl-manual-content').disabled = fromList;
  document.querySelectorAll('.bl-preset-choice').forEach(function(input) {{
    input.disabled = !fromList;
  }});
}}
function blPresetTypeChanged() {{
  var t = document.getElementById('bl-add-type').value;
  var blockPanel = document.getElementById('bl-preset-block');
  var allowPanel = document.getElementById('bl-preset-allow');
  if (blockPanel) blockPanel.style.display = t === 'block' ? '' : 'none';
  if (allowPanel) allowPanel.style.display = t === 'allow' ? '' : 'none';
  document.querySelectorAll('input[name="preset_choice"]').forEach(function(input) {{
    if (!input.value.startsWith(t + '-') || input.disabled) input.checked = false;
  }});
}}
function validateBlocklistAdd() {{
  if (document.getElementById('bl-add-mode').value !== 'from-list') return true;
  if (document.querySelector('input[name="preset_choice"]:checked')) return true;
  alert('Please select a list first.');
  return false;
}}
let blJobWasActive = false;
let blReloadScheduled = false;
function blEnsureStatusBox(id, cls) {{
  let el = document.getElementById(id);
  if (!el) {{
    el = document.createElement('div');
    el.id = id;
    el.className = cls + ' py-2 mb-3';
    const panel = document.querySelector('.panel');
    if (panel && panel.parentNode) panel.parentNode.insertBefore(el, panel);
  }}
  return el;
}}
function blFormatStatus(prefix, s) {{
  const fallback = prefix === 'Blocklist import' ? 'Preparing import' : (prefix === 'Blocklist delete' ? 'Preparing delete' : 'Preparing reload');
  const current = s.current || fallback;
  return `${{prefix}} running: ${{current}} (${{s.done || 0}} done, ${{s.failed || 0}} failed, ${{s.queued || 0}} queued).`;
}}
function blClearStatusBoxes() {{
  document.querySelectorAll('#bl-job-status,#bl-delete-status,#bl-toggle-status').forEach(function(el) {{ el.remove(); }});
}}
async function refreshBlocklistJobStatus() {{
  try {{
    const r = await fetch('/api/blocklists/job-status', {{cache:'no-store'}});
    if (!r.ok) return;
    const data = await r.json();
    const imp = data.import || {{}};
    const del = data.delete || {{}};
    const tog = data.toggle || {{}};
    const active = !!(imp.running || del.running || tog.running);
    if (!active) {{
      const hadStatusBox = !!document.querySelector('#bl-job-status,#bl-delete-status,#bl-toggle-status');
      blClearStatusBoxes();
      if ((blJobWasActive || hadStatusBox) && !blReloadScheduled) {{
        blReloadScheduled = true;
        setTimeout(function() {{ window.location.reload(); }}, 700);
      }}
      return;
    }}
    if (imp.running) {{
      blEnsureStatusBox('bl-job-status', 'alert alert-info').textContent = blFormatStatus('Blocklist import', imp);
    }} else {{
      document.querySelectorAll('#bl-job-status').forEach(function(el) {{ el.remove(); }});
    }}
    if (del.running) {{
      blEnsureStatusBox('bl-delete-status', 'alert alert-warning').textContent = blFormatStatus('Blocklist delete', del);
    }} else {{
      document.querySelectorAll('#bl-delete-status').forEach(function(el) {{ el.remove(); }});
    }}
    if (tog.running) {{
      blEnsureStatusBox('bl-toggle-status', 'alert alert-info').textContent = blFormatStatus('Blocklist reload', tog);
    }} else {{
      document.querySelectorAll('#bl-toggle-status').forEach(function(el) {{ el.remove(); }});
    }}
    blJobWasActive = true;
  }} catch (e) {{}}
}}
setTimeout(function() {{
  var n = document.getElementById('bl-notification');
  if (!n) return;
  n.style.transition = 'opacity .25s ease, transform .25s ease';
  n.style.opacity = '0';
  n.style.transform = 'translateY(-8px)';
  setTimeout(function() {{ n.remove(); }}, 280);
}}, 3500);
refreshBlocklistJobStatus();
setInterval(refreshBlocklistJobStatus, 1000);
</script>
<style>
.preset-list-option {{
  display:flex;
  align-items:center;
  gap:.6rem;
  padding:.55rem .65rem;
  border:1px solid rgba(148,163,184,.24);
  border-radius:6px;
  cursor:pointer;
}}
.preset-list-option:hover {{ background:rgba(148,163,184,.09); }}
.preset-list-option-disabled {{
  cursor:not-allowed;
  opacity:.55;
}}
.preset-list-option-disabled:hover {{ background:transparent; }}
.preset-list-option > span:first-of-type {{ flex:1; }}
.preset-list-scroll {{
  display:grid;
  gap:.4rem;
  max-height:min(52vh,520px);
  overflow:auto;
  padding-right:.25rem;
}}
</style>
<div id="bl-modal" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 class="h5" style="margin:0">Add Blocklist</h2>
      <button class="btn btn-sm btn-outline-light" onclick="document.getElementById('bl-modal').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
    </div>
    <form method="post" action="/blocklists/add" onsubmit="return validateBlocklistAdd()">
      <input type="hidden" id="bl-add-mode" name="add_mode" value="from-list">
      <div class="btn-group w-100 mb-3" role="group">
        <button id="bl-mode-from-list" type="button" class="btn btn-outline-light active" onclick="setBlocklistAddMode('from-list')">From List</button>
        <button id="bl-mode-manual" type="button" class="btn btn-outline-light" onclick="setBlocklistAddMode('manual')">Manual</button>
      </div>
      <label class="form-label">List Type</label><select id="bl-add-type" class="form-select mb-3" name="list_type" onchange="blPresetTypeChanged()"><option value="block" {"selected" if selected_type == "block" else ""}>Blocklist</option><option value="allow" {"selected" if selected_type == "allow" else ""}>Allowlist</option></select>
      <div id="bl-from-list-panel">
        <div id="bl-preset-block" class="preset-list-scroll">{preset_block_options}</div>
        <div id="bl-preset-allow" class="preset-list-scroll" style="display:none">{preset_allow_options}</div>
      </div>
      <div id="bl-manual-panel" style="display:none">
        <label class="form-label">Name</label><input id="bl-manual-name" class="form-control mb-2" name="name" placeholder="HaGeZi" required disabled>
        <label class="form-label">URL</label><input id="bl-manual-url" class="form-control mb-2" name="url" placeholder="https://raw.githubusercontent.com/..." disabled>
        <label class="form-label">Or paste list content</label><textarea id="bl-manual-content" class="form-control mb-3" name="content" rows="6" placeholder="0.0.0.0 ads.example.com&#10;||tracker.com^" disabled></textarea>
      </div>
      <button class="btn btn-success w-100" type="submit">Add</button>
    </form>
  </div>
</div>""", "Blocklists")


def rewrites_page():
    rewrites = rows("SELECT * FROM rules WHERE action = 'rewrite' ORDER BY id DESC LIMIT 500")
    edit_modals = ""
    table = "".join(
        f"<tr><td data-label='ID'>{r['id']}</td><td data-label='Enabled'>{toggle(r['enabled'])}</td>"
        f"<td data-label='Type'>{r['pattern_type']}</td><td data-label='Domain' class='td-domain'>{r['pattern']}</td>"
        f"<td data-label='Target' class='td-domain'>{r['target']}</td><td data-label='Comment'>{r['comment']}</td>"
        f"<td data-label='Actions'>"
        f"<button class='btn btn-sm btn-outline-light' type='button' onclick=\"document.getElementById('rwEdit-{r['id']}').classList.add('show')\">&#x270E;</button>"
        f"<form method='post' action='/rewrites/delete' style='display:inline;margin-left:.35rem'><input type='hidden' name='id' value='{r['id']}'>"
        f"<button class='btn btn-sm btn-outline-danger'>Delete</button></form></td></tr>"
        for r in rewrites
    )
    for r in rewrites:
        eid = f"rwEdit-{r['id']}"
        edit_modals += f"""
<div id="{eid}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 class="h5" style="margin:0">Edit Rewrite #{r['id']}</h2>
      <button class="btn btn-sm btn-outline-light" onclick="document.getElementById('{eid}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
    </div>
    <form method="post" action="/rewrites/edit">
      <input type="hidden" name="id" value="{r['id']}">
      <label class="form-label">Type</label><select class="form-select mb-2" name="pattern_type"><option value="domain" {"selected" if r['pattern_type'] == 'domain' else ""}>domain</option><option value="wildcard" {"selected" if r['pattern_type'] == 'wildcard' else ""}>wildcard</option><option value="regex" {"selected" if r['pattern_type'] == 'regex' else ""}>regex</option></select>
      <label class="form-label">Domain</label><input class="form-control mb-2" name="pattern" value="{html_escape(r['pattern'])}" required>
      <label class="form-label">Target (IP or CNAME)</label><input class="form-control mb-2" name="target" value="{html_escape(r['target'])}" required>
      <label class="form-label">Comment</label><input class="form-control mb-3" name="comment" value="{html_escape(r['comment'])}">
      <label class="form-check mb-3"><input type="hidden" name="enabled" value="0"><input class="form-check-input" type="checkbox" name="enabled" value="1" {"checked" if r['enabled'] else ""}><span class="form-check-label">Enabled</span></label>
      <button class="btn btn-success w-100" type="submit">Save</button>
    </form>
  </div>
</div>"""
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
</div>{edit_modals}""", "DNS Rewrites")


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
    data = um.get_all()
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
    edit_modals = ""
    def upstream_row(r):
        nonlocal edit_modals
        rid = r['id']
        edit_id = f"upstreamEdit-{rid}"
        enabled_checked = "checked" if r["enabled"] else ""
        edit_modals += f"""
<div id="{edit_id}" class="modal-overlay" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 class="h5" style="margin:0">Edit {html_escape(r['name'])}</h2>
      <button class="btn btn-sm btn-outline-light" type="button" onclick="document.getElementById('{edit_id}').classList.remove('show')" style="border:none;font-size:1.2rem">&times;</button>
    </div>
    <form method="post" action="/upstreams/edit">
      <input type="hidden" name="id" value="{rid}">
      <label class="form-label">Name</label><input class="form-control mb-2" name="name" value="{html_escape(r['name'])}" required>
      <label class="form-label">Resolver</label><input class="form-control mb-2" name="resolver" value="{html_escape(r['resolver'] or (r['address'] + ':' + str(r['port'])))}" required>
      <label class="form-label">DNSCrypt Relay (optional)</label><input class="form-control mb-2" name="dnscrypt_relay" value="{html_escape(r.get('dnscrypt_relay', ''))}" placeholder="sdns://gQ04OS4xMDYuNzguMTA2">
      <label class="settings-switch mb-3" for="upstream-enabled-{rid}">
        <span><span class="settings-label">Enabled</span><span class="settings-help">Use this upstream for DNS forwarding.</span></span>
        <input type="hidden" name="enabled" value="0">
        <span class="toggle settings-toggle">
          <input id="upstream-enabled-{rid}" type="checkbox" role="switch" name="enabled" value="1" {enabled_checked}>
          <span class="toggle-track"></span><span class="toggle-thumb"></span>
        </span>
      </label>
      <div style="display:flex;gap:.5rem;justify-content:flex-end">
        <button class="btn btn-outline-light" type="button" onclick="document.getElementById('{edit_id}').classList.remove('show')">Cancel</button>
        <button class="btn btn-success">Save</button>
      </div>
    </form>
  </div>
</div>"""
        return (
            f"<tr id='upstream-row-{rid}'>"
            f"<td data-label='Name'>{html_escape(r['name'])}</td>"
            f"<td data-label='Resolver' class='text-break'>{html_escape(r['resolver'] or (r['address'] + ':' + str(r['port'])))}</td>"
            f"<td data-label='Type'><span class='badge text-bg-secondary'>{html_escape(r['resolver_type'])}</span></td>"
            f"<td data-label='Transport'>{html_escape(r['transport'])}</td>"
            f"<td data-label='Relay' class='text-break'>{html_escape(r.get('dnscrypt_relay', ''))}</td>"
            f"<td data-label='Enabled'>{upstream_toggle(r)}</td>"
            f"<td data-label='Latency ms' id='upstream-latency-{rid}'>{latency_badge(r)}</td>"
            f"<td data-label='Error' class='text-secondary' id='upstream-error-{rid}'>{html_escape(r['last_error'])}</td>"
            f"<td data-label='Actions' class='d-flex gap-2'>"
            f"<button class='btn btn-sm btn-outline-light' onclick='testUpstream({rid},this)'>Test</button>"
            f"<button class='btn btn-sm btn-outline-light' type='button' onclick=\"document.getElementById('{edit_id}').classList.add('show')\">Edit</button>"
            f"<form method='post' action='/upstreams/delete'><input type='hidden' name='id' value='{rid}'><button class='btn btn-sm btn-outline-danger'>Delete</button></form>"
            f"</td></tr>"
        )
    table = "".join(upstream_row(r) for r in data)
    mode_options = select_options([
        ("sequential",       "Sequential - try upstreams one after another"),
        ("load_balance",     "Load balancing - round-robin across upstreams"),
        ("parallel_fastest", "Parallel fastest - race top N upstreams"),
        ("parallel_race",    "Parallel race - race all upstreams, first valid wins"),
        ("fastest_addr",     "Fastest address - sort by lowest latency"),
        ("strict_order",     "Strict order - use first upstream only, fallback on failure"),
    ], current_mode)
    mode_desc = {
        "sequential":       "Upstreams are queried in order. If one fails, the next one is tried.",
        "load_balance":     "One upstream server is queried at a time. Requests are distributed across all active upstreams with round-robin.",
        "parallel_fastest": "Parallel queries speed up resolution by racing the top N upstreams. The fastest response wins.",
        "parallel_race":    "All upstreams are queried simultaneously. The first valid response wins. Slower upstreams do not block fast responses.",
        "fastest_addr":     "Upstreams are sorted by average latency. The fastest upstream is tried first.",
        "strict_order":     "Only the first upstream is used. If it fails, the next one is tried as fallback.",
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
<label class="form-label">DNSCrypt Relay (optional)</label><input class="form-control mb-2" id="relay-input" name="dnscrypt_relay" placeholder="sdns://gQ04OS4xMDYuNzguMTA2">
<div class="alert alert-secondary py-2" id="relay-detect">Relay is used only for DNSCrypt upstream stamps.</div>
<div class="alert alert-secondary py-2" id="resolver-detect">Type is detected automatically.</div>
<div class="small text-secondary mb-3">Use <code>https://domain/dns-query</code> for DNS-over-HTTPS, <code>h3://domain/dns-query</code> for DNS-over-HTTPS over QUIC/HTTP3, <code>tls://domain</code> for pooled DNS-over-TLS, or <code>sdns://...</code> for DNSCrypt/DoH stamps. A DNSCrypt relay stamp can be pasted into Resolver to save it as a relay entry; active relay entries are used automatically by DNSCrypt upstreams without their own relay.</div>
<button class="btn btn-success w-100">Save</button></form></div>
<div class="col-xl-8"><div class="panel rounded-2 border border-secondary-subtle p-3"><div class="table-responsive"><table class="table table-dark table-hover mobile-card-table"><thead><tr><th>Name</th><th>Resolver</th><th>Type</th><th>Transport</th><th>Relay</th><th>Enabled</th><th>Latency ms</th><th>Error</th><th></th></tr></thead><tbody>{table}</tbody></table></div></div></div></div>
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
const relayInput = document.getElementById('relay-input');
const relayDetect = document.getElementById('relay-detect');
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
    if (data.type === 'dnscrypt_relay') {{
      resolverDetect.textContent = data.label + ' - saved as relay entry and used by DNSCrypt upstreams.';
      resolverDetect.className = 'alert py-2 alert-success';
    }} else {{
      resolverDetect.textContent = data.label + (data.supported ? ' - forwarding active.' : ' - detected, forwarding is not implemented yet.');
      resolverDetect.className = 'alert py-2 ' + (data.supported ? 'alert-success' : 'alert-warning');
    }}
  }} catch (error) {{}}
}}
resolverInput.addEventListener('input', detectResolver);
async function detectRelay() {{
  const relay = relayInput.value.trim();
  if (!relay) {{
    relayDetect.textContent = 'Relay is used only for DNSCrypt upstream stamps.';
    relayDetect.className = 'alert alert-secondary py-2';
    return;
  }}
  try {{
    const response = await fetch('/api/upstreams/detect?resolver=' + encodeURIComponent(relay), {{cache:'no-store'}});
    const data = await response.json();
    const ok = data.type === 'dnscrypt_relay';
    relayDetect.textContent = data.label;
    relayDetect.className = 'alert py-2 ' + (ok ? 'alert-success' : 'alert-warning');
  }} catch (error) {{}}
}}
relayInput.addEventListener('input', detectRelay);
</script>{edit_modals}""", "Upstreams")


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
.settings-subhead{{font-size:.72rem;font-weight:800;letter-spacing:.07em;text-transform:uppercase;color:var(--muted2);margin-top:.4rem;padding-top:.85rem;border-top:1px solid rgba(30,45,61,.55)}}
.settings-subhead:first-child{{margin-top:0;padding-top:0;border-top:none}}
.settings-toggle{{margin-left:auto}}
.settings-actions{{display:flex;justify-content:flex-end;gap:.65rem;margin-top:.1rem}}
.settings-textarea{{min-height:150px;font-family:ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace;font-size:.8rem;line-height:1.35;resize:vertical}}
.settings-pem-field{{background:#0a1018;border:1px solid rgba(30,45,61,.7);border-radius:.5rem;padding:1rem;transition:all .2s}}
.settings-pem-field:hover{{border-color:#2f455e;background:#0d1626}}
.settings-pem-field:focus-within{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(124,58,237,.1)}}
.settings-pem-label{{display:flex;align-items:center;gap:.5rem;font-size:.85rem;font-weight:700;color:var(--text);margin-bottom:.65rem}}
.settings-pem-label svg{{opacity:.7}}
.settings-pem-textarea{{width:100%;min-height:180px;font-family:ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace;font-size:.78rem;line-height:1.5;resize:vertical;background:#050810;border:1px solid rgba(30,45,61,.5);border-radius:.4rem;padding:.85rem;color:#e2e8f0;transition:all .2s;tab-size:2}}
.settings-pem-textarea:focus{{outline:none;border-color:var(--accent);background:#060a12;box-shadow:0 0 0 3px rgba(124,58,237,.08)}}
.settings-pem-textarea::placeholder{{color:rgba(100,116,139,.5)}}
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
    <div style="display:flex;gap:.65rem;align-items:center">
      <button type="button" class="btn btn-outline-light" id="settings-update-btn" onclick="settingsCheckUpdate()">
        <svg style="vertical-align:middle;margin-right:.35rem" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        Check for Updates
      </button>
      <button class="btn btn-success">Save Changes</button>
    </div>
  </div>
  <div id="settings-update-result"></div>
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

        <div class="settings-subhead">Web &amp; DNS Listener</div>
        <div class="settings-field-grid">
          <div><label class="form-label">LOCALDNSGUARD_WEB_HOST</label><input class="form-control" name="localdnsguard_web_host" value="{html_escape(value('localdnsguard_web_host', WEB_HOST))}"></div>
          <div><label class="form-label">LOCALDNSGUARD_WEB_PORT</label><input class="form-control" name="localdnsguard_web_port" type="number" min="0" max="65535" value="{html_escape(value('localdnsguard_web_port', WEB_PORT))}"></div>
          <div><label class="form-label">LOCALDNSGUARD_DNS_HOST</label><input class="form-control" name="localdnsguard_dns_host" value="{html_escape(value('localdnsguard_dns_host', DNS_HOST))}"></div>
          <div><label class="form-label">LOCALDNSGUARD_DNS_PORT</label><input class="form-control" name="localdnsguard_dns_port" type="number" min="0" max="65535" value="{html_escape(value('localdnsguard_dns_port', DNS_PORT))}"></div>
        </div>

        <div class="settings-subhead">Upstream &amp; Validation Timeouts</div>
        <div class="settings-field-grid">
          <div><label class="form-label">Upstream Timeout</label><input class="form-control" name="upstream_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('upstream_timeout', '2.5'))}"></div>
          <div><label class="form-label">TCP Connect Timeout</label><input class="form-control" name="tcp_connect_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('tcp_connect_timeout', '3.0'))}"></div>
          <div><label class="form-label">TLS Handshake Timeout</label><input class="form-control" name="tls_handshake_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('tls_handshake_timeout', '4.0'))}"></div>
        </div>
        <div class="settings-field-grid">
          <div><label class="form-label">DNS Query Timeout</label><input class="form-control" name="dns_query_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('dns_query_timeout', '2.5'))}"></div>
          <div><label class="form-label">DNSSEC Validation Timeout</label><input class="form-control" name="dnssec_validation_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('dnssec_validation_timeout', '3.0'))}"></div>
        </div>
        <div class="settings-field-grid">
          <div><label class="form-label">DoQ Total Timeout</label><input class="form-control" name="doq_total_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('doq_total_timeout', '1.8'))}"></div>
          <div><label class="form-label">DoH/3 Total Timeout</label><input class="form-control" name="doh3_total_timeout" type="number" min="0.1" step="0.1" value="{html_escape(value('doh3_total_timeout', '2.2'))}"></div>
        </div>

        <div class="settings-subhead">Encrypted DNS Endpoints</div>
        <div class="settings-field-grid">
          <div><label class="form-label">Encrypted DNS Listen Host</label><input class="form-control" name="encrypted_dns_host" value="{html_escape(value('encrypted_dns_host', DNS_HOST))}"></div>
          <div><label class="form-label">Public DNS Domain</label><input class="form-control" name="encrypted_dns_domain" placeholder="dns.example.com" value="{html_escape(value('encrypted_dns_domain', ENCRYPTED_DNS_DOMAIN))}"></div>
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
          <div class="settings-pem-field">
            <label class="settings-pem-label">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
              Certificate PEM
            </label>
            <textarea class="settings-pem-textarea" name="encrypted_dns_certificate_pem" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gc...&#10;-----END CERTIFICATE-----">{html_escape(value('encrypted_dns_certificate_pem', ''))}</textarea>
          </div>
          <div class="settings-pem-field">
            <label class="settings-pem-label">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              RSA Private Key PEM
            </label>
            <textarea class="settings-pem-textarea" name="encrypted_dns_private_key_pem" spellcheck="false" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWeF...&#10;-----END RSA PRIVATE KEY-----">{html_escape(value('encrypted_dns_private_key_pem', ''))}</textarea>
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
          <div class="settings-section-subtitle">TTL limits, memory budget, negative cache, prefetch, and stale serving.</div>
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
        <div class="settings-field-grid">
          {switch("negative_cache_enabled", "Negative Cache", "Cache NXDOMAIN and NODATA responses to reduce upstream queries.", "1")}
          <div><label class="form-label">Negative Cache Max TTL (sec.)</label><input class="form-control" name="negative_cache_max_ttl" type="number" min="0" value="{get_setting('negative_cache_max_ttl','300')}"></div>
          <div><label class="form-label">Negative Cache Min TTL (sec.)</label><input class="form-control" name="negative_cache_min_ttl" type="number" min="0" value="{get_setting('negative_cache_min_ttl','30')}"></div>
        </div>
        <div class="settings-field-grid">
          {switch("prefetch_enabled", "Prefetch Cache", "Refresh frequently used domains before TTL expires.", "1")}
          <div><label class="form-label">Prefetch Min Hits</label><input class="form-control" name="prefetch_min_hits" type="number" min="1" value="{get_setting('prefetch_min_hits','3')}"></div>
          <div><label class="form-label">Prefetch TTL Percentage</label><input class="form-control" name="prefetch_ttl_percentage" type="number" min="1" max="100" value="{get_setting('prefetch_ttl_percentage','20')}"></div>
        </div>
        <div class="settings-field-grid">
          {switch("serve_stale_enabled", "Serve Stale", "Serve expired cache entries when upstream is unavailable.", "0")}
          <div><label class="form-label">Serve Stale Max Age (sec.)</label><input class="form-control" name="serve_stale_max_age" type="number" min="0" value="{get_setting('serve_stale_max_age','86400')}"></div>
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

async function settingsCheckUpdate() {{
  const btn = document.getElementById('settings-update-btn');
  const result = document.getElementById('settings-update-result');
  if (!btn || !result) return;
  
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Checking...';
  result.innerHTML = '';
  
  try {{
    const r = await fetch('/api/update/check?force=1', {{cache:'no-store'}});
    const d = await r.json();
    
    if (d.ok) {{
      if (d.available && d.count > 0) {{
        const commitList = d.commits.slice(0, 5).map(c => `<li>${{c}}</li>`).join('');
        const moreText = d.count > 5 ? `<li>...and ${{d.count - 5}} more</li>` : '';
        result.innerHTML = `
          <div class="alert alert-warning">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem">
              <div>
                <strong>Update available: ${{d.count}} new commit${{d.count > 1 ? 's' : ''}}</strong>
                <ul style="margin:.5rem 0 0 0;padding-left:1.5rem;font-size:.85rem">${{commitList}}${{moreText}}</ul>
                <div style="margin-top:.5rem;font-size:.85rem;color:var(--muted2)">Use "Apply Update" to install and restart</div>
              </div>
              <button type="button" class="btn btn-dark" onclick="settingsApplyUpdate()">Apply Update</button>
            </div>
          </div>
        `;
      }} else {{
        result.innerHTML = '<div class="alert alert-success">No updates available. You are up to date.</div>';
      }}
    }} else {{
      result.innerHTML = `<div class="alert alert-danger">Update check failed: ${{d.error || 'Unknown error'}}</div>`;
    }}
  }} catch(e) {{
    result.innerHTML = `<div class="alert alert-danger">Update check failed: ${{e.message}}</div>`;
  }} finally {{
    btn.disabled = false;
    btn.innerHTML = '<svg style="vertical-align:middle;margin-right:.35rem" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>Check for Updates';
  }}
}}

async function settingsApplyUpdate() {{
  const result = document.getElementById('settings-update-result');
  if (result) {{
    result.innerHTML = `
      <div class="alert alert-info text-center">
        <span class="spinner-border spinner-border-sm me-2"></span>
        <strong>Applying update...</strong> Server will restart.
      </div>
    `;
  }}
  
  try {{
    const r = await fetch('/api/update/apply', {{method:'POST'}});
    const d = await r.json();
    if (!d.ok) {{
      result.innerHTML = `<div class="alert alert-danger">Update failed: ${{d.error || 'Unknown error'}}</div>`;
    }}
  }} catch(e) {{
    result.innerHTML = `<div class="alert alert-danger">Update failed: ${{e.message}}</div>`;
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
             '{\n  "today": {"total": 1024, "blocked": 312, "avg_ms": 14.2},\n  "sparklines": {"total": [...24 values...], "blocked": [...24 values...]},\n  "top_domains": [{"domain": "example.com", "cnt": 45}],\n  "top_blocked": [...],\n  "top_cache_domains": [...],\n  "top_upstreams": [...],\n  "top_clients": [...]\n}'),
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
        ("Updates", [
            ("GET", "/api/update/check", "Check GitHub for new commits. Use ?force=1 to bypass the 6-hour cache.",
             None,
             '{\n  "ok": true,\n  "available": true,\n  "count": 3,\n  "commits": ["abc1234 Fix bug", "def5678 Add feature", ...]\n}'),
            ("POST", "/api/update/apply", "Download and install the latest update from GitHub, then restart the server.",
             None,
             '{\n  "ok": true,\n  "output": "Update erfolgreich installiert (abc1234)"\n}'),
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
            step_rows += (
                "<div class='domain-test-row'>"
                f"<div class='domain-test-label'>{html_escape(str(item.get('step', '')))}</div>"
                f"<div class='domain-test-value'>{detail or '-'}</div>"
                "</div>"
            )
        steps_html = f"""
  <div class="domain-test-list">{step_rows}</div>"""

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
        rows_html += (
            "<div class='domain-test-row'>"
            f"<div class='domain-test-label'>{html_escape(label)}</div>"
            f"<div class='domain-test-value'>{value_html}</div>"
            "</div>"
        )

    return f"""
<div class="panel rounded-2 border border-secondary-subtle p-3">
  <div class="panel-head px-0 pt-0"><span class="panel-title">Test Result</span></div>
  <div class="domain-test-list">{rows_html}</div>
</div>"""


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
    prefix = "ad::" if action == "allow" else "bd::"
    pg_rule = f"{prefix}{domain}"
    if scope == "global":
        current = read_rules()
        if current and not current.endswith("\n"):
            current += "\n"
        current += pg_rule + "\n"
        write_rules(current)
        invalidate_rules_cache()
        return {"ok": True, "scope": "global", "action": action, "pattern": domain, "rule": pg_rule}
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
        _invalidate_settings_cache()
        counts["settings"] = len(settings_rows)
        rule_lines = []
        for row in data.get("rules", []):
            action = row.get("action", "block")
            pt = row.get("pattern_type", "domain")
            pattern = row.get("pattern", "")
            if not pattern:
                continue
            prefix_map = {"block": {"domain": "bd::", "exact": "bd::", "wildcard": "bs::", "regex": "br::"},
                          "allow": {"domain": "ad::", "exact": "ad::", "wildcard": "as::", "regex": "ar::"}}
            prefix = prefix_map.get(action, {}).get(pt, "bd::")
            rule_lines.append(f"{prefix}{pattern}")
        for row in data.get("dns_rewrites", []):
            pattern = row.get("pattern", "")
            target = row.get("target", "")
            if pattern and target:
                rule_lines.append(f"# rewrite: {pattern} -> {target}")
        if rule_lines:
            write_rules("\n".join(rule_lines) + "\n")
        counts["rules"] = len(rule_lines)
        db.execute("DELETE FROM blocklists")
        restored_blocklists = 0
        for row in data.get("blocklists", []):
            name = row.get("name", "") or "unknown"
            url = row.get("url", row.get("source", ""))
            list_type = "allow" if row.get("list_type") == "allow" else "block"
            enabled = int(row.get("enabled", 1))
            last_update = row.get("last_update", "")
            last_error = ""
            content = row.get("content", "")
            entries = []
            if not content and str(url).startswith(("http://", "https://")):
                try:
                    fetched = fetch_url_text(url)
                    content = fetched["text"]
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
            if content:
                list_id_str = str(bl_id)
                result = convert_blocklist_text(content, list_id_str, url)
                save_blocklist_cache(list_id_str, result["cache"])
                save_cosmetic_rules(list_id_str, result["cosmetic"])
                save_unsupported_rules(list_id_str, result["unsupported"])
                if not url:
                    save_original_text(list_id_str, content)
            restored_blocklists += 1
        counts["blocklists"] = restored_blocklists
        for up in um.get_all():
            um.delete(up["id"])
        for row in data.get("upstreams", []):
            um.create(row.get("name",""), row.get("address","1.1.1.1"), int(row.get("port",53)),
                      row.get("resolver",""), row.get("resolver_type","plain_udp"),
                      row.get("transport","udp"), row.get("dnscrypt_relay",""),
                      enabled=bool(row.get("enabled",1)),
                      latency_ms=row.get("latency_ms"), last_error=row.get("last_error",""),
                      created_at=row.get("created_at", now_iso()))
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
    regex_stats = get_filter_engine().regex_index_stats()
    dot_metrics = dot_pool_metrics()
    quic_metrics = quic_pool_metrics()
    queue_metrics = upstream_queue_wait_metrics()
    dnssec_metrics = get_dnssec_metrics()
    validator = get_dnssec_validator()
    dnssec_cache = validator.cache_stats() if validator else {}
    dnssec_anchor = validator.trust_anchor_info() if validator else {}
    return {
        "total_queries": summary.get("total", 0),
        "blocked_queries": summary.get("blocked", 0),
        "block_rate": summary.get("block_rate", 0.0),
        "avg_response_ms": summary.get("avg_ms", 0.0),
        "cache_rate": summary.get("cache_rate", 0.0),
        "active_clients": summary.get("clients", 0),
        "filter_rules": summary.get("rules", 0),
        "active_upstreams": summary.get("upstreams", 0),
        **regex_stats,
        "cache_entries": cache_stats_data.get("entries", 0),
        "cache_bytes": cache_stats_data.get("bytes_used", 0),
        "dnssec_secure": dnssec_metrics.get("secure", 0),
        "dnssec_insecure": dnssec_metrics.get("insecure", 0),
        "dnssec_bogus": dnssec_metrics.get("bogus", 0),
        "dnssec_indeterminate": dnssec_metrics.get("indeterminate", 0),
        "dnssec_validation_seconds": dnssec_metrics.get("validation_seconds_total", 0.0),
        "dnssec_nsec_validations": dnssec_metrics.get("nsec_validations", 0),
        "dnssec_nsec3_validations": dnssec_metrics.get("nsec3_validations", 0),
        "dnssec_nsec3_failures": dnssec_metrics.get("nsec3_failures", 0),
        "dnssec_dnskey_cache_entries": dnssec_cache.get("dnskey_cache_entries", 0),
        "dnssec_rfc5011_enabled": dnssec_anchor.get("rfc5011_auto_update", False),
        "dnssec_active_ksks": len(dnssec_anchor.get("active_ksks", [])),
        "dnssec_pending_ksks": len(dnssec_anchor.get("pending_ksks", [])),
        "dnssec_revoked_ksks": len(dnssec_anchor.get("revoked_ksks", [])),
        "dnssec_retired_ksks": len(dnssec_anchor.get("retired_ksks", [])),
        "dnssec_last_rfc5011_check": dnssec_anchor.get("last_checked", ""),
        "dnssec_next_rfc5011_check": dnssec_anchor.get("next_check", ""),
        "dnssec_last_error": dnssec_anchor.get("last_error", ""),
        **dot_metrics,
        **quic_metrics,
        **queue_metrics,
        **get_runtime_metrics(),
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
            profile = client_manager.get_profile(pid) if client_manager else None
            if client_manager and client_manager.delete_profile(pid):
                pname = profile["name"] if profile else f"ID {pid}"
                console_event("info", "Profile deleted", pname)
                self.send_json({"ok": True})
            else:
                console_event("warn", "Profile delete failed", f"ID {pid} not found or default profile")
                self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+/rules/\d+$", path):
            parts = path.strip("/").split("/")
            pid = int(parts[2])
            rule_id = int(parts[4])
            profile = client_manager.get_profile(pid) if client_manager else None
            rule = next((r for r in client_manager.get_profile_rules(pid) if int(r["id"]) == rule_id), None) if client_manager else None
            if client_manager and client_manager.delete_profile_rule(rule_id):
                pname = profile["name"] if profile else f"ID {pid}"
                detail = f"#{rule['id']} {rule['action']} {rule['pattern_type']} {rule['pattern']}" if rule else f"#{rule_id}"
                console_event("info", "Profile rule deleted", f"{pname}: {detail}")
                self.send_json({"ok": True})
            else:
                console_event("warn", "Profile rule delete failed", f"ID {rule_id} not found")
                self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+/blocklists/\d+$", path):
            parts = path.strip("/").split("/")
            pid = int(parts[2])
            bl_id = int(parts[4])
            profile = client_manager.get_profile(pid) if client_manager else None
            bl = blocklist_manager.get_by_id(bl_id) if blocklist_manager else None
            if client_manager and client_manager.remove_blocklist_from_profile(pid, bl_id):
                pname = profile["name"] if profile else f"ID {pid}"
                bname = bl["name"] if bl else f"ID {bl_id}"
                console_event("info", "Profile blocklist removed", f"{pname}: {bname}")
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "not found"}, 404)
        elif re.search(r"/api/profiles/\d+/services/\w+$", path):
            parts = path.strip("/").split("/")
            pid = int(parts[2])
            svc = parts[4]
            if client_manager is not None:
                profile = client_manager.get_profile(pid)
                if client_manager.remove_profile_service(pid, svc):
                    pname = profile["name"] if profile else f"ID {pid}"
                    console_event("info", "Profile service block removed", f"{pname}: {svc}")
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
        if path == "/rules/save":
            new_rules = form.get("rules", "")
            write_rules(new_rules)
            errs = validate_rules(new_rules)
            cnts = count_rules(new_rules)
            if errs:
                console_event("warn", "Rules saved with errors", f"{len(errs)} invalid rule(s), {cnts['total']} valid")
            else:
                console_event("ok", "Rules saved", f"{cnts['total']} valid rules")
            invalidate_rules_cache(reload_now=False)
            enqueue_rules_reload("Rules saved")
            self.redirect("/rules")
        elif path == "/rules/add":
            action = form.get("action", "block")
            pattern_type = form.get("pattern_type", "domain")
            pattern = normalize_domain(form.get("pattern", ""))
            target = form.get("target", "")
            with db_lock:
                cur = db.execute(
                    "INSERT INTO rules(action,pattern_type,pattern,target,comment,created_at) VALUES(?,?,?,?,?,?)",
                    (action, pattern_type, pattern, target, form.get("comment", ""), now_iso()),
                )
                db.commit()
            console_event("ok", "Rule added", f"#{cur.lastrowid} {action} {pattern_type} {pattern}")
            invalidate_rules_cache(reload_now=False)
            enqueue_rules_reload("Rule added")
            self.redirect("/rules")
        elif path == "/blocklists/add":
            global blocklist_manager
            name = form.get("name", "").strip()
            url = form.get("url", "").strip()
            list_type = "allow" if form.get("list_type") == "allow" else "block"
            content = form.get("content", "")
            try:
                queued_jobs = []
                if form.get("add_mode") == "from-list":
                    preset_choices = form.get_all("preset_choice")
                    prefix = f"{list_type}-"
                    if not preset_choices:
                        raise ValueError("Select at least one list")
                    preset_items = load_adlist_presets()[list_type]
                    selected_presets = []
                    for preset_choice in preset_choices:
                        if not preset_choice.startswith(prefix):
                            raise ValueError("Select valid lists")
                        try:
                            preset_index = int(preset_choice[len(prefix):])
                        except ValueError:
                            raise ValueError("Select valid lists")
                        if preset_index < 0 or preset_index >= len(preset_items):
                            raise ValueError("Select valid lists")
                        selected_presets.append(preset_items[preset_index])
                    existing_rows = blocklist_manager.get_all() if blocklist_manager else []
                    existing_rows = [
                        row for row in existing_rows
                        if ("allow" if row.get("list_type") == "allow" else "block") == list_type
                    ]
                    selected_presets = [
                        preset for preset in selected_presets
                        if not preset_exists(preset, existing_rows)
                    ]
                    if not selected_presets:
                        raise ValueError("Selected lists are already added")
                    queued_jobs = [
                        {
                            "source": "url",
                            "name": preset["name"],
                            "url": preset["url"],
                            "list_type": list_type,
                            "replace_by_name": True,
                            "check_duplicates": False,
                        }
                        for preset in selected_presets
                    ]
                else:
                    if url:
                        duplicate = duplicate_blocklist_by_url(url, list_type)
                        if duplicate:
                            raise ValueError(f"List URL is already added as {duplicate.get('name', 'existing list')}")
                        queued_jobs = [{
                            "source": "url",
                            "name": name,
                            "url": url,
                            "list_type": list_type,
                            "replace_by_name": False,
                            "check_duplicates": True,
                        }]
                    elif content.strip():
                        queued_jobs = [{
                            "source": "text",
                            "name": name,
                            "content": content,
                            "list_type": list_type,
                            "replace_by_name": False,
                            "check_duplicates": True,
                        }]
                    else:
                        raise ValueError("Provide URL or paste content")
                enqueue_blocklist_imports(queued_jobs)
                queued_count = len(queued_jobs)
                success_msg = "List import queued" if queued_count == 1 else f"{queued_count} list imports queued"
                self.redirect(f"/blocklists?type={list_type}&success={quote(success_msg)}")
            except Exception as exc:
                self.redirect(f"/blocklists?type={list_type}&error={quote(str(exc))}")
        elif path == "/blocklists/update":
            try:
                bl_id = form.get("id")
                if not bl_id:
                    raise ValueError("No blocklist ID provided")
                bl_id = int(bl_id)
                bl_item = blocklist_manager.get_by_id(bl_id) if blocklist_manager else None
                if not bl_item:
                    raise ValueError("Blocklist not found")
                if not bl_item.get("url", "").startswith(("http://", "https://")):
                    raise ValueError("Blocklist has no remote URL to update from")
                blocklist_manager.update(bl_id)
                list_type = "allow" if bl_item.get("list_type") == "allow" else "block"
                self.redirect(f"/blocklists?type={list_type}&success={quote('Update started')}")
            except Exception as exc:
                list_type = form.get("list_type", "block")
                self.redirect(f"/blocklists?type={list_type}&error={quote(str(exc))}")
        elif path == "/blocklists/toggle":
            bl_id = int(form.get("id"))
            enabled = form.get("enabled") == "1"
            item = blocklist_manager.get_by_id(bl_id) if blocklist_manager else None
            if blocklist_manager and blocklist_manager.set_enabled(bl_id, enabled, notify_reload=False):
                name = item.get("name") if item else f"ID {bl_id}"
                state = "active" if enabled else "inactive"
                console_event("ok", f"Blocklist set {state}", name)
                enqueue_blocklist_toggle_reload()
            else:
                console_event("warn", "Blocklist toggle failed", f"ID {bl_id} not found")
            self.redirect("/blocklists")
        elif path == "/blocklists/delete":
            bl_id = int(form.get("id"))
            item = blocklist_manager.get_by_id(bl_id) if blocklist_manager else None
            if item:
                list_type = "allow" if item.get("list_type") == "allow" else "block"
                if bl_id not in queued_blocklist_delete_ids():
                    enqueue_blocklist_deletes([{"id": bl_id, "name": item.get("name", f"ID {bl_id}")}])
                self.redirect(f"/blocklists?type={list_type}&success={quote('List delete queued')}")
            else:
                self.redirect(f"/blocklists?error={quote('List not found')}")
        elif path == "/blocklists/edit":
            bl_id = int(form.get("id"))
            name = form.get("name", "").strip()
            url = form.get("url", "").strip()
            list_type = form.get("list_type", "block")
            if name:
                blocklist_manager.update_metadata(bl_id, name, url, list_type)
            self.redirect("/blocklists")
        elif path == "/rules/delete":
            self.redirect("/rules")
        elif path == "/rewrites/add":
            pattern_type = form.get("pattern_type", "domain")
            pattern = normalize_domain(form.get("pattern", ""))
            target = form.get("target", "")
            with db_lock:
                cur = db.execute(
                    "INSERT INTO rules(action,pattern_type,pattern,target,comment,created_at) VALUES(?,?,?,?,?,?)",
                    ("rewrite", pattern_type, pattern, target, form.get("comment", ""), now_iso()),
                )
                db.commit()
            console_event("ok", "Rewrite rule added", f"#{cur.lastrowid} {pattern_type} {pattern} -> {target}")
            invalidate_rules_cache(reload_now=False)
            enqueue_rules_reload("Rewrite rule added")
            self.redirect("/rewrites")
        elif path == "/rewrites/edit":
            with db_lock:
                rule = db.execute("SELECT id FROM rules WHERE id=?", (form.get("id"),)).fetchone()
                if rule:
                    pattern_type = form.get("pattern_type", "domain")
                    pattern = normalize_domain(form.get("pattern", ""))
                    target = form.get("target", "")
                    comment = form.get("comment", "")
                    enabled = 1 if form.get("enabled") == "1" else 0
                    db.execute(
                        "UPDATE rules SET pattern_type=?,pattern=?,target=?,comment=?,enabled=? WHERE id=?",
                        (pattern_type, pattern, target, comment, enabled, rule["id"]),
                    )
                    db.commit()
                    console_event("ok", "Rewrite rule updated", f"#{rule['id']} {pattern_type} {pattern} -> {target}")
                else:
                    console_event("warn", "Rewrite rule edit failed", f"ID {form.get('id')} not found")
            invalidate_rules_cache(reload_now=False)
            enqueue_rules_reload("Rewrite rule updated")
            self.redirect("/rewrites")
        elif path == "/rewrites/delete":
            with db_lock:
                rule = db.execute("SELECT id,pattern_type,pattern,target FROM rules WHERE id=?", (form.get("id"),)).fetchone()
                db.execute("DELETE FROM rules WHERE id=?", (form.get("id"),))
                db.commit()
            if rule:
                console_event("ok", "Rewrite rule deleted", f"#{rule['id']} {rule['pattern_type']} {rule['pattern']} -> {rule['target']}")
            else:
                console_event("warn", "Rewrite rule delete failed", f"ID {form.get('id')} not found")
            invalidate_rules_cache(reload_now=False)
            enqueue_rules_reload("Rewrite rule deleted")
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
                    profile = client_manager.create_profile(name, desc)
                    console_event("info", "Profile added", f"#{profile['id']} {profile['name']}")
            self.redirect("/profiles")
        elif path == "/profiles/rule-add":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                profile = client_manager.get_profile(pid)
                action = form.get("action", "block")
                pt = form.get("pattern_type", "domain")
                pattern = form.get("pattern", "").strip()
                if pattern:
                    rule = client_manager.add_profile_rule(pid, action, pt, pattern)
                    if rule:
                        pname = profile["name"] if profile else f"ID {pid}"
                        console_event("info", "Profile rule added", f"{pname}: #{rule['id']} {action} {pt} {pattern}")
            self.redirect("/profiles")
        elif path == "/profiles/rule-delete":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                rule_id = int(form.get("rule_id"))
                profile = client_manager.get_profile(pid)
                rule = next((r for r in client_manager.get_profile_rules(pid) if int(r["id"]) == rule_id), None)
                if client_manager.delete_profile_rule(rule_id):
                    pname = profile["name"] if profile else f"ID {pid}"
                    detail = f"#{rule['id']} {rule['action']} {rule['pattern_type']} {rule['pattern']}" if rule else f"#{rule_id}"
                    console_event("info", "Profile rule deleted", f"{pname}: {detail}")
                else:
                    console_event("warn", "Profile rule delete failed", f"ID {rule_id} not found")
            self.redirect("/profiles")
        elif path == "/profiles/blocklist-add":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                bl_id = int(form.get("blocklist_id"))
                profile = client_manager.get_profile(pid)
                bl = blocklist_manager.get_by_id(bl_id) if blocklist_manager else None
                if client_manager.add_blocklist_to_profile(pid, bl_id):
                    pname = profile["name"] if profile else f"ID {pid}"
                    bname = bl["name"] if bl else f"ID {bl_id}"
                    console_event("info", "Profile blocklist added", f"{pname}: {bname}")
            self.redirect("/profiles")
        elif path == "/profiles/blocklist-remove":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                bl_id = int(form.get("blocklist_id"))
                profile = client_manager.get_profile(pid)
                bl = blocklist_manager.get_by_id(bl_id) if blocklist_manager else None
                if client_manager.remove_blocklist_from_profile(pid, bl_id):
                    pname = profile["name"] if profile else f"ID {pid}"
                    bname = bl["name"] if bl else f"ID {bl_id}"
                    console_event("info", "Profile blocklist removed", f"{pname}: {bname}")
            self.redirect("/profiles")
        elif path == "/profiles/service-add":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                profile = client_manager.get_profile(pid)
                svc = form.get("service_name", "").strip()
                if svc:
                    if client_manager.add_profile_service(pid, svc):
                        pname = profile["name"] if profile else f"ID {pid}"
                        console_event("info", "Profile service block added", f"{pname}: {svc}")
                    invalidate_rules_cache()
            self.redirect("/profiles")
        elif path == "/profiles/service-remove":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                profile = client_manager.get_profile(pid)
                svc = form.get("service_name", "").strip()
                if svc:
                    if client_manager.remove_profile_service(pid, svc):
                        pname = profile["name"] if profile else f"ID {pid}"
                        console_event("info", "Profile service block removed", f"{pname}: {svc}")
                    invalidate_rules_cache()
            self.redirect("/profiles")
        elif path == "/profiles/edit":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                name = form.get("name", "").strip()
                if name:
                    profile = client_manager.update_profile(pid,
                        name=name,
                        description=form.get("description", "").strip(),
                        filtering_enabled=form.get("filtering_enabled") == "1",
                        safe_search_google=form.get("safe_search_google") == "1",
                        safe_search_bing=form.get("safe_search_bing") == "1",
                        safe_search_ddg=form.get("safe_search_ddg") == "1",
                        youtube_restricted=form.get("youtube_restricted") == "1",
                    )
                    if profile:
                        console_event("info", "Profile updated", f"#{profile['id']} {profile['name']}")
                    else:
                        console_event("warn", "Profile update failed", f"ID {pid} not found")
            self.redirect("/profiles")
        elif path == "/profiles/delete":
            if client_manager is not None:
                pid = int(form.get("profile_id"))
                profile = client_manager.get_profile(pid)
                if client_manager.delete_profile(pid):
                    pname = profile["name"] if profile else f"ID {pid}"
                    console_event("info", "Profile deleted", pname)
                else:
                    console_event("warn", "Profile delete failed", f"ID {pid} not found or default profile")
            self.redirect("/profiles")
        elif path == "/upstreams/add":
            parsed = parse_upstream_form(form)
            um.create(parsed["name"], parsed["address"], parsed["port"],
                      parsed["resolver"], parsed["resolver_type"],
                      parsed["transport"], parsed["dnscrypt_relay"],
                      enabled=True)
            self.redirect("/upstreams")
        elif path == "/upstreams/edit":
            parsed = parse_upstream_form(form)
            enabled = form.get("enabled") == "1"
            uid = int(form.get("id"))
            um.update(uid, name=parsed["name"], address=parsed["address"], port=parsed["port"],
                      resolver=parsed["resolver"], resolver_type=parsed["resolver_type"],
                      transport=parsed["transport"], dnscrypt_relay=parsed["dnscrypt_relay"],
                      enabled=enabled, latency_ms=None, last_error="")
            self.redirect("/upstreams")
        elif path == "/upstreams/mode":
            set_setting("upstream_mode", form.get("upstream_mode", "sequential"))
            self.redirect("/upstreams")
        elif path == "/upstreams/toggle":
            enabled = form.get("enabled") == "1"
            um.set_enabled(int(form.get("id")), enabled)
            self.redirect("/upstreams")
        elif path == "/upstreams/delete":
            um.delete(int(form.get("id")))
            self.redirect("/upstreams")
        elif path == "/upstreams/test":
            test_upstream(form.get("id"))
            self.redirect("/upstreams")
        elif path == "/settings":
            settings_keys = [
                "filtering_enabled", "cache_enabled", "query_log_enabled", "lan_only", "dnssec_validation_enabled",
                "block_mode", "block_response_ttl", "disable_ipv6", "cache_ttl", "cache_size", "cache_min_ttl", "cache_max_ttl", "cache_optimistic",
                "negative_cache_enabled", "negative_cache_max_ttl", "negative_cache_min_ttl",
                "prefetch_enabled", "prefetch_min_hits", "prefetch_ttl_percentage",
                "serve_stale_enabled", "serve_stale_max_age",
                "filter_update_interval_hours", "allowed_networks", "custom_block_ipv4", "custom_block_ipv6",
                "log_retention_days", "auto_clear_query_log_hours", "localdnsguard_web_host", "localdnsguard_web_port",
                "localdnsguard_dns_host", "localdnsguard_dns_port", "encrypted_dns_host", "encrypted_dns_domain",
                "upstream_timeout", "tcp_connect_timeout", "tls_handshake_timeout", "dns_query_timeout",
                "dnssec_validation_timeout", "doq_total_timeout", "doh3_total_timeout",
                "dns_over_tls_enabled", "dns_over_tls_port", "dns_over_https_enabled", "dns_over_https_port",
                "dns_over_quic_enabled", "dns_over_quic_port",
                "encrypted_dns_certificate_pem", "encrypted_dns_private_key_pem",
            ]
            try:
                parse_port(form.get("localdnsguard_web_port", WEB_PORT), WEB_PORT, "LOCALDNSGUARD_WEB_PORT")
                parse_port(form.get("localdnsguard_dns_port", DNS_PORT), DNS_PORT, "LOCALDNSGUARD_DNS_PORT")
                parse_positive_float(form.get("upstream_timeout", "2.5"), 2.5, "Upstream timeout")
                parse_positive_float(form.get("tcp_connect_timeout", "3.0"), 3.0, "TCP connect timeout")
                parse_positive_float(form.get("tls_handshake_timeout", "4.0"), 4.0, "TLS handshake timeout")
                parse_positive_float(form.get("dns_query_timeout", "2.5"), 2.5, "DNS query timeout")
                parse_positive_float(form.get("dnssec_validation_timeout", "3.0"), 3.0, "DNSSEC validation timeout")
                parse_positive_float(form.get("doq_total_timeout", "1.8"), 1.8, "DoQ total timeout")
                parse_positive_float(form.get("doh3_total_timeout", "2.2"), 2.2, "DoH/3 total timeout")
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
                _invalidate_settings_cache("admin_password_set")
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
        return FormData(parsed)

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
            _invalidate_settings_cache()
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
            restored_blocklists = 0
            for row in data.get("blocklists", []):
                name = row.get("name", "") or "unknown"
                url = row.get("url", row.get("source", ""))
                list_type = "allow" if row.get("list_type") == "allow" else "block"
                enabled = int(row.get("enabled", 1))
                last_update = row.get("last_update", "")
                last_error = ""
                content = row.get("content", "")
                entries = []
                if not content and str(url).startswith(("http://", "https://")):
                    try:
                        fetched = fetch_url_text(url)
                        content = fetched["text"]
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
                if content:
                    list_id_str = str(bl_id)
                    result = convert_blocklist_text(content, list_id_str, url)
                    save_blocklist_cache(list_id_str, result["cache"])
                    save_cosmetic_rules(list_id_str, result["cosmetic"])
                    save_unsupported_rules(list_id_str, result["unsupported"])
                    if not url:
                        save_original_text(list_id_str, content)
                restored_blocklists += 1
            counts["blocklists"] = restored_blocklists

            for up in um.get_all():
                um.delete(up["id"])
            upstream_rows = data.get("upstreams", [])
            for row in upstream_rows:
                um.create(row.get("name",""), row.get("address","1.1.1.1"), int(row.get("port",53)),
                          row.get("resolver",""), row.get("resolver_type","plain_udp"),
                          row.get("transport","udp"), row.get("dnscrypt_relay",""),
                          enabled=bool(row.get("enabled",1)),
                          latency_ms=row.get("latency_ms"), last_error=row.get("last_error",""),
                          created_at=row.get("created_at", now_iso()))
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
            "# HELP pyguarddns_regex_rules Regex rules loaded into the filter engine",
            "# TYPE pyguarddns_regex_rules gauge",
            f"pyguarddns_regex_rules {m['regex_rules']}",
            "",
            "# HELP pyguarddns_regex_fallback_rules Regex rules that could not be indexed by required literals",
            "# TYPE pyguarddns_regex_fallback_rules gauge",
            f"pyguarddns_regex_fallback_rules {m['regex_fallback_rules']}",
            "",
            "# HELP pyguarddns_regex_fallback_ratio Ratio of regex rules on the fallback scan path",
            "# TYPE pyguarddns_regex_fallback_ratio gauge",
            f"pyguarddns_regex_fallback_ratio {m['regex_fallback_ratio']}",
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
            "",
            "# HELP pyguarddns_dnssec_nsec_validations_total DNSSEC NSEC negative proof validations",
            "# TYPE pyguarddns_dnssec_nsec_validations_total counter",
            f"pyguarddns_dnssec_nsec_validations_total {m['dnssec_nsec_validations']}",
            "",
            "# HELP pyguarddns_dnssec_nsec3_validations_total DNSSEC NSEC3 negative proof validations",
            "# TYPE pyguarddns_dnssec_nsec3_validations_total counter",
            f"pyguarddns_dnssec_nsec3_validations_total {m['dnssec_nsec3_validations']}",
            "",
            "# HELP pyguarddns_dnssec_nsec3_failures_total DNSSEC NSEC3 negative proof failures",
            "# TYPE pyguarddns_dnssec_nsec3_failures_total counter",
            f"pyguarddns_dnssec_nsec3_failures_total {m['dnssec_nsec3_failures']}",
            "",
            "# HELP pyguarddns_dnssec_rfc5011_enabled DNSSEC RFC5011 trust anchor rollover enabled",
            "# TYPE pyguarddns_dnssec_rfc5011_enabled gauge",
            f"pyguarddns_dnssec_rfc5011_enabled {1 if m['dnssec_rfc5011_enabled'] else 0}",
            "",
            "# HELP pyguarddns_dnssec_active_root_ksks Active RFC5011 root KSKs",
            "# TYPE pyguarddns_dnssec_active_root_ksks gauge",
            f"pyguarddns_dnssec_active_root_ksks {m['dnssec_active_ksks']}",
            "",
            "# HELP pyguarddns_dnssec_pending_root_ksks Pending RFC5011 root KSKs",
            "# TYPE pyguarddns_dnssec_pending_root_ksks gauge",
            f"pyguarddns_dnssec_pending_root_ksks {m['dnssec_pending_ksks']}",
            "",
            "# HELP pyguarddns_dnssec_revoked_root_ksks Revoked RFC5011 root KSKs",
            "# TYPE pyguarddns_dnssec_revoked_root_ksks gauge",
            f"pyguarddns_dnssec_revoked_root_ksks {m['dnssec_revoked_ksks']}",
            "# HELP pyguarddns_dnssec_retired_root_ksks Retired RFC5011 root KSKs",
            "# TYPE pyguarddns_dnssec_retired_root_ksks gauge",
            f"pyguarddns_dnssec_retired_root_ksks {m['dnssec_retired_ksks']}",
            "",
            "# HELP pyguarddns_dns_requests_total DNS requests handled by the hot path",
            "# TYPE pyguarddns_dns_requests_total counter",
            f"pyguarddns_dns_requests_total {m['dns_requests_total']}",
            "",
            "# HELP pyguarddns_dns_cache_hits_total DNS responses served from the response cache",
            "# TYPE pyguarddns_dns_cache_hits_total counter",
            f"pyguarddns_dns_cache_hits_total {m['dns_cache_hits_total']}",
            "",
            "# HELP pyguarddns_dns_cache_misses_total DNS responses requiring upstream resolution",
            "# TYPE pyguarddns_dns_cache_misses_total counter",
            f"pyguarddns_dns_cache_misses_total {m['dns_cache_misses_total']}",
            "",
            "# HELP pyguarddns_dns_filter_blocks_total DNS queries blocked by the filter engine",
            "# TYPE pyguarddns_dns_filter_blocks_total counter",
            f"pyguarddns_dns_filter_blocks_total {m['dns_filter_blocks_total']}",
            "",
            "# HELP pyguarddns_dns_filter_allows_total DNS queries allowed through the filter engine",
            "# TYPE pyguarddns_dns_filter_allows_total counter",
            f"pyguarddns_dns_filter_allows_total {m['dns_filter_allows_total']}",
            "",
            "# HELP pyguarddns_dns_upstream_errors_total DNS requests that failed with an upstream/handler error",
            "# TYPE pyguarddns_dns_upstream_errors_total counter",
            f"pyguarddns_dns_upstream_errors_total {m['dns_upstream_errors_total']}",
            "",
            "# HELP pyguarddns_query_log_dropped_total Query log entries dropped because the async write queue was full",
            "# TYPE pyguarddns_query_log_dropped_total counter",
            f"pyguarddns_query_log_dropped_total {m['query_log_dropped_total']}",
            "",
            "# HELP pyguarddns_query_log_queue_size Current size of the async query log write queue",
            "# TYPE pyguarddns_query_log_queue_size gauge",
            f"pyguarddns_query_log_queue_size {m['query_log_queue_size']}",
            "",
            "# HELP pyguarddns_unknown_client_queue_size Current size of the async unknown-client registration queue",
            "# TYPE pyguarddns_unknown_client_queue_size gauge",
            f"pyguarddns_unknown_client_queue_size {m['unknown_client_queue_size']}",
            "",
            "# HELP pyguarddns_unknown_client_dropped_total Unknown-client registrations dropped because the queue was full",
            "# TYPE pyguarddns_unknown_client_dropped_total counter",
            f"pyguarddns_unknown_client_dropped_total {m['unknown_client_dropped_total']}",
            "",
            "# HELP pyguarddns_runtime_snapshot_generation Generation counter of the in-RAM client/profile snapshot",
            "# TYPE pyguarddns_runtime_snapshot_generation counter",
            f"pyguarddns_runtime_snapshot_generation {m['runtime_snapshot_generation']}",
            "",
            "# HELP pyguarddns_filter_engine_generation Generation counter of the active filter engine instance",
            "# TYPE pyguarddns_filter_engine_generation counter",
            f"pyguarddns_filter_engine_generation {m['filter_engine_generation']}",
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
            upstream_health = []
            for u in um.get_all():
                h = u.get("health", {})
                upstream_health.append({
                    "id": u["id"],
                    "name": u.get("name", ""),
                    "address": u.get("address", ""),
                    "port": u.get("port", 0),
                    "resolver_type": u.get("resolver_type", ""),
                    "success_rate": h.get("success_rate"),
                    "latency_ms": h.get("latency_ms"),
                    "consecutive_failures": h.get("consecutive_failures", 0),
                    "paused": h.get("paused", False),
                    "last_checked": h.get("last_checked"),
                })
            validator = get_dnssec_validator()
            dnssec_anchor = validator.trust_anchor_info() if validator else {}
            dnssec_metrics = get_dnssec_metrics()
            regex_stats = get_filter_engine().regex_index_stats()
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
                "dnssec": {
                    "enabled": get_setting("dnssec_validation_enabled", "0") == "1",
                    "trust_anchor_loaded": bool(dnssec_anchor.get("loaded")),
                    "rfc5011_enabled": bool(dnssec_anchor.get("rfc5011_auto_update")),
                    "active_root_ksks": dnssec_anchor.get("active_ksks", []),
                    "pending_root_ksks": dnssec_anchor.get("pending_ksks", []),
                    "revoked_root_ksks": dnssec_anchor.get("revoked_ksks", []),
                    "retired_root_ksks": dnssec_anchor.get("retired_ksks", []),
                    "last_rfc5011_check": dnssec_anchor.get("last_checked", ""),
                    "next_rfc5011_check": dnssec_anchor.get("next_check", ""),
                    "last_error": dnssec_anchor.get("last_error") or dnssec_anchor.get("error", ""),
                    "nsec_validations": dnssec_metrics.get("nsec_validations", 0),
                    "nsec3_validations": dnssec_metrics.get("nsec3_validations", 0),
                    "nsec3_failures": dnssec_metrics.get("nsec3_failures", 0),
                    "bogus": dnssec_metrics.get("bogus", 0),
                    "indeterminate": dnssec_metrics.get("indeterminate", 0),
                    "validation_seconds_total": dnssec_metrics.get("validation_seconds_total", 0.0),
                },
                "summary": stats_summary(),
                "filter_engine": {
                    "regex_index": regex_stats,
                    "warnings": [regex_stats["warning"]] if regex_stats.get("warning") else [],
                },
                "upstream_health": upstream_health,
                "healthcheck_last_run": hc_last,
            })
        elif path == "/api/dashboard":
            if params.get("refresh", [""])[0] == "1":
                dash_cache["data"] = None
                dash_cache["ts"] = 0.0
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
            rules_text = read_rules()
            parsed = []
            for i, line in enumerate(rules_text.split("\n"), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    parsed.append({"line": i, "text": line.rstrip(), "valid": True, "comment": True})
                    continue
                result = parse_rule_line(stripped)
                if result and "error" not in result:
                    parsed.append({"line": i, "text": line.rstrip(), "valid": True, "prefix": result["prefix"], "action": result["action"], "pattern": result["pattern"]})
                else:
                    parsed.append({"line": i, "text": line.rstrip(), "valid": False, "error": result.get("error", "unknown error") if result else "parse failed"})
            self.send_json({"rules": parsed, "raw": rules_text})
        elif path == "/api/blocklists":
            self.send_json(blocklist_manager.get_all() if blocklist_manager else [])
        elif path == "/api/blocklists/stats":
            self.send_json(blocklist_manager.get_stats() if blocklist_manager else [])
        elif path == "/api/blocklists/update-status":
            self.send_json(blocklist_manager.update_status() if blocklist_manager else {"running": False, "status": "not_available"})
        elif path == "/api/blocklists/job-status":
            self.send_json({
                "import": current_blocklist_import_status(),
                "delete": current_blocklist_delete_status(),
                "toggle": current_blocklist_toggle_status(),
            })
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
            self.send_json(um.get_all())
        elif path == "/api/upstreams/detect":
            self.send_json(detect_upstream(params.get("resolver", [""])[0]))
        elif path == "/api/upstreams/health":
            all_health = []
            for up in um.get_all():
                h = up.get("health", {})
                all_health.append({
                    "id": up["id"],
                    "name": up.get("name", ""),
                    "address": up.get("address", ""),
                    "port": up.get("port", 0),
                    "resolver_type": up.get("resolver_type", ""),
                    **h,
                })
            self.send_json(all_health)
        elif path == "/api/update/check":
            force = params.get("force", ["0"])[0] == "1"
            self.send_json(check_for_updates(force=force))
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
                "upstreams": um.get_all(),
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
        elif path == "/api/runtime_metrics":
            self.send_json(get_runtime_metrics())
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
        elif path == "/api/update/apply":
            result = perform_update()
            if result.get("ok"):
                log_admin_action(self.session_user(), "update_apply", "Update applied, restarting...", self.client_address[0])
                restart_server()
            self.send_json(result)
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
            try:
                bl_id = form.get("id")
                if not bl_id:
                    raise ValueError("No blocklist ID provided")
                bl_id = int(bl_id)
                blocklist_manager.update(bl_id)
                log_admin_action(self.session_user(), "blocklist_update", f"Updated blocklist {bl_id}", self.client_address[0])
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)
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
                    console_event("info", "Profile added", f"#{p['id']} {p['name']}")
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
                    console_event("info", "Profile updated", f"#{p['id']} {p['name']}")
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
                    profile = client_manager.get_profile(pid)
                    r = client_manager.add_profile_rule(pid, action, pattern_type, pattern)
                    log_admin_action(self.session_user(), "profile_rule_add", f"Added rule {action} {pattern} to profile {pid}", self.client_address[0])
                    if r:
                        pname = profile["name"] if profile else f"ID {pid}"
                        console_event("info", "Profile rule added", f"{pname}: #{r['id']} {action} {pattern_type} {pattern}")
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
                    blocklist_id = int(bl_id)
                    profile = client_manager.get_profile(pid)
                    bl = blocklist_manager.get_by_id(blocklist_id) if blocklist_manager else None
                    ok = client_manager.add_blocklist_to_profile(pid, blocklist_id)
                    log_admin_action(self.session_user(), "profile_blocklist_add", f"Added blocklist {bl_id} to profile {pid}", self.client_address[0])
                    if ok:
                        pname = profile["name"] if profile else f"ID {pid}"
                        bname = bl["name"] if bl else f"ID {blocklist_id}"
                        console_event("info", "Profile blocklist added", f"{pname}: {bname}")
                    self.send_json({"ok": ok})
        elif re.search(r"/api/profiles/\d+/services/add$", path):
            pid = int(path.strip("/").split("/")[2])
            svc = form.get("service_name", "").strip()
            profile = client_manager.get_profile(pid) if client_manager else None
            if client_manager is not None and client_manager.add_profile_service(pid, svc):
                log_admin_action(self.session_user(), "profile_service_add", f"Added service block {svc} to profile {pid}", self.client_address[0])
                pname = profile["name"] if profile else f"ID {pid}"
                console_event("info", "Profile service block added", f"{pname}: {svc}")
                invalidate_rules_cache()
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "failed"}, 400)
        elif re.search(r"/api/profiles/\d+/services/remove$", path):
            pid = int(path.strip("/").split("/")[2])
            svc = form.get("service_name", "").strip()
            if client_manager is not None:
                profile = client_manager.get_profile(pid)
                if client_manager.remove_profile_service(pid, svc):
                    pname = profile["name"] if profile else f"ID {pid}"
                    console_event("info", "Profile service block removed", f"{pname}: {svc}")
                log_admin_action(self.session_user(), "profile_service_remove", f"Removed service block {svc} from profile {pid}", self.client_address[0])
                invalidate_rules_cache()
                self.send_json({"ok": True})
        elif path == "/api/upstreams/health/pause":
            up_id = form.get("id")
            if not up_id:
                self.send_json({"error": "id required"}, 400)
            else:
                h = um.get_health(int(up_id))
                new_paused = not h.get("paused", False)
                um.set_health_paused(int(up_id), new_paused)
                log_admin_action(self.session_user(), "upstream_pause_toggle", f"{'Paused' if new_paused else 'Unpaused'} upstream {up_id}", self.client_address[0])
                self.send_json({"ok": True, "paused": new_paused})
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
                    self._stream_count = 0

                def quic_event_received(self, event):
                    peer = self._quic._network_paths[0].addr[0] if self._quic._network_paths else ""
                    event_type = type(event).__name__
                    
                    # Schreibe immer in Log - auch bei Fehlern
                    try:
                        with open("web-error.log", "a", encoding="utf-8") as log:
                            log.write(f"{now_iso()} dns-over-quic EVENT type={event_type} peer={peer}\n")
                    except Exception as e:
                        print(f"LOG ERROR: {e}")
                    
                    if isinstance(event, ProtocolNegotiated):
                        update_doq_metric("last_peer", peer)
                        log_doq_event(f"PROTOCOL_NEGOTIATED alpn={event.alpn_protocol}")
                        return
                    if isinstance(event, HandshakeCompleted):
                        update_doq_metric("handshakes")
                        update_doq_metric("last_peer", peer)
                        log_doq_event(f"HANDSHAKE_COMPLETED alpn={self._quic.alpn_protocol} resumed={event.session_resumed}")
                        return
                    if isinstance(event, ConnectionTerminated):
                        error_msg = f"code={event.error_code} (0x{event.error_code:x}) reason={event.reason_phrase}" if event.error_code else "no error code"
                        update_doq_metric("last_error", f"connection terminated {error_msg}")
                        log_doq_event(f"CONNECTION_TERMINATED {error_msg}")
                        return
                    if not isinstance(event, StreamDataReceived):
                        log_doq_event(f"NON_STREAM_EVENT type={event_type}")
                        return
                    sid = event.stream_id
                    data = self._buffers.get(sid, b"") + event.data
                    log_doq_event(f"STREAM_DATA sid={sid} len={len(event.data)} total={len(data)} end_stream={event.end_stream}")
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
                config = QuicConfiguration(
                    alpn_protocols=["doq", "doq-i00", "doq-i02", "doq-i04", "doq-i05", "doq-i07", "doq-i10", "doq-i11", "doq-i12", "doq-i13", "doq-i14"],
                    is_client=False,
                    max_datagram_frame_size=65536,
                    idle_timeout=60.0
                )
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
            console_event("error", "Failed to start DoT server", exc)
    if get_setting("dns_over_https_enabled", "0") == "1":
        try:
            doh = ReusableThreadingHTTPSServer((ENCRYPTED_DNS_HOST, DNS_HTTPS_PORT), DNSHTTPSHandler, ssl_context())
            threading.Thread(target=doh.serve_forever, name="dns-over-https-server", daemon=True).start()
            servers.append(doh)
        except Exception as exc:
            console_event("error", "Failed to start DoH server", exc)
    if get_setting("dns_over_quic_enabled", "0") == "1":
        try:
            doq = DoQRuntimeServer(ENCRYPTED_DNS_HOST, DNS_QUIC_PORT, make_encrypted_dns_ssl_context())
            doq.start()
            servers.append(doq)
        except Exception as exc:
            console_event("error", "Failed to start DoQ server", exc)
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
            console_event("error", "Web shutdown error", exc)
        web_server = None
    shutdown_dns_runtime_servers()


def shutdown_dns_runtime_servers():
    global dns_servers, encrypted_dns_servers
    for srv in dns_servers:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception as exc:
            console_event("error", "DNS shutdown error", exc)
    dns_servers = []
    for srv in encrypted_dns_servers:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception as exc:
            console_event("error", "Encrypted DNS shutdown error", exc)
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
        console_event("error", "DNS restart failed", exc)


def schedule_dns_runtime_restart(delay=0.6):
    timer = threading.Timer(delay, safe_restart_dns_runtime_servers)
    timer.daemon = True
    timer.start()


def console_style(text, style):
    return text


def console_print(text="", style=None):
    print(console_style(str(text), style) if style else str(text), flush=True)


CONSOLE_COMMANDS = [
    "status",
    "domain test",
    "dnssec test",
    "cache clear",
    "update blocklist",
    "dedupe blocklists",
    "check update",
    "apply update",
    "restart",
    "stop",
    "help",
]

_readline_completion_ready = False


def console_command_completions(prefix):
    normalized = prefix.replace(chr(0xFEFF), "").lower()
    return [command for command in CONSOLE_COMMANDS if command.startswith(normalized)]


def setup_readline_completion():
    global _readline_completion_ready
    if _readline_completion_ready:
        return True
    try:
        import readline
    except Exception:
        return False

    def complete(text, state):
        prefix = readline.get_line_buffer()
        matches = console_command_completions(prefix)
        if state < len(matches):
            return matches[state]
        return None

    try:
        readline.set_completer_delims("")
        readline.set_completer(complete)
        try:
            readline.parse_and_bind("tab: menu-complete")
        except Exception:
            readline.parse_and_bind("tab: complete")
        _readline_completion_ready = True
        return True
    except Exception:
        return False


def console_event(level, message, detail=""):
    labels = {
        "ok": ("OK", "ok"),
        "info": ("INFO", "info"),
        "warn": ("WARN", "warn"),
        "error": ("ERROR", "error"),
        "work": ("...", "info"),
    }
    label, style = labels.get(level, ("INFO", "info"))
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = f"{timestamp} [{label:5}]"
    line = f"{console_style(prefix, style)} {message}"
    if detail:
        line += f" {console_style(str(detail), 'muted')}"
    print(line, flush=True)


def console_box(title, rows):
    normalized = [(str(label), str(value)) for label, value in rows]
    label_width = max([len(label) for label, _ in normalized] + [0])
    value_width = max([len(value) for _, value in normalized] + [0])
    width = max(len(title), label_width + value_width + 5, 36)
    border = "+" + "-" * (width + 2) + "+"
    console_print(border, "muted")
    console_print(f"| {title.ljust(width)} |", "title")
    console_print(border, "muted")
    for label, value in normalized:
        left = label.ljust(label_width)
        body = f"{left} : {value}"
        console_print(f"| {body.ljust(width)} |")
    console_print(border, "muted")


def console_help():
    descriptions = {
        "status": "Show runtime metrics",
        "domain test": "Test filtering decision: domain test example.com [client-ip] [qtype]",
        "dnssec test": "Run DNSSEC self-validation",
        "cache clear": "Clear DNS cache",
        "update blocklist": "Update remote blocklists",
        "dedupe blocklists": "Remove duplicate blocklist entries",
        "check update": "Check for available updates from GitHub",
        "apply update": "Install updates and restart server",
        "restart": "Restart runtime servers",
        "stop": "Stop server",
        "help": "Show this help",
    }
    console_box("Console commands", [(command, descriptions[command]) for command in CONSOLE_COMMANDS])


def print_console_status():
    summary = stats_summary()
    cache_info = cache_stats()
    public_name = ENCRYPTED_DNS_DOMAIN or ENCRYPTED_DNS_HOST
    encrypted_dns = (
        f"tls://{public_name}:{DNS_TLS_PORT} | "
        f"https://{public_name}{'' if DNS_HTTPS_PORT == 443 else ':' + str(DNS_HTTPS_PORT)}/dns-query | "
        f"quic://{public_name}:{DNS_QUIC_PORT}"
    )
    console_box(f"{APP_NAME} status", [
        ("Web UI", f"http://127.0.0.1:{WEB_PORT}"),
        ("DNS", f"{DNS_HOST}:{DNS_PORT} UDP/TCP"),
        ("Encrypted DNS", encrypted_dns),
        ("Total queries", summary.get("total", 0)),
        ("Blocked queries", summary.get("blocked", 0)),
        ("Block rate", f"{summary.get('block_rate', 0.0):.1f}%"),
        ("Avg response", f"{summary.get('avg_ms', 0.0):.1f} ms"),
        ("Active clients", summary.get("clients", 0)),
        ("Filter rules", summary.get("rules", 0)),
        ("Cache entries", cache_info.get("entries", 0)),
    ])


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
    console_box("DNSSEC self-validation", [
        ("Server", result["server"]),
        ("Validation", "enabled" if result.get("enabled") else "disabled"),
    ])
    if not result.get("enabled"):
        console_event("warn", "dnssec_validation_enabled is off")
    if result.get("error"):
        console_event("error", result["error"])
    for item in result.get("tests", []):
        level = "ok" if item["ok"] else "error"
        status = "OK" if item["ok"] else "FAIL"
        ad_text = "AD" if item["ad"] else "no AD"
        details = item["error"] or f"rcode={item['rcode']} {ad_text} expected={item['expected_rcode']}"
        console_event(level, f"{status} {item['domain']} {item['qtype']}", f"{details} ({item['duration_ms']} ms)")
    overall_level = "ok" if result["overall"] == "pass" else "error"
    console_event(overall_level, f"Overall: {result['overall'].upper()}")


def print_console_domain_test(domain, client="127.0.0.1", query_type="A"):
    result = run_domain_test({"domain": domain, "query_type": query_type, "client": client})
    rows = [
        ("Domain", result.get("domain", "")),
        ("Query type", result.get("query_type", "")),
        ("Client", result.get("client", "")),
        ("Action", result.get("action", "")),
        ("Reason", result.get("reason", "")),
        ("Matched rule", result.get("matched_rule") or result.get("matched_domain") or "-"),
        ("List", result.get("list_name") or "-"),
        ("Client name", result.get("client_name") or "-"),
        ("Profile", result.get("profile_name") or "-"),
    ]
    if result.get("target"):
        rows.append(("Target", result["target"]))
    console_box("Domain test", rows)
    for step in result.get("steps", []):
        console_event("info", step)


def run_console_command(command):
    global dns_servers
    command = command.replace(chr(0xFEFF), "")
    cleaned = "".join(ch for ch in command if ch.isprintable())
    cmd = " ".join(cleaned.strip().lower().split())
    if not cmd:
        return True
    if cmd in {"help", "?"}:
        console_help()
        return True
    if cmd == "status":
        print_console_status()
        return True
    if cmd in {"domain test", "test domain"} or cmd.startswith("domain test ") or cmd.startswith("test domain "):
        parts = cleaned.strip().split()
        if len(parts) < 3:
            console_event("error", "Usage: domain test example.com [client-ip] [qtype]")
            return True
        domain = parts[2]
        client = parts[3] if len(parts) >= 4 else "127.0.0.1"
        query_type = parts[4] if len(parts) >= 5 else "A"
        try:
            print_console_domain_test(domain, client, query_type)
        except Exception as exc:
            console_event("error", "Domain test failed", exc)
        return True
    if cmd in {"dnssec test", "test dnssec", "dnssec"}:
        print_dnssec_self_validation_test()
        return True
    if cmd == "cache clear":
        result = clear_dns_cache()
        console_event("ok", "Cache cleared", f"{result['entries']} entries, {result['bytes_used']} bytes")
        return True
    if cmd in {"update blocklist", "update blocklists"}:
        if blocklist_manager is None:
            console_event("warn", "Blocklist manager is not available")
        else:
            lists = [
                bl for bl in blocklist_manager.get_all()
                if bl.get("url", "").startswith(("http://", "https://"))
            ]
            if not lists:
                console_event("info", "No remote blocklists found")
                return True
            total = len(lists)
            for idx, bl in enumerate(lists, 1):
                name = bl.get("name") or f"ID {bl.get('id')}"
                console_event("work", f"Updating blocklist {idx}/{total}", name)
                try:
                    blocklist_manager.update(bl["id"], background=False)
                    updated = blocklist_manager.get_by_id(bl["id"]) or {}
                    if updated.get("last_error"):
                        console_event("error", f"Blocklist {idx}/{total} failed", f"{name}: {updated['last_error']}")
                    else:
                        console_event("ok", f"Blocklist {idx}/{total} updated", f"{name} ({updated.get('rule_count', 0)} rules)")
                except Exception as exc:
                    console_event("error", f"Blocklist {idx}/{total} failed", f"{name}: {exc}")
            console_event("ok", "Blocklist update finished")
        return True
    if cmd in {"dedupe blocklists", "dedupe blocklist", "dedupe lists", "blocklist dedupe", "duplicate blocklists", "doppelte blocklists"}:
        console_event("work", "Checking existing blocklist entries for duplicates")
        try:
            result = dedupe_existing_blocklist_entries()
            removed = result["removed"]
            if removed == 0:
                console_event("ok", "No duplicate blocklist entries found")
            else:
                console_event("ok", "Removed duplicate blocklist entries", removed)
                for item in result["lists"]:
                    console_event("info", item["name"], f"removed {item['removed']}")
                console_event("ok", "Filter engine reloaded")
        except Exception as exc:
            console_event("error", "Blocklist dedupe failed", exc)
        return True
    if cmd in {"check update", "check updates", "update check"}:
        console_event("work", "Checking for updates...")
        try:
            result = check_for_updates(force=True)
            if not result.get("ok"):
                console_event("error", "Update check failed", result.get("error", "Unknown error"))
            elif result.get("available") and result.get("count", 0) > 0:
                console_event("ok", f"Update available: {result['count']} new commit(s)")
                for commit in result.get("commits", [])[:5]:
                    console_event("info", f"  {commit}")
                if result["count"] > 5:
                    console_event("info", f"  ...and {result['count'] - 5} more")
                console_event("info", "Use 'apply update' to install and restart")
            else:
                console_event("ok", "No updates available. You are up to date.")
        except Exception as exc:
            console_event("error", "Update check failed", exc)
        return True
    if cmd in {"apply update", "update apply", "install update"}:
        console_event("work", "Checking for updates...")
        try:
            check_result = check_for_updates(force=True)
            if not check_result.get("ok"):
                console_event("error", "Update check failed", check_result.get("error", "Unknown error"))
                return True
            if not check_result.get("available") or check_result.get("count", 0) == 0:
                console_event("ok", "No updates available. You are up to date.")
                return True
            
            console_event("work", f"Applying {check_result['count']} update(s)...")
            result = perform_update()
            if result.get("ok"):
                console_event("ok", "Update applied successfully")
                console_event("info", "DNS Server Update...")
                restart_server()
            else:
                console_event("error", "Update failed", result.get("error", "Unknown error"))
        except Exception as exc:
            console_event("error", "Update failed", exc)
        return True
    if cmd == "restart":
        console_event("work", "Restarting runtime servers")
        try:
            restart_runtime_servers()
            console_event("ok", "Runtime restarted", f"Web UI: http://127.0.0.1:{WEB_PORT} | DNS: {DNS_HOST}:{DNS_PORT}")
        except Exception as exc:
            console_event("error", "Runtime restart failed", exc)
            try:
                with open("startup.log", "a", encoding="utf-8") as log:
                    log.write(f"{now_iso()} runtime restart failed: {type(exc).__name__}: {exc}\n")
            except Exception:
                pass
        return True
    if cmd == "stop":
        console_event("info", "Stopping server")
        server_shutdown_event.set()
        shutdown_runtime_servers()
        return False
    console_event("warn", f"Unknown command: {command}", "Type 'help'.")
    return True


def console_input(prompt):
    if os.name != "nt":
        if getattr(sys.stdin, "isatty", lambda: False)():
            setup_readline_completion()
        return input(prompt)
    if not getattr(sys.stdin, "isatty", lambda: False)():
        return input(prompt)

    import msvcrt

    buffer = ""
    last_len = 0
    tab_prefix = None
    tab_matches = []
    tab_index = -1

    def redraw():
        nonlocal last_len
        clear_len = max(last_len, len(buffer))
        sys.stdout.write("\r" + " " * (len(prompt) + clear_len) + "\r" + prompt + buffer)
        sys.stdout.flush()
        last_len = len(buffer)

    sys.stdout.write(prompt)
    sys.stdout.flush()

    while True:
        char = msvcrt.getwch()
        if char in ("\x00", "\xe0"):
            msvcrt.getwch()
            continue
        if char in ("\r", "\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
            return buffer
        if char == "\x03":
            raise KeyboardInterrupt
        if char == "\x1a":
            raise EOFError
        if char == "\x08":
            if buffer:
                buffer = buffer[:-1]
                tab_prefix = None
                tab_matches = []
                tab_index = -1
                redraw()
            continue
        if char == "\x1b":
            if buffer:
                buffer = ""
                tab_prefix = None
                tab_matches = []
                tab_index = -1
                redraw()
            continue
        if char == "\t":
            if tab_matches and buffer == tab_matches[tab_index]:
                pass
            else:
                tab_prefix = buffer.lower()
                tab_matches = console_command_completions(tab_prefix)
                tab_index = -1
            if tab_matches:
                tab_index = (tab_index + 1) % len(tab_matches)
                buffer = tab_matches[tab_index]
                redraw()
            else:
                sys.stdout.write("\a")
                sys.stdout.flush()
            continue
        if char.isprintable():
            buffer += char
            tab_prefix = None
            tab_matches = []
            tab_index = -1
            redraw()


def console_loop():
    console_help()
    while not server_shutdown_event.is_set():
        try:
            command = console_input("pyguarddns> ")
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
        console_event("work", "Missing packages; installing", ", ".join(to_install))
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install"] + to_install,
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            console_event("error", f"pip install failed (exit {result.returncode})", f"{result.stdout}\n{result.stderr}")
        else:
            console_event("ok", "Dependencies installed")
    except Exception as e:
        console_event("warn", "Could not verify requirements", e)


def main():
    global dns_servers, encrypted_dns_servers, _active_engine, _filter_engine_generation
    threading.Thread(target=ensure_requirements, name="ensure-reqs", daemon=True).start()
    install_crash_handlers()
    if not acquire_instance_lock():
        console_event("warn", f"{APP_NAME} is already running", "Please do not start a second window.")
        return
    server_shutdown_event.clear()
    console_event("info", "DNS server starting ...")
    set_runtime_status("DNS server starting ...", ready=False)
    start_web_server()
    with open("startup.log", "a", encoding="utf-8") as log:
        log.write(f"{now_iso()} starting {APP_NAME}\n")
        log.flush()
        init_db()
        log.write(f"{now_iso()} database ready\n")
        log.flush()
        start_memory_db_sync()
        if DB_IN_MEMORY:
            ram_location = RAM_DB_PATH if RAM_DB_PATH else ":memory:"
            log.write(f"{now_iso()} database running in RAM ({ram_location}) with {DB_MEMORY_SYNC_INTERVAL:g}s disk sync\n")
            log.flush()
        threading.Thread(target=lambda: (
            process_dnssec_trust_anchor_startup()
        ), name="dnssec-startup", daemon=True).start()
        log.write(f"{now_iso()} web ready on {WEB_HOST}:{WEB_PORT}\n")
        log.flush()
        start_db_writer()
        log.write(f"{now_iso()} db writer ready\n")
        log.flush()
        start_unknown_client_worker()
        log.write(f"{now_iso()} unknown-client worker ready\n")
        log.flush()
        threading.Thread(target=db_maintenance_loop, name="db-maintenance", daemon=True).start()
        log.write(f"{now_iso()} db maintenance ready\n")
        log.flush()
        threading.Thread(target=_healthcheck_worker, name="healthcheck", daemon=True).start()
        log.write(f"{now_iso()} healthcheck worker ready\n")
        log.flush()
        start_update_checker()
        log.write(f"{now_iso()} update checker ready (checks every 6 hours)\n")
        log.flush()
        try:
            eng = build_filter_engine()
            with _active_engine_lock:
                _active_engine = eng
                _filter_engine_generation += 1
            log.write(f"{now_iso()} engine ready: {len(eng.suffix_block)} suffix blocks, gen={_filter_engine_generation}\n")
        except Exception as exc:
            log.write(f"{now_iso()} engine build FAILED: {exc}\n")
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
        console_event("ok", f"{APP_NAME} is ready")
        print_console_status()
    try:
        console_loop()
    finally:
        shutdown_runtime_servers()
        stop_memory_db_sync()


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
    start_memory_db_sync()
    start_db_writer()
    start_unknown_client_worker()

    if cmd == "status":
        print_console_status()

    elif cmd == "reload":
        invalidate_rules_cache()
        console_event("ok", "Rules cache invalidated")

    elif cmd == "update-lists":
        if blocklist_manager is not None:
            result = blocklist_manager.update_all()
            console_event("ok", "Updated blocklists", result)
        else:
            console_event("warn", "No blocklist manager available")

    elif cmd == "backup":
        sensitive_keys = {"admin_password_set", "api_token", "encrypted_dns_private_key_pem"}
        data = {
            "version": 2,
            "settings": [r for r in rows("SELECT * FROM settings") if r["key"] not in sensitive_keys],
            "rules": rows("SELECT * FROM rules WHERE action <> 'rewrite' ORDER BY id ASC"),
            "dns_rewrites": rows("SELECT * FROM rules WHERE action = 'rewrite' ORDER BY id ASC"),
            "upstreams": um.get_all(),
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
        console_event("ok", "Backup written", backup_path)

    elif cmd == "restore":
        if not args.file:
            console_event("error", "--file argument required for restore command")
            return
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                data = json.load(f)
            handle_restore_data(data)
            console_event("ok", "Restore completed", args.file)
        except Exception as exc:
            console_event("error", "Restore failed", exc)

    elif cmd == "test-domain":
        if not args.domain:
            console_event("error", "--domain argument required for test-domain command")
            return
        try:
            result = run_domain_test({"domain": args.domain, "query_type": args.query_type, "client": args.client})
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except Exception as exc:
            console_event("error", "Domain test failed", exc)

    elif cmd == "dnssec-test":
        print_dnssec_self_validation_test()

    else:
        console_event("warn", f"Unknown command: {cmd}")
        parser.print_help()


if __name__ == "__main__":
    try:
        cli_main()
    except Exception as exc:
        write_crash_report("fatal main exception", traceback.format_exc())
        with open("startup.log", "a", encoding="utf-8") as log:
            log.write(f"{now_iso()} fatal: {type(exc).__name__}: {exc}\n")
        raise
