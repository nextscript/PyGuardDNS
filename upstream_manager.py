import json
import os
import tempfile
import threading
import time
from datetime import datetime
from typing import Optional

UPSTREAMS_DIR = os.path.join("data", "upstreams")

_cache: dict[int, dict] = {}
_cache_lock = threading.RLock()
_cache_loaded = False


def _ensure_dir():
    os.makedirs(UPSTREAMS_DIR, exist_ok=True)


def _path(upstream_id: int) -> str:
    return os.path.join(UPSTREAMS_DIR, f"{upstream_id}.json")


def _load_file(upstream_id: int) -> Optional[dict]:
    path = _path(upstream_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_file(data: dict):
    _ensure_dir()
    path = _path(data["id"])
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _delete_file(upstream_id: int):
    path = _path(upstream_id)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def _invalidate_cache():
    global _cache_loaded
    with _cache_lock:
        _cache.clear()
        _cache_loaded = False


def _load_cache():
    global _cache_loaded
    with _cache_lock:
        if _cache_loaded:
            return
        _cache.clear()
        _ensure_dir()
        for fname in os.listdir(UPSTREAMS_DIR):
            if fname.endswith(".json"):
                try:
                    uid = int(fname[:-5])
                    data = _load_file(uid)
                    if data:
                        _cache[uid] = data
                except ValueError:
                    pass
        _cache_loaded = True


def _get_from_cache(upstream_id: int) -> Optional[dict]:
    _load_cache()
    with _cache_lock:
        d = _cache.get(upstream_id)
        return dict(d) if d else None


def _update_cache(data: dict):
    with _cache_lock:
        _cache[data["id"]] = dict(data)


def _remove_from_cache(upstream_id: int):
    with _cache_lock:
        _cache.pop(upstream_id, None)


def _next_id() -> int:
    _ensure_dir()
    max_id = 0
    for fname in os.listdir(UPSTREAMS_DIR):
        if fname.endswith(".json"):
            try:
                mid = int(fname[:-5])
                if mid > max_id:
                    max_id = mid
            except ValueError:
                pass
    return max_id + 1


def load_all() -> list[dict]:
    _load_cache()
    with _cache_lock:
        return [dict(v) for v in _cache.values()]


def get(upstream_id: int) -> Optional[dict]:
    return _get_from_cache(upstream_id) or _load_file(upstream_id)


def get_all() -> list[dict]:
    return load_all()


def create(name: str, address: str, port: int = 53, resolver: str = "",
           resolver_type: str = "plain_udp", transport: str = "udp",
           dnscrypt_relay: str = "", enabled: bool = True,
           latency_ms=None, last_error: str = "", created_at: str = "") -> int:
    now = created_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    uid = _next_id()
    data = {
        "id": uid,
        "name": name,
        "address": address,
        "port": port,
        "resolver": resolver,
        "resolver_type": resolver_type,
        "transport": transport,
        "dnscrypt_relay": dnscrypt_relay,
        "enabled": enabled,
        "latency_ms": latency_ms,
        "last_error": last_error,
        "created_at": now,
        "health": {
            "latency_ms": 0.0,
            "success_rate": 1.0,
            "timeout_count": 0,
            "last_error": "",
            "last_checked": 0.0,
            "consecutive_failures": 0,
            "paused": False,
            "total_queries": 0,
            "successful_queries": 0,
        },
    }
    _save_file(data)
    _update_cache(data)
    return uid


def update(upstream_id: int, **kwargs) -> bool:
    data = _load_file(upstream_id)
    if not data:
        return False
    for key, val in kwargs.items():
        if key in ("id", "health", "created_at"):
            continue
        if key == "enabled":
            val = bool(val)
        data[key] = val
    _save_file(data)
    _update_cache(data)
    return True


def delete(upstream_id: int):
    _delete_file(upstream_id)
    _remove_from_cache(upstream_id)


def set_enabled(upstream_id: int, enabled: bool) -> bool:
    return update(upstream_id, enabled=enabled)


def update_health(upstream_id: int, success: bool, latency_ms: float = 0.0, error: str = "") -> bool:
    data = _load_file(upstream_id)
    if not data:
        return False
    h = data.setdefault("health", {})
    h["total_queries"] = h.get("total_queries", 0) + 1
    h["successful_queries"] = h.get("successful_queries", 0) + (1 if success else 0)
    h["timeout_count"] = h.get("timeout_count", 0) + (0 if success else 1)
    total = h["total_queries"]
    h["success_rate"] = h["successful_queries"] / total if total > 0 else 1.0
    h["consecutive_failures"] = (h.get("consecutive_failures", 0) + 1) if not success else 0
    h["last_checked"] = time.time()
    if success:
        h["latency_ms"] = latency_ms
        h["last_error"] = ""
        if h["consecutive_failures"] == 0:
            h["paused"] = False
    else:
        h["last_error"] = (error or "")[:500]
        if h["consecutive_failures"] >= 5:
            h["paused"] = True
    data["latency_ms"] = h["latency_ms"] if success else data.get("latency_ms")
    data["last_error"] = h["last_error"]
    _save_file(data)
    _update_cache(data)
    return h.get("paused", False)


def get_health(upstream_id: int) -> dict:
    data = get(upstream_id)
    if data:
        return data.get("health", {})
    return {"upstream_id": upstream_id}


def set_health_paused(upstream_id: int, paused: bool) -> bool:
    data = _load_file(upstream_id)
    if not data:
        return False
    h = data.setdefault("health", {})
    h["paused"] = bool(paused)
    _save_file(data)
    _update_cache(data)
    return True


def active_upstreams() -> list[dict]:
    _load_cache()
    result = []
    with _cache_lock:
        for uid, data in list(_cache.items()):
            if not data.get("enabled", False):
                continue
            if data.get("resolver_type") == "dnscrypt_relay":
                continue
            h = data.get("health", {})
            if h.get("paused", False):
                continue
            result.append({
                **data,
                "health_paused": h.get("paused", False),
                "success_rate": h.get("success_rate", 1.0),
                "timeout_count": h.get("timeout_count", 0),
                "consecutive_failures": h.get("consecutive_failures", 0),
                "last_checked": h.get("last_checked", 0),
                "total_queries": h.get("total_queries", 0),
                "successful_queries": h.get("successful_queries", 0),
            })
    result.sort(key=lambda x: (
        0 if not x.get("last_error") else 1,
        x.get("latency_ms") or 999999,
        x.get("id", 0),
    ))
    return result


def active_dnscrypt_relays() -> list[dict]:
    _load_cache()
    result = []
    with _cache_lock:
        for uid, data in list(_cache.items()):
            if not data.get("enabled", False):
                continue
            if data.get("resolver_type") != "dnscrypt_relay":
                continue
            h = data.get("health", {})
            if h.get("paused", False):
                continue
            result.append(dict(data))
    return result


def maybe_update_latency(upstream_id: int, latency_ms: float, error: str = ""):
    data = _load_file(upstream_id)
    if not data:
        return
    if error:
        data["latency_ms"] = None
        data["last_error"] = (error or "")[:500]
    else:
        old = data.get("latency_ms")
        if old is not None:
            data["latency_ms"] = old * 0.65 + latency_ms * 0.35
        else:
            data["latency_ms"] = latency_ms
        data["last_error"] = ""
    _save_file(data)
    _update_cache(data)


def normalize_dnscrypt_relay():
    for up in get_all():
        resolver = (up.get("resolver") or "").strip()
        if not resolver.startswith("sdns://"):
            continue
        try:
            from app import detect_dns_stamp_type, parse_dnscrypt_relay_stamp
            stamp_type = detect_dns_stamp_type(resolver)
            if stamp_type == "dnscrypt_relay":
                info = parse_dnscrypt_relay_stamp(resolver)
                update(up["id"],
                       address=info["address"],
                       port=info["port"],
                       resolver_type="dnscrypt_relay",
                       transport="dnscrypt-relay",
                       dnscrypt_relay="")
        except Exception:
            pass


def migrate_from_sqlite(db):
    rows = db.execute("SELECT * FROM upstreams ORDER BY id ASC").fetchall()
    for row in rows:
        r = dict(row)
        uid = r.pop("id")
        health_row = db.execute(
            "SELECT * FROM upstream_health WHERE upstream_id=?", (uid,)
        ).fetchone()
        health = dict(health_row) if health_row else {}
        data = {
            "id": uid,
            "name": r.get("name", ""),
            "address": r.get("address", ""),
            "port": r.get("port", 53),
            "resolver": r.get("resolver", ""),
            "resolver_type": r.get("resolver_type", "plain_udp"),
            "transport": r.get("transport", "udp"),
            "dnscrypt_relay": r.get("dnscrypt_relay", ""),
            "enabled": bool(r.get("enabled", 1)),
            "latency_ms": r.get("latency_ms"),
            "last_error": r.get("last_error", ""),
            "created_at": r.get("created_at", ""),
            "health": {
                "latency_ms": health.get("latency_ms", 0.0),
                "success_rate": health.get("success_rate", 1.0),
                "timeout_count": health.get("timeout_count", 0),
                "last_error": health.get("last_error", ""),
                "last_checked": health.get("last_checked", 0.0),
                "consecutive_failures": health.get("consecutive_failures", 0),
                "paused": bool(health.get("paused", 0)),
                "total_queries": health.get("total_queries", 0),
                "successful_queries": health.get("successful_queries", 0),
            },
        }
        _save_file(data)
        _update_cache(data)
    _invalidate_cache()
