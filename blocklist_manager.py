import ipaddress
import gzip
import hashlib
import io
import json
import re
import socket
import ssl
import threading
import time
import zipfile
import os
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

try:
    import idna
except ImportError:
    idna = None

_dns_resolver = None


def set_dns_resolver(fn):
    global _dns_resolver
    _dns_resolver = fn


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain:
        return ""
    if idna and any(ord(c) >= 128 for c in domain):
        try:
            domain = idna.encode(domain).decode("ascii")
        except Exception:
            return ""
    if not re.match(r"^[a-z0-9._-]+$", domain):
        return ""
    return domain


def _valid_filter_domain(value: str) -> bool:
    if not value or "." not in value or ".." in value:
        return False
    return bool(re.match(r"^[a-z0-9*_.-]+$", value))


def _normalize_filter_pattern(value: str):
    value = value.strip().rstrip(".").lower()
    if not value:
        return "domain", ""
    value = value.lstrip(".")
    if value.startswith("*."):
        return "wildcard", "*" + value[1:]
    if "*" in value:
        return "wildcard", value
    domain = normalize_domain(value)
    return "domain", domain


def _domain_from_urlish(value: str) -> str:
    value = value.strip()
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    if value.startswith("|"):
        value = value.lstrip("|")
    return value.split("/", 1)[0].split(":", 1)[0]


def _extract_filter_domains(text: str):
    base = text.split("$", 1)[0].split("##", 1)[0].split("#@#", 1)[0]
    for raw in base.split(","):
        candidate = raw.strip()
        if not candidate:
            continue
        if candidate.startswith("||"):
            candidate = candidate[2:]
        candidate = candidate.split("^", 1)[0].strip("|")
        candidate = _domain_from_urlish(candidate).rstrip(".")
        pattern_type, pattern = _normalize_filter_pattern(candidate)
        if _valid_filter_domain(pattern.replace("*.", "x.", 1).replace("*", "x")):
            yield pattern_type, pattern


def _parse_hosts_line(line: str):
    parts = line.split()
    if len(parts) < 2:
        return []
    try:
        ipaddress.ip_address(parts[0])
    except ValueError:
        return []
    out = []
    for host in parts[1:]:
        host = host.strip()
        if host.lower() in ("localhost", "localhost.localdomain", "local"):
            continue
        pattern_type, pattern = _normalize_filter_pattern(host)
        if _valid_filter_domain(pattern.replace("*.", "x.", 1).replace("*", "x")):
            out.append(("block", pattern_type, pattern))
    return out


def _parse_umatrix_line(line: str):
    parts = line.split()
    if len(parts) != 4 or parts[3] not in ("allow", "block"):
        return []
    source, destination, resource_type, action = parts
    if resource_type.startswith(("ua-spoof:", "referrer-spoof:")):
        return []
    if destination == "*":
        destination = source
    if destination == "*":
        return []
    pattern_type, pattern = _normalize_filter_pattern(destination)
    if _valid_filter_domain(pattern.replace("*.", "x.", 1).replace("*", "x")):
        return [(action, pattern_type, pattern)]
    return []


def _parse_umatrix_markdown(text: str, default_action: str):
    if "```" not in text:
        return []
    entries = []
    skipped_block_rules = 0
    for block in re.findall(r"```(.*?)```", text, flags=re.S):
        for raw in block.splitlines():
            line = raw.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 4 or parts[3] not in ("allow", "block"):
                continue
            source, destination, resource_type, action = parts
            if resource_type.startswith(("ua-spoof:", "referrer-spoof:")):
                continue
            if default_action == "allow":
                if action != "allow":
                    skipped_block_rules += 1
                    continue
                if resource_type == "*":
                    continue
                candidates = [source, destination if destination != "*" else source]
                for candidate in candidates:
                    pattern_type, pattern = _normalize_filter_pattern(candidate)
                    if _valid_filter_domain(pattern.replace("*.", "x.", 1).replace("*", "x")):
                        entries.append(("allow", pattern_type, pattern))
            else:
                candidate = destination if destination != "*" else source
                pattern_type, pattern = _normalize_filter_pattern(candidate)
                if _valid_filter_domain(pattern.replace("*.", "x.", 1).replace("*", "x")):
                    entries.append((action, pattern_type, pattern))
    if default_action == "allow" and skipped_block_rules:
        entries = _drop_redundant_occurrences(entries, skipped_block_rules)
    return entries


def _dangerous_regex(pattern: str) -> bool:
    return bool(re.search(r"\((?:[^()\\]|\\.)*[*+](?:[^()\\]|\\.)*\)[*+{]", pattern))


def _drop_redundant_occurrences(entries, count: int):
    if count <= 0:
        return entries
    occurrence_counts = {}
    for item in entries:
        occurrence_counts[item] = occurrence_counts.get(item, 0) + 1
    drop_indexes = set()
    for idx in range(len(entries) - 1, -1, -1):
        item = entries[idx]
        if occurrence_counts.get(item, 0) > 1:
            drop_indexes.add(idx)
            occurrence_counts[item] -= 1
            count -= 1
            if count == 0:
                break
    if not drop_indexes:
        return entries
    return [item for idx, item in enumerate(entries) if idx not in drop_indexes]


def parse_filter_rule(line: str, default_action: str = "block"):
    action = default_action
    if line.startswith("@@"):
        action = "allow"
        line = line[2:].strip()
    if "$badfilter" in line:
        return []
    if line.startswith("/") and line.count("/") >= 2:
        end = line.rfind("/")
        pattern = line[1:end]
        if _dangerous_regex(pattern):
            return []
        try:
            re.compile(pattern)
        except re.error:
            return []
        return [(action, "regex", pattern)]
    hosts = _parse_hosts_line(line)
    if hosts:
        return hosts
    umatrix = _parse_umatrix_line(line)
    if umatrix:
        return umatrix
    line = line.split("$", 1)[0].strip()
    if line.startswith("||"):
        value = line[2:].split("^", 1)[0].strip("/")
        pattern_type, pattern = _normalize_filter_pattern(value)
        if _valid_filter_domain(pattern.replace("*.", "x.", 1).replace("*", "x")):
            return [(action, pattern_type, pattern)]
        return []
    if line.startswith("|"):
        line = line.lstrip("|")
    if line.startswith(("http://", "https://")):
        line = _domain_from_urlish(line)
    else:
        line = line.split("^", 1)[0].split("/", 1)[0]
    pattern_type, pattern = _normalize_filter_pattern(line)
    if _valid_filter_domain(pattern.replace("*.", "x.", 1).replace("*", "x")):
        return [(action, pattern_type, pattern)]
    return [(action, pt, p) for pt, p in _extract_filter_domains(line)]


def parse_filter_list(text: str, default_action: str = "block"):
    umatrix_entries = _parse_umatrix_markdown(text, default_action)
    if umatrix_entries:
        return umatrix_entries

    parsed = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#", "[", ";")):
            continue
        if line.startswith(("address=/", "server=/")):
            parts = line.split("/")
            if len(parts) >= 3:
                pattern_type, pattern = _normalize_filter_pattern(parts[1])
                parsed.append(("block", pattern_type, pattern))
            continue
        parsed.extend(parse_filter_rule(line, default_action))
    seen = set()
    unique = []
    for item in parsed:
        if item[2] and item not in seen:
            seen.add(item)
            unique.append(item)
    domain_set = {(a, p) for a, pt, p in unique if pt == "domain"}
    regex_seen = set()
    filtered = []
    for action, pt, pattern in unique:
        if pt == "regex":
            key = (action, pattern)
            if key in regex_seen:
                continue
            regex_seen.add(key)
            filtered.append((action, pt, pattern))
        elif pt == "wildcard" and pattern.startswith("*.") and (action, pattern[2:]) in domain_set:
            continue
        else:
            filtered.append((action, pt, pattern))
    return filtered


TEXT_EXTENSIONS = (".txt", ".hosts", ".domains", ".list", ".conf", ".rules")
MAX_EXTRACTED_BYTES = 100_000_000


def _looks_like_html(data: bytes) -> bool:
    sample = data[:2048].lstrip().lower()
    return sample.startswith(b"<!doctype html") or sample.startswith(b"<html") or b"<body" in sample[:512]


def decode_blocklist_content(data: bytes, url: str = "", max_bytes: int = MAX_EXTRACTED_BYTES) -> str:
    lower = (url or "").lower()
    if lower.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    elif lower.endswith(".zip") or data[:4] == b"PK\x03\x04":
        total = 0
        chunks = []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/"):
                    raise ValueError("ZIP blocklist contains unsafe path")
                if info.is_dir() or not name.lower().endswith(TEXT_EXTENSIONS):
                    continue
                total += info.file_size
                if total > max_bytes:
                    raise ValueError("ZIP blocklist is too large")
                with archive.open(info) as fh:
                    chunks.append(fh.read(max_bytes - sum(len(c) for c in chunks)))
        if not chunks:
            raise ValueError("ZIP blocklist contains no supported text file")
        data = b"\n".join(chunks)
    if len(data) > max_bytes:
        raise ValueError("Blocklist is too large")
    if not data.strip():
        raise ValueError("Downloaded blocklist is empty")
    if _looks_like_html(data):
        raise ValueError("Downloaded blocklist looks like an HTML error page")
    return data.decode("utf-8", errors="ignore")


def fetch_url_text(url: str, max_bytes: int = 100_000_000, etag: str = "", last_modified: str = ""):
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; PyGuardDNS/1.0; +https://github.com/)",
        "Accept": "text/plain,text/*,application/gzip,application/zip,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = Request(
        url,
        headers=headers,
    )
    timeout = float(os.environ.get("LOCALDNSGUARD_BLOCKLIST_DOWNLOAD_TIMEOUT", "20") or "20")
    chunk_size = 1024 * 1024
    try:
        deadline = time.monotonic() + timeout
        with urlopen(request, timeout=min(10, timeout)) as response:
            status = getattr(response, "status", 200)
            chunks = []
            total = 0
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Blocklist download timed out after {timeout:g}s")
                chunk = response.read(min(chunk_size, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    break
            data = b"".join(chunks)
            return {
                "status": status,
                "text": decode_blocklist_content(data, url, max_bytes),
                "etag": response.headers.get("ETag", ""),
                "last_modified": response.headers.get("Last-Modified", ""),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
    except HTTPError as exc:
        if exc.code == 304:
            return {"status": 304, "text": "", "etag": etag, "last_modified": last_modified, "sha256": ""}
        raise
    except OSError as original_error:
        if _dns_resolver is None:
            raise original_error
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise original_error
        ips = _dns_resolver(parsed.hostname)
        if not ips:
            raise original_error
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        extra_headers = ""
        if etag:
            extra_headers += f"If-None-Match: {etag}\r\n"
        if last_modified:
            extra_headers += f"If-Modified-Since: {last_modified}\r\n"
        last_err = original_error
        for ip in ips[:4]:
            try:
                raw = socket.create_connection((ip, port), timeout=min(10, timeout))
                with raw:
                    raw.settimeout(timeout)
                    conn = raw
                    if parsed.scheme == "https":
                        context = ssl.create_default_context()
                        conn = context.wrap_socket(raw, server_hostname=parsed.hostname)
                        conn.settimeout(timeout)
                    with conn:
                        req = (
                            f"GET {path} HTTP/1.1\r\n"
                            f"Host: {parsed.hostname}\r\n"
                            f"User-Agent: Mozilla/5.0 (compatible; PyGuardDNS/1.0)\r\n"
                            f"Accept: text/plain,*/*\r\n"
                            + extra_headers
                            + "Connection: close\r\n\r\n"
                        ).encode("ascii", errors="replace")
                        conn.sendall(req)
                        data = b""
                        deadline2 = time.monotonic() + timeout
                        while len(data) < max_bytes + 8192:
                            if time.monotonic() > deadline2:
                                raise TimeoutError(f"Blocklist download timed out after {timeout:g}s")
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                header_part, _, body = data.partition(b"\r\n\r\n")
                status_line = header_part.splitlines()[0].decode("latin1", errors="ignore") if header_part else ""
                if " 304 " in status_line:
                    return {"status": 304, "text": "", "etag": etag, "last_modified": last_modified, "sha256": ""}
                if not any(f" {c} " in status_line for c in ("200", "301", "302")):
                    raise OSError(status_line or "HTTP download failed")
                body = body[:max_bytes]
                return {
                    "status": 200,
                    "text": decode_blocklist_content(body, url, max_bytes),
                    "etag": "",
                    "last_modified": "",
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            except OSError as exc:
                last_err = exc
                continue
        raise last_err


def import_report(entries, total_lines: int = 0, invalid_rules: int = 0) -> dict:
    unique = set(entries)
    regex_rules = sum(1 for _, pt, _ in entries if pt == "regex")
    allow_rules = sum(1 for action, _, _ in entries if action == "allow")
    block_rules = sum(1 for action, _, _ in entries if action == "block")
    return {
        "total_lines": total_lines,
        "valid_rules": len(entries),
        "unique_rules": len(unique),
        "duplicate_rules": max(0, len(entries) - len(unique)),
        "invalid_rules": invalid_rules,
        "regex_rules": regex_rules,
        "allow_rules": allow_rules,
        "block_rules": block_rules,
        "rejected_regex_rules": 0,
    }


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS blocklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    list_type TEXT NOT NULL DEFAULT 'block',
    enabled INTEGER NOT NULL DEFAULT 1,
    rule_count INTEGER NOT NULL DEFAULT 0,
    last_update TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    last_successful_update TEXT NOT NULL DEFAULT '',
    last_failed_update TEXT NOT NULL DEFAULT '',
    last_rule_count INTEGER NOT NULL DEFAULT 0,
    last_unique_rule_count INTEGER NOT NULL DEFAULT 0,
    last_sha256 TEXT NOT NULL DEFAULT '',
    etag TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    duplicate_rule_count INTEGER NOT NULL DEFAULT 0,
    import_report TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocklist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocklist_id INTEGER NOT NULL,
    action TEXT NOT NULL DEFAULT 'block',
    pattern_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocklist_entries_list ON blocklist_entries(blocklist_id);
CREATE INDEX IF NOT EXISTS idx_blocklist_entries_action ON blocklist_entries(action, pattern_type, pattern);
"""


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class BlocklistManager:
    def __init__(self, db, reload_callback=None):
        self.db = db
        self.reload_callback = reload_callback
        self._update_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._update_status = {
            "running": False,
            "status": "idle",
            "total": 0,
            "current_index": 0,
            "current_id": None,
            "current_name": "",
            "results": [],
            "started_at": "",
            "finished_at": "",
        }

    def init_schema(self):
        self.db.executescript(SCHEMA_SQL)
        existing = [row["name"] for row in self.db.execute("PRAGMA table_info(blocklists)").fetchall()]
        migrations = {
            "enabled": "INTEGER NOT NULL DEFAULT 1",
            "last_successful_update": "TEXT NOT NULL DEFAULT ''",
            "last_failed_update": "TEXT NOT NULL DEFAULT ''",
            "last_rule_count": "INTEGER NOT NULL DEFAULT 0",
            "last_unique_rule_count": "INTEGER NOT NULL DEFAULT 0",
            "last_sha256": "TEXT NOT NULL DEFAULT ''",
            "etag": "TEXT NOT NULL DEFAULT ''",
            "last_modified": "TEXT NOT NULL DEFAULT ''",
            "duplicate_rule_count": "INTEGER NOT NULL DEFAULT 0",
            "import_report": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in migrations.items():
            if column not in existing:
                self.db.execute(f"ALTER TABLE blocklists ADD COLUMN {column} {definition}")
        self.db.commit()

    def add_from_url(self, name: str, url: str, list_type: str = "block", notify_reload: bool = True) -> int:
        fetched = fetch_url_text(url)
        return self.add_from_text(name, fetched["text"], list_type, source=url, sha256=fetched.get("sha256", ""), etag=fetched.get("etag", ""), last_modified=fetched.get("last_modified", ""), notify_reload=notify_reload)

    def add_from_text(self, name: str, text: str, list_type: str = "block", source: str = "", sha256: str = "", etag: str = "", last_modified: str = "", replace_by_name: bool = True, notify_reload: bool = True, skip_existing_entries: bool = True) -> int:
        list_type = "allow" if list_type == "allow" else "block"
        entries = parse_filter_list(text, default_action=list_type)
        if list_type == "allow":
            entries = [(action, pt, pattern) for action, pt, pattern in entries if action == "allow"]
        if not entries:
            return 0
        report = import_report(entries, total_lines=len(text.splitlines()))
        seen_entries = set()
        unique_entries = []
        for entry in entries:
            if entry in seen_entries:
                continue
            seen_entries.add(entry)
            unique_entries.append(entry)
        if skip_existing_entries:
            existing_entries = {
                (row["action"], row["pattern_type"], row["pattern"])
                for row in self.db.execute(
                    """
                    SELECT be.action, be.pattern_type, be.pattern
                    FROM blocklist_entries be
                    JOIN blocklists bl ON bl.id = be.blocklist_id
                    WHERE bl.list_type=?
                    """,
                    (list_type,),
                ).fetchall()
            }
            before_existing_filter = len(unique_entries)
            unique_entries = [entry for entry in unique_entries if entry not in existing_entries]
            report["existing_rule_duplicates"] = before_existing_filter - len(unique_entries)
        else:
            report["existing_rule_duplicates"] = 0
        if not unique_entries:
            return 0
        created = now_iso()
        with self._update_lock:
            if replace_by_name:
                self._delete_by_name(name)
            curs = self.db.execute(
                """INSERT INTO blocklists(name,url,list_type,rule_count,last_update,last_successful_update,last_rule_count,
                   last_unique_rule_count,last_sha256,etag,last_modified,duplicate_rule_count,import_report,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (name, source, list_type, len(unique_entries), created, created, len(unique_entries), report["unique_rules"], sha256, etag, last_modified, report["duplicate_rules"] + report["existing_rule_duplicates"], json.dumps(report), created),
            )
            bl_id = curs.lastrowid
            self.db.executemany(
                "INSERT INTO blocklist_entries(blocklist_id,action,pattern_type,pattern,created_at) VALUES(?,?,?,?,?)",
                [(bl_id, action, pt, pattern, created) for action, pt, pattern in unique_entries],
            )
            self.db.commit()
        if notify_reload:
            self._notify_reload()
        return len(unique_entries)

    def update(self, list_id: int, background: bool = True) -> dict:
        item = self._get(list_id)
        if not item:
            raise ValueError(f"Blocklist {list_id} not found")
        if not item["url"] or not item["url"].startswith(("http://", "https://")):
            raise ValueError("Blocklist has no remote URL")

        def _do():
            try:
                fetched = fetch_url_text(item["url"], etag=item.get("etag", ""), last_modified=item.get("last_modified", ""))
                if fetched["status"] == 304:
                    with self._update_lock:
                        self.db.execute("UPDATE blocklists SET last_update=?, last_error='' WHERE id=?", (now_iso(), list_id))
                        self.db.commit()
                    return
                text = fetched["text"]
                list_type = "allow" if item.get("list_type") == "allow" else "block"
                entries = parse_filter_list(text, default_action=list_type)
                if list_type == "allow":
                    entries = [(action, pt, pattern) for action, pt, pattern in entries if action == "allow"]
                if not entries:
                    raise ValueError("Download succeeded but no valid rules found")
                old_count = int(item.get("last_rule_count") or item.get("rule_count") or 0)
                if old_count > 10000 and len(entries) < old_count * 0.5:
                    raise ValueError("New list is suspiciously smaller than previous version")
                report = import_report(entries, total_lines=len(text.splitlines()))
                created = now_iso()
                with self._update_lock:
                    self._delete_entries(list_id)
                    self.db.executemany(
                        "INSERT INTO blocklist_entries(blocklist_id,action,pattern_type,pattern,created_at) VALUES(?,?,?,?,?)",
                        [(list_id, action, pt, pattern, created) for action, pt, pattern in entries],
                    )
                    self.db.execute(
                        """UPDATE blocklists SET rule_count=?, last_update=?, last_error='', last_successful_update=?,
                           last_rule_count=?, last_unique_rule_count=?, last_sha256=?, etag=?, last_modified=?,
                           duplicate_rule_count=?, import_report=? WHERE id=?""",
                        (len(entries), created, created, len(entries), report["unique_rules"], fetched.get("sha256", ""),
                         fetched.get("etag", ""), fetched.get("last_modified", ""), report["duplicate_rules"], json.dumps(report), list_id),
                    )
                    self.db.commit()
                self._notify_reload()
            except Exception as exc:
                with self._update_lock:
                    self.db.execute("UPDATE blocklists SET last_error=?, last_failed_update=? WHERE id=?", (str(exc), now_iso(), list_id))
                    self.db.commit()

        if background:
            threading.Thread(target=_do, name=f"bl-update-{list_id}", daemon=True).start()
            return {"status": "started", "id": list_id}
        _do()
        item = self._get(list_id)
        return {"status": "done" if not (item and item["last_error"]) else "error", "id": list_id}

    def update_all(self, background: bool = True) -> dict:
        lists = self.get_all()
        urls = [bl for bl in lists if bl["url"].startswith(("http://", "https://"))]
        if not urls:
            self._set_update_status({
                "running": False,
                "status": "no_lists",
                "total": 0,
                "current_index": 0,
                "current_id": None,
                "current_name": "",
                "results": [],
                "started_at": now_iso(),
                "finished_at": now_iso(),
            })
            return {"status": "no_lists", "updated": 0}

        def _do_all():
            self._set_update_status({
                "running": True,
                "status": "running",
                "total": len(urls),
                "current_index": 0,
                "current_id": None,
                "current_name": "",
                "results": [],
                "started_at": now_iso(),
                "finished_at": "",
            })
            for idx, bl in enumerate(urls, 1):
                self._set_update_status({
                    "running": True,
                    "status": "running",
                    "current_index": idx,
                    "current_id": bl["id"],
                    "current_name": bl.get("name", "") or f"ID {bl['id']}",
                })
                try:
                    self.update(bl["id"], background=False)
                    updated = self._get(bl["id"]) or {}
                    last_error = updated.get("last_error", "")
                    result = {
                        "id": bl["id"],
                        "name": bl.get("name", "") or f"ID {bl['id']}",
                        "status": "error" if last_error else "done",
                        "error": last_error,
                        "rules": updated.get("rule_count", bl.get("rule_count", 0)),
                    }
                except Exception as exc:
                    result = {
                        "id": bl["id"],
                        "name": bl.get("name", "") or f"ID {bl['id']}",
                        "status": "error",
                        "error": str(exc),
                        "rules": bl.get("rule_count", 0),
                    }
                self._append_update_result(result)
            self._set_update_status({
                "running": False,
                "status": "done",
                "current_id": None,
                "current_name": "",
                "finished_at": now_iso(),
            })

        if background:
            current = self.update_status()
            if current.get("running"):
                return {"status": "already_running", "count": current.get("total", 0)}
            threading.Thread(target=_do_all, name="bl-update-all", daemon=True).start()
            return {"status": "started", "count": len(urls)}
        _do_all()
        status = self.update_status()
        return {"status": "done", "updated": len(status.get("results", [])), "results": status.get("results", [])}

    def update_status(self) -> dict:
        with self._status_lock:
            status = dict(self._update_status)
            status["results"] = [dict(item) for item in self._update_status.get("results", [])]
            return status

    def _set_update_status(self, updates: dict) -> None:
        with self._status_lock:
            self._update_status.update(updates)

    def _append_update_result(self, result: dict) -> None:
        with self._status_lock:
            self._update_status.setdefault("results", []).append(result)

    def update_metadata(self, list_id: int, name: str, url: str, list_type: str) -> bool:
        item = self._get(list_id)
        if not item:
            return False
        list_type = "allow" if list_type == "allow" else "block"
        with self._update_lock:
            self.db.execute(
                "UPDATE blocklists SET name=?, url=?, list_type=? WHERE id=?",
                (name, url, list_type, list_id),
            )
            self.db.commit()
        return True

    def set_enabled(self, list_id: int, enabled: bool) -> bool:
        item = self._get(list_id)
        if not item:
            return False
        with self._update_lock:
            self.db.execute(
                "UPDATE blocklists SET enabled=? WHERE id=?",
                (1 if enabled else 0, list_id),
            )
            self.db.commit()
        self._notify_reload()
        return True

    def delete(self, list_id: int, notify_reload: bool = True) -> bool:
        item = self._get(list_id)
        if not item:
            return False
        with self._update_lock:
            self._delete_entries(list_id)
            self.db.execute("DELETE FROM blocklists WHERE id=?", (list_id,))
            self.db.commit()
        if notify_reload:
            self._notify_reload()
        return True

    def get_all(self):
        return [
            dict(r) for r in self.db.execute(
                "SELECT * FROM blocklists ORDER BY id ASC"
            ).fetchall()
        ]

    def get_by_id(self, list_id: int) -> Optional[dict]:
        return self._get(list_id)

    def get_stats(self):
        rows = self.db.execute(
            "SELECT bl.id, bl.name, bl.list_type, bl.rule_count, bl.last_update, "
            "bl.last_error, bl.enabled, COUNT(be.id) as actual_rules "
            "FROM blocklists bl LEFT JOIN blocklist_entries be ON be.blocklist_id = bl.id "
            "GROUP BY bl.id ORDER BY bl.id ASC"
        ).fetchall()
        return [dict(r) for r in rows]

    def _get(self, list_id: int) -> Optional[dict]:
        row = self.db.execute("SELECT * FROM blocklists WHERE id=?", (list_id,)).fetchone()
        return dict(row) if row else None

    def _delete_by_name(self, name: str):
        existing = self.db.execute("SELECT id FROM blocklists WHERE name=?", (name,)).fetchone()
        if existing:
            self._delete_entries(existing["id"])
            self.db.execute("DELETE FROM blocklists WHERE id=?", (existing["id"],))

    def _delete_entries(self, list_id: int):
        self.db.execute("DELETE FROM blocklist_entries WHERE blocklist_id=?", (list_id,))

    def _notify_reload(self):
        if self.reload_callback:
            self.reload_callback()

    def get_entries(self, list_id: int):
        return [dict(r) for r in self.db.execute(
            """
            SELECT be.action, be.pattern_type, be.pattern, bl.name as list_name
            FROM blocklist_entries be
            JOIN blocklists bl ON bl.id = be.blocklist_id
            WHERE be.blocklist_id=? AND bl.enabled=1
            ORDER BY be.id ASC
            """,
            (list_id,)
        ).fetchall()]

    def load_into_engine(self, engine):
        rows = self.db.execute(
            """
            SELECT be.action, be.pattern_type, be.pattern, bl.name as list_name
            FROM blocklist_entries be
            JOIN blocklists bl ON bl.id = be.blocklist_id
            WHERE bl.enabled = 1
            ORDER BY be.id ASC
            """
        ).fetchall()
        for row in rows:
            action = row["action"]
            pt = row["pattern_type"]
            pattern = row["pattern"]
            list_name = row["list_name"]
            if pt == "domain":
                raw = f"{'@@' if action == 'allow' else ''}||{pattern}^"
            elif pt == "regex":
                raw = f"/{pattern}/"
                if action == "allow":
                    raw = "@@" + raw
            elif pt == "wildcard":
                raw = f"{'@@' if action == 'allow' else ''}*.{pattern.lstrip('*.')}"
            else:
                continue
            engine.add_rule(raw, action, list_name=list_name)
