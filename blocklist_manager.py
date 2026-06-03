import ipaddress
import re
import threading
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    import idna
except ImportError:
    idna = None


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


def fetch_url_text(url: str, max_bytes: int = 100_000_000) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; PyGuardDNS/1.0; +https://github.com/)",
            "Accept": "text/plain,text/*,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    with urlopen(request, timeout=10) as response:
        return response.read(max_bytes).decode("utf-8", errors="ignore")


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

    def init_schema(self):
        self.db.executescript(SCHEMA_SQL)
        existing = [row["name"] for row in self.db.execute("PRAGMA table_info(blocklists)").fetchall()]
        if "enabled" not in existing:
            self.db.execute("ALTER TABLE blocklists ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        self.db.commit()

    def add_from_url(self, name: str, url: str, list_type: str = "block") -> int:
        text = fetch_url_text(url)
        return self.add_from_text(name, text, list_type, source=url)

    def add_from_text(self, name: str, text: str, list_type: str = "block", source: str = "") -> int:
        list_type = "allow" if list_type == "allow" else "block"
        entries = parse_filter_list(text, default_action=list_type)
        if list_type == "allow":
            entries = [(action, pt, pattern) for action, pt, pattern in entries if action == "allow"]
        if not entries:
            return 0
        created = now_iso()
        with self._update_lock:
            self._delete_by_name(name)
            curs = self.db.execute(
                "INSERT INTO blocklists(name,url,list_type,rule_count,last_update,created_at) VALUES(?,?,?,?,?,?)",
                (name, source, list_type, len(entries), created, created),
            )
            bl_id = curs.lastrowid
            self.db.executemany(
                "INSERT INTO blocklist_entries(blocklist_id,action,pattern_type,pattern,created_at) VALUES(?,?,?,?,?)",
                [(bl_id, action, pt, pattern, created) for action, pt, pattern in entries],
            )
            self.db.commit()
        self._notify_reload()
        return len(entries)

    def update(self, list_id: int, background: bool = True) -> dict:
        item = self._get(list_id)
        if not item:
            raise ValueError(f"Blocklist {list_id} not found")
        if not item["url"] or not item["url"].startswith(("http://", "https://")):
            raise ValueError("Blocklist has no remote URL")

        def _do():
            try:
                text = fetch_url_text(item["url"])
                list_type = "allow" if item.get("list_type") == "allow" else "block"
                entries = parse_filter_list(text, default_action=list_type)
                if list_type == "allow":
                    entries = [(action, pt, pattern) for action, pt, pattern in entries if action == "allow"]
                if not entries:
                    raise ValueError("Download succeeded but no valid rules found")
                created = now_iso()
                with self._update_lock:
                    self._delete_entries(list_id)
                    self.db.executemany(
                        "INSERT INTO blocklist_entries(blocklist_id,action,pattern_type,pattern,created_at) VALUES(?,?,?,?,?)",
                        [(list_id, action, pt, pattern, created) for action, pt, pattern in entries],
                    )
                    self.db.execute(
                        "UPDATE blocklists SET rule_count=?, last_update=?, last_error='' WHERE id=?",
                        (len(entries), created, list_id),
                    )
                    self.db.commit()
                self._notify_reload()
            except Exception as exc:
                with self._update_lock:
                    self.db.execute("UPDATE blocklists SET last_error=? WHERE id=?", (str(exc), list_id))
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
            return {"status": "no_lists", "updated": 0}

        def _do_all():
            for bl in urls:
                try:
                    self.update(bl["id"], background=False)
                except Exception:
                    pass

        if background:
            threading.Thread(target=_do_all, name="bl-update-all", daemon=True).start()
            return {"status": "started", "count": len(urls)}
        for bl in urls:
            self.update(bl["id"], background=False)
        return {"status": "done", "updated": len(urls)}

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
        self._notify_reload()
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

    def delete(self, list_id: int) -> bool:
        item = self._get(list_id)
        if not item:
            return False
        with self._update_lock:
            self._delete_entries(list_id)
            self.db.execute("DELETE FROM blocklists WHERE id=?", (list_id,))
            self.db.commit()
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
