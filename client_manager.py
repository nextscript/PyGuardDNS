import ipaddress
import threading
from datetime import datetime
from typing import Optional

PROFILE_SCHEMA_SQL = """
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

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL UNIQUE,
    cidr TEXT NOT NULL DEFAULT '',
    profile_id INTEGER REFERENCES profiles(id),
    filtering_enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profile_custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES profiles(id),
    action TEXT NOT NULL DEFAULT 'block',
    pattern_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profile_blocklists (
    profile_id INTEGER NOT NULL,
    blocklist_id INTEGER NOT NULL,
    PRIMARY KEY (profile_id, blocklist_id)
);

CREATE TABLE IF NOT EXISTS profile_service_blocks (
    profile_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    PRIMARY KEY (profile_id, service_name)
);

CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip);
CREATE INDEX IF NOT EXISTS idx_clients_profile ON clients(profile_id);
CREATE INDEX IF NOT EXISTS idx_profile_rules_profile ON profile_custom_rules(profile_id);
"""


SERVICE_DOMAINS = {
    "YouTube": [
        "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
        "ytimg.com", "googlevideo.com", "youtubei.googleapis.com",
        "youtube.googleapis.com", "youtube-nocookie.com",
    ],
    "TikTok": [
        "tiktok.com", "www.tiktok.com", "m.tiktok.com", "tiktokcdn.com",
        "tiktokv.com", "musical.ly",
    ],
    "Instagram": [
        "instagram.com", "www.instagram.com", "cdninstagram.com",
        "instagram.fotp1-1.fna.fbcdn.net",
    ],
    "Facebook": [
        "facebook.com", "www.facebook.com", "m.facebook.com",
        "fbcdn.net", "fb.com", "fbsbx.com",
    ],
    "X/Twitter": [
        "twitter.com", "www.twitter.com", "x.com", "www.x.com",
        "twimg.com", "t.co",
    ],
    "Discord": [
        "discord.com", "www.discord.com", "discordapp.com",
        "cdn.discordapp.com", "discord.gg",
    ],
    "Twitch": [
        "twitch.tv", "www.twitch.tv", "ttvnw.net", "jtvnw.net",
    ],
    "Netflix": [
        "netflix.com", "www.netflix.com", "nflxvideo.net",
        "nflximg.net", "nflxext.com",
    ],
    "Spotify": [
        "spotify.com", "www.spotify.com", "open.spotify.com",
        "scdn.co", "spotifycdn.com",
    ],
    "Steam": [
        "steampowered.com", "steamcommunity.com", "steamcdn.com",
        "steamstore.com", "steamstatic.com",
    ],
    "Epic Games": [
        "epicgames.com", "www.epicgames.com", "unrealengine.com",
        "easistent.com",
    ],
    "Roblox": [
        "roblox.com", "www.roblox.com", "rbxcdn.com",
    ],
    "Snapchat": [
        "snapchat.com", "www.snapchat.com", "sc-cdn.net",
    ],
    "WhatsApp": [
        "whatsapp.com", "www.whatsapp.com", "whatsapp.net",
        "cdn.whatsapp.net",
    ],
    "Telegram": [
        "telegram.org", "t.me", "cdn-telegram.org",
    ],
    "Reddit": [
        "reddit.com", "www.reddit.com", "redditmedia.com",
        "redditstatic.com", "redd.it",
    ],
    "Pornhub": [
        "pornhub.com", "www.pornhub.com", "phncdn.com",
    ],
    "OnlyFans": [
        "onlyfans.com", "www.onlyfans.com",
    ],
}

SAFESEARCH_REWRITES = {
    "google.com": {"force": "forcesafesearch.google.com", "qtype": "CNAME"},
    "www.google.com": {"force": "forcesafesearch.google.com", "qtype": "CNAME"},
    "bing.com": {"force": "strict.bing.com", "qtype": "CNAME"},
    "www.bing.com": {"force": "strict.bing.com", "qtype": "CNAME"},
    "duckduckgo.com": {"force": "safe.duckduckgo.com", "qtype": "CNAME"},
    "www.duckduckgo.com": {"force": "safe.duckduckgo.com", "qtype": "CNAME"},
}

YOUTUBE_SAFESEARCH_REWRITES = {
    "youtube.com": {"force": "restrict.youtube.com", "qtype": "CNAME"},
    "www.youtube.com": {"force": "restrict.youtube.com", "qtype": "CNAME"},
    "m.youtube.com": {"force": "restrict.youtube.com", "qtype": "CNAME"},
}

SAFESEARCH_PROFILE_COLUMNS = {
    "google": "safe_search_google",
    "bing": "safe_search_bing",
    "ddg": "safe_search_ddg",
}

SAFESEARCH_COLUMN_SERVICE = {
    "safe_search_google": "google",
    "safe_search_bing": "bing",
    "safe_search_ddg": "ddg",
}


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ClientManager:
    def __init__(self, db, reload_callback=None):
        self.db = db
        self.reload_callback = reload_callback
        self._lock = threading.Lock()

    def init_schema(self):
        self.db.executescript(PROFILE_SCHEMA_SQL)
        self.db.commit()
        self._ensure_default_profile()
        self._ensure_existing_clients_have_profiles()

    def _ensure_default_profile(self):
        existing = self.db.execute("SELECT id FROM profiles WHERE is_default=1").fetchone()
        if not existing:
            now = now_iso()
            self.db.execute(
                "INSERT INTO profiles(name,description,is_default,filtering_enabled,safe_search_google,safe_search_bing,safe_search_ddg,youtube_restricted,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("Default", "Default profile for all clients", 1, 1, 0, 0, 0, 0, now, now),
            )
            self.db.commit()

    def _ensure_existing_clients_have_profiles(self):
        default = self.db.execute("SELECT id FROM profiles WHERE is_default=1").fetchone()
        if not default:
            return
        default_id = default["id"]
        self.db.execute(
            "UPDATE clients SET profile_id=? WHERE profile_id IS NULL",
            (default_id,),
        )
        self.db.commit()

    def _notify(self):
        if self.reload_callback:
            self.reload_callback()

    # ------------------------------------------------------------------ #
    #  Profiles                                                          #
    # ------------------------------------------------------------------ #

    def get_profiles(self):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM profiles ORDER BY is_default DESC, id ASC"
        ).fetchall()]

    def get_profile(self, profile_id: int) -> Optional[dict]:
        row = self.db.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        return dict(row) if row else None

    def create_profile(self, name: str, description: str = "", filtering_enabled: bool = True) -> dict:
        now = now_iso()
        with self._lock:
            self.db.execute(
                "INSERT INTO profiles(name,description,filtering_enabled,safe_search_google,safe_search_bing,safe_search_ddg,youtube_restricted,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (name, description, int(filtering_enabled), 0, 0, 0, 0, now, now),
            )
            self.db.commit()
            pid = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
        self._notify()
        return self.get_profile(pid)

    def update_profile(self, profile_id: int, **kwargs) -> Optional[dict]:
        profile = self.get_profile(profile_id)
        if not profile:
            return None
        name = kwargs.get("name", profile["name"])
        description = kwargs.get("description", profile["description"])
        filtering_enabled = kwargs.get("filtering_enabled", bool(profile["filtering_enabled"]))
        safe_search_google = int(kwargs.get("safe_search_google", profile.get("safe_search_google", 0)))
        safe_search_bing = int(kwargs.get("safe_search_bing", profile.get("safe_search_bing", 0)))
        safe_search_ddg = int(kwargs.get("safe_search_ddg", profile.get("safe_search_ddg", 0)))
        youtube_restricted = int(kwargs.get("youtube_restricted", profile.get("youtube_restricted", 0)))
        now = now_iso()
        with self._lock:
            self.db.execute(
                "UPDATE profiles SET name=?, description=?, filtering_enabled=?, safe_search_google=?, safe_search_bing=?, safe_search_ddg=?, youtube_restricted=?, updated_at=? WHERE id=?",
                (name, description, int(filtering_enabled), safe_search_google, safe_search_bing, safe_search_ddg, youtube_restricted, now, profile_id),
            )
            self.db.commit()
        self._notify()
        return self.get_profile(profile_id)

    def delete_profile(self, profile_id: int) -> bool:
        profile = self.get_profile(profile_id)
        if not profile:
            return False
        if profile["is_default"]:
            return False
        default = self.db.execute("SELECT id FROM profiles WHERE is_default=1").fetchone()
        default_id = default["id"] if default else None
        with self._lock:
            if default_id:
                self.db.execute("UPDATE clients SET profile_id=? WHERE profile_id=?", (default_id, profile_id))
            else:
                self.db.execute("UPDATE clients SET profile_id=NULL WHERE profile_id=?", (profile_id,))
            self.db.execute("DELETE FROM profile_custom_rules WHERE profile_id=?", (profile_id,))
            self.db.execute("DELETE FROM profile_blocklists WHERE profile_id=?", (profile_id,))
            self.db.execute("DELETE FROM profile_service_blocks WHERE profile_id=?", (profile_id,))
            self.db.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
            self.db.commit()
        self._notify()
        return True

    def get_services(self):
        return sorted(SERVICE_DOMAINS.keys())

    def get_profile_services(self, profile_id: int):
        rows = self.db.execute(
            "SELECT service_name FROM profile_service_blocks WHERE profile_id=? ORDER BY service_name ASC",
            (profile_id,),
        ).fetchall()
        return [r["service_name"] for r in rows]

    def add_profile_service(self, profile_id: int, service_name: str) -> bool:
        sname = service_name.strip()
        if sname not in SERVICE_DOMAINS:
            return False
        if not self.get_profile(profile_id):
            return False
        with self._lock:
            self.db.execute(
                "INSERT OR IGNORE INTO profile_service_blocks(profile_id,service_name) VALUES(?,?)",
                (profile_id, sname),
            )
            self.db.commit()
        self._notify()
        return True

    def remove_profile_service(self, profile_id: int, service_name: str) -> bool:
        with self._lock:
            self.db.execute(
                "DELETE FROM profile_service_blocks WHERE profile_id=? AND service_name=?",
                (profile_id, service_name.strip()),
            )
            self.db.commit()
        self._notify()
        return True

    # ------------------------------------------------------------------ #
    #  Clients                                                           #
    # ------------------------------------------------------------------ #

    def get_clients(self):
        rows = self.db.execute("""
            SELECT c.*, p.name as profile_name
            FROM clients c
            LEFT JOIN profiles p ON p.id = c.profile_id
            ORDER BY c.id DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_client_by_ip(self, ip: str) -> Optional[dict]:
        try:
            client_ip = ipaddress.ip_address(ip)
        except ValueError:
            return None
        rows = self.db.execute("""
            SELECT c.*, p.name as profile_name, p.filtering_enabled as profile_filtering,
                   p.safe_search_google, p.safe_search_bing, p.safe_search_ddg,
                   p.youtube_restricted
            FROM clients c
            LEFT JOIN profiles p ON p.id = c.profile_id
            ORDER BY c.id ASC
        """).fetchall()
        for row in rows:
            try:
                cidr_str = (row["cidr"] or row["ip"] or "").strip()
                if not cidr_str:
                    continue
                if "/" in cidr_str:
                    net = ipaddress.ip_network(cidr_str, strict=False)
                    if client_ip in net:
                        return dict(row)
                elif cidr_str == ip:
                    return dict(row)
            except ValueError:
                continue
        return None

    def get_client(self, client_id: int) -> Optional[dict]:
        row = self.db.execute("""
            SELECT c.*, p.name as profile_name,
                   p.safe_search_google, p.safe_search_bing, p.safe_search_ddg,
                   p.youtube_restricted
            FROM clients c
            LEFT JOIN profiles p ON p.id = c.profile_id
            WHERE c.id=?
        """, (client_id,)).fetchone()
        return dict(row) if row else None

    def create_client(self, ip: str, name: str = "", cidr: str = "", profile_id: Optional[int] = None) -> dict:
        now = now_iso()
        if not name:
            name = ip
        if profile_id is None:
            default = self.db.execute("SELECT id FROM profiles WHERE is_default=1").fetchone()
            profile_id = default["id"] if default else None
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO clients(name,ip,cidr,profile_id,filtering_enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (name, ip, cidr, profile_id, 1, now, now),
            )
            self.db.commit()
            cid = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return self.get_client(cid)

    def update_client(self, client_id: int, **kwargs) -> Optional[dict]:
        client = self.get_client(client_id)
        if not client:
            return None
        name = kwargs.get("name", client["name"])
        ip = kwargs.get("ip", client["ip"])
        cidr = kwargs.get("cidr", client["cidr"])
        profile_id = kwargs.get("profile_id", client["profile_id"])
        filtering_enabled = kwargs.get("filtering_enabled", bool(client["filtering_enabled"]))
        now = now_iso()
        with self._lock:
            self.db.execute(
                "UPDATE clients SET name=?, ip=?, cidr=?, profile_id=?, filtering_enabled=?, updated_at=? WHERE id=?",
                (name, ip, cidr, profile_id, int(filtering_enabled), now, client_id),
            )
            self.db.commit()
        return self.get_client(client_id)

    def delete_client(self, client_id: int) -> bool:
        client = self.get_client(client_id)
        if not client:
            return False
        with self._lock:
            self.db.execute("DELETE FROM clients WHERE id=?", (client_id,))
            self.db.commit()
        return True

    # ------------------------------------------------------------------ #
    #  Profile Custom Rules                                               #
    # ------------------------------------------------------------------ #

    def get_profile_rules(self, profile_id: int):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM profile_custom_rules WHERE profile_id=? ORDER BY id ASC",
            (profile_id,)
        ).fetchall()]

    def add_profile_rule(self, profile_id: int, action: str, pattern_type: str, pattern: str) -> Optional[dict]:
        if not self.get_profile(profile_id):
            return None
        now = now_iso()
        with self._lock:
            self.db.execute(
                "INSERT INTO profile_custom_rules(profile_id,action,pattern_type,pattern,created_at) VALUES(?,?,?,?,?)",
                (profile_id, action, pattern_type, pattern, now),
            )
            self.db.commit()
            rid = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
        self._notify()
        row = self.db.execute("SELECT * FROM profile_custom_rules WHERE id=?", (rid,)).fetchone()
        return dict(row) if row else None

    def delete_profile_rule(self, rule_id: int) -> bool:
        row = self.db.execute("SELECT * FROM profile_custom_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            return False
        with self._lock:
            self.db.execute("DELETE FROM profile_custom_rules WHERE id=?", (rule_id,))
            self.db.commit()
        self._notify()
        return True

    # ------------------------------------------------------------------ #
    #  Profile Blocklists                                                 #
    # ------------------------------------------------------------------ #

    def get_profile_blocklists(self, profile_id: int):
        return [dict(r) for r in self.db.execute("""
            SELECT pb.*, bl.name, bl.list_type, bl.rule_count, bl.enabled
            FROM profile_blocklists pb
            JOIN blocklists bl ON bl.id = pb.blocklist_id
            WHERE pb.profile_id=?
            ORDER BY bl.name ASC
        """, (profile_id,)).fetchall()]

    def add_blocklist_to_profile(self, profile_id: int, blocklist_id: int) -> bool:
        if not self.get_profile(profile_id):
            return False
        with self._lock:
            self.db.execute(
                "INSERT OR IGNORE INTO profile_blocklists(profile_id,blocklist_id) VALUES(?,?)",
                (profile_id, blocklist_id),
            )
            self.db.commit()
        self._notify()
        return True

    def remove_blocklist_from_profile(self, profile_id: int, blocklist_id: int) -> bool:
        with self._lock:
            self.db.execute(
                "DELETE FROM profile_blocklists WHERE profile_id=? AND blocklist_id=?",
                (profile_id, blocklist_id),
            )
            self.db.commit()
        self._notify()
        return True

    # ------------------------------------------------------------------ #
    #  Load into engine                                                   #
    # ------------------------------------------------------------------ #

    def load_profile_into_engine(self, engine, profile_id: int) -> None:
        profile = self.get_profile(profile_id)
        if not profile:
            return
        if not profile["filtering_enabled"]:
            return
        rules = self.get_profile_rules(profile_id)
        for rule in rules:
            action = rule["action"]
            pt = rule["pattern_type"]
            pattern = rule["pattern"]
            raw_rule = self._reconstruct_rule(action, pt, pattern)
            if raw_rule:
                engine.add_rule(raw_rule, action, list_name=profile["name"], profile_id=profile_id)

    def load_profile_blocklists_into_engine(self, engine, profile_id: int, blocklist_manager) -> None:
        profile = self.get_profile(profile_id)
        if not profile:
            return
        if not profile["filtering_enabled"]:
            return
        if blocklist_manager is None:
            return
        pbs = self.get_profile_blocklists(profile_id)
        for pb in pbs:
            bl_id = pb["blocklist_id"]
            entries = blocklist_manager.get_entries(bl_id)
            for entry in entries:
                action = entry["action"]
                pt = entry["pattern_type"]
                pattern = entry["pattern"]
                raw_rule = self._reconstruct_rule(action, pt, pattern)
                if raw_rule:
                    engine.add_rule(raw_rule, action, list_name=entry.get("list_name", pb.get("name", "")), profile_id=profile_id)

    def _reconstruct_rule(self, action: str, pattern_type: str, pattern: str) -> Optional[str]:
        if action == "rewrite":
            return None
        if pattern_type == "domain":
            return f"{'@@' if action == 'allow' else ''}||{pattern}^"
        elif pattern_type == "regex":
            raw = f"/{pattern}/"
            return f"@@{raw}" if action == "allow" else raw
        elif pattern_type == "wildcard":
            return f"{'@@' if action == 'allow' else ''}*.{pattern.lstrip('*.')}"
        return None
