import base64
import json
import logging
import os
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import dns.tsig

logger = logging.getLogger("dnssec")

RFC5011_ADD_HOLD_DOWN_DAYS = 30
RFC5011_REMOVE_HOLD_DOWN_DAYS = 30
RETIRED_KEY_RETENTION_DAYS = 90
DNSKEY_REVOKE_FLAG = 0x0080
DNSKEY_ZONE_FLAG = 0x0100
DNSKEY_SEP_FLAG = 0x0001
NSEC3_OPT_OUT_FLAG = 0x01

_EMBEDDED_ROOT_ANCHOR_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="0C05FDD6-422C-4910-8ED6-430ED15E11C2" source="http://data.iana.org/root-anchors/root-anchors.xml">
    <Zone>.</Zone>
    <KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
        <KeyTag>19036</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
    </KeyDigest>
    <KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
        <KeyTag>20326</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
        <PublicKey>AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=</PublicKey>
        <Flags>257</Flags>
    </KeyDigest>
    <KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00">
        <KeyTag>38696</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
        <PublicKey>AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=</PublicKey>
        <Flags>257</Flags>
    </KeyDigest>
</TrustAnchor>"""

_EMBEDDED_ROOT_KEY = """\
; Root Zone Trust Anchor (DNSKEY)
; This file contains the root DNSKEY records that serve as the
; DNSSEC trust anchor for local validation.
. IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
. IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=
. IN DNSKEY 256 3 8 AwEAAb5dDYffpgAJ8VUGLwQtWXPlQWsjIFJtCM00/XaKU+8ln+ofah3q2KxEIjvzQg+nqdxRj+8emtPne1mtYcbFWP4Q9E+DniOJLK09R05FuzvGbrG7DDdRDUX/cedFdV7O8pFEAYpJqYNR9BCTIAV973DO2biauKSA31b7I2lK/woxoR1tf5cqJ4SMbJUviuHicAEoUi2ATswloZNWd5T5thmEFZnxFx7D5UgKCY7oflS7+GU7dNJwEtmFnWYVETHN0kHXVz6aguouaAZp706YXNIoR/iTgQhmsR7XX+wL0Z8QM2LxQIyU6vRZ06IyuJMGRMiwkSuGElbumyBt12JZbrU=
"""


def _default_data_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _utc_now():
    return datetime.now(timezone.utc)


def _iso(dt=None):
    dt = dt or _utc_now()
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _as_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _read_root_anchor_entries(xml_text):
    root = ET.fromstring(xml_text)
    anchors = []
    for kd in root.findall("KeyDigest"):
        digest = kd.findtext("Digest", "").strip().upper()
        if not digest:
            continue
        anchor = {
            "key_tag": int(kd.findtext("KeyTag", "0")),
            "algorithm": int(kd.findtext("Algorithm", "8")),
            "digest_type": int(kd.findtext("DigestType", "2")),
            "digest": digest,
            "source": "IANA root-anchors.xml",
        }
        public_key = kd.findtext("PublicKey", "").strip()
        flags = kd.findtext("Flags", "").strip()
        if public_key:
            anchor["public_key"] = public_key
        if flags:
            anchor["flags"] = int(flags)
        valid_from = kd.attrib.get("validFrom")
        valid_until = kd.attrib.get("validUntil")
        if valid_from:
            anchor["valid_from"] = valid_from
        if valid_until:
            anchor["valid_until"] = valid_until
        anchors.append(anchor)
    return anchors


def _write_trust_anchor_json(json_path, xml_text):
    anchors = _read_root_anchor_entries(xml_text)
    now_dt = _utc_now()
    now = _iso(now_dt)
    state_anchors = []
    for anchor in anchors:
        valid_until = anchor.get("valid_until")
        first_seen_dt = _as_utc(_parse_iso(anchor.get("valid_from"))) or now_dt
        add_until_dt = first_seen_dt + timedelta(days=RFC5011_ADD_HOLD_DOWN_DAYS)
        has_public_key = bool(anchor.get("public_key"))
        state = "retired" if valid_until else "active"
        if state == "active" and has_public_key and anchor.get("key_tag") not in (20326,):
            state = "active" if now_dt >= add_until_dt else "pending"
        state_anchor = dict(anchor)
        state_anchor.update({
            "state": state,
            "first_seen": anchor.get("valid_from") or now,
            "last_seen": now,
            "revoked": False,
        })
        if state == "pending":
            state_anchor["hold_down_until"] = _iso(add_until_dt)
        state_anchors.append(state_anchor)
    payload = {
        "zone": ".",
        "anchors": state_anchors,
        "status": "rfc5011_state",
        "source": "embedded IANA root-anchors.xml",
        "updated_at": now,
        "last_checked": now,
        "next_check": _iso(_utc_now() + timedelta(hours=24)),
        "rfc5011_auto_update": True,
        "add_hold_down_days": RFC5011_ADD_HOLD_DOWN_DAYS,
        "remove_hold_down_days": RFC5011_REMOVE_HOLD_DOWN_DAYS,
        "last_error": "",
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def _backup_broken_file(path):
    if not os.path.exists(path):
        return ""
    backup = f"{path}.broken.{int(time.time())}"
    try:
        os.replace(path, backup)
        return backup
    except Exception:
        return ""


def ensure_root_trust_anchor(data_dir=None, xml_path=None, key_path=None, json_path=None):
    data_dir = data_dir or _default_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    xml_path = xml_path or os.path.join(data_dir, "root-anchors.xml")
    key_path = key_path or os.path.join(data_dir, "root.key")
    json_path = json_path or os.path.join(data_dir, "trust_anchors.json")

    if not os.path.exists(xml_path):
        try:
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(_EMBEDDED_ROOT_ANCHOR_XML)
            logger.info("Created %s from embedded IANA root anchor", xml_path)
        except Exception as e:
            logger.error("Failed to create %s: %s", xml_path, e)
    key_path = os.path.join(data_dir, "root.key")
    if not os.path.exists(key_path):
        try:
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(_EMBEDDED_ROOT_KEY)
            logger.info("Created %s from embedded root DNSKEYs", key_path)
        except Exception as e:
            logger.error("Failed to create %s: %s", key_path, e)
    if not os.path.exists(json_path):
        try:
            with open(xml_path, "r", encoding="utf-8") as f:
                xml_text = f.read()
            _write_trust_anchor_json(json_path, xml_text)
            logger.info("Created %s from root trust anchor XML", json_path)
        except Exception as e:
            logger.error("Failed to create %s: %s", json_path, e)
    else:
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if not isinstance(payload, dict) or payload.get("zone") != ".":
                raise ValueError("invalid trust anchor state")
            if payload.get("rfc5011_auto_update") is not True:
                with open(xml_path, "r", encoding="utf-8") as f:
                    xml_text = f.read()
                _write_trust_anchor_json(json_path, xml_text)
                logger.info("Migrated %s to RFC5011 trust anchor state", json_path)
        except Exception as e:
            backup = _backup_broken_file(json_path)
            logger.warning("Broken DNSSEC trust anchor state %s backed up to %s: %s", json_path, backup or "unavailable", e)
            try:
                with open(xml_path, "r", encoding="utf-8") as f:
                    xml_text = f.read()
                _write_trust_anchor_json(json_path, xml_text)
            except Exception as inner:
                logger.error("Failed to recreate %s from embedded anchors: %s", json_path, inner)

    missing = [path for path in (xml_path, key_path, json_path) if not os.path.exists(path)]
    if missing:
        return False, "Missing DNSSEC trust anchor file(s): " + ", ".join(missing)
    return True, ""


def _ensure_data_files():
    ensure_root_trust_anchor()


_ensure_data_files()

_trust_anchor_lock = threading.Lock()
_trust_anchor_loaded = False
_trust_anchor_ds_set = None
_trust_anchor_dnskey_set = None
_trust_anchor_error = ""

_metrics_lock = threading.Lock()
_metrics = {
    "secure": 0,
    "insecure": 0,
    "bogus": 0,
    "indeterminate": 0,
    "validation_seconds_total": 0.0,
    "nsec_validations": 0,
    "nsec3_validations": 0,
    "nsec3_failures": 0,
}


def get_dnssec_metrics():
    with _metrics_lock:
        return dict(_metrics)


def _incr_metric(name, value=1):
    with _metrics_lock:
        _metrics[name] = _metrics.get(name, 0) + value


def _add_validation_time(seconds):
    with _metrics_lock:
        _metrics["validation_seconds_total"] = _metrics.get("validation_seconds_total", 0.0) + seconds


class DNSSECValidationStatus:
    SECURE = "secure"
    INSECURE = "insecure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"


@dataclass
class DNSSECValidationResult:
    status: str
    reason: str
    ad_flag_allowed: bool = False
    validated_rrsets: list = field(default_factory=list)


class DNSSECCache:
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry and entry["expires"] > time.time():
                return entry["value"]
            if entry:
                del self._data[key]
            return None

    def set(self, key, value, ttl):
        with self._lock:
            self._data[key] = {"value": value, "expires": time.time() + max(30, ttl)}

    def clear(self):
        with self._lock:
            self._data.clear()

    def size(self):
        with self._lock:
            return len(self._data)

    def set_bogus(self, key, ttl=60):
        with self._lock:
            self._data[key] = {"value": None, "expires": time.time() + min(ttl, 60)}


class TrustAnchorStore:
    def __init__(self, xml_path=None, key_path=None, json_path=None):
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        self._anchor_path = xml_path or os.path.join(data_dir, "root-anchors.xml")
        self._key_path = key_path or os.path.join(data_dir, "root.key")
        self._json_path = json_path or os.path.join(data_dir, "trust_anchors.json")

    def _load_json_state(self):
        ds_set = set()
        dnskey_set = set()
        if not os.path.exists(self._json_path):
            return ds_set, dnskey_set, ""
        try:
            with open(self._json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if not isinstance(payload, dict) or payload.get("zone") != ".":
                raise ValueError("invalid trust anchor JSON")
            for anchor in payload.get("anchors", []):
                if anchor.get("state") not in ("active", "revoked"):
                    continue
                key_tag = int(anchor.get("key_tag", 0))
                algorithm = int(anchor.get("algorithm", 0))
                digest = str(anchor.get("digest", "")).strip()
                digest_type = int(anchor.get("digest_type", 2))
                public_key = str(anchor.get("public_key", "")).strip()
                flags = int(anchor.get("flags", 257))
                if digest:
                    ds_rdata = dns.rdata.from_text(
                        dns.rdataclass.IN,
                        dns.rdatatype.DS,
                        f"{key_tag} {algorithm} {digest_type} {digest}",
                    )
                    ds_set.add((key_tag, algorithm, ds_rdata))
                if public_key:
                    dnskey_rdata = dns.rdata.from_text(
                        dns.rdataclass.IN,
                        dns.rdatatype.DNSKEY,
                        f"{flags} 3 {algorithm} {public_key}",
                    )
                    dnskey_set.add(dnskey_rdata)
            return ds_set, dnskey_set, ""
        except Exception as e:
            backup = _backup_broken_file(self._json_path)
            err = f"Failed to parse trust_anchors.json; backed up to {backup or 'unavailable'}: {e}"
            logger.warning(err)
            return ds_set, dnskey_set, err

    def load(self):
        global _trust_anchor_loaded, _trust_anchor_ds_set, _trust_anchor_dnskey_set, _trust_anchor_error
        with _trust_anchor_lock:
            if _trust_anchor_loaded:
                return True, _trust_anchor_error

            ds_set, dnskey_set, json_error = self._load_json_state()

            xml_path = self._anchor_path
            key_path = self._key_path

            if not ds_set and not dnskey_set and os.path.exists(xml_path):
                try:
                    tree = ET.parse(xml_path)
                    root = tree.getroot()
                    for kd in root.findall("KeyDigest"):
                        digest_text = kd.findtext("Digest", "")
                        digest_type = int(kd.findtext("DigestType", "2"))
                        algorithm = int(kd.findtext("Algorithm", "8"))
                        key_tag = int(kd.findtext("KeyTag", "0"))
                        public_key_b64 = kd.findtext("PublicKey", "")
                        if digest_text:
                            ds_rdtype = dns.rdatatype.DS
                            ds_rdata = dns.rdata.from_text(
                                dns.rdataclass.IN, ds_rdtype,
                                f"{key_tag} {algorithm} {digest_type} {digest_text}"
                            )
                            ds_set.add((key_tag, algorithm, ds_rdata))
                        if public_key_b64:
                            dnskey_rdtype = dns.rdatatype.DNSKEY
                            dnskey_rdata = dns.rdata.from_text(
                                dns.rdataclass.IN, dnskey_rdtype,
                                f"257 3 {algorithm} {public_key_b64}"
                            )
                            dnskey_set.add(dnskey_rdata)
                except Exception as e:
                    _trust_anchor_error = f"Failed to parse root-anchors.xml: {e}"
                    logger.error(_trust_anchor_error)

            if not dnskey_set and os.path.exists(key_path):
                try:
                    with open(key_path, "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith(";") or line.startswith("#"):
                                continue
                            parts = line.split()
                            if len(parts) >= 5 and parts[3] == "DNSKEY":
                                text = " ".join(parts[3:])
                                dnskey_rdata = dns.rdata.from_text(
                                    dns.rdataclass.IN, dns.rdatatype.DNSKEY, text
                                )
                                dnskey_set.add(dnskey_rdata)
                except Exception as e:
                    _trust_anchor_error = f"Failed to parse root.key: {e}"
                    logger.error(_trust_anchor_error)

            if not ds_set and not dnskey_set:
                _trust_anchor_error = json_error or "No root trust anchor found"
                _trust_anchor_loaded = True
                return False, _trust_anchor_error

            _trust_anchor_ds_set = ds_set
            _trust_anchor_dnskey_set = dnskey_set
            _trust_anchor_loaded = True

            zsk_count = sum(1 for k in dnskey_set if hasattr(k, "flags") and k.flags == 256)
            ksk_count = sum(1 for k in dnskey_set if hasattr(k, "flags") and k.flags == 257)
            logger.info(
                "Trust anchor loaded: %d DS digests, %d DNSKEYs (%d KSK, %d ZSK)",
                len(ds_set), len(dnskey_set), ksk_count, zsk_count,
            )
            return True, ""


class DNSSECValidator:
    def __init__(self, upstream_resolver=None, trust_anchor_path=None, trust_anchor_key_path=None, trust_anchor_json_path=None, timeout=3.0, query_func=None):
        self._timeout = timeout
        self._cache = DNSSECCache()
        self._anchor = TrustAnchorStore(xml_path=trust_anchor_path, key_path=trust_anchor_key_path, json_path=trust_anchor_json_path)
        self._resolver = upstream_resolver
        self._query_func = query_func
        self._anchor_ok = False
        self._anchor_error = ""
        self._trust_anchor_json_path = trust_anchor_json_path or os.path.join(_default_data_dir(), "trust_anchors.json")

    def reload_trust_anchor(self):
        global _trust_anchor_loaded
        with _trust_anchor_lock:
            _trust_anchor_loaded = False
        ok, err = self._anchor.load()
        if ok and self.process_rfc5011_state():
            with _trust_anchor_lock:
                _trust_anchor_loaded = False
            ok, err = self._anchor.load()
        self._anchor_ok = ok
        self._anchor_error = err
        return ok, err

    def trust_anchor_status(self):
        self._anchor_ok, self._anchor_error = self._anchor.load()
        return {
            "loaded": self._anchor_ok,
            "error": self._anchor_error if not self._anchor_ok else "",
        }

    def trust_anchor_info(self):
        with _trust_anchor_lock:
            dnskey_count = len(_trust_anchor_dnskey_set) if _trust_anchor_dnskey_set else 0
            ds_count = len(_trust_anchor_ds_set) if _trust_anchor_ds_set else 0
        info = {
            "loaded": self._anchor_ok,
            "error": self._anchor_error,
            "dnskey_count": dnskey_count,
            "ds_count": ds_count,
            "rfc5011_auto_update": False,
            "active_ksks": [],
            "pending_ksks": [],
            "revoked_ksks": [],
            "retired_ksks": [],
            "last_checked": "",
            "next_check": "",
            "last_error": "",
        }
        try:
            with open(self._trust_anchor_json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            info["rfc5011_auto_update"] = bool(payload.get("rfc5011_auto_update"))
            info["last_checked"] = payload.get("last_checked", "")
            info["next_check"] = payload.get("next_check", "")
            info["last_error"] = payload.get("last_error", "")
            for anchor in payload.get("anchors", []):
                item = {
                    "key_tag": anchor.get("key_tag"),
                    "algorithm": anchor.get("algorithm"),
                    "state": anchor.get("state"),
                    "hold_down_until": anchor.get("hold_down_until", ""),
                }
                if anchor.get("state") == "active":
                    info["active_ksks"].append(item)
                elif anchor.get("state") == "pending":
                    info["pending_ksks"].append(item)
                elif anchor.get("state") == "revoked":
                    info["revoked_ksks"].append(item)
                elif anchor.get("state") == "retired":
                    info["retired_ksks"].append(item)
        except Exception as e:
            info["last_error"] = str(e)
        return info

    def cache_stats(self):
        return {
            "dnskey_cache_entries": self._cache.size(),
        }

    def _load_anchor_state_payload(self):
        with open(self._trust_anchor_json_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if not isinstance(payload, dict) or payload.get("zone") != ".":
            raise ValueError("invalid trust anchor state")
        payload.setdefault("anchors", [])
        payload["rfc5011_auto_update"] = True
        return payload

    def _save_anchor_state_payload(self, payload):
        tmp = self._trust_anchor_json_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self._trust_anchor_json_path)

    def process_rfc5011_state(self):
        try:
            payload = self._load_anchor_state_payload()
        except Exception as e:
            logger.warning("RFC5011 state processing skipped: %s", e)
            return False

        now = _utc_now()
        now_text = _iso(now)
        changed = False
        for anchor in payload.get("anchors", []):
            remove_until = _as_utc(_parse_iso(anchor.get("remove_hold_down_until")))
            if anchor.get("revoked", False) and anchor.get("state") != "retired":
                if remove_until is not None and now >= remove_until:
                    anchor["state"] = "retired"
                    anchor["retired_at"] = now_text
                    anchor["last_seen"] = now_text
                    anchor.pop("hold_down_until", None)
                    logger.warning("RFC5011 retired key_tag=%s", anchor.get("key_tag"))
                    changed = True
                continue

            if anchor.get("state") != "pending":
                continue
            hold_until = _parse_iso(anchor.get("hold_down_until"))
            first_seen = _parse_iso(anchor.get("first_seen") or anchor.get("valid_from"))
            effective_hold_until = None
            if first_seen is not None:
                effective_hold_until = _as_utc(first_seen) + timedelta(days=RFC5011_ADD_HOLD_DOWN_DAYS)
            if hold_until is None:
                hold_until = effective_hold_until
            else:
                hold_until = _as_utc(hold_until)
                if effective_hold_until is not None and effective_hold_until < hold_until:
                    hold_until = effective_hold_until
            if hold_until is None:
                continue
            if now < hold_until:
                continue

            anchor["state"] = "active"
            anchor["promoted_at"] = now_text
            anchor["last_seen"] = now_text
            anchor.pop("hold_down_until", None)
            logger.warning("RFC5011 promoted key_tag=%s to active", anchor.get("key_tag"))
            changed = True

        retained_anchors = []
        for anchor in payload.get("anchors", []):
            if anchor.get("state") != "retired":
                retained_anchors.append(anchor)
                continue
            retired_at = _as_utc(_parse_iso(anchor.get("retired_at")))
            if retired_at is None:
                retained_anchors.append(anchor)
                continue
            if now < retired_at + timedelta(days=RETIRED_KEY_RETENTION_DAYS):
                retained_anchors.append(anchor)
                continue
            logger.warning("RFC5011 removed retired key_tag=%s", anchor.get("key_tag"))
            changed = True
        if len(retained_anchors) != len(payload.get("anchors", [])):
            payload["anchors"] = retained_anchors

        if not changed:
            return False

        payload["updated_at"] = now_text
        self._save_anchor_state_payload(payload)
        return True

    def update_rfc5011_trust_anchors(self, root_dnskey_rrset):
        if root_dnskey_rrset is None:
            return False
        try:
            payload = self._load_anchor_state_payload()
        except Exception as e:
            backup = _backup_broken_file(self._trust_anchor_json_path)
            logger.warning("RFC5011 state load failed; backed up to %s: %s", backup or "unavailable", e)
            return False

        now = _utc_now()
        now_text = _iso(now)
        changed = False
        by_key = {
            (int(a.get("key_tag", 0)), int(a.get("algorithm", 0))): a
            for a in payload.get("anchors", [])
        }

        seen = set()
        for key in root_dnskey_rrset:
            flags = int(getattr(key, "flags", 0))
            if not (flags & DNSKEY_ZONE_FLAG) or not (flags & DNSKEY_SEP_FLAG):
                continue
            key_tag = dns.dnssec.key_id(key)
            algorithm = int(getattr(key, "algorithm", 0))
            ident = (key_tag, algorithm)
            seen.add(ident)
            revoked = bool(flags & DNSKEY_REVOKE_FLAG)
            public_key = key.to_text().split()[-1]
            anchor = by_key.get(ident)
            if anchor is None:
                anchor = {
                    "key_tag": key_tag,
                    "algorithm": algorithm,
                    "digest_type": 2,
                    "digest": dns.dnssec.make_ds(dns.name.root, key, "SHA256", validating=True).digest.hex().upper(),
                    "flags": flags,
                    "public_key": public_key,
                    "source": "RFC5011 root DNSKEY",
                    "state": "revoked" if revoked else "pending",
                    "first_seen": now_text,
                    "last_seen": now_text,
                    "revoked": revoked,
                }
                if revoked:
                    anchor["remove_hold_down_until"] = _iso(now + timedelta(days=RFC5011_REMOVE_HOLD_DOWN_DAYS))
                    anchor["revoked_at"] = now_text
                    logger.warning("RFC5011 revoked key_tag=%s", key_tag)
                else:
                    anchor["hold_down_until"] = _iso(now + timedelta(days=RFC5011_ADD_HOLD_DOWN_DAYS))
                    logger.info("RFC5011 detected new key_tag=%s", key_tag)
                payload["anchors"].append(anchor)
                by_key[ident] = anchor
                changed = True
            else:
                if anchor.get("last_seen") != now_text:
                    anchor["last_seen"] = now_text
                    changed = True
                if public_key and anchor.get("public_key") != public_key:
                    anchor["public_key"] = public_key
                    changed = True
                if revoked and not anchor.get("revoked"):
                    anchor["revoked"] = True
                    anchor["state"] = "revoked"
                    anchor["revoked_at"] = now_text
                    anchor["remove_hold_down_until"] = _iso(now + timedelta(days=RFC5011_REMOVE_HOLD_DOWN_DAYS))
                    logger.warning("RFC5011 revoked key_tag=%s", key_tag)
                    changed = True

        for anchor in payload.get("anchors", []):
            state = anchor.get("state")
            if state == "pending" and not anchor.get("revoked"):
                hold_until = _parse_iso(anchor.get("hold_down_until"))
                ident = (int(anchor.get("key_tag", 0)), int(anchor.get("algorithm", 0)))
                if hold_until and now >= hold_until and ident in seen:
                    anchor["state"] = "active"
                    logger.info("RFC5011 pending root KSK promoted key_tag=%s algorithm=%s", ident[0], ident[1])
                    changed = True
            elif state == "revoked":
                remove_until = _parse_iso(anchor.get("remove_hold_down_until"))
                if remove_until and now >= remove_until:
                    anchor["state"] = "retired"
                    anchor["retired_at"] = now_text
                    logger.warning("RFC5011 retired key_tag=%s", anchor.get("key_tag"))
                    changed = True

        payload["last_checked"] = now_text
        payload["next_check"] = _iso(now + timedelta(hours=24))
        payload["updated_at"] = now_text
        payload["last_error"] = ""
        if changed:
            self._save_anchor_state_payload(payload)
            self.reload_trust_anchor()
        else:
            self._save_anchor_state_payload(payload)
            if self.process_rfc5011_state():
                self.reload_trust_anchor()
        return True

    def _get_upstream_response(self, qname, rdtype, want_dnssec=True):
        try:
            msg = dns.message.make_query(qname, rdtype, want_dnssec=want_dnssec)
            msg.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
            msg.flags |= dns.flags.CD
            if self._query_func is not None:
                return dns.message.from_wire(self._query_func(msg.to_wire()))
            if self._resolver is None:
                return None
            response = self._resolver.resolve(qname, rdtype, raise_on_no_answer=False)
            return response.response
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NXDOMAIN:
            msg = dns.message.make_query(qname, rdtype, want_dnssec=True)
            msg.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
            try:
                response = self._resolver.resolve(qname, rdtype)
                return response.response
            except dns.resolver.NXDOMAIN as e:
                return e.response
            except Exception:
                return None
        except dns.exception.Timeout:
            return None
        except Exception:
            return None

    def _fetch_rrset(self, owner, rdtype):
        owner = dns.name.from_text(owner) if isinstance(owner, str) else owner
        rdtype = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        cache_key = ("rrset", owner.to_text().lower(), int(rdtype))
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        response = self._get_upstream_response(owner, rdtype, want_dnssec=True)
        if response is None:
            return None, None, None
        rrset = self._find_rrset(response, owner, rdtype)
        rrsig = self._find_rrsig(response, owner, rdtype)
        ttl = rrset.ttl if rrset is not None else 60
        value = (rrset, rrsig, response)
        self._cache.set(cache_key, value, min(ttl, 3600))
        return value

    def _find_rrset(self, response, owner, rdtype):
        owner = dns.name.from_text(owner) if isinstance(owner, str) else owner
        for section in (response.answer, response.authority, response.additional):
            for rrset in section:
                if rrset.name == owner and rrset.rdtype == rdtype:
                    return rrset
        return None

    def _find_rrsig(self, response, owner, covered_rdtype):
        owner = dns.name.from_text(owner) if isinstance(owner, str) else owner
        out = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.name != owner or rrset.rdtype != dns.rdatatype.RRSIG:
                    continue
                for rdata in rrset:
                    if getattr(rdata, "type_covered", None) == covered_rdtype:
                        out.add(rdata, rrset.ttl)
        return out if len(out) else None

    def _root_anchor_matches(self, dnskey_rrset):
        with _trust_anchor_lock:
            ds_set = list(_trust_anchor_ds_set or [])
            dnskey_set = list(_trust_anchor_dnskey_set or [])
        for key in dnskey_rrset:
            for anchor_key in dnskey_set:
                if key.to_text() == anchor_key.to_text():
                    return True
            for key_tag, algorithm, anchor_ds in ds_set:
                if getattr(key, "algorithm", None) != algorithm:
                    continue
                if dns.dnssec.key_id(key) != key_tag:
                    continue
                for digest_name in ("SHA256", "SHA384", "SHA1"):
                    try:
                        made_ds = dns.dnssec.make_ds(dns.name.root, key, digest_name, validating=True)
                        if made_ds.to_text().upper() == anchor_ds.to_text().upper():
                            return True
                    except Exception:
                        continue
        return False

    def _validate_rrset_with_keys(self, rrset, rrsig_rrset, keys, reason_prefix):
        if rrset is None:
            raise dns.dnssec.ValidationFailure(f"{reason_prefix}: missing RRset")
        if rrsig_rrset is None:
            raise dns.dnssec.ValidationFailure(f"{reason_prefix}: missing RRSIG")
        dns.dnssec.validate(rrset, rrsig_rrset, keys)

    def _zone_chain(self, zone):
        zone = dns.name.from_text(zone) if isinstance(zone, str) else zone
        zone = zone.derelativize(dns.name.root)
        labels = list(zone.labels)
        if labels == [b""]:
            return [dns.name.root]
        zones = [dns.name.root]
        for index in range(len(labels) - 2, -1, -1):
            zones.append(dns.name.Name(labels[index:]))
        return zones

    def _dnskey_matches_ds(self, zone, dnskey_rrset, ds_rrset):
        for key in dnskey_rrset:
            for ds in ds_rrset:
                if dns.dnssec.key_id(key) != ds.key_tag:
                    continue
                if getattr(key, "algorithm", None) != ds.algorithm:
                    continue
                digest_name = {
                    1: "SHA1",
                    2: "SHA256",
                    4: "SHA384",
                }.get(ds.digest_type)
                if not digest_name:
                    continue
                try:
                    made_ds = dns.dnssec.make_ds(zone, key, digest_name, validating=True)
                    if made_ds.to_text().upper() == ds.to_text().upper():
                        return True
                except Exception:
                    continue
        return False

    def _validated_zone_keys(self, zone):
        cache_key = ("zone_keys", dns.name.from_text(zone).to_text().lower() if isinstance(zone, str) else zone.to_text().lower())
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        if not self._anchor_ok:
            self.reload_trust_anchor()
        if not self._anchor_ok:
            raise dns.dnssec.ValidationFailure("no root trust anchor loaded")

        chain = self._zone_chain(zone)
        root_dnskey, root_rrsig, _ = self._fetch_rrset(dns.name.root, dns.rdatatype.DNSKEY)
        if root_dnskey is None:
            raise dns.dnssec.ValidationFailure("missing root DNSKEY RRset")
        if not self._root_anchor_matches(root_dnskey):
            raise dns.dnssec.ValidationFailure("root DNSKEY does not match local trust anchor")
        if root_rrsig is not None:
            self._validate_rrset_with_keys(root_dnskey, root_rrsig, {dns.name.root: root_dnskey}, "root DNSKEY")
        self.update_rfc5011_trust_anchors(root_dnskey)

        current_keys = root_dnskey
        current_zone = dns.name.root
        for child_zone in chain[1:]:
            ds_rrset, ds_rrsig, _ = self._fetch_rrset(child_zone, dns.rdatatype.DS)
            if ds_rrset is None:
                raise LookupError(f"insecure delegation proven or DS missing for {child_zone.to_text()}")
            self._validate_rrset_with_keys(ds_rrset, ds_rrsig, {current_zone: current_keys}, f"{child_zone.to_text()} DS")
            child_dnskey, child_rrsig, _ = self._fetch_rrset(child_zone, dns.rdatatype.DNSKEY)
            if child_dnskey is None:
                raise dns.dnssec.ValidationFailure(f"missing DNSKEY RRset for {child_zone.to_text()}")
            if not self._dnskey_matches_ds(child_zone, child_dnskey, ds_rrset):
                raise dns.dnssec.ValidationFailure(f"DNSKEY does not match parent DS for {child_zone.to_text()}")
            self._validate_rrset_with_keys(child_dnskey, child_rrsig, {child_zone: child_dnskey}, f"{child_zone.to_text()} DNSKEY")
            current_zone = child_zone
            current_keys = child_dnskey

        self._cache.set(cache_key, current_keys, 3600)
        return current_keys

    def _rrsig_signers(self, response_message, rrset):
        signers = []
        sigs = self._find_rrsig(response_message, rrset.name, rrset.rdtype)
        if sigs is None:
            return signers
        for sig in sigs:
            signer = sig.signer.derelativize(dns.name.root)
            if signer not in signers:
                signers.append(signer)
        return signers

    def _canonical_name_key(self, name):
        return name.derelativize(dns.name.root).canonicalize().to_wire()

    def _nsec_covers_name(self, nsec_rrset, qname):
        qkey = self._canonical_name_key(qname)
        owner_key = self._canonical_name_key(nsec_rrset.name)
        for nsec in nsec_rrset:
            next_key = self._canonical_name_key(nsec.next)
            if owner_key < next_key and owner_key <= qkey < next_key:
                return True
            if owner_key > next_key and (qkey >= owner_key or qkey < next_key):
                return True
            if owner_key == qkey:
                return True
        return False

    def _nsec_has_type(self, nsec_rdata, rdtype):
        rdtype = int(rdtype)
        try:
            for window, bitmap in nsec_rdata.windows:
                base = int(window) * 256
                for index, value in enumerate(bitmap):
                    for bit in range(8):
                        if value & (0x80 >> bit):
                            if base + index * 8 + bit == rdtype:
                                return True
            return False
        except Exception:
            return False

    def _nsec_proves_nodata(self, nsec_rrset, qname, qtype):
        if nsec_rrset.name != qname:
            return False
        for nsec in nsec_rrset:
            if self._nsec_has_type(nsec, qtype):
                return False
            if qtype != dns.rdatatype.CNAME and self._nsec_has_type(nsec, dns.rdatatype.CNAME):
                return False
            return True
        return False

    def _b32hex_from_bytes(self, value):
        return base64.b32hexencode(value).decode("ascii").rstrip("=").lower()

    def _nsec3_owner_hash(self, rrset):
        if len(rrset.name.labels) < 2:
            raise dns.dnssec.ValidationFailure("malformed NSEC3 owner name")
        return rrset.name.labels[0].decode("ascii").lower()

    def _nsec3_next_hash(self, nsec3):
        return self._b32hex_from_bytes(nsec3.next)

    def _nsec3_hash_name(self, name, nsec3):
        if int(nsec3.algorithm) != 1:
            raise dns.dnssec.ValidationFailure(f"unsupported NSEC3 hash algorithm {nsec3.algorithm}")
        if int(nsec3.iterations) < 0 or int(nsec3.iterations) > 2500:
            raise dns.dnssec.ValidationFailure(f"invalid NSEC3 iterations {nsec3.iterations}")
        return dns.dnssec.nsec3_hash(
            name.derelativize(dns.name.root),
            nsec3.salt,
            int(nsec3.iterations),
            int(nsec3.algorithm),
        ).lower()

    def _nsec3_hash_covered(self, hashed, owner_hash, next_hash):
        hashed = hashed.lower()
        owner_hash = owner_hash.lower()
        next_hash = next_hash.lower()
        if owner_hash < next_hash:
            return owner_hash < hashed < next_hash
        if owner_hash > next_hash:
            return hashed > owner_hash or hashed < next_hash
        return False

    def _nsec3_matching_rrset(self, nsec3_rrsets, name):
        for rrset in nsec3_rrsets:
            for nsec3 in rrset:
                if self._nsec3_hash_name(name, nsec3) == self._nsec3_owner_hash(rrset):
                    return rrset, nsec3
        return None, None

    def _nsec3_covering_rrset(self, nsec3_rrsets, name):
        for rrset in nsec3_rrsets:
            owner_hash = self._nsec3_owner_hash(rrset)
            for nsec3 in rrset:
                hashed = self._nsec3_hash_name(name, nsec3)
                next_hash = self._nsec3_next_hash(nsec3)
                if self._nsec3_hash_covered(hashed, owner_hash, next_hash):
                    return rrset, nsec3
        return None, None

    def _closest_encloser_candidates(self, qname):
        qname = qname.derelativize(dns.name.root)
        labels = list(qname.labels)
        out = []
        for index in range(0, len(labels) - 1):
            out.append(dns.name.Name(labels[index:]))
        out.append(dns.name.root)
        return out

    def _prove_nsec3_denial(self, nsec3_rrsets, qname, qtype, rcode):
        if not nsec3_rrsets:
            return False, "no NSEC3 rrsets"
        qname = qname.derelativize(dns.name.root)
        closest = None
        candidates = self._closest_encloser_candidates(qname)
        if rcode == dns.rcode.NXDOMAIN and len(candidates) > 1:
            candidates = candidates[1:]
        for candidate in candidates:
            rrset, _ = self._nsec3_matching_rrset(nsec3_rrsets, candidate)
            if rrset is not None:
                closest = candidate
                logger.debug("NSEC3 closest encloser proof success qname=%s closest=%s", qname, closest)
                break
        if closest is None:
            return False, "NSEC3 closest encloser proof failed"

        wildcard = dns.name.from_text("*." + closest.to_text())
        wildcard_cover, _ = self._nsec3_covering_rrset(nsec3_rrsets, wildcard)
        wildcard_match, wildcard_nsec3 = self._nsec3_matching_rrset(nsec3_rrsets, wildcard)
        if wildcard_match is not None and wildcard_nsec3 is not None:
            if self._nsec_has_type(wildcard_nsec3, qtype) or self._nsec_has_type(wildcard_nsec3, dns.rdatatype.CNAME):
                return False, "NSEC3 wildcard exists for requested type"
        elif wildcard_cover is None:
            return False, "NSEC3 wildcard denial proof failed"
        logger.debug("NSEC3 wildcard denial success qname=%s wildcard=%s", qname, wildcard)

        if rcode == dns.rcode.NXDOMAIN:
            if qname == closest:
                return False, "NSEC3 NXDOMAIN qname equals closest encloser"
            labels_to_add = len(qname.labels) - len(closest.labels)
            next_closer = dns.name.Name(qname.labels[labels_to_add - 1:])
            next_cover, next_nsec3 = self._nsec3_covering_rrset(nsec3_rrsets, next_closer)
            if next_cover is None:
                return False, "NSEC3 next closer proof failed"
            if next_nsec3 is not None and (int(next_nsec3.flags) & NSEC3_OPT_OUT_FLAG):
                logger.info("NSEC3 opt-out used for next closer proof name=%s", next_closer)
            logger.debug("NSEC3 next closer proof success qname=%s next_closer=%s", qname, next_closer)
            return True, "NSEC3 NXDOMAIN proof valid"

        qmatch, qnsec3 = self._nsec3_matching_rrset(nsec3_rrsets, qname)
        if qmatch is not None and qnsec3 is not None:
            if self._nsec_has_type(qnsec3, qtype):
                return False, "NSEC3 NODATA proof includes requested type"
            if qtype != dns.rdatatype.CNAME and self._nsec_has_type(qnsec3, dns.rdatatype.CNAME):
                return False, "NSEC3 NODATA proof includes CNAME"
            return True, "NSEC3 NODATA proof valid"

        qcover, qcover_nsec3 = self._nsec3_covering_rrset(nsec3_rrsets, qname)
        if qcover is not None and qcover_nsec3 is not None and (int(qcover_nsec3.flags) & NSEC3_OPT_OUT_FLAG):
            logger.info("NSEC3 opt-out used for insecure delegation name=%s", qname)
            return True, "NSEC3 opt-out insecure delegation proof valid"
        return False, "NSEC3 NODATA proof failed"

    def validate_response(self, query_message, response_message):
        start = time.perf_counter()
        try:
            result = self._validate_impl(query_message, response_message)
            return result
        finally:
            _add_validation_time(time.perf_counter() - start)

    def _validate_impl(self, query_message, response_message):
        if query_message is None or response_message is None:
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE, "missing query or response"
            )

        rcode = response_message.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            return self._validate_negative(response_message, "NXDOMAIN")
        if rcode == dns.rcode.SERVFAIL:
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE, "upstream SERVFAIL"
            )
        if rcode != dns.rcode.NOERROR:
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE, f"unexpected rcode {rcode}"
            )

        question = query_message.question[0] if query_message.question else None
        if question is None:
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE, "no question in query"
            )

        qname = question.name
        qtype = question.rdtype
        has_answer_for_qtype = any(
            rrset.name == qname and rrset.rdtype == qtype
            for rrset in response_message.answer
        )
        has_negative_proof = any(
            rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
            for rrset in response_message.authority
        )
        if not has_answer_for_qtype and has_negative_proof:
            return self._validate_negative(response_message, "NODATA")

        has_sig = False
        for section in (response_message.answer, response_message.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    has_sig = True
                    break

        if not has_sig:
            return self._validate_unsigned(response_message, qname, qtype)

        return self._validate_signed(response_message, qname, qtype)

    def _validate_unsigned(self, response_message, qname, qtype):
        qname_str = qname.to_text().rstrip(".")
        logger.debug(
            "DNSSEC no signatures for %s type=%s - checking delegation status",
            qname_str, dns.rdatatype.to_text(qtype),
        )
        if self._query_func is not None:
            try:
                candidate_zones = self._zone_chain(qname)[1:]
                if len(qname.derelativize(dns.name.root).labels) > 3:
                    candidate_zones = candidate_zones[:-1]
                for zone in reversed(candidate_zones):
                    ds_rrset, _, _ = self._fetch_rrset(zone, dns.rdatatype.DS)
                    if ds_rrset is None:
                        _incr_metric("insecure")
                        return DNSSECValidationResult(
                            DNSSECValidationStatus.INSECURE,
                            f"unsigned delegation for {qname_str}; no DS for {zone.to_text().rstrip('.')}",
                        )
                _incr_metric("indeterminate")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.INDETERMINATE,
                    f"unsigned answer for {qname_str} without proven insecure delegation",
                )
            except LookupError as e:
                _incr_metric("insecure")
                return DNSSECValidationResult(DNSSECValidationStatus.INSECURE, str(e))
            except Exception as e:
                _incr_metric("indeterminate")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.INDETERMINATE,
                    f"insecure delegation proof failed: {e}",
                )
        _incr_metric("insecure")
        return DNSSECValidationResult(
            DNSSECValidationStatus.INSECURE,
            f"unsigned delegation for {qname_str}",
        )

    def _validate_negative(self, response_message, reason_detail):
        auth = response_message.authority
        nsec_rrsets = []
        nsec3_rrsets = []
        for rrset in auth:
            if rrset.rdtype == dns.rdatatype.NSEC:
                nsec_rrsets.append(rrset)
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                nsec3_rrsets.append(rrset)

        if not nsec_rrsets and not nsec3_rrsets:
            _incr_metric("insecure")
            return DNSSECValidationResult(
                DNSSECValidationStatus.INSECURE,
                f"{reason_detail} without DNSSEC proof",
            )

        question = response_message.question[0] if response_message.question else None
        qname = question.name if question else None
        qtype = question.rdtype if question else dns.rdatatype.A
        try:
            validated_rrsets = []
            proof_covers = False
            for rrset in nsec_rrsets + nsec3_rrsets:
                rrsig = self._find_rrsig(response_message, rrset.name, rrset.rdtype)
                signers = self._rrsig_signers(response_message, rrset)
                if not rrsig or not signers:
                    _incr_metric("indeterminate")
                    return DNSSECValidationResult(
                        DNSSECValidationStatus.INDETERMINATE,
                        f"{reason_detail} proof missing RRSIG for {rrset.name.to_text()} {dns.rdatatype.to_text(rrset.rdtype)}",
                    )
                last_error = None
                for signer in signers:
                    try:
                        keys = self._validated_zone_keys(signer)
                        self._validate_rrset_with_keys(
                            rrset, rrsig, {signer: keys}, f"{reason_detail} proof"
                        )
                        validated_rrsets.append(
                            rrset.name.to_text() + " " + dns.rdatatype.to_text(rrset.rdtype)
                        )
                        if rrset.rdtype == dns.rdatatype.NSEC and qname is not None:
                            if reason_detail == "NODATA":
                                proof_covers = proof_covers or self._nsec_proves_nodata(rrset, qname, qtype)
                            else:
                                proof_covers = proof_covers or self._nsec_covers_name(rrset, qname)
                        if rrset.rdtype == dns.rdatatype.NSEC3:
                            ok, detail = self._prove_nsec3_denial(
                                nsec3_rrsets,
                                qname,
                                qtype,
                                response_message.rcode(),
                            )
                            if not ok:
                                _incr_metric("nsec3_failures")
                                logger.warning("NSEC3 proof failure qname=%s reason=%s", qname, detail)
                                raise dns.dnssec.ValidationFailure(detail)
                            proof_covers = True
                        last_error = None
                        break
                    except LookupError:
                        raise
                    except Exception as e:
                        last_error = e
                if last_error is not None:
                    raise last_error
            if qname is not None and nsec_rrsets and not proof_covers:
                raise dns.dnssec.ValidationFailure(f"{reason_detail} NSEC proof does not cover query name")
            _incr_metric("secure")
            proof_type = "NSEC3" if nsec3_rrsets else "NSEC"
            _incr_metric("nsec3_validations" if nsec3_rrsets else "nsec_validations")
            return DNSSECValidationResult(
                DNSSECValidationStatus.SECURE,
                f"{reason_detail} validated with {proof_type}",
                ad_flag_allowed=True,
                validated_rrsets=validated_rrsets,
            )
        except LookupError as e:
            _incr_metric("insecure")
            return DNSSECValidationResult(
                DNSSECValidationStatus.INSECURE,
                f"{reason_detail} below insecure delegation: {e}",
            )
        except (dns.dnssec.ValidationFailure, dns.exception.DNSException) as e:
            _incr_metric("bogus")
            return DNSSECValidationResult(
                DNSSECValidationStatus.BOGUS,
                f"{reason_detail} denial validation failed: {e}",
            )
        except Exception as e:
            _incr_metric("indeterminate")
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE,
                f"{reason_detail} denial validation error: {e}",
            )

    def _validate_signed(self, response_message, qname, qtype):
        qname_str = qname.to_text().rstrip(".")
        try:
            answer_rrsets = [
                rrset
                for rrset in response_message.answer
                if rrset.rdtype != dns.rdatatype.RRSIG
            ]
            if not answer_rrsets:
                answer_rrsets = [
                    rrset
                    for rrset in response_message.authority
                    if rrset.rdtype not in (dns.rdatatype.RRSIG, dns.rdatatype.OPT)
                ]

            validated_rrsets = []
            for rrset in answer_rrsets:
                rrsig = self._find_rrsig(response_message, rrset.name, rrset.rdtype)
                if rrsig is None:
                    continue
                signers = self._rrsig_signers(response_message, rrset)
                if not signers:
                    continue
                validated = False
                last_error = None
                for signer in signers:
                    try:
                        zone_keys = self._validated_zone_keys(signer)
                        self._validate_rrset_with_keys(
                            rrset,
                            rrsig,
                            {signer: zone_keys},
                            f"{rrset.name.to_text()} {dns.rdatatype.to_text(rrset.rdtype)}",
                        )
                        validated_rrsets.append(
                            rrset.name.to_text() + " " + dns.rdatatype.to_text(rrset.rdtype)
                        )
                        validated = True
                        break
                    except LookupError as e:
                        _incr_metric("insecure")
                        return DNSSECValidationResult(
                            DNSSECValidationStatus.INSECURE,
                            f"signed-looking answer below insecure delegation: {e}",
                        )
                    except Exception as e:
                        last_error = e
                if not validated:
                    raise dns.dnssec.ValidationFailure(last_error or "no signer DNSKEY validated")

            if validated_rrsets:
                logger.info(
                    "DNSSEC secure %s type=%s reason=chain validated to root trust anchor",
                    qname_str, dns.rdatatype.to_text(qtype),
                )
                _incr_metric("secure")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.SECURE,
                    "chain validated to root trust anchor",
                    ad_flag_allowed=True,
                    validated_rrsets=validated_rrsets,
                )

            _incr_metric("indeterminate")
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE,
                "no answer RRsets with matching RRSIG records could be validated",
            )

        except (dns.dnssec.ValidationFailure, dns.exception.DNSException) as e:
            logger.warning(
                "DNSSEC bogus %s %s reason=%s",
                qname_str, dns.rdatatype.to_text(qtype), e,
            )
            _incr_metric("bogus")
            return DNSSECValidationResult(
                DNSSECValidationStatus.BOGUS,
                f"validation failed: {e}",
            )
        except Exception as e:
            logger.error("DNSSEC validation error for %s: %s", qname_str, e)
            _incr_metric("indeterminate")
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE,
                f"validation error: {e}",
            )
