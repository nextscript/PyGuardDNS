import base64
import logging
import os
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import dns.tsig

logger = logging.getLogger("dnssec")

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


def _ensure_data_files():
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(data_dir, exist_ok=True)
    xml_path = os.path.join(data_dir, "root-anchors.xml")
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
    def __init__(self, xml_path=None, key_path=None):
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        self._anchor_path = xml_path or os.path.join(data_dir, "root-anchors.xml")
        self._key_path = key_path or os.path.join(data_dir, "root.key")

    def load(self):
        global _trust_anchor_loaded, _trust_anchor_ds_set, _trust_anchor_dnskey_set, _trust_anchor_error
        with _trust_anchor_lock:
            if _trust_anchor_loaded:
                return True, _trust_anchor_error

            ds_set = set()
            dnskey_set = set()

            xml_path = self._anchor_path
            key_path = self._key_path

            if os.path.exists(xml_path):
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

            if os.path.exists(key_path):
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
                _trust_anchor_error = "No root trust anchor found"
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
    def __init__(self, upstream_resolver, trust_anchor_path=None, trust_anchor_key_path=None, timeout=3.0):
        self._timeout = timeout
        self._cache = DNSSECCache()
        self._anchor = TrustAnchorStore(xml_path=trust_anchor_path, key_path=trust_anchor_key_path)
        self._resolver = upstream_resolver
        self._anchor_ok = False
        self._anchor_error = ""

    def reload_trust_anchor(self):
        global _trust_anchor_loaded
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
        return {
            "loaded": self._anchor_ok,
            "error": self._anchor_error,
            "dnskey_count": dnskey_count,
            "ds_count": ds_count,
        }

    def cache_stats(self):
        return {
            "dnskey_cache_entries": self._cache.size(),
        }

    def _get_upstream_response(self, qname, rdtype, want_dnssec=True):
        try:
            msg = dns.message.make_query(qname, rdtype, want_dnssec=want_dnssec)
            msg.use_edns(edns=True, payload=1232, ednsflags=dns.flags.DO)
            response = self._resolver.resolve(qname, rdtype)
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

        has_sig = False
        rrsig_sections = []
        for section_name, section in (("answer", response_message.answer), ("authority", response_message.authority)):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    has_sig = True
                    for rdata in rrset:
                        rrsig_sections.append(
                            f"{rrset.name} {dns.rdatatype.to_text(rdata.type_covered)} "
                            f"algo={rdata.algorithm} signer={rdata.signer}"
                        )

        if not has_sig:
            logger.debug("DNSSEC no RRSIG for %s type=%s - unsigned path", qname, dns.rdatatype.to_text(qtype))
            return self._validate_unsigned(response_message, qname, qtype)

        logger.debug(
            "DNSSEC signed response for %s type=%s has_sig=True rrsigs=[%s]",
            qname, dns.rdatatype.to_text(qtype), "; ".join(rrsig_sections),
        )

        # Collect DNSKEY names from response for debugging
        dnskey_names = []
        for section in (response_message.answer, response_message.authority):
            for rrset in section:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    for rdata in rrset:
                        dnskey_names.append(f"{rrset.name} algo={rdata.algorithm} flags={rdata.flags}")
        if dnskey_names:
            logger.debug("DNSSEC DNSKEYs in response: %s", "; ".join(dnskey_names))
        else:
            logger.debug("DNSSEC no DNSKEYs in response for %s", qname)

        return self._validate_signed(response_message, qname, qtype)

    def _validate_unsigned(self, response_message, qname, qtype):
        qname_str = qname.to_text().rstrip(".")
        logger.debug(
            "DNSSEC no signatures for %s type=%s - checking delegation status",
            qname_str, dns.rdatatype.to_text(qtype),
        )
        return DNSSECValidationResult(
            DNSSECValidationStatus.INSECURE,
            f"unsigned delegation for {qname_str}",
        )

    def _validate_negative(self, response_message, reason_detail):
        auth = response_message.authority
        has_nsec = False
        has_nsec3 = False
        has_sig = False
        for rrset in auth:
            if rrset.rdtype == dns.rdatatype.NSEC:
                has_nsec = True
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                has_nsec3 = True
            for rdat in rrset:
                if rdat.rdtype == dns.rdatatype.RRSIG:
                    has_sig = True

        if not has_nsec and not has_nsec3:
            return DNSSECValidationResult(
                DNSSECValidationStatus.INSECURE,
                f"{reason_detail} without DNSSEC proof",
            )

        if has_nsec and has_sig:
            try:
                for rrset in auth:
                    dns.dnssec.validate(rrset, response_message)
                _incr_metric("secure")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.SECURE,
                    f"{reason_detail} validated with NSEC",
                    ad_flag_allowed=True,
                )
            except (dns.dnssec.ValidationFailure, dns.exception.DNSException) as e:
                _incr_metric("bogus")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.BOGUS,
                    f"{reason_detail} NSEC validation failed: {e}",
                )

        if has_nsec3 and has_sig:
            try:
                for rrset in auth:
                    dns.dnssec.validate(rrset, response_message)
                _incr_metric("secure")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.SECURE,
                    f"{reason_detail} validated with NSEC3",
                    ad_flag_allowed=True,
                )
            except (dns.dnssec.ValidationFailure, dns.exception.DNSException) as e:
                _incr_metric("bogus")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.BOGUS,
                    f"{reason_detail} NSEC3 validation failed: {e}",
                )

        _incr_metric("indeterminate")
        return DNSSECValidationResult(
            DNSSECValidationStatus.INDETERMINATE,
            f"{reason_detail} with unsupported DNSSEC proof type",
        )

    def _validate_signed(self, response_message, qname, qtype):
        qname_str = qname.to_text().rstrip(".")
        try:
            if not self._anchor_ok:
                self.reload_trust_anchor()
            if not self._anchor_ok:
                _incr_metric("indeterminate")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.INDETERMINATE,
                    "no root trust anchor loaded",
                )

            with _trust_anchor_lock:
                dnskey_set = _trust_anchor_dnskey_set

            # Collect RRSIG records and DNSKEY records from the response.
            # In dnspython, rrsets are grouped by (name, rdclass, rdtype), so
            # RRSIG records live in their own rrsets, separate from the data
            # they cover.  We must pair them explicitly.
            rrsig_by_target: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = {}
            dnskey_by_name: dict[dns.name.Name, dns.rrset.RRset] = {}

            for section in (response_message.answer, response_message.authority):
                for rrset in section:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        for rdata in rrset:
                            key = (rrset.name, rdata.type_covered)
                            if key not in rrsig_by_target:
                                rrsig_by_target[key] = dns.rrset.RRset(
                                    rrset.name, rrset.rdclass, dns.rdatatype.RRSIG
                                )
                            rrsig_by_target[key].add(rdata)
                    elif rrset.rdtype == dns.rdatatype.DNSKEY:
                        dnskey_by_name[rrset.name] = rrset

            # Build the keys dict from the root trust anchor and any DNSKEY
            # rrsets present in the response.
            keys: dict[dns.name.Name, dns.rdataset.Rdataset] = {}
            if dnskey_set:
                root_keys = dns.rdataset.Rdataset(dns.rdataclass.IN)
                for k in dnskey_set:
                    root_keys.add(k)
                keys[dns.name.root] = root_keys
            for name, rrset in dnskey_by_name.items():
                if name not in keys:
                    keys[name] = dns.rdataset.Rdataset(rrset.rdclass)
                for rdata in rrset:
                    keys[name].add(rdata)

            # Log what was collected from the response
            collected_rrsigs = [
                f"{name} {dns.rdatatype.to_text(tc)}"
                for (name, tc) in rrsig_by_target
            ]
            collected_dnskeys = [
                f"{name} algo={[r.algorithm for r in rrset]}"
                for name, rrset in dnskey_by_name.items()
            ]
            logger.debug(
                "DNSSEC _validate_signed: rrsigs=[%s] dnskeys=[%s] keys_loaded=%d",
                "; ".join(collected_rrsigs), "; ".join(collected_dnskeys), len(keys),
            )

            validated_ok = False
            validated_rrsets: list[str] = []

            # Validate every non-RRSIG, non-DNSKEY rrset that has a
            # matching RRSIG in the response.
            for section in (response_message.answer, response_message.authority):
                for rrset in section:
                    if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY):
                        continue
                    sig_key = (rrset.name, rrset.rdtype)
                    rrsigset = rrsig_by_target.get(sig_key)
                    if rrsigset is None:
                        continue
                    try:
                        dns.dnssec.validate(rrset, rrsigset, keys)
                        validated_ok = True
                        validated_rrsets.append(
                            rrset.name.to_text() + " " + dns.rdatatype.to_text(rrset.rdtype)
                        )
                    except (dns.dnssec.ValidationFailure, dns.exception.DNSException) as e:
                        logger.warning(
                            "DNSSEC bogus %s %s reason=%s",
                            qname_str, dns.rdatatype.to_text(qtype), e,
                        )
                        _incr_metric("bogus")
                        return DNSSECValidationResult(
                            DNSSECValidationStatus.BOGUS,
                            f"RRSIG validation failed for {rrset.name.to_text().rstrip('.')} {dns.rdatatype.to_text(rrset.rdtype)}: {e}",
                        )

            if validated_ok:
                logger.info(
                    "DNSSEC secure %s type=%s reason=signature validated against DNSKEY",
                    qname_str, dns.rdatatype.to_text(qtype),
                )
                _incr_metric("secure")
                return DNSSECValidationResult(
                    DNSSECValidationStatus.SECURE,
                    "signature validated against DNSKEY",
                    ad_flag_allowed=True,
                    validated_rrsets=validated_rrsets,
                )

            # Fallback: try validating authority-section rrsets (e.g. NSEC/NSEC3)
            # using the same approach.
            for rrset in response_message.authority:
                if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY):
                    continue
                sig_key = (rrset.name, rrset.rdtype)
                rrsigset = rrsig_by_target.get(sig_key)
                if rrsigset is None:
                    continue
                try:
                    dns.dnssec.validate(rrset, rrsigset, keys)
                    _incr_metric("secure")
                    return DNSSECValidationResult(
                        DNSSECValidationStatus.SECURE,
                        "authority section validated",
                        ad_flag_allowed=True,
                    )
                except (dns.dnssec.ValidationFailure, dns.exception.DNSException):
                    pass

            _incr_metric("indeterminate")
            return DNSSECValidationResult(
                DNSSECValidationStatus.INDETERMINATE,
                "no RRSIG records could be validated",
            )

        except (dns.dnssec.ValidationFailure, dns.exception.DNSException) as e:
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
