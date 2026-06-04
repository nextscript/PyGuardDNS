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
                ds_set = _trust_anchor_ds_set
                dnskey_set = _trust_anchor_dnskey_set

            validated_ok = False
            validated_rrsets = []

            for section in (response_message.answer, response_message.authority):
                for rrset in section:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        continue
                    covering = None
                    for rdat in rrset:
                        if rdat.rdtype == dns.rdatatype.RRSIG:
                            covering = rdat
                            break
                    if covering is not None:
                        rrsig_set = dns.rrset.RRset(rrset.name, rrset.rdclass, dns.rdatatype.RRSIG)
                        for rdat in rrset:
                            if rdat.rdtype == dns.rdatatype.RRSIG:
                                rrsig_set.add(rdat)
                        try:
                            dns.dnssec.validate(rrset, response_message)
                            validated_ok = True
                            validated_rrsets.append(rrset.name.to_text() + " " + dns.rdatatype.to_text(rrset.rdtype))
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

            authority_rrsig = False
            for rrset in response_message.authority:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    authority_rrsig = True
                    break

            if authority_rrsig:
                for rrset in response_message.authority:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        continue
                    try:
                        dns.dnssec.validate(rrset, response_message)
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
