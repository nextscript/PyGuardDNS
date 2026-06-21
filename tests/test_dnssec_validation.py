import base64
import os
import sys
import time
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rcode
import dns.resolver

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dnssec_validator import (
    DNSSECCache,
    DNSSECLookupFailure,
    DNSSECValidationResult,
    DNSSECValidationStatus,
    DNSSECValidator,
    TrustAnchorStore,
    ensure_root_trust_anchor,
    get_dnssec_metrics,
    _metrics,
    _metrics_lock,
)


def _reset_metrics():
    with _metrics_lock:
        _metrics.clear()
        _metrics.update({
            "secure": 0,
            "insecure": 0,
            "bogus": 0,
            "indeterminate": 0,
            "validation_seconds_total": 0.0,
            "nsec_validations": 0,
            "nsec3_validations": 0,
            "nsec3_failures": 0,
        })


class TestDNSSECCache(unittest.TestCase):
    def setUp(self):
        self.cache = DNSSECCache()

    def test_set_and_get(self):
        self.cache.set("test-key", "test-value", ttl=300)
        self.assertEqual(self.cache.get("test-key"), "test-value")

    def test_expiry(self):
        self.cache.set("expire-key", "value", ttl=0)
        self.cache._data["expire-key"]["expires"] = time.time() - 1
        self.assertIsNone(self.cache.get("expire-key"))

    def test_bogus(self):
        self.cache.set_bogus("bogus-key", ttl=60)
        bogus_val = self.cache.get("bogus-key")
        self.assertIsNone(bogus_val)

    def test_clear(self):
        self.cache.set("a", 1, ttl=300)
        self.cache.set("b", 2, ttl=300)
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)

    def test_size(self):
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)
        self.cache.set("k1", "v1", ttl=100)
        self.assertEqual(self.cache.size(), 1)
        self.cache.set("k2", "v2", ttl=100)
        self.assertEqual(self.cache.size(), 2)


class TestDNSSECValidatorBase(unittest.TestCase):
    def setUp(self):
        _reset_metrics()
        self.mock_resolver = MagicMock(spec=dns.resolver.Resolver)
        self.mock_resolver.nameservers = ["1.1.1.1"]
        self.validator = DNSSECValidator(self.mock_resolver)

    def _make_query_response(self, qname="example.com", qtype="A"):
        qname_obj = dns.name.from_text(qname)
        qmsg = dns.message.make_query(qname_obj, dns.rdatatype.from_text(qtype))
        rmsg = dns.message.make_response(qmsg)
        return qmsg, rmsg

    def _add_a_answer(self, rmsg, qname="example.com", ttl=300):
        qname_obj = dns.name.from_text(qname)
        rrset = dns.rrset.RRset(qname_obj, dns.rdataclass.IN, dns.rdatatype.A)
        a_rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        rrset.add(a_rdata)
        rrset.ttl = ttl
        rmsg.answer.append(rrset)
        return rrset


class TestDNSSECValidationStatus(TestDNSSECValidatorBase):
    def test_unsigned_response_is_insecure(self):
        qmsg, rmsg = self._make_query_response()
        self._add_a_answer(rmsg)
        result = self.validator.validate_response(qmsg, rmsg)
        self.assertEqual(result.status, DNSSECValidationStatus.INSECURE)

    def test_servfail_is_indeterminate(self):
        qmsg, rmsg = self._make_query_response()
        rmsg.set_rcode(dns.rcode.SERVFAIL)
        result = self.validator.validate_response(qmsg, rmsg)
        self.assertEqual(result.status, DNSSECValidationStatus.INDETERMINATE)
        self.assertIn("SERVFAIL", result.reason)

    def test_nxdomain_without_proof_is_insecure(self):
        qmsg, rmsg = self._make_query_response()
        rmsg.set_rcode(dns.rcode.NXDOMAIN)
        result = self.validator.validate_response(qmsg, rmsg)
        self.assertEqual(result.status, DNSSECValidationStatus.INSECURE)

    def test_nxdomain_with_nsec_validates(self):
        qmsg, rmsg = self._make_query_response()
        rmsg.set_rcode(dns.rcode.NXDOMAIN)
        name = dns.name.from_text("example.com")
        nsec_rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.NSEC)
        nsec_rdata = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.NSEC,
            "example.com A NS SOA MX TXT"
        )
        nsec_rrset.add(nsec_rdata)
        rmsg.authority.append(nsec_rrset)
        result = self.validator.validate_response(qmsg, rmsg)
        self.assertIn(result.status, ("secure", "insecure", "indeterminate"))

    def test_missing_query_returns_indeterminate(self):
        result = self.validator.validate_response(None, dns.message.Message())
        self.assertEqual(result.status, DNSSECValidationStatus.INDETERMINATE)

    def test_missing_response_returns_indeterminate(self):
        qmsg, _ = self._make_query_response()
        result = self.validator.validate_response(qmsg, None)
        self.assertEqual(result.status, DNSSECValidationStatus.INDETERMINATE)

    def test_metrics_after_validation(self):
        qmsg, rmsg = self._make_query_response()
        self._add_a_answer(rmsg)
        self.validator.validate_response(qmsg, rmsg)
        metrics = get_dnssec_metrics()
        self.assertIn("secure", metrics)
        self.assertIn("insecure", metrics)
        self.assertIn("bogus", metrics)
        self.assertIn("indeterminate", metrics)
        self.assertIn("validation_seconds_total", metrics)


class TestTrustAnchorStore(unittest.TestCase):
    def setUp(self):
        self.orig_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.xml_path = os.path.join(self.orig_dir, "data", "root-anchors.xml")
        self.key_path = os.path.join(self.orig_dir, "data", "root.key")

    def test_xml_exists(self):
        self.assertTrue(os.path.exists(self.xml_path), "root-anchors.xml should exist")

    def test_key_exists(self):
        self.assertTrue(os.path.exists(self.key_path), "root.key should exist")

    def test_load_xml_anchor(self):
        store = TrustAnchorStore(xml_path=self.xml_path, key_path="")
        ok, err = store.load()
        self.assertTrue(ok, f"Trust anchor should load: {err}")

    def test_load_key_anchor(self):
        store = TrustAnchorStore(xml_path="", key_path=self.key_path)
        ok, err = store.load()
        self.assertTrue(ok, f"Trust anchor should load: {err}")

    def test_ensure_root_trust_anchor_creates_missing_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, err = ensure_root_trust_anchor(data_dir=tmpdir)
            self.assertTrue(ok, err)
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "root-anchors.xml")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "root.key")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "trust_anchors.json")))
            with open(os.path.join(tmpdir, "trust_anchors.json"), "r", encoding="utf-8") as f:
                payload = __import__("json").load(f)
            self.assertTrue(payload["rfc5011_auto_update"])
            self.assertIn("anchors", payload)

    def test_corrupted_trust_anchor_state_is_backed_up(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, err = ensure_root_trust_anchor(data_dir=tmpdir)
            self.assertTrue(ok, err)
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            with open(json_path, "w", encoding="utf-8") as f:
                f.write("{not-json")
            ok, err = ensure_root_trust_anchor(data_dir=tmpdir)
            self.assertTrue(ok, err)
            backups = [name for name in os.listdir(tmpdir) if ".broken." in name]
            self.assertTrue(backups)

    def test_bootstrapped_rfc5011_anchor_with_elapsed_hold_down_is_active(self):
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            ok, err = ensure_root_trust_anchor(data_dir=tmpdir)
            self.assertTrue(ok, err)
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            current_root_ksk = next(a for a in payload["anchors"] if a.get("key_tag") == 38696)
            self.assertEqual(current_root_ksk["state"], "active")
            self.assertNotIn("hold_down_until", current_root_ksk)

    def _write_rfc5011_state(self, json_path, pending_anchor):
        import json

        payload = {
            "zone": ".",
            "anchors": [
                {
                    "key_tag": 20326,
                    "algorithm": 8,
                    "digest_type": 2,
                    "digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
                    "state": "active",
                    "revoked": False,
                },
                pending_anchor,
            ],
            "rfc5011_auto_update": True,
            "updated_at": "2026-01-01T00:00:00Z",
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    def test_process_rfc5011_state_promotes_expired_pending_anchor(self):
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            self._write_rfc5011_state(json_path, {
                "key_tag": 38696,
                "algorithm": 8,
                "digest_type": 2,
                "digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
                "state": "pending",
                "hold_down_until": "2026-01-01T00:00:00Z",
                "revoked": False,
            })
            validator = DNSSECValidator(
                trust_anchor_path=os.path.join(tmpdir, "missing.xml"),
                trust_anchor_key_path=os.path.join(tmpdir, "missing.key"),
                trust_anchor_json_path=json_path,
            )

            self.assertTrue(validator.process_rfc5011_state())
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            promoted = next(a for a in payload["anchors"] if a["key_tag"] == 38696)
            self.assertEqual(promoted["state"], "active")
            self.assertIn("promoted_at", promoted)
            self.assertNotIn("hold_down_until", promoted)

    def test_process_rfc5011_state_repairs_bootstrap_hold_down_from_first_seen(self):
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            self._write_rfc5011_state(json_path, {
                "key_tag": 38696,
                "algorithm": 8,
                "digest_type": 2,
                "digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
                "state": "pending",
                "first_seen": "2024-07-18T00:00:00+00:00",
                "hold_down_until": "2026-07-05T09:41:34Z",
                "revoked": False,
            })
            validator = DNSSECValidator(
                trust_anchor_path=os.path.join(tmpdir, "missing.xml"),
                trust_anchor_key_path=os.path.join(tmpdir, "missing.key"),
                trust_anchor_json_path=json_path,
            )

            self.assertTrue(validator.process_rfc5011_state())
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            promoted = next(a for a in payload["anchors"] if a["key_tag"] == 38696)
            self.assertEqual(promoted["state"], "active")
            self.assertNotIn("hold_down_until", promoted)

    def test_process_rfc5011_state_does_not_promote_revoked_anchor(self):
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            self._write_rfc5011_state(json_path, {
                "key_tag": 38696,
                "algorithm": 8,
                "digest_type": 2,
                "digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
                "state": "pending",
                "hold_down_until": "2026-01-01T00:00:00Z",
                "revoked": True,
            })
            validator = DNSSECValidator(
                trust_anchor_path=os.path.join(tmpdir, "missing.xml"),
                trust_anchor_key_path=os.path.join(tmpdir, "missing.key"),
                trust_anchor_json_path=json_path,
            )

            self.assertFalse(validator.process_rfc5011_state())
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            revoked = next(a for a in payload["anchors"] if a["key_tag"] == 38696)
            self.assertEqual(revoked["state"], "pending")

    def test_process_rfc5011_state_retires_revoked_active_anchor(self):
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "zone": ".",
                    "anchors": [{
                        "key_tag": 20326,
                        "algorithm": 8,
                        "digest_type": 2,
                        "digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
                        "state": "active",
                        "remove_hold_down_until": "2026-01-01T00:00:00Z",
                        "revoked": True,
                    }],
                    "rfc5011_auto_update": True,
                }, f)
            validator = DNSSECValidator(
                trust_anchor_path=os.path.join(tmpdir, "missing.xml"),
                trust_anchor_key_path=os.path.join(tmpdir, "missing.key"),
                trust_anchor_json_path=json_path,
            )

            self.assertTrue(validator.process_rfc5011_state())
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            retired = next(a for a in payload["anchors"] if a["key_tag"] == 20326)
            self.assertEqual(retired["state"], "retired")
            self.assertIn("retired_at", retired)

    def test_revoked_anchor_remains_trusted_during_remove_hold_down(self):
        import dnssec_validator
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "zone": ".",
                    "anchors": [{
                        "key_tag": 20326,
                        "algorithm": 8,
                        "digest_type": 2,
                        "digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
                        "state": "revoked",
                        "remove_hold_down_until": "2099-01-01T00:00:00Z",
                        "revoked": True,
                    }],
                    "rfc5011_auto_update": True,
                }, f)
            dnssec_validator._trust_anchor_loaded = False
            store = TrustAnchorStore(
                xml_path=os.path.join(tmpdir, "missing.xml"),
                key_path=os.path.join(tmpdir, "missing.key"),
                json_path=json_path,
            )

            ok, err = store.load()
            self.assertTrue(ok, err)

    def test_process_rfc5011_state_removes_old_retired_anchor(self):
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "zone": ".",
                    "anchors": [
                        {
                            "key_tag": 20326,
                            "algorithm": 8,
                            "digest_type": 2,
                            "digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
                            "state": "retired",
                            "retired_at": "2026-01-01T00:00:00Z",
                            "revoked": True,
                        },
                        {
                            "key_tag": 38696,
                            "algorithm": 8,
                            "digest_type": 2,
                            "digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
                            "state": "active",
                            "revoked": False,
                        },
                    ],
                    "rfc5011_auto_update": True,
                }, f)
            validator = DNSSECValidator(
                trust_anchor_path=os.path.join(tmpdir, "missing.xml"),
                trust_anchor_key_path=os.path.join(tmpdir, "missing.key"),
                trust_anchor_json_path=json_path,
            )

            self.assertTrue(validator.process_rfc5011_state())
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            self.assertNotIn(20326, [a["key_tag"] for a in payload["anchors"]])
            self.assertIn(38696, [a["key_tag"] for a in payload["anchors"]])

    def test_reload_trust_anchor_processes_rfc5011_promotion(self):
        import dnssec_validator
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "trust_anchors.json")
            self._write_rfc5011_state(json_path, {
                "key_tag": 38696,
                "algorithm": 8,
                "digest_type": 2,
                "digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
                "state": "pending",
                "hold_down_until": "2026-01-01T00:00:00Z",
                "revoked": False,
            })
            dnssec_validator._trust_anchor_loaded = False
            validator = DNSSECValidator(
                trust_anchor_path=os.path.join(tmpdir, "missing.xml"),
                trust_anchor_key_path=os.path.join(tmpdir, "missing.key"),
                trust_anchor_json_path=json_path,
            )

            ok, err = validator.reload_trust_anchor()
            self.assertTrue(ok, err)
            with open(json_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            promoted = next(a for a in payload["anchors"] if a["key_tag"] == 38696)
            self.assertEqual(promoted["state"], "active")

    def test_bootstrapped_trust_anchor_loads(self):
        import dnssec_validator

        with tempfile.TemporaryDirectory() as tmpdir:
            ok, err = ensure_root_trust_anchor(data_dir=tmpdir)
            self.assertTrue(ok, err)
            dnssec_validator._trust_anchor_loaded = False
            store = TrustAnchorStore(
                xml_path=os.path.join(tmpdir, "root-anchors.xml"),
                key_path=os.path.join(tmpdir, "root.key"),
            )
            ok, err = store.load()
            self.assertTrue(ok, f"Bootstrapped trust anchor should load: {err}")


class TestDNSSECMetrics(unittest.TestCase):
    def setUp(self):
        _reset_metrics()

    def test_metrics_have_defaults(self):
        metrics = get_dnssec_metrics()
        self.assertEqual(metrics["secure"], 0)
        self.assertEqual(metrics["insecure"], 0)
        self.assertEqual(metrics["bogus"], 0)
        self.assertEqual(metrics["indeterminate"], 0)
        self.assertEqual(metrics["validation_seconds_total"], 0.0)


class TestNSEC3Proofs(TestDNSSECValidatorBase):
    def test_nsec3_hash_uses_dnssec_algorithm(self):
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            "1 0 12 AABBCC 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A NS SOA",
        )
        result = self.validator._nsec3_hash_name(dns.name.from_text("example.com."), rdata)
        self.assertIsInstance(result, str)
        self.assertTrue(result)

    def test_nsec3_is_not_valid_just_because_rrset_exists(self):
        name = dns.name.from_text("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.com.")
        rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.NSEC3)
        rrset.add(dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            "1 0 12 AABBCC 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A NS SOA",
        ))
        ok, reason = self.validator._prove_nsec3_denial(
            [rrset],
            dns.name.from_text("missing.example.com."),
            dns.rdatatype.A,
            dns.rcode.NXDOMAIN,
        )
        self.assertFalse(ok)
        self.assertIn("proof", reason)

    def test_metrics_are_isolated(self):
        from dnssec_validator import _incr_metric
        _incr_metric("secure", 3)
        _incr_metric("bogus", 1)
        metrics = get_dnssec_metrics()
        self.assertEqual(metrics["secure"], 3)
        self.assertEqual(metrics["bogus"], 1)


class TestDNSSECLookupFailure(TestDNSSECValidatorBase):
    """Infrastructure failures (timeout, missing DNSKEY, missing RRSIG) must
    return INDETERMINATE, not BOGUS, so the response passes through instead
    of being blocked with SERVFAIL."""

    def _make_signed_response(self, qname="proton.me", qtype="A"):
        qmsg, rmsg = self._make_query_response(qname, qtype)
        self._add_a_answer(rmsg, qname)
        qname_obj = dns.name.from_text(qname)
        rrsig_rrset = dns.rrset.RRset(qname_obj, dns.rdataclass.IN, dns.rdatatype.RRSIG)
        rrsig_rdata = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.RRSIG,
            "A 8 2 300 20260101000000 20250101000000 12345 proton.me. AAAA",
        )
        rrsig_rrset.add(rrsig_rdata)
        rrsig_rrset.ttl = 300
        rmsg.answer.append(rrsig_rrset)
        return qmsg, rmsg

    def test_dnskey_fetch_failure_returns_indeterminate(self):
        """When DNSKEY fetch fails (timeout), result must be INDETERMINATE."""
        def failing_query(wire):
            raise Exception("timeout")

        validator = DNSSECValidator(query_func=failing_query)
        validator._anchor_ok = True

        qmsg, rmsg = self._make_signed_response()
        result = validator.validate_response(qmsg, rmsg)
        self.assertEqual(result.status, DNSSECValidationStatus.INDETERMINATE)
        self.assertNotEqual(result.status, DNSSECValidationStatus.BOGUS)

    def test_lookup_failure_exception_is_distinct_from_validation_failure(self):
        self.assertNotIsInstance(DNSSECLookupFailure("test"), dns.dnssec.ValidationFailure)

    def test_dnskey_none_raises_lookup_failure_not_validation_failure(self):
        """_validated_zone_keys must raise DNSSECLookupFailure when root
        DNSKEY fetch returns None, not ValidationFailure."""
        def null_query(wire):
            msg = dns.message.make_response(dns.message.from_wire(wire))
            return msg.to_wire()

        validator = DNSSECValidator(query_func=null_query)
        validator._anchor_ok = True
        with self.assertRaises(DNSSECLookupFailure):
            validator._validated_zone_keys(dns.name.from_text("example.com."))


if __name__ == "__main__":
    unittest.main()
