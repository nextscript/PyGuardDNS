import base64
import os
import sys
import time
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
    DNSSECValidationResult,
    DNSSECValidationStatus,
    DNSSECValidator,
    TrustAnchorStore,
    get_dnssec_metrics,
    _metrics,
    _metrics_lock,
)


def _reset_metrics():
    with _metrics_lock:
        _metrics.clear()
        _metrics.update({"secure": 0, "insecure": 0, "bogus": 0, "indeterminate": 0, "validation_seconds_total": 0.0})


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

    def test_metrics_are_isolated(self):
        from dnssec_validator import _incr_metric
        _incr_metric("secure", 3)
        _incr_metric("bogus", 1)
        metrics = get_dnssec_metrics()
        self.assertEqual(metrics["secure"], 3)
        self.assertEqual(metrics["bogus"], 1)


if __name__ == "__main__":
    unittest.main()
