# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.

# tests/test_matchers.py — Unit tests for modules/matchers.py

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from modules.matchers import (
    normalize_product_name,
    normalize_version,
    service_matches_product,
    version_is_relevant,
    finding_confidence,
)


class TestNormalizeProductName(unittest.TestCase):

    def test_basic_names(self):
        self.assertEqual(normalize_product_name("nginx"),         "nginx")
        self.assertEqual(normalize_product_name("Apache"),        "apache")
        self.assertEqual(normalize_product_name("OpenSSH"),       "openssh")
        self.assertEqual(normalize_product_name("Microsoft IIS"), "microsoft iis")

    def test_strips_version(self):
        self.assertEqual(normalize_product_name("Apache 2.4.7"),      "apache")
        self.assertEqual(normalize_product_name("OpenSSH 6.6.1p1"),   "openssh")
        self.assertEqual(normalize_product_name("nginx 1.18.0"),      "nginx")

    def test_strips_suffixes(self):
        self.assertEqual(normalize_product_name("Apache httpd"),       "apache")
        self.assertEqual(normalize_product_name("Apache HTTP Server"), "apache")
        self.assertEqual(normalize_product_name("nginx HTTP server"),  "nginx")

    def test_tomcat_variants(self):
        self.assertEqual(normalize_product_name("Apache Tomcat"),      "apache tomcat")
        self.assertEqual(normalize_product_name("Tomcat"),             "apache tomcat")
        self.assertEqual(normalize_product_name("Coyote"),             "apache tomcat")

    def test_empty_input(self):
        self.assertEqual(normalize_product_name(""),   "")
        self.assertEqual(normalize_product_name(None), "")  # type: ignore

    def test_unknown_product_passes_through(self):
        result = normalize_product_name("SomeUnknownProduct123")
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)


class TestNormalizeVersion(unittest.TestCase):

    def test_simple_versions(self):
        self.assertEqual(normalize_version("2.4.7"),    (2, 4, 7))
        self.assertEqual(normalize_version("1.18.0"),   (1, 18, 0))
        self.assertEqual(normalize_version("6.6.1"),    (6, 6, 1))
        self.assertEqual(normalize_version("10"),       (10,))
        self.assertEqual(normalize_version("1.2"),      (1, 2))

    def test_complex_banners(self):
        # OpenSSH banner includes extra info
        result = normalize_version("6.6.1p1 Ubuntu 2ubuntu2.13")
        self.assertEqual(result, (6, 6, 1))

    def test_empty_and_unknown(self):
        self.assertEqual(normalize_version(""),        ())
        self.assertEqual(normalize_version("unknown"), ())
        self.assertEqual(normalize_version("x"),       ())
        self.assertEqual(normalize_version(None),      ())  # type: ignore

    def test_comparison(self):
        self.assertLess(normalize_version("2.4.7"), normalize_version("2.4.55"))
        self.assertGreater(normalize_version("3.0.0"), normalize_version("2.9.9"))
        self.assertEqual(normalize_version("1.18.0"), normalize_version("1.18.0"))


class TestServiceMatchesProduct(unittest.TestCase):

    def test_exact_matches(self):
        self.assertTrue(service_matches_product("apache", "http", "Apache httpd"))
        self.assertTrue(service_matches_product("nginx",  "http", "nginx"))
        self.assertTrue(service_matches_product("openssh","ssh",  "OpenSSH"))

    def test_no_false_matches(self):
        # nginx should not match Apache service
        self.assertFalse(service_matches_product("nginx", "http", "Apache httpd"))
        # MySQL should not match PostgreSQL
        self.assertFalse(service_matches_product("mysql", "postgresql", "PostgreSQL"))

    def test_empty_inputs(self):
        self.assertFalse(service_matches_product("", "http", "Apache"))
        self.assertFalse(service_matches_product("apache", "", ""))

    def test_tomcat_matching(self):
        self.assertTrue(service_matches_product("apache tomcat", "http", "Apache Tomcat Coyote"))
        self.assertTrue(service_matches_product("apache tomcat", "http", "Tomcat"))


class TestVersionIsRelevant(unittest.TestCase):

    def test_confirmed_in_range(self):
        # Apache 2.4.49 is in "2.4.49 - 2.4.50"
        self.assertEqual(version_is_relevant("2.4.49", "2.4.49 - 2.4.50"), "CONFIRMED")

    def test_unlikely_outside_range(self):
        # Apache 2.4.7 is NOT in "2.4.49 - 2.4.50"
        result = version_is_relevant("2.4.7", "2.4.49 - 2.4.50")
        self.assertEqual(result, "UNLIKELY")

    def test_less_than_operator(self):
        # Version 1.18.0 is < 1.20.1 (affected range "< 1.20.1")
        self.assertEqual(version_is_relevant("1.18.0", "< 1.20.1"), "CONFIRMED")
        # Version 1.21.0 is NOT < 1.20.1
        self.assertEqual(version_is_relevant("1.21.0", "< 1.20.1"), "UNLIKELY")

    def test_unknown_version(self):
        self.assertEqual(version_is_relevant("",        "< 1.18.0"), "UNKNOWN")
        self.assertEqual(version_is_relevant("unknown", "< 1.18.0"), "UNKNOWN")

    def test_no_range_info(self):
        self.assertEqual(version_is_relevant("2.4.7", "x"),  "POSSIBLE")
        self.assertEqual(version_is_relevant("2.4.7", ""),   "POSSIBLE")


class TestFindingConfidence(unittest.TestCase):

    def _cve(self, cvss=9.8, epss=0.5, affected="2.4.0 - 2.4.55"):
        return {"cvss": cvss, "epss": epss, "affected_versions": affected}

    def test_high_confidence(self):
        cve  = self._cve(cvss=9.8, epss=0.5)
        conf = finding_confidence(cve, "2.4.49", port_matched=True, service_matched=True)
        self.assertEqual(conf, "HIGH")

    def test_medium_confidence_no_epss(self):
        cve  = self._cve(cvss=7.0, epss=0.05)
        conf = finding_confidence(cve, "2.4.49", port_matched=True, service_matched=True)
        self.assertEqual(conf, "MEDIUM")

    def test_low_confidence_no_service_match(self):
        cve  = self._cve(cvss=9.8, epss=0.5)
        conf = finding_confidence(cve, "2.4.49", port_matched=True, service_matched=False)
        self.assertEqual(conf, "LOW")

    def test_low_confidence_outside_version(self):
        cve  = self._cve(cvss=9.8, epss=0.5, affected="2.4.49 - 2.4.50")
        conf = finding_confidence(cve, "2.4.7", port_matched=True, service_matched=True)
        # Version 2.4.7 is outside the affected range
        self.assertEqual(conf, "LOW")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestNarrativeAndFingerprintIntegration(unittest.TestCase):
    """Test that matchers work correctly with the fingerprint enrichment data."""

    def test_http_fingerprint_product_matches_nmap(self):
        """HTTP-detected Apache should match Nmap's Apache httpd."""
        # "Apache httpd" normalises to "apache"
        self.assertEqual(normalize_product_name("Apache httpd"), "apache")
        # "Apache/2.4.7" — slash is stripped, version stripped, result is "apache"
        # normalize_product_name strips non-alphanum except space/hyphen
        result = normalize_product_name("Apache/2.4.7")
        # Should resolve to "apache" — slash+version stripped before alias lookup
        self.assertEqual(result, "apache")

    def test_version_from_server_header(self):
        """Version extraction from Server header banner."""
        # normalize_version handles complex banners
        self.assertEqual(normalize_version("2.4.7"),           (2, 4, 7))
        self.assertEqual(normalize_version("Apache/2.4.7"),    ())  # not a pure version
        # But regex in analyse.py handles "Apache/2.4.7" → "2.4.7"
        import re
        m = re.search(r'[/\s](\d+\.\d+[\.\d]*)', "Apache/2.4.7")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "2.4.7")

    def test_service_match_with_http_fingerprint(self):
        """HTTP-detected product names should match against CVE products."""
        # Apache from HTTP fingerprint vs apache CVE product
        self.assertTrue(service_matches_product("apache", "http", "Apache"))
        # nginx from Server header vs nginx CVE
        self.assertTrue(service_matches_product("nginx", "http", "nginx"))
        # IIS from Server header
        self.assertTrue(service_matches_product("microsoft iis", "http", "Microsoft IIS"))

    def test_no_false_positive_from_empty_http(self):
        """Empty HTTP fingerprint should not match anything."""
        self.assertFalse(service_matches_product("apache", "", ""))
        self.assertFalse(service_matches_product("nginx", "", ""))
