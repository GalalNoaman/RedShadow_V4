# tests/test_validators.py — Unit tests for IP/CIDR validation in main.py

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest

# Import validation functions directly
from main import is_valid_ip, is_valid_cidr, is_valid_domain, expand_cidr


class TestIsValidIP(unittest.TestCase):

    def test_valid_ips(self):
        valid = ["192.168.1.1", "10.0.0.1", "45.33.32.156",
                 "0.0.0.0", "255.255.255.255", "51.141.1.28"]
        for ip in valid:
            with self.subTest(ip=ip):
                self.assertTrue(is_valid_ip(ip), f"Should be valid: {ip}")

    def test_invalid_ips(self):
        invalid = ["999.999.999.999", "256.0.0.1", "10.10.10.10.10",
                   "not-an-ip", "", "10.0.0", "10.0.0.0/24"]
        for ip in invalid:
            with self.subTest(ip=ip):
                self.assertFalse(is_valid_ip(ip), f"Should be invalid: {ip}")


class TestIsValidCIDR(unittest.TestCase):

    def test_valid_cidrs(self):
        valid = ["10.0.0.0/8", "192.168.0.0/16", "10.0.0.0/24",
                 "172.16.0.0/12", "45.33.32.0/24"]
        for cidr in valid:
            with self.subTest(cidr=cidr):
                self.assertTrue(is_valid_cidr(cidr), f"Should be valid: {cidr}")

    def test_invalid_cidrs(self):
        invalid = ["10.0.0.0/99", "999.0.0.0/8", "not-a-cidr",
                   "10.0.0.0", "10.0.0.0/33"]
        for cidr in invalid:
            with self.subTest(cidr=cidr):
                self.assertFalse(is_valid_cidr(cidr), f"Should be invalid: {cidr}")


class TestIsValidDomain(unittest.TestCase):

    def test_valid_domains(self):
        valid = ["example.com", "hackerone.com", "sub.domain.co.uk",
                 "test-domain.org", "api.example.com"]
        for d in valid:
            with self.subTest(d=d):
                self.assertTrue(is_valid_domain(d), f"Should be valid: {d}")

    def test_invalid_domains(self):
        invalid = ["", "localhost", "not_a_domain", "192.168.1.1",
                   ".example.com", "example"]
        for d in invalid:
            with self.subTest(d=d):
                self.assertFalse(is_valid_domain(d), f"Should be invalid: {d}")


class TestExpandCIDR(unittest.TestCase):

    def test_small_cidr(self):
        ips = expand_cidr("10.0.0.0/30")
        self.assertEqual(len(ips), 2)   # /30 = 2 usable hosts
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)

    def test_single_host(self):
        ips = expand_cidr("192.168.1.5/32")
        # /32 = 0 hosts() but should handle gracefully
        self.assertIsInstance(ips, list)

    def test_invalid_cidr_raises(self):
        with self.assertRaises(ValueError):
            expand_cidr("not-a-cidr")

    def test_too_large_raises(self):
        with self.assertRaises(ValueError):
            expand_cidr("10.0.0.0/8")   # /8 = 16M hosts, over the /16 limit


if __name__ == "__main__":
    unittest.main(verbosity=2)
