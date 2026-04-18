# tests/test_schemas.py — Unit tests for modules/schemas.py

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import types
fake_termcolor = types.ModuleType("termcolor")
fake_termcolor.cprint = lambda *a, **kw: None
sys.modules["termcolor"] = fake_termcolor

import unittest
from modules.schemas import validate_stage_output, ValidationResult


class TestSchemas(unittest.TestCase):
    """Tests updated to use ValidationResult API (schemas v2)."""

    def test_valid_passive_results(self):
        data = [{"url": "http://10.0.0.1", "status": 200}]
        result = validate_stage_output("passive_results", data)
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.valid)
        self.assertEqual(result.errors, [])

    def test_invalid_passive_results_missing_key(self):
        data = [{"status": 200}]   # missing "url"
        result = validate_stage_output("passive_results", data)
        self.assertFalse(result.valid)
        self.assertTrue(any("url" in e["error"] for e in result.errors))

    def test_valid_analysis_results(self):
        data = [{"url": "10.0.0.1", "tech_matches": [{"tech": "apache", "cves": []}]}]
        result = validate_stage_output("analysis_results", data)
        self.assertTrue(result.valid)

    def test_wrong_type_for_list_schema(self):
        data = {"url": "http://10.0.0.1"}  # dict instead of list
        result = validate_stage_output("passive_results", data)
        self.assertFalse(result.valid)

    def test_empty_list_is_valid(self):
        result = validate_stage_output("passive_results", [])
        self.assertTrue(result.valid)

    def test_unknown_schema_passes(self):
        result = validate_stage_output("nonexistent_schema", {"anything": True})
        self.assertTrue(result.valid)

    def test_valid_attack_paths(self):
        data = [{
            "type": "RCE_CANDIDATE", "confidence": "MEDIUM", "score": 7.5,
            "title": "Test lead", "validation_checks": ["check 1"],
            "source_modules": ["analyse"]
        }]
        result = validate_stage_output("attack_paths", data)
        self.assertTrue(result.valid)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestDeepValidation(unittest.TestCase):
    """Test the deep nested validation in schemas v2 using ValidationResult API."""

    def test_cvss_range_enforced(self):
        """CVSS must be 0.0–10.0"""
        data = [{"url": "10.0.0.1", "tech_matches": [{
            "tech": "apache", "cves": [{"cve": "CVE-2021-41773", "cvss": 15.0}]
        }]}]
        result = validate_stage_output("analysis_results", data)
        self.assertFalse(result.valid)
        self.assertTrue(any("maximum" in e["error"] for e in result.errors))

    def test_severity_allowed_values(self):
        """probe_results severity must be in allowed set"""
        data = [{"url": "http://10.0.0.1", "findings": [{
            "name": "Test", "severity": "MEGA_CRITICAL", "finding_type": "vulnerability"
        }]}]
        result = validate_stage_output("probe_results", data)
        self.assertFalse(result.valid)
        self.assertTrue(any("allowed" in e["error"] for e in result.errors))

    def test_confidence_allowed_values(self):
        """attack_paths confidence must be HIGH/MEDIUM/LOW"""
        data = [{"type": "RCE_CANDIDATE", "confidence": "SUPER_HIGH",
                 "score": 7.5, "title": "Test",
                 "validation_checks": [], "source_modules": ["scan"]}]
        result = validate_stage_output("attack_paths", data)
        self.assertFalse(result.valid)

    def test_port_range_enforced(self):
        """passive_results port must be 1–65535"""
        data = [{"url": "http://10.0.0.1", "status": 200, "port": 99999}]
        result = validate_stage_output("passive_results", data)
        self.assertFalse(result.valid)

    def test_status_code_range(self):
        """HTTP status must be 100–599"""
        data = [{"url": "http://10.0.0.1", "status": 42}]
        result = validate_stage_output("passive_results", data)
        self.assertFalse(result.valid)

    def test_nested_cve_required_keys(self):
        """CVEs must have cve and cvss"""
        data = [{"url": "10.0.0.1", "tech_matches": [{
            "tech": "apache", "cves": [{"cvss": 9.8}]  # missing "cve"
        }]}]
        result = validate_stage_output("analysis_results", data)
        self.assertFalse(result.valid)
        self.assertTrue(any("cve" in e["error"] for e in result.errors))
