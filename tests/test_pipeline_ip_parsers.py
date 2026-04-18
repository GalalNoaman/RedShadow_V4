# tests/test_pipeline_ip_parsers.py — Unit tests for pipeline_ip.py parsers

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock

# Patch modules that need external dependencies
import types
fake_termcolor = types.ModuleType("termcolor")
fake_termcolor.cprint = lambda *a, **kw: None
sys.modules["termcolor"] = fake_termcolor

fake_pipeline = types.ModuleType("modules.pipeline")
for attr in ["StageRecord","STATE_PASSED","STATE_FAILED","STATE_SKIPPED",
             "STATE_RESUMED","run_stage","run_stages_parallel","stage_already_done",
             "mark_stage_done","_write_meta","_meta_valid","file_has_content",
             "_load_json_list","_load_json_dict","TOOL_VERSION"]:
    setattr(fake_pipeline, attr, MagicMock())
fake_pipeline.STATE_PASSED  = "PASSED"
fake_pipeline.STATE_FAILED  = "FAILED"
fake_pipeline.STATE_SKIPPED = "SKIPPED"
fake_pipeline.STATE_RESUMED = "RESUMED"
sys.modules["modules.pipeline"] = fake_pipeline

fake_logger = types.ModuleType("modules.logger")
fake_logger.init_logger = MagicMock(return_value=MagicMock())
fake_logger.get_logger  = MagicMock(return_value=MagicMock())
sys.modules["modules.logger"] = fake_logger

fake_utils = types.ModuleType("modules.utils")
fake_utils.load_config = MagicMock(return_value={})
sys.modules["modules.utils"] = fake_utils

from modules.pipeline_ip import _parse_scan_results, _is_likely_http_service


class TestParseScanResults(unittest.TestCase):

    def _write_and_parse(self, data, tmp_path):
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        return _parse_scan_results(tmp_path)

    def test_dict_wrapped_format(self):
        """scan.py output format: {"results": {"ip": {"protocols": {"tcp": {port: {...}}}}}}"""
        data = {
            "results": {
                "45.33.32.156": {
                    "ip": "45.33.32.156",
                    "protocols": {
                        "tcp": {
                            80:  {"state": "open", "service": "http",  "product": "Apache httpd", "version": "2.4.7"},
                            22:  {"state": "open", "service": "ssh",   "product": "OpenSSH",      "version": "6.6.1"},
                            443: {"state": "closed","service": "https", "product": "",             "version": ""},
                        }
                    }
                }
            }
        }
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(data, f)
            tmp = f.name

        result = _parse_scan_results(tmp)
        os.unlink(tmp)

        self.assertEqual(len(result), 1)
        entry = result[0]
        self.assertEqual(entry["host"], "45.33.32.156")
        # Only open ports should be included
        ports = entry["ports"]
        self.assertEqual(len(ports), 2)
        port_nums = [p["port"] for p in ports]
        self.assertIn(80, port_nums)
        self.assertIn(22, port_nums)
        self.assertNotIn(443, port_nums)  # closed port excluded

    def test_missing_file_returns_empty(self):
        result = _parse_scan_results("/nonexistent/path/scan.json")
        self.assertEqual(result, [])

    def test_empty_protocols(self):
        import tempfile
        data = {"results": {"10.0.0.1": {"ip": "10.0.0.1", "protocols": {}}}}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(data, f)
            tmp = f.name
        result = _parse_scan_results(tmp)
        os.unlink(tmp)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ports"], [])


class TestIsLikelyHttpService(unittest.TestCase):

    def test_known_http_ports(self):
        self.assertEqual(_is_likely_http_service(80,   "http",  ""),       "http")
        self.assertEqual(_is_likely_http_service(443,  "https", ""),       "https")
        self.assertEqual(_is_likely_http_service(8080, "http",  ""),       "http")
        self.assertEqual(_is_likely_http_service(8443, "https", ""),       "https")

    def test_non_http_ports_excluded(self):
        self.assertIsNone(_is_likely_http_service(22,   "ssh",   "OpenSSH"))
        self.assertIsNone(_is_likely_http_service(3306, "mysql", "MySQL"))
        self.assertIsNone(_is_likely_http_service(6379, "redis", "Redis"))
        self.assertIsNone(_is_likely_http_service(179,  "bgp",   ""))

    def test_ambiguous_ports_try_both(self):
        self.assertEqual(_is_likely_http_service(8081, "http",  ""), "both")
        self.assertEqual(_is_likely_http_service(7999, "",      ""), "both")
        self.assertEqual(_is_likely_http_service(20000,"",      ""), "both")
        self.assertEqual(_is_likely_http_service(9000, "",      ""), "both")

    def test_ssl_service_name(self):
        result = _is_likely_http_service(9443, "ssl/http", "")
        self.assertIn(result, ("https", "both"))

    def test_fail_open_unknown_port(self):
        # Unknown port with no service info → probe it (fail-open)
        result = _is_likely_http_service(54321, "", "")
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
