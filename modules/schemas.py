# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/schemas.py  v2
# Deep JSON schema validation for all stage outputs.
#

#   - Deep nested structure validation (not just top-level shape)
#   - Type checking per field (str, int, float, list, dict, bool)
#   - Optional vs required field distinction enforced recursively
#   - Field value constraints (min/max, allowed values, non-empty)
#   - Validation errors are structured (path, expected, got)
#   - validate_file() returns structured ValidationResult
#   - Used by pipeline stages before consuming output from prior stages

import json
import os
from termcolor import cprint


# ─────────────────────────────────────────
# ValidationResult
# ─────────────────────────────────────────

class ValidationResult:
    def __init__(self, schema_name: str):
        self.schema_name = schema_name
        self.errors      = []
        self.warnings    = []
        self.checked     = 0

    @property
    def valid(self):
        return len(self.errors) == 0

    def add_error(self, path: str, msg: str):
        self.errors.append({"path": path, "error": msg})

    def add_warning(self, path: str, msg: str):
        self.warnings.append({"path": path, "warning": msg})

    def report(self, verbose: bool = False):
        if self.valid:
            if verbose:
                cprint(f"  [✓] Schema {self.schema_name!r}: {self.checked} field(s) validated", "green")
        else:
            cprint(f"  [!] Schema {self.schema_name!r}: {len(self.errors)} error(s)", "yellow")
            for e in self.errors[:5]:
                cprint(f"      {e['path']}: {e['error']}", "yellow")
        if self.warnings and verbose:
            for w in self.warnings[:3]:
                cprint(f"  [~] {w['path']}: {w['warning']}", "cyan")


# ─────────────────────────────────────────
# Field Validators
# ─────────────────────────────────────────

def _check_type(value, expected_types, path, result):
    """Validate value is one of the expected Python types."""
    if not isinstance(value, tuple(expected_types)):
        got = type(value).__name__
        exp = " or ".join(t.__name__ for t in expected_types)
        result.add_error(path, f"expected {exp}, got {got}")
        return False
    result.checked += 1
    return True


def _check_non_empty(value, path, result):
    """Warn if string or list is empty when it probably shouldn't be."""
    if isinstance(value, str) and not value.strip():
        result.add_warning(path, "string is empty")
    elif isinstance(value, list) and len(value) == 0:
        result.add_warning(path, "list is empty")


def _check_allowed(value, allowed, path, result):
    """Validate value is in allowed set."""
    if value not in allowed:
        result.add_error(path, f"value {value!r} not in allowed set: {allowed}")


def _check_range(value, min_val, max_val, path, result):
    """Validate numeric value is within range."""
    if min_val is not None and value < min_val:
        result.add_error(path, f"value {value} is below minimum {min_val}")
    if max_val is not None and value > max_val:
        result.add_error(path, f"value {value} exceeds maximum {max_val}")


# ─────────────────────────────────────────
# Deep Schema Definitions
# Each field entry: (type, required, constraints_dict)
# Constraints: allowed=[], min=N, max=N, non_empty=bool, nested={}
# ─────────────────────────────────────────

DEEP_SCHEMAS = {

    "scan_results": {
        "_type": dict,
        "_required_keys": ["results"],
        "_fields": {
            "results": {
                "_type": dict,
                "_required": True,
                "_each_value": {
                    "_type": dict,
                    "_required_keys": ["ip", "protocols"],
                    "_fields": {
                        "ip":        {"_type": str,  "_required": True},
                        "hostname":  {"_type": str,  "_required": False},
                        "state":     {"_type": str,  "_required": False},
                        "protocols": {"_type": dict, "_required": True},
                    }
                }
            },
            "total_open_ports": {"_type": int,  "_required": False, "_min": 0},
            "targets_scanned":  {"_type": int,  "_required": False, "_min": 0},
        }
    },

    "passive_results": {
        "_type": list,
        "_each_item": {
            "_type": dict,
            "_required_keys": ["url", "status"],
            "_fields": {
                "url":          {"_type": str,  "_required": True,  "_non_empty": True},
                "status":       {"_type": int,  "_required": True,  "_min": 100, "_max": 599},
                "ip":           {"_type": str,  "_required": False},
                "hostname":     {"_type": str,  "_required": False},
                "title":        {"_type": str,  "_required": False},
                "tech_matches": {"_type": list, "_required": False},
                "headers":      {"_type": dict, "_required": False},
                "port":         {"_type": int,  "_required": False, "_min": 1, "_max": 65535},
                "service":      {"_type": str,  "_required": False},
                "product":      {"_type": str,  "_required": False},
                "version":      {"_type": str,  "_required": False},
            }
        }
    },

    "probe_results": {
        "_type": list,
        "_each_item": {
            "_type": dict,
            "_required_keys": ["url"],
            "_fields": {
                "url":       {"_type": str,  "_required": True, "_non_empty": True},
                "findings":  {
                    "_type": list,
                    "_required": False,
                    "_each_item": {
                        "_type": dict,
                        "_required_keys": ["name", "severity", "finding_type"],
                        "_fields": {
                            "name":         {"_type": str, "_required": True},
                            "severity":     {"_type": str, "_required": True,
                                             "_allowed": ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},
                            "finding_type": {"_type": str, "_required": True,
                                             "_allowed": ["vulnerability","recon","hardening"]},
                            "confidence":   {"_type": str, "_required": False,
                                             "_allowed": ["CONFIRMED","LIKELY","POSSIBLE",""]},
                            "path":         {"_type": str, "_required": False},
                        }
                    }
                },
                "technology": {"_type": dict, "_required": False},
            }
        }
    },

    "secret_results": {
        "_type": list,
        "_each_item": {
            "_type": dict,
            "_required_keys": ["url"],
            "_fields": {
                "url":      {"_type": str,  "_required": True,  "_non_empty": True},
                "findings": {
                    "_type": list,
                    "_required": False,
                    "_each_item": {
                        "_type": dict,
                        "_required_keys": ["type", "severity"],
                        "_fields": {
                            "type":       {"_type": str,   "_required": True},
                            "severity":   {"_type": str,   "_required": True,
                                           "_allowed": ["CRITICAL","HIGH","MEDIUM","LOW"]},
                            "confidence": {"_type": str,   "_required": False},
                            "entropy":    {"_type": float, "_required": False, "_min": 0.0},
                        }
                    }
                }
            }
        }
    },

    "analysis_results": {
        "_type": list,
        "_each_item": {
            "_type": dict,
            "_required_keys": ["url", "tech_matches"],
            "_fields": {
                "url":          {"_type": str,   "_required": True,  "_non_empty": True},
                "ip":           {"_type": str,   "_required": False},
                "hostname":     {"_type": str,   "_required": False},
                "risk_score":   {"_type": float, "_required": False, "_min": 0.0, "_max": 10.0},
                "tech_matches": {
                    "_type": list,
                    "_required": True,
                    "_each_item": {
                        "_type": dict,
                        "_required_keys": ["tech", "cves"],
                        "_fields": {
                            "tech":    {"_type": str,  "_required": True, "_non_empty": True},
                            "version": {"_type": str,  "_required": False},
                            "ports":   {"_type": list, "_required": False},
                            "cves":    {
                                "_type": list,
                                "_required": True,
                                "_each_item": {
                                    "_type": dict,
                                    "_required_keys": ["cve", "cvss"],
                                    "_fields": {
                                        "cve":               {"_type": str,   "_required": True},
                                        "cvss":              {"_type": (int, float), "_required": True,
                                                              "_min": 0.0, "_max": 10.0},
                                        "epss":              {"_type": float, "_required": False,
                                                              "_min": 0.0, "_max": 1.0},
                                        "attack_surface":    {"_type": list,  "_required": False},
                                        "version_relevance": {"_type": str,   "_required": False,
                                                              "_allowed": ["CONFIRMED","POSSIBLE",
                                                                           "UNLIKELY","UNKNOWN",""]},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    },

    "attack_paths": {
        "_type": list,
        "_each_item": {
            "_type": dict,
            "_required_keys": ["type", "confidence", "score", "title",
                               "validation_checks", "source_modules"],
            "_fields": {
                "type":              {"_type": str,   "_required": True, "_non_empty": True},
                "confidence":        {"_type": str,   "_required": True,
                                      "_allowed": ["HIGH","MEDIUM","LOW"]},
                "score":             {"_type": float, "_required": True, "_min": 0.0, "_max": 10.0},
                "title":             {"_type": str,   "_required": True, "_non_empty": True},
                "validation_checks": {"_type": list,  "_required": True},
                "source_modules":    {"_type": list,  "_required": True},
                "rank":              {"_type": int,   "_required": False, "_min": 1},
                "hosts":             {"_type": list,  "_required": False},
                "source_count":      {"_type": int,   "_required": False, "_min": 1},
                "validation_state":  {"_type": str,   "_required": False,
                                      "_allowed": ["UNVALIDATED","VALIDATED","FALSE_POSITIVE",""]},
            }
        }
    },
}


# ─────────────────────────────────────────
# Deep Validator
# ─────────────────────────────────────────

def _validate_deep(data, schema, path, result, max_items=5):
    """Recursive deep validator against a schema node."""
    expected_type = schema.get("_type")

    # Type check — handle tuple of types (e.g. int or float)
    if expected_type is not None:
        if isinstance(expected_type, tuple):
            types = expected_type
        else:
            types = (expected_type,) if not isinstance(expected_type, tuple) else expected_type

        if not isinstance(data, types):
            got = type(data).__name__
            exp = " or ".join(t.__name__ for t in types)
            result.add_error(path, f"expected {exp}, got {got}")
            return
        result.checked += 1

    # Non-empty check
    if schema.get("_non_empty"):
        _check_non_empty(data, path, result)

    # Range check for numbers
    if isinstance(data, (int, float)):
        if "_min" in schema:
            _check_range(data, schema["_min"], None, path, result)
        if "_max" in schema:
            _check_range(data, None, schema["_max"], path, result)

    # Allowed values
    if "_allowed" in schema and data is not None:
        allowed = schema["_allowed"]
        if allowed and data not in allowed:
            result.add_error(path, f"{data!r} not in allowed values: {allowed}")

    # Dict-specific: check required keys and recurse into fields
    if isinstance(data, dict):
        for key in schema.get("_required_keys", []):
            if key not in data:
                result.add_error(path, f"missing required key '{key}'")

        fields = schema.get("_fields", {})
        for field_name, field_schema in fields.items():
            if field_name not in data:
                if field_schema.get("_required", False):
                    result.add_error(f"{path}.{field_name}", "required field missing")
                continue
            _validate_deep(data[field_name], field_schema,
                          f"{path}.{field_name}", result, max_items)

        # Per-value validation for dicts of unknown keys
        each_val_schema = schema.get("_each_value")
        if each_val_schema:
            for i, (k, v) in enumerate(list(data.items())[:max_items]):
                _validate_deep(v, each_val_schema, f"{path}[{k!r}]", result, max_items)

    # List-specific: recurse into items
    elif isinstance(data, list):
        each_schema = schema.get("_each_item")
        if each_schema:
            for i, item in enumerate(data[:max_items]):
                _validate_deep(item, each_schema, f"{path}[{i}]", result, max_items)


def validate_stage_output(schema_name: str, data,
                          warn_only: bool = True,
                          verbose: bool = False) -> ValidationResult:
    """
    Deep validate stage output data against its schema.

    Args:
        schema_name: key into DEEP_SCHEMAS
        data:        loaded JSON data
        warn_only:   log warnings but don't raise exceptions
        verbose:     print validation result to console

    Returns:
        ValidationResult with .valid, .errors, .warnings
    """
    result = ValidationResult(schema_name)
    schema = DEEP_SCHEMAS.get(schema_name)

    if not schema:
        result.add_warning("schema", f"no schema defined for {schema_name!r} — skipped")
        return result

    _validate_deep(data, schema, schema_name, result)
    result.report(verbose=verbose)
    return result


def validate_file(schema_name: str, filepath: str,
                  warn_only: bool = True,
                  verbose: bool = False) -> ValidationResult:
    """
    Load a JSON file and deep-validate it.
    Returns ValidationResult with full error list.
    """
    result = ValidationResult(schema_name)

    if not os.path.exists(filepath):
        result.add_warning("file", f"{filepath} does not exist — skipped")
        return result

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as ex:
        result.add_error("json_parse", f"JSON parse error in {filepath}: {ex}")
        result.report(verbose=True)
        return result
    except Exception as ex:
        result.add_error("file_read", f"could not read {filepath}: {ex}")
        return result

    return validate_stage_output(schema_name, data,
                                  warn_only=warn_only, verbose=verbose)
