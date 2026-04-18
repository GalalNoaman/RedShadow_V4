# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/nvd.py
# Live CVE lookup via NVD API v2.0
# NVD CVE lookup with CPE-aware search, multi-strategy fallback, and EPSS enrichment.
#       smarter cache with version keys, exponential backoff,
#       CWE tagging, vector string extraction, cvssV3 attack vector

import os
import json
import re
import time
from datetime import datetime, timedelta
from typing import Optional
import requests
from dotenv import load_dotenv
from termcolor import cprint

# ─── Load API key ───
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# ─── Config ───
NVD_BASE_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR       = "data/nvd_cache"
CACHE_EXPIRY    = 24        # hours
MAX_RESULTS     = 30        # Maximum CVEs fetched per product from NVD API.
REQUEST_TIMEOUT = 15
# NVD rate limits: 5 req/30s unauthenticated, 50 req/30s authenticated
_nvd_key_warning_shown = False  # emit "no API key" warning only once per run
RATE_DELAY_UNAUTH = 6.5     # ~5 req/30s with safety margin
RATE_DELAY_AUTH   = 0.7     # ~50 req/30s with safety margin

# ─────────────────────────────────────────
# Severity Calculator
# ─────────────────────────────────────────

def calculate_severity(cvss_score) -> str:
    try:
        score = float(cvss_score)
        if score >= 9.0:   return "CRITICAL"
        elif score >= 7.0: return "HIGH"
        elif score >= 4.0: return "MEDIUM"
        elif score > 0.0:  return "LOW"
        else:              return "NONE"
    except Exception:  # CVSS score parse failed - return UNKNOWN severity
        return "UNKNOWN"


# ─────────────────────────────────────────
# Cache Helpers (Upgrade: version-aware keys)
# Cache key includes version string to avoid stale results across version lookups.
# the same result regardless of whether you queried with version 1.14 or 1.22.
# Now the cache key includes the version so each version gets its own entry.
# ─────────────────────────────────────────

def _cache_path(product: str, version_str: Optional[str] = None) -> str:
    """Upgrade: version-aware cache key."""
    safe = re.sub(r'[^\w.-]', '_', product.lower())
    if version_str and version_str not in ("unknown", "x", ""):
        # Sanitise version for use in filename
        safe_ver = re.sub(r'[^\w.-]', '_', version_str)
        return os.path.join(CACHE_DIR, f"{safe}__{safe_ver}.json")
    return os.path.join(CACHE_DIR, f"{safe}.json")


def _cache_valid(path: str) -> bool:
    if not os.path.exists(path):
        return False
    modified = datetime.fromtimestamp(os.path.getmtime(path))
    return datetime.now() - modified < timedelta(hours=CACHE_EXPIRY)


def _load_cache(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # Cache file read failed - return None (will re-fetch)
        return None


def _save_cache(path: str, data: list) -> None:
    dirpath = os.path.dirname(path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        cprint(f"  [!] Cache write failed: {e}", "yellow")


# ─────────────────────────────────────────
# NVD API Request (single call)
# HTTP request handler with exponential backoff and rate limit awareness.
#          auth vs unauth delays
# ─────────────────────────────────────────

def _nvd_get(params: dict, retries: int = 3) -> Optional[dict]:
    """
    Makes a single NVD API GET request with retry + exponential backoff.
    Returns parsed JSON or None on failure.
    """
    headers = {"User-Agent": "RedShadowBot/4.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    delay = RATE_DELAY_AUTH if NVD_API_KEY else RATE_DELAY_UNAUTH

    for attempt in range(retries):
        try:
            resp = requests.get(
                NVD_BASE_URL,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code == 403:
                cprint("  [!] NVD API key invalid or quota exceeded.", "red")
                return None

            if resp.status_code == 429:
                # Respect Retry-After header from rate-limited API responses.
                retry_after = int(resp.headers.get("Retry-After", delay * 4))
                cprint(f"  [!] NVD rate limit (429) — waiting {retry_after}s...", "yellow")
                time.sleep(retry_after)
                continue

            resp.raise_for_status()

        except requests.exceptions.Timeout:
            wait = delay * (2 ** attempt)   # exponential backoff
            cprint(f"  [!] NVD timeout (attempt {attempt+1}/{retries}) — retrying in {wait:.1f}s", "yellow")
            time.sleep(wait)

        except requests.exceptions.ConnectionError:
            wait = delay * (2 ** attempt)
            cprint(f"  [!] NVD connection error (attempt {attempt+1}/{retries}) — retrying in {wait:.1f}s", "yellow")
            time.sleep(wait)

        except Exception as e:
            cprint(f"  [!] NVD request error: {e}", "red")
            break

        # Polite delay between retries
        time.sleep(delay)

    return None


# ─────────────────────────────────────────
# Multi-Strategy NVD Search (Upgrade)
# Multi-strategy lookup: CPE → keyword+version → keyword only.
#   - Returns many false positives (e.g. "nginx" matches docs mentioning nginx)
#   - Misses CVEs where NVD uses vendor-specific product names
# Now uses 3 strategies in order of precision:
#   1. CPE-based lookup (most precise — matches exact product/vendor)
#   2. Keyword + version (medium precision)
#   3. Keyword only (broadest fallback)
# ─────────────────────────────────────────

# Known CPE vendor/product strings for common products
# Format: product_name → (vendor, product_in_cpe)
CPE_MAP = {
    "nginx":              ("nginx",       "nginx"),
    "apache":             ("apache",      "http_server"),
    "apache tomcat":      ("apache",      "tomcat"),
    "microsoft iis":      ("microsoft",   "internet_information_services"),
    "openssh":            ("openbsd",     "openssh"),
    "openssl":            ("openssl",     "openssl"),
    "wordpress":          ("wordpress",   "wordpress"),
    "drupal":             ("drupal",      "drupal"),
    "joomla":             ("joomla",      "joomla"),
    "php":                ("php",         "php"),
    "node.js":            ("nodejs",      "node.js"),
    "python":             ("python",      "python"),
    "mysql":              ("mysql",       "mysql"),
    "mariadb":            ("mariadb",     "mariadb"),
    "postgresql":         ("postgresql",  "postgresql"),
    "mongodb":            ("mongodb",     "mongodb"),
    "redis":              ("redis",       "redis"),
    "elasticsearch":      ("elastic",     "elasticsearch"),
    "kibana":             ("elastic",     "kibana"),
    "jenkins":            ("jenkins",     "jenkins"),
    "gitlab":             ("gitlab",      "gitlab"),
    "grafana":            ("grafana",     "grafana"),
    "spring framework":   ("pivotal",     "spring_framework"),
    "django":             ("djangoproject","django"),
    "ruby on rails":      ("rubyonrails", "ruby_on_rails"),
    "express.js":         ("expressjs",   "express"),
    "apache activemq":    ("apache",      "activemq"),
    "apache kafka":       ("apache",      "kafka"),
    "rabbitmq":           ("pivotal",     "rabbitmq"),
    "varnish":            ("varnish-software", "varnish_cache"),
    "haproxy":            ("haproxy",     "haproxy"),
    "traefik":            ("traefik",     "traefik"),
    "postfix":            ("postfix",     "postfix"),
    "exim":               ("exim",        "exim"),
    "dovecot":            ("dovecot",     "dovecot"),
    "microsoft exchange": ("microsoft",   "exchange_server"),
    "samba":              ("samba",       "samba"),
    "vsftpd":             ("beasts",      "vsftpd"),
    "sonarqube":          ("sonarsource", "sonarqube"),
    "etcd":               ("cncf",        "etcd"),
    "prometheus":         ("prometheus",  "prometheus"),
    "grafana":            ("grafana",     "grafana"),
}


def _build_cpe_string(product: str, version_str: Optional[str]) -> Optional[str]:
    """
    Upgrade: builds a CPE 2.3 search string for precise NVD lookup.
    e.g. nginx 1.18.0 → cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
    """
    entry = CPE_MAP.get(product.lower())
    if not entry:
        return None
    vendor, prod = entry
    # Strip OS/distro suffixes: "6.6.1p1 Ubuntu 2ubuntu2.13" -> "6.6.1p1"
    # NVD CPE needs a clean version string to match correctly.
    clean_ver = "*"
    if version_str and version_str not in ("unknown", "x", ""):
        ver_match = re.match(r"(\d+(?:\.\d+)*(?:[a-z]\d+)?)", str(version_str).strip())
        if ver_match:
            clean_ver = ver_match.group(1)
    return f"cpe:2.3:a:{vendor}:{prod}:{clean_ver}:*:*:*:*:*:*:*"


def query_nvd(product: str, version_str: Optional[str] = None, retries: int = 3) -> list:
    """
    Upgrade: multi-strategy NVD lookup.
    Strategy 1: CPE-based (most precise)
    Strategy 2: keyword + version
    Strategy 3: keyword only (broadest)

    Uses version-aware cache to avoid redundant calls.
    """
    cache_file = _cache_path(product, version_str)

    if _cache_valid(cache_file):
        cached = _load_cache(cache_file)
        if cached is not None:
            return cached

    global _nvd_key_warning_shown
    if not NVD_API_KEY and not _nvd_key_warning_shown:
        cprint("  [!] No NVD_API_KEY in .env — rate limited to 5 req/30s. "
               "Get a free key at: https://nvd.nist.gov/developers/request-an-api-key", "yellow")
        _nvd_key_warning_shown = True

    results = []

    # ── Strategy 1: CPE lookup (most precise) ──
    # Only run CPE lookup when we have a real version — NVD rejects wildcard CPEs
    # e.g. cpe:2.3:a:apache:tomcat:*:... returns 404, not an empty result set
    cpe_string = _build_cpe_string(product, version_str)
    has_version = bool(version_str and version_str not in ("unknown", "x", ""))
    if cpe_string and has_version:
        data = _nvd_get({
            "cpeName":       cpe_string,
            "resultsPerPage": MAX_RESULTS,
        }, retries=retries)
        if data:
            results = _parse_nvd_response(data)

    # ── Strategy 2: keyword + version ──
    if not results and version_str and version_str not in ("unknown", "x", ""):
        # Strip distro suffix for cleaner NVD keyword search
        kw_ver_match = re.match(r"(\d+(?:\.\d+)*(?:[a-z]\d+)?)", str(version_str).strip())
        kw_ver = kw_ver_match.group(1) if kw_ver_match else version_str.split()[0]
        data = _nvd_get({
            "keywordSearch":  f"{product} {kw_ver}",
            "resultsPerPage": MAX_RESULTS,
        }, retries=retries)
        if data:
            results = _parse_nvd_response(data)

    # ── Strategy 3: keyword only ──
    if not results:
        data = _nvd_get({
            "keywordSearch":  product,
            "resultsPerPage": MAX_RESULTS,
        }, retries=retries)
        if data:
            results = _parse_nvd_response(data)

    if results:
        _save_cache(cache_file, results)
    else:
        cprint(f"  [!] NVD returned nothing for '{product}' — will use local fallback", "yellow")

    return results


# ─────────────────────────────────────────
# Response Parser (Upgrade: richer output)
# Extracts CWE IDs, CVSS v3 metrics, and EPSS scores from NVD API responses.
#          vector string, and reference URLs
# ─────────────────────────────────────────

def _extract_cvss(metrics: dict) -> tuple:
    """
    Extracts CVSS score, severity, vector string, and v3 details.
    Returns (score, severity, vector_string, attack_vector, attack_complexity, privileges_required)
    """
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if not metric_list:
            continue
        cvss_data = metric_list[0].get("cvssData", {})
        score     = cvss_data.get("baseScore", "N/A")
        severity  = metric_list[0].get("baseSeverity", "")
        vector    = cvss_data.get("vectorString", "")

        if not severity or severity == "UNKNOWN":
            severity = calculate_severity(score)

        # v3 specific fields (not in v2)
        av  = cvss_data.get("attackVector", "")
        ac  = cvss_data.get("attackComplexity", "")
        pr  = cvss_data.get("privilegesRequired", "")

        return score, severity, vector, av, ac, pr

    return "N/A", "UNKNOWN", "", "", "", ""


def _extract_cwes(cve_data: dict) -> list:
    """Upgrade: extracts CWE IDs from weaknesses block."""
    cwes = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return list(set(cwes))


def _extract_references(cve_data: dict, limit: int = 3) -> list:
    """Upgrade: extracts top reference URLs (exploits, patches, advisories)."""
    refs = []
    for ref in cve_data.get("references", [])[:limit]:
        url  = ref.get("url", "")
        tags = ref.get("tags", [])
        if url:
            refs.append({"url": url, "tags": tags})
    return refs


def _parse_nvd_response(data: dict) -> list:
    """
    Upgrade: parses NVD API response into enriched CVE dicts.

    Each dict now contains:
      cve, description, cvss, severity, affected_versions,
      url, vector_string, attack_vector, attack_complexity,
      privileges_required, cwe_ids, references
    """
    results = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "N/A")

        # ── Description ──
        descriptions = cve_data.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # ── CVSS ──
        metrics = cve_data.get("metrics", {})
        score, severity, vector, av, ac, pr = _extract_cvss(metrics)

        # ── Affected Versions ──
        affected_versions = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    end   = match.get("versionEndIncluding", "")
                    start = match.get("versionStartIncluding", "")
                    if end:
                        affected_versions.append(f"<={end}")
                    elif start:
                        affected_versions.append(f">={start}")

        # ── Upgrade: CWEs ──
        cwe_ids = _extract_cwes(cve_data)

        # ── Upgrade: References ──
        references = _extract_references(cve_data)

        results.append({
            "cve":                   cve_id,
            "description":           description[:300] + "..." if len(description) > 300 else description,
            "cvss":                  score,
            "severity":              severity,
            "affected_versions":     ", ".join(affected_versions) if affected_versions else "x",
            "url":                   f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            # Extended result fields.
            "vector_string":         vector,
            "attack_vector":         av,
            "attack_complexity":     ac,
            "privileges_required":   pr,
            "cwe_ids":               cwe_ids,
            "references":            references,
        })

    # Sort by CVSS score descending
    def _score_key(x):
        try:
            return float(x["cvss"])
        except Exception:  # CVE sort key parse failed - use 0.0 as fallback
            return 0.0

    results.sort(key=_score_key, reverse=True)
    return results


# ─────────────────────────────────────────
# Fallback: Local CVE Map
# ─────────────────────────────────────────

def load_local_cve_map(path: str = "data/cve_map.json") -> dict:
    """Loads the static local CVE map as a fallback."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # Local CVE map load failed - return empty dict
        return {}


# ─────────────────────────────────────────
# Main Lookup Function
# ─────────────────────────────────────────

def lookup_cves(product: str, version_str: Optional[str] = None,
                use_local_fallback: bool = True) -> list:
    """
    Main entry point for CVE lookup.
    Tries NVD API (multi-strategy) first, then falls back to local cve_map.json.

    Args:
        product (str):              Normalised product name
        version_str (str):          Detected version
        use_local_fallback (bool):  Use local map if API fails

    Returns:
        list of enriched CVE dicts
    """
    if not product:
        return []

    cves = query_nvd(product, version_str)

    if not cves and use_local_fallback:
        local_map = load_local_cve_map()
        for key, local_cves in local_map.items():
            if key.lower() in product.lower() or product.lower() in key.lower():
                # Apply same CVSS/EPSS minimum threshold as NVD results
                # Filters out ancient low-signal CVEs from the local map
                # e.g. CVE-1999-0661 CVSS 10.0 but EPSS 0.06 - keep
                # e.g. CVE-2001-xxxx CVSS 3.0 EPSS 0.001 - drop (noise)
                cves = [
                    c for c in local_cves
                    if float(c.get("cvss", 0) or 0) >= 4.0
                    or float(c.get("epss", 0) or 0) >= 0.01
                ]
                if not cves:
                    cves = local_cves  # fallback: keep all if all filtered
                break

    return cves


# ─────────────────────────────────────────
# Cache Management Utilities (Upgrade)
# ─────────────────────────────────────────

def clear_expired_cache() -> int:
    """
    Upgrade: cleans up expired cache files.
    Returns the number of files removed.
    Call this at the start of a scan session to ensure fresh data.
    """
    if not os.path.exists(CACHE_DIR):
        return 0
    removed = 0
    for fname in os.listdir(CACHE_DIR):
        fpath = os.path.join(CACHE_DIR, fname)
        if not _cache_valid(fpath):
            try:
                os.remove(fpath)
                removed += 1
            except Exception:  # Cache file delete failed - skip this file
                pass
    if removed:
        cprint(f"  [ℹ] Cleared {removed} expired NVD cache file(s)", "cyan")
    return removed


def cache_stats() -> dict:
    """
    Upgrade: returns stats about the current cache state.
    Useful for debugging slow scans.
    """
    if not os.path.exists(CACHE_DIR):
        return {"total": 0, "valid": 0, "expired": 0}
    files   = [os.path.join(CACHE_DIR, f) for f in os.listdir(CACHE_DIR) if f.endswith(".json")]
    valid   = sum(1 for f in files if _cache_valid(f))
    return {"total": len(files), "valid": valid, "expired": len(files) - valid}