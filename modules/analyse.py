# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/analyse.py

#   - Expanded product normalization (50+ mappings)
#   - Version-aware CVE filtering (semver comparison)
#   - Risk scoring per target (weighted CVSS aggregate)
#   - EPSS score enrichment (exploit probability from first.org)
#   - Attack surface tagging (RCE / Auth Bypass / SQLi / etc.)
#   - Critical-only fast-path summary
#   - Consistent makedirs fix

import json
import os
import re
import time
import requests
from termcolor import cprint
from modules.utils import load_config
from modules.nvd import lookup_cves
from modules.matchers import normalize_version, version_is_relevant, extract_version_from_response

config   = load_config(section="analyse")
cve_path = config.get("cve_source", "data/cve_map.json")

# EPSS API — returns exploit probability score (0.0–1.0) per CVE
EPSS_API = "https://api.first.org/data/v1/epss"

# Risk score weights
CVSS_WEIGHT  = 0.6
EPSS_WEIGHT  = 0.4
EPSS_SCALE   = 10.0   # EPSS is 0–1, scale to 0–10 to match CVSS

# ─────────────────────────────────────────
# Product Normalisation (Expanded)
# Comprehensive product name mappings covering common Nmap service/product strings.
# ─────────────────────────────────────────

PRODUCT_MAPPINGS = {
    # ── Web Servers ──
    "nginx":                            "nginx",
    "nginx http server":                "nginx",
    "apache":                           "apache",
    "apache httpd":                     "apache",
    "apache http server":               "apache",
    "apache tomcat":                    "apache tomcat",
    "tomcat":                           "apache tomcat",
    "iis":                              "microsoft iis",
    "microsoft iis":                    "microsoft iis",
    "microsoft iis httpd":              "microsoft iis",
    "microsoft iis http server":        "microsoft iis",
    "lighttpd":                         "lighttpd",
    "caddy":                            "caddy",
    "gunicorn":                         "gunicorn",
    "uvicorn":                          "uvicorn",
    "jetty":                            "eclipse jetty",
    "eclipse jetty":                    "eclipse jetty",
    "jboss":                            "jboss",
    "wildfly":                          "wildfly",

    # ── CDN / Proxy ──
    "cloudfront":                       "cloudfront",
    "amazon cloudfront":                "cloudfront",
    "amazon cloudfront httpd":          "cloudfront",
    "cloudflare":                       "cloudflare",
    "cloudflare http proxy":            "cloudflare",
    "akamaighost":                      "akamai",
    "akamai ghost":                     "akamai",
    "akamai":                           "akamai",
    "fastly":                           "fastly",
    "varnish":                          "varnish",
    "varnish cache":                    "varnish",
    "squid":                            "squid",
    "envoy":                            "envoy",
    "haproxy":                          "haproxy",
    "traefik":                          "traefik",
    "cloudinary":                       "cloudinary",

    # ── TLS / Crypto ──
    "openssl":                          "openssl",
    "openssh":                          "openssh",
    "openssh server":                   "openssh",
    "libssl":                           "openssl",

    # ── CMS ──
    "wordpress":                        "wordpress",
    "drupal":                           "drupal",
    "joomla":                           "joomla",
    "magento":                          "magento",
    "typo3":                            "typo3",
    "strapi":                           "strapi",

    # ── Databases ──
    "mysql":                            "mysql",
    "mysql community server":           "mysql",
    "mariadb":                          "mariadb",
    "postgresql":                       "postgresql",
    "mongodb":                          "mongodb",
    "redis":                            "redis",
    "elasticsearch":                    "elasticsearch",
    "elastic":                          "elasticsearch",
    "cassandra":                        "cassandra",
    "couchdb":                          "couchdb",
    "memcached":                        "memcached",
    "influxdb":                         "influxdb",

    # ── Message Queues ──
    "rabbitmq":                         "rabbitmq",
    "kafka":                            "apache kafka",
    "activemq":                         "apache activemq",

    # ── Monitoring / Observability ──
    "grafana":                          "grafana",
    "kibana":                           "kibana",
    "prometheus":                       "prometheus",
    "zabbix":                           "zabbix",
    "nagios":                           "nagios",
    "splunk":                           "splunk",
    "datadog":                          "datadog",

    # ── CI/CD ──
    "jenkins":                          "jenkins",
    "gitlab":                           "gitlab",
    "gitea":                            "gitea",
    "nexus":                            "sonatype nexus",
    "artifactory":                      "jfrog artifactory",
    "sonarqube":                        "sonarqube",

    # ── Cloud / Container ──
    "kubernetes":                       "kubernetes",
    "k8s":                              "kubernetes",
    "docker":                           "docker",
    "etcd":                             "etcd",

    # ── Mail ──
    "postfix":                          "postfix",
    "sendmail":                         "sendmail",
    "exim":                             "exim",
    "dovecot":                          "dovecot",
    "microsoft exchange":               "microsoft exchange",
    "exchange":                         "microsoft exchange",

    # ── Languages / Runtimes ──
    "php":                              "php",
    "node.js":                          "node.js",
    "nodejs":                           "node.js",
    "python":                           "python",
    "ruby":                             "ruby",
    "java":                             "java",
    "spring":                           "spring framework",
    "spring framework":                 "spring framework",
    "django":                           "django",
    "flask":                            "flask",
    "rails":                            "ruby on rails",
    "ruby on rails":                    "ruby on rails",
    "express":                          "express.js",

    # ── OS / Network ──
    "openssh sftp":                     "openssh",
    "vsftpd":                           "vsftpd",
    "proftpd":                          "proftpd",
    "samba":                            "samba",
    "bind":                             "bind dns",
    "unbound":                          "unbound dns",
}


def normalize_product_name(product):
    """
    Normalises a raw Nmap product string to a canonical lookup name.
    Upgrade: 50+ mappings vs original 15.
    """
    if not product:
        return ""
    cleaned = product.strip().lower()
    # Strip version numbers from product string before lookup
    cleaned = re.sub(r'\s+[\d.]+.*$', '', cleaned).strip()
    # Strip common suffixes that Nmap appends
    for suffix in ("httpd", "server", "daemon", "service"):
        cleaned = cleaned.replace(suffix, "").strip()
    cleaned = cleaned.replace("-", " ").replace("_", " ").strip()
    return PRODUCT_MAPPINGS.get(cleaned, cleaned) if cleaned else ""


# ─────────────────────────────────────────
# Version-aware CVE Filtering (Upgrade)
# Filters CVEs by detected version range when available.
# ─────────────────────────────────────────

def _parse_version(version_str):
    """Extracts leading numeric version tuple from a string. e.g. '1.18.0' → (1,18,0)"""
    match = re.match(r'(\d+)(?:\.(\d+))?(?:\.(\d+))?', str(version_str or ""))
    if not match:
        return None
    return tuple(int(x) for x in match.groups() if x is not None)


def _version_in_range(detected, affected_str):
    """
    Checks if detected version falls within an affected_versions range string.
    Supports: '<=1.18.0', '>=1.14.0', '1.16.1'
    Returns True if affected (i.e. keep the CVE), None if can't determine.
    """
    if not detected or not affected_str:
        return None

    det = _parse_version(detected)
    if not det:
        return None

    for part in affected_str.split(","):
        part = part.strip()
        if part.startswith("<="):
            bound = _parse_version(part[2:])
            if bound and det <= bound:
                return True
        elif part.startswith(">="):
            bound = _parse_version(part[2:])
            if bound and det >= bound:
                return True
        else:
            bound = _parse_version(part)
            if bound and det == bound:
                return True

    return False


def filter_cves_by_version(cves, version_str):
    """
    Filters CVE list using matchers.version_is_relevant() for precise range checking.

    Three-stage filter:
    1. Version relevance — uses matchers.version_is_relevant() which returns
       CONFIRMED / POSSIBLE / UNLIKELY / UNKNOWN.
       Drops CVEs where relevance is UNLIKELY (clearly outside affected range).
    2. Minimum quality threshold — drops CVSS < 4.0 AND EPSS < 0.01 (noise).
    3. Attaches version_relevance field to each CVE for use in reporting.

    Never returns an empty list — falls back to top 10 by CVSS.
    Always sorted by combined EPSS×CVSS score descending.
    """
    if not version_str or version_str in ("unknown", "x", ""):
        working = cves
    else:
        working = []
        for cve in cves:
            affected  = cve.get("affected_versions", "")
            relevance = version_is_relevant(version_str, affected)
            if relevance != "UNLIKELY":
                cve["version_relevance"] = relevance
                working.append(cve)

    if not working:
        working = cves   # fallback: nothing confirmed, keep all

    # Minimum quality threshold
    relevant = [
        c for c in working
        if float(c.get("cvss", 0) or 0) >= 4.0 or float(c.get("epss", 0) or 0) >= 0.01
    ]
    if not relevant:
        relevant = sorted(working,
                          key=lambda c: float(c.get("cvss", 0) or 0),
                          reverse=True)[:10]

    # Sort by combined risk score
    relevant.sort(
        key=lambda c: float(c.get("cvss", 0) or 0) * 0.6 + float(c.get("epss", 0) or 0) * 10 * 0.4,
        reverse=True
    )
    return relevant


# ─────────────────────────────────────────
# EPSS Enrichment (Upgrade)
# EPSS = Exploit Prediction Scoring System
# Returns probability (0.0–1.0) that a CVE will be exploited in the wild.
# High EPSS + high CVSS = prioritise immediately.
# ─────────────────────────────────────────

def fetch_epss_scores(cve_ids):
    """
    Upgrade: fetches EPSS scores from first.org for a list of CVE IDs.
    Returns dict {cve_id: epss_score}.
    Gracefully returns empty dict if API is unreachable.
    """
    if not cve_ids:
        return {}

    scores = {}
    # API accepts up to 100 CVE IDs per request
    chunk_size = 100
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i + chunk_size]
        try:
            resp = requests.get(
                EPSS_API,
                params={"cve": ",".join(chunk)},
                timeout=10,
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    cve_id = item.get("cve", "")
                    epss   = float(item.get("epss", 0))
                    scores[cve_id] = round(epss, 4)
        except Exception as ex:
            cprint(f"  [!] EPSS API error (non-fatal): {ex}", "yellow")
        time.sleep(0.3)   # be polite to the API

    return scores


# ─────────────────────────────────────────
# Attack Surface Tagger (Upgrade)
# Tags each CVE with what kind of attack it enables.
# ─────────────────────────────────────────

ATTACK_TAGS = {
    "RCE":          ["remote code execution", "code execution", "arbitrary command", "execute arbitrary"],
    "Auth Bypass":  ["authentication bypass", "bypass authentication", "bypass auth", "unauthenticated"],
    "SQLi":         ["sql injection", "sql"],
    "XSS":          ["cross-site scripting", "xss"],
    "SSRF":         ["server-side request forgery", "ssrf"],
    "XXE":          ["xml external entity", "xxe"],
    "Path Trav":    ["path traversal", "directory traversal"],
    "DoS":          ["denial of service", "dos", "crash", "memory exhaustion"],
    "Priv Esc":     ["privilege escalation", "escalate privileges"],
    "Info Disc":    ["information disclosure", "sensitive information", "expose"],
    "IDOR":         ["insecure direct object", "idor"],
    "Deserial":     ["deserialization", "deserializ"],
}


def tag_attack_surface(description):
    """
    Upgrade: returns a list of attack surface tags from a CVE description.
    e.g. ["RCE", "Auth Bypass"]
    """
    desc_lower = description.lower()
    tags = []
    for tag, keywords in ATTACK_TAGS.items():
        if any(kw in desc_lower for kw in keywords):
            tags.append(tag)
    return tags


# ─────────────────────────────────────────
# CVE Precision Context
# Flags that add accuracy to CVE associations —
# identifying conditions required for exploitability
# that a plain version match cannot determine.
# Source: NVD, Ubuntu, Red Hat, vendor advisories.
# ─────────────────────────────────────────

# CVEs requiring non-default modules or specific configuration
_REQUIRES_COMPONENT = {
    "CVE-2011-2688": "mod_authnz_external module — not installed by default",
    "CVE-2017-3167": "third-party module using ap_get_basic_auth_pw() outside auth phase",
    "CVE-2017-7679": "mod_mime with malicious client-controlled Content-Type header",
    "CVE-2022-31813": "mod_proxy with specific RewriteRule/ProxyPassMatch configuration",
    "CVE-2023-25690": "mod_proxy with RewriteRule or ProxyPassMatch — not default",
}

# CVEs requiring ssh-agent forwarding to an attacker-controlled host
# NOT exploitable against a plain internet-facing SSH daemon on port 22
_FORWARDED_AGENT_ONLY = {
    "CVE-2023-38408": (
        "Requires ssh-agent forwarding to an attacker-controlled server. "
        "The attacker must control the SSH server the victim connects to. "
        "Not exploitable against a standard internet-facing SSH daemon."
    ),
    "CVE-2016-10009": (
        "Requires ssh-agent forwarding with attacker controlling the forwarded socket. "
        "Not exploitable against a plain SSH daemon on port 22."
    ),
}

# CVEs that are brute-force/auth-rate related, not direct RCE
_AUTH_RATE_ONLY = {
    "CVE-2015-5600": (
        "Allows bypassing MaxAuthTries limit via keyboard-interactive auth. "
        "Enables brute-force attacks, not direct code execution."
    ),
}

# Products where distro backporting is common —
# Ubuntu/Debian/RHEL patch without changing upstream version string
_BACKPORT_RISK_PRODUCTS = {"openssh", "apache", "nginx", "openssl", "php", "apache tomcat"}


def enrich_cve_context(cve: dict, product: str) -> dict:
    """
    Adds precision context flags to a CVE based on known exploitability conditions.
    Called after CVE filtering in the analysis loop.

    Fields added:
      requires_component (str)    — non-default module/feature required
      forwarded_agent_only (str)  — only via ssh-agent forwarding, not plain daemon
      auth_rate_only (str)        — brute-force/rate concern, not direct RCE
      backport_risk (bool)        — Ubuntu/Debian may have silently backported fix
    """
    cve_id       = cve.get("cve", "")
    norm_product = product.lower().strip()

    # Component requirement flag
    if cve_id in _REQUIRES_COMPONENT:
        cve["requires_component"] = _REQUIRES_COMPONENT[cve_id]

    # Forwarded-agent-only flag — downgrade RCE tag to be accurate
    if cve_id in _FORWARDED_AGENT_ONLY:
        cve["forwarded_agent_only"] = _FORWARDED_AGENT_ONLY[cve_id]
        # Replace generic "RCE" with context-specific tag
        if "RCE" in cve.get("attack_surface", []):
            cve["attack_surface"] = [
                t for t in cve["attack_surface"] if t != "RCE"
            ]
            cve["attack_surface"].append("RCE (agent-forwarding condition)")

    # Auth-rate-only flag — downgrade misleading RCE
    if cve_id in _AUTH_RATE_ONLY:
        cve["auth_rate_only"] = _AUTH_RATE_ONLY[cve_id]

    # Backport risk flag for distro-packaged products
    if norm_product in _BACKPORT_RISK_PRODUCTS:
        cve["backport_risk"] = True

    return cve


# ─────────────────────────────────────────
# Risk Score Calculator (Upgrade)
# Produces a weighted risk score per target based on CVSS + EPSS.
# ─────────────────────────────────────────

def calculate_target_risk(tech_matches, epss_scores):
    """
    Upgrade: calculates a composite risk score (0–10) for a target.
    Uses top-3 CVEs by CVSS × EPSS weight.
    """
    all_scores = []
    for match in tech_matches:
        for cve in match.get("cves", []):
            try:
                cvss      = float(cve.get("cvss", 0) or 0)
                epss      = float(epss_scores.get(cve.get("cve", ""), 0))
                composite = (cvss * CVSS_WEIGHT) + (epss * EPSS_SCALE * EPSS_WEIGHT)
                all_scores.append(min(composite, 10.0))
            except Exception as ex:
                cprint(f"  [!] Risk score calculation error for CVE: {ex}", "yellow")
                continue

    if not all_scores:
        return 0.0

    all_scores.sort(reverse=True)
    top3_avg = sum(all_scores[:3]) / min(len(all_scores), 3)
    return round(top3_avg, 2)


# ─────────────────────────────────────────
# CVE Deduplication
# ─────────────────────────────────────────

def deduplicate_cves(cve_list):
    """Removes duplicate CVEs by CVE ID, keeps first occurrence."""
    seen   = set()
    unique = []
    for cve in cve_list:
        cve_id = cve.get("cve", "")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique.append(cve)
    return unique


# ─────────────────────────────────────────
# Main Analysis Entry Point
# ─────────────────────────────────────────

def analyse_scan_results(input_file, output_file="outputs/analysis_results.json",
                         passive_file=None, probe_file=None):
    """
    Analyses Nmap scan results, looks up CVEs, enriches with EPSS,
    filters by version, tags attack surface, scores each target.

    Args:
        input_file  (str): Path to scan_results.json from scan.py
        output_file (str): Path to write analysis_results.json
        passive_file(str): Optional passive_results.json — enriches tech detection
                           with HTTP Server headers, X-Powered-By, HTML fingerprints
        probe_file  (str): Optional probe_results.json — enriches tech detection
                           with technology field from HTTP probing

    Fingerprint enrichment (reviewer request #5):
        When passive or probe data is provided, HTTP-detected technologies are
        merged with Nmap-detected ones. This catches services where Nmap returned
        a vague banner but HTTP responses reveal the actual product and version.
        HTTP-enriched detections are flagged with "source": "http_fingerprint"
        and assigned a version_confidence of "MEDIUM" (lower than Nmap's HIGH).
    """

    if not os.path.exists(input_file):
        cprint(f"[!] Input file not found: {input_file}", "red")
        return

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        data = raw.get("results", raw)
    except json.JSONDecodeError as error:
        cprint(f"[!] Analyse: failed to parse scan results JSON: {error}", "red")
        return
    except Exception as error:
        cprint(f"[!] Analyse: error reading input file: {error}", "red")
        return

    analysed = []

    # ── HTTP Fingerprint Enrichment (reviewer request #5) ──
    # Build an index of HTTP-detected technologies per host IP.
    # These supplement Nmap detections when banners are vague.
    http_tech_index = {}   # host_ip → {norm_product: version_or_empty}

    def _load_json_safe(path):
        if not path or not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, list) else []
        except Exception:  # HTTP fingerprint JSON parse failed - use empty list (enrichment is optional)
            return []

    # Extract from passive_results.json
    for entry in _load_json_safe(passive_file):
        ip = entry.get("ip", entry.get("hostname", ""))
        if not ip:
            continue
        # Server header
        headers = entry.get("headers", {})
        server  = headers.get("server", headers.get("Server", ""))
        xpb     = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
        for raw_tech in [server, xpb]:
            if not raw_tech:
                continue
            norm = normalize_product_name(raw_tech)
            if norm and len(norm) >= 3:
                # Try to extract version from server banner e.g. "Apache/2.4.7"
                import re as _re
                ver_match = _re.search(r'[/\s](\d+\.\d+[\.\d]*)', raw_tech)
                ver = ver_match.group(1) if ver_match else ""
                existing = http_tech_index.get(ip, {})
                # Only add if not already detected with a better version
                if norm not in existing or (ver and not existing[norm]):
                    existing[norm] = ver
                    http_tech_index[ip] = existing
        # tech_matches from passive detection
        for tm in entry.get("tech_matches", []):
            tech = tm.get("tech", "")
            norm = normalize_product_name(tech)
            if norm and len(norm) >= 3:
                existing = http_tech_index.get(ip, {})
                if norm not in existing:
                    existing[norm] = ""
                    http_tech_index[ip] = existing

        # Deep version extraction from response body + headers
        # This catches cases where Nmap gave a vague banner but
        # the HTTP response reveals the exact version
        stored_headers = entry.get("headers", {})
        stored_body    = entry.get("_body", "")  # not always present
        extracted = extract_version_from_response(stored_body, stored_headers)
        for norm_ex, ver_ex in extracted.items():
            existing = http_tech_index.get(ip, {})
            if norm_ex not in existing or (ver_ex and not existing[norm_ex]):
                existing[norm_ex] = ver_ex
                http_tech_index[ip] = existing

    # Extract from probe_results.json
    for entry in _load_json_safe(probe_file):
        # probe output has "technology" dict e.g. {"Server": "Apache/2.4.7"}
        ip = entry.get("ip", "")
        if not ip:
            from urllib.parse import urlparse as _up
            try:
                ip = _up(entry.get("url", "")).hostname or ""
            except Exception:  # HTTP tech enrichment URL parse failed - skip this entry
                ip = ""
        tech_dict = entry.get("technology", {})
        for _label, raw_val in tech_dict.items():
            if not raw_val:
                continue
            norm = normalize_product_name(raw_val)
            if norm and len(norm) >= 3:
                import re as _re
                ver_match = _re.search(r'[/\s](\d+\.\d+[\.\d]*)', raw_val)
                ver = ver_match.group(1) if ver_match else ""
                existing = http_tech_index.get(ip, {})
                if norm not in existing or (ver and not existing[norm]):
                    existing[norm] = ver
                    http_tech_index[ip] = existing

    if http_tech_index:
        cprint(f"  [+] HTTP fingerprint enrichment: {sum(len(v) for v in http_tech_index.values())} "
               f"additional tech signals across {len(http_tech_index)} host(s)", "cyan")

    for domain, info in data.items():
        if not isinstance(info, dict):
            continue

        protocols = info.get("protocols", {})
        if not isinstance(protocols, dict):
            continue

        # ── Collect unique technologies across all ports ──
        tech_seen    = {}   # norm_name → set of ports
        tech_version = {}   # norm_name → version string

        for proto, ports in protocols.items():
            if not isinstance(ports, dict):
                continue
            for port, port_data in ports.items():
                if not isinstance(port_data, dict):
                    continue

                product  = port_data.get("product", "")
                version  = port_data.get("version", "")
                norm     = normalize_product_name(product)

                if not norm:
                    continue

                if norm not in tech_seen:
                    tech_seen[norm]    = set()
                    tech_version[norm] = version

                tech_seen[norm].add(str(port))

        # ── Merge HTTP fingerprint data for this host ──
        # Look up this host's IP in the HTTP fingerprint index and merge
        # any technologies not already detected by Nmap.
        host_ip    = info.get("ip", domain)
        http_techs = http_tech_index.get(host_ip, {})

        for http_raw_norm, http_ver in http_techs.items():
            # Re-normalise the key to catch cases where the enrichment loop
            # stored a partially-normalised string (e.g. "apache/2.4.7 (ubuntu)")
            http_norm = normalize_product_name(http_raw_norm)
            if not http_norm or len(http_norm) < 3:
                continue
            # Skip if the normalised key contains slashes or parens
            # (indicates a failed normalisation — raw string leaked through)
            if "/" in http_norm or "(" in http_norm:
                continue

            if http_norm not in tech_seen:
                tech_seen[http_norm]    = set(["http"])
                tech_version[http_norm] = http_ver
                cprint(f"  [+] HTTP enrichment: added {http_norm!r} "
                       f"(version: {http_ver or 'unknown'}) for {host_ip}", "cyan")
            elif not tech_version.get(http_norm) and http_ver:
                # Nmap detected the product but no version — HTTP has one
                tech_version[http_norm] = http_ver
                cprint(f"  [+] HTTP version enrichment: {http_norm!r} → {http_ver} for {host_ip}", "cyan")

        if not tech_seen:
            continue

        # ── CVE lookup + version filtering per technology ──
        tech_matches    = []
        all_cve_ids_here = []

        for norm_name, ports in tech_seen.items():
            version_str = tech_version.get(norm_name, "")
            cprint(f"  [→] CVE lookup: {norm_name} {version_str or 'x'}", "cyan")

            raw_cves = lookup_cves(norm_name, version_str)
            deduped  = deduplicate_cves(raw_cves)
            filtered = filter_cves_by_version(deduped, version_str)

            # Apply configurable CVE cap — prevents one service flooding the report
            # Reads cve_quality.max_per_service from config (default: 15)
            _cve_cfg  = config.get("max_results", 30)
            max_shown = load_config(section="cve_quality").get("max_per_service", 15)
            if len(filtered) > max_shown:
                # Keep the highest-priority CVEs only
                filtered = sorted(
                    filtered,
                    key=lambda c: (
                        float(c.get("cvss", 0) or 0) * 0.6 +
                        float(c.get("epss", 0) or 0) * 10 * 0.4
                    ),
                    reverse=True
                )[:max_shown]
                cprint(f"  [ℹ] CVE cap applied: showing top {max_shown} of {len(deduped)} "
                       f"for {norm_name} (set cve_quality.max_per_service in config to change)",
                       "cyan")

            if filtered:
                # Enrich each CVE with precision context flags
                enriched = [enrich_cve_context(c, norm_name) for c in filtered]
                all_cve_ids_here.extend(c.get("cve", "") for c in enriched)
                tech_matches.append({
                    "tech":    norm_name,
                    "version": version_str or "unknown",
                    "ports":   sorted(ports),
                    "cves":    enriched,
                })

        if not tech_matches:
            continue

        # ── Upgrade: EPSS enrichment ──
        cve_ids     = [c for c in all_cve_ids_here if c]
        epss_scores = fetch_epss_scores(cve_ids)

        # ── Upgrade: attach EPSS + attack tags to each CVE ──
        for match in tech_matches:
            enriched = []
            for cve in match["cves"]:
                cve_id                = cve.get("cve", "")
                cve["epss"]           = epss_scores.get(cve_id, None)
                cve["attack_surface"] = tag_attack_surface(cve.get("description", ""))
                enriched.append(cve)
            match["cves"] = enriched

        # ── Upgrade: risk score per target ──
        risk_score = calculate_target_risk(tech_matches, epss_scores)

        # ── Sort tech matches by highest CVSS in each ──
        tech_matches.sort(
            key=lambda m: max(
                (float(c.get("cvss", 0) or 0) for c in m["cves"]),
                default=0
            ),
            reverse=True
        )

        analysed.append({
            "url":          domain,
            "ip":           info.get("ip", "N/A"),
            "hostname":     info.get("hostname", "N/A"),
            "risk_score":   risk_score,
            "tech_matches": tech_matches,
        })

    # ── Sort targets by risk score descending ──
    analysed.sort(key=lambda x: x["risk_score"], reverse=True)

    # ── Summary output ──
    if not analysed:
        cprint("[!] No vulnerable technologies detected.", "yellow")
    else:
        # Aggregate statistics for reporting.
        total_cves    = sum(len(m["cves"]) for e in analysed for m in e["tech_matches"])
        critical_cves = sum(
            1 for e in analysed for m in e["tech_matches"]
            for c in m["cves"] if str(c.get("cvss", 0)) >= "9"
        )
        rce_count     = sum(
            1 for e in analysed for m in e["tech_matches"]
            for c in m["cves"] if "RCE" in c.get("attack_surface", [])
        )

        cprint(f"\n{'='*60}", "red")
        cprint(f"  🔍 CVE ANALYSIS RESULTS", "red")
        cprint(f"{'='*60}", "red")
        cprint(f"  Targets with findings : {len(analysed)}", "white")
        cprint(f"  Total CVEs matched    : {total_cves}", "white")
        cprint(f"  Critical (CVSS ≥9)    : {critical_cves}", "red")
        cprint(f"  RCE CVEs              : {rce_count}", "red")
        cprint(f"{'='*60}\n", "red")

        for entry in analysed:
            risk_colour = "red" if entry["risk_score"] >= 7 else \
                          "yellow" if entry["risk_score"] >= 4 else "white"
            cprint(
                f"[→] {entry['url']} ({entry['ip']}) "
                f"— Risk Score: {entry['risk_score']}/10",
                risk_colour
            )
            for match in entry["tech_matches"]:
                ports_str = ", ".join(match["ports"])
                cprint(f"    [{match['tech']} {match['version']} — ports {ports_str}]", "white")
                for cve in match["cves"][:5]:
                    cve_id   = cve.get("cve", "N/A")
                    cvss     = cve.get("cvss", "?")
                    severity = cve.get("severity", "")
                    epss     = cve.get("epss")
                    tags     = cve.get("attack_surface", [])
                    epss_str = f" | EPSS: {epss:.3f}" if epss is not None else ""
                    tags_str = f" | {', '.join(tags)}" if tags else ""
                    colour   = "red" if str(cvss) >= "9" else "yellow"
                    cprint(
                        f"      - {cve_id} (CVSS: {cvss} | {severity}{epss_str}{tags_str})",
                        colour
                    )

    # ── Save ──
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            json.dump(analysed, out, indent=2)
        cprint(f"\n[✓] Analysis saved to {output_file}", "green")
    except Exception as error:
        cprint(f"[!] Failed to write analysis output: {error}", "red")