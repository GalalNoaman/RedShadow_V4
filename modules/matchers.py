# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/matchers.py
# Precision helpers for product normalisation, version matching, and CVE confidence scoring.
#
# Replaces loose string matching like:
#   product.lower() in p["service"] or product.lower() in p["version"]
#
# With proper normalised matching:
#   service_matches_product(product, service, nmap_product)
#
# Used by: correlate.py, pipeline_ip.py, analyse.py
#
# Design:
#   - normalize_product_name()  — canonical product string for lookup
#   - normalize_version()       — structured version tuple for comparison
#   - service_matches_product() — true match check with alias table
#   - version_is_relevant()     — confidence-aware version match

import re


# ─────────────────────────────────────────
# Product Alias Map
# Maps all known Nmap service/product strings to canonical names.
# These are the same canonical names used in PRODUCT_MAPPINGS in analyse.py
# and in cve_map.json keys.
# ─────────────────────────────────────────

_PRODUCT_ALIASES = {
    # Web servers
    "apache":             "apache",
    "apache httpd":       "apache",
    "apache http server": "apache",
    "httpd":              "apache",
    "nginx":              "nginx",
    "nginx http server":  "nginx",
    "openresty":          "nginx",
    "microsoft iis":      "microsoft iis",
    "microsoft-iis":      "microsoft iis",
    "iis":                "microsoft iis",
    "lighttpd":           "lighttpd",
    "caddy":              "caddy",
    "gunicorn":           "gunicorn",
    "uvicorn":            "uvicorn",
    "tomcat":             "apache tomcat",
    "apache tomcat":      "apache tomcat",
    "coyote":             "apache tomcat",  # Tomcat HTTP connector
    "jetty":              "eclipse jetty",
    "eclipse jetty":      "eclipse jetty",
    "jboss":              "jboss",
    "wildfly":            "wildfly",
    "glassfish":          "glassfish",
    "weblogic":           "weblogic",
    "websphere":          "websphere",

    # Databases
    "mysql":              "mysql",
    "mariadb":            "mariadb",
    "postgresql":         "postgresql",
    "postgres":           "postgresql",
    "mongodb":            "mongodb",
    "mongod":             "mongodb",
    "redis":              "redis",
    "elasticsearch":      "elasticsearch",
    "elastic":            "elasticsearch",
    "cassandra":          "cassandra",
    "couchdb":            "couchdb",
    "memcached":          "memcached",
    "influxdb":           "influxdb",
    "mssql":              "microsoft sql server",
    "microsoft sql":      "microsoft sql server",
    "oracle":             "oracle db",

    # Message brokers
    "rabbitmq":           "rabbitmq",
    "activemq":           "apache activemq",
    "kafka":              "apache kafka",

    # Security / infra
    "openssh":            "openssh",
    "openssl":            "openssl",
    "openssl ssl":        "openssl",
    "vsftpd":             "vsftpd",
    "proftpd":            "proftpd",
    "postfix":            "postfix",
    "exim":               "exim",
    "sendmail":           "sendmail",
    "dovecot":            "dovecot",
    "samba":              "samba",
    "smbd":               "samba",
    "bind":               "bind dns",
    "named":              "bind dns",

    # DevOps
    "jenkins":            "jenkins",
    "gitlab":             "gitlab",
    "gitea":              "gitea",
    "kubernetes":         "kubernetes",
    "k8s":                "kubernetes",
    "docker":             "docker",
    "etcd":               "etcd",
    "consul":             "consul",
    "vault":              "vault",
    "prometheus":         "prometheus",
    "grafana":            "grafana",
    "kibana":             "kibana",
    "zabbix":             "zabbix",
    "nagios":             "nagios",
    "splunk":             "splunk",
    "sonarqube":          "sonarqube",
    "nexus":              "sonatype nexus",
    "artifactory":        "jfrog artifactory",

    # CMS / frameworks
    "wordpress":          "wordpress",
    "drupal":             "drupal",
    "joomla":             "joomla",
    "magento":            "magento",
    "php":                "php",
    "django":             "django",
    "rails":              "ruby on rails",
    "express":            "express.js",
    "spring":             "spring framework",
    "flask":              "flask",

    # Microsoft / Windows services
    "microsoft-httpapi":  "microsoft httpapi",
    "microsoft httpapi":  "microsoft httpapi",
    "httpapi":            "microsoft httpapi",
    "microsoft iis httpapi": "microsoft httpapi",

    # Proxies / CDN
    "varnish":            "varnish",
    "haproxy":            "haproxy",
    "traefik":            "traefik",
    "envoy":              "envoy",
    "squid":              "squid",
}

# Nmap service name → canonical product name
# Used when Nmap reports service but not product
_SERVICE_TO_PRODUCT = {
    "http":         "http",
    "https":        "http",
    "http-alt":     "http",
    "ssh":          "openssh",
    "ftp":          "ftp",
    "smtp":         "smtp",
    "mysql":        "mysql",
    "postgresql":   "postgresql",
    "redis":        "redis",
    "mongodb":      "mongodb",
    "elasticsearch":"elasticsearch",
    "memcached":    "memcached",
    "kafka":        "apache kafka",
    "amqp":         "rabbitmq",
    "smb":          "samba",
    "msrpc":        "microsoft rpc",
    "netbios":      "netbios",
}


def normalize_product_name(raw: str) -> str:
    """
    Convert any raw product/service string to a canonical lowercase name.
    Uses the alias table first, then falls back to cleaned raw string.

    Examples:
        "Apache httpd"          → "apache"
        "OpenSSH 6.6.1p1"       → "openssh"
        "Microsoft IIS httpd"   → "microsoft iis"
        "nginx"                 → "nginx"
    """
    if not raw:
        return ""
    cleaned = str(raw).lower().strip()

    # Strip version numbers in multiple formats:
    # "Apache 2.4.7" → "apache", "Apache/2.4.7" → "apache", "nginx-1.18" → "nginx"
    cleaned = re.sub(r'[/\s_]+[\d][\d.]*.*$', '', cleaned).strip()
    # Strip common suffixes
    for suffix in (" httpd", " http server", " server", " daemon", " service"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)].strip()
    # Strip non-alphanumeric except space/hyphen
    cleaned = re.sub(r'[^a-z0-9 \-]', '', cleaned).strip()
    # Replace hyphens with spaces for consistent lookup
    lookup = cleaned.replace("-", " ")

    return _PRODUCT_ALIASES.get(lookup, _PRODUCT_ALIASES.get(cleaned, cleaned))


def normalize_version(raw: str) -> tuple:
    """
    Parse a version string into a comparable tuple of integers.

    Examples:
        "2.4.7"                     → (2, 4, 7)
        "6.6.1p1 Ubuntu 2ubuntu2"   → (6, 6, 1)
        "unknown"                   → ()
        ""                          → ()
    """
    if not raw or str(raw).strip().lower() in ("unknown", "x", "n/a", ""):
        return ()
    match = re.match(r'(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?', str(raw).strip())
    if not match:
        return ()
    return tuple(int(g) for g in match.groups() if g is not None)


def service_matches_product(product: str, nmap_service: str, nmap_product: str) -> bool:
    """
    Proper service-to-product match check.
    Replaces: product.lower() in p["service"] or product.lower() in p["version"]

    Logic:
    1. Normalise both the CVE product and the Nmap service/product strings
    2. Check canonical name equality first (most reliable)
    3. Fall back to substring match only on normalised strings (not raw)
    4. Check service alias map as final fallback

    Returns True only when there is a genuine match.
    """
    if not product:
        return False

    norm_product = normalize_product_name(product)
    norm_service  = normalize_product_name(nmap_service)
    norm_nmap     = normalize_product_name(nmap_product)

    # Exact canonical match — most reliable
    if norm_product and norm_product in (norm_service, norm_nmap):
        return True

    # Canonical prefix match — e.g. "apache" matches "apache tomcat"
    # Only when both sides are non-empty to avoid empty-string false matches
    if norm_product and norm_service and (
        norm_service.startswith(norm_product) or
        norm_product.startswith(norm_service)
    ) and len(norm_product) >= 4:
        return True
    if norm_product and norm_nmap and (
        norm_nmap.startswith(norm_product) or
        norm_product.startswith(norm_nmap)
    ) and len(norm_product) >= 4:
        return True

    # Service name alias lookup
    service_canonical = _SERVICE_TO_PRODUCT.get(nmap_service.lower().strip(), "")
    if service_canonical and normalize_product_name(service_canonical) == norm_product:
        return True

    return False


def version_is_relevant(detected_version: str, affected_versions: str) -> str:
    """
    Check whether a detected version is relevant to a CVE's affected range.

    Returns one of:
        "CONFIRMED"     — version is clearly within affected range
        "POSSIBLE"      — version is close but range is ambiguous
        "UNLIKELY"      — version appears outside the affected range
        "UNKNOWN"       — cannot determine (no version info)

    This replaces the binary True/False from _version_in_range,
    adding "POSSIBLE" as a middle ground for uncertain matches.
    """
    if not detected_version or str(detected_version).strip().lower() in ("unknown", "x", ""):
        return "UNKNOWN"
    if not affected_versions or str(affected_versions).strip() in ("x", ""):
        return "POSSIBLE"   # No range info — can't exclude, but not confirmed

    det = normalize_version(detected_version)
    if not det:
        return "UNKNOWN"

    affected_str = str(affected_versions).strip()

    # Parse each part of the affected range (comma-separated)
    for part in affected_str.split(","):
        part = part.strip()
        if not part:
            continue

        # Range with dash: "2.4.0 - 2.4.55"
        if " - " in part:
            bounds = part.split(" - ", 1)
            lo = normalize_version(bounds[0].strip())
            hi = normalize_version(bounds[1].strip())
            if lo and hi and lo <= det <= hi:
                return "CONFIRMED"
            if lo and hi and det < lo:
                return "UNLIKELY"
            continue

        # Operators: <, <=, >, >=
        op = ""
        val_str = part
        for operator in ("<=", ">=", "<", ">"):
            if part.startswith(operator):
                op = operator
                val_str = part[len(operator):].strip()
                break

        bound = normalize_version(val_str)
        if not bound:
            continue

        if op == "<="  and det <= bound: return "CONFIRMED"
        if op == ">="  and det >= bound: return "CONFIRMED"
        if op == "<"   and det <  bound: return "CONFIRMED"
        if op == ">"   and det >  bound: return "CONFIRMED"
        if op == "<"   and det >= bound: return "UNLIKELY"
        if op == "<="  and det >  bound: return "UNLIKELY"

        # Exact version match
        if not op and det == bound:
            return "CONFIRMED"
        if not op and det != bound:
            return "UNLIKELY"

    return "POSSIBLE"


# ─────────────────────────────────────────
# HTTP Response Version Extractor
# Extracts version strings from HTTP response bodies and headers
# when Nmap banners are vague or missing.
# Used by analyse.py fingerprint enrichment.
# ─────────────────────────────────────────

_VERSION_PATTERNS = [
    # Apache error page: "Apache/2.4.7 (Ubuntu)"
    (re.compile(r'Apache/(\d+\.\d+[\.\d]*)', re.IGNORECASE), "apache"),
    # nginx error page: "nginx/1.18.0"
    (re.compile(r'nginx/(\d+\.\d+[\.\d]*)', re.IGNORECASE), "nginx"),
    # PHP: "PHP/7.4.3" in X-Powered-By
    (re.compile(r'PHP/(\d+\.\d+[\.\d]*)', re.IGNORECASE), "php"),
    # OpenSSL in server header: "OpenSSL/1.1.1"
    (re.compile(r'OpenSSL/(\d+\.\d+[\.\d]*)', re.IGNORECASE), "openssl"),
    # Tomcat: "Apache Tomcat/9.0.45"
    (re.compile(r'Apache Tomcat/(\d+\.\d+[\.\d]*)', re.IGNORECASE), "apache tomcat"),
    # Jetty: "Jetty(9.4.43.v20210629)"
    (re.compile(r'Jetty\((\d+\.\d+[\.\d]*)', re.IGNORECASE), "eclipse jetty"),
    # Express: "Express" + version from X-Powered-By
    (re.compile(r'Express/(\d+\.\d+[\.\d]*)', re.IGNORECASE), "express.js"),
    # Django version in debug pages
    (re.compile(r'Django[/\s]+(\d+\.\d+[\.\d]*)', re.IGNORECASE), "django"),
    # WordPress generator meta tag
    (re.compile(r'WordPress[/\s]+(\d+\.\d+[\.\d]*)', re.IGNORECASE), "wordpress"),
    # Spring Boot: "Spring Boot v2.7.0"
    (re.compile(r'Spring Boot[/\s]+v?(\d+\.\d+[\.\d]*)', re.IGNORECASE), "spring framework"),
    # Rails: "Ruby on Rails 6.1.7"
    (re.compile(r'Ruby on Rails[/\s]+(\d+\.\d+[\.\d]*)', re.IGNORECASE), "ruby on rails"),
    # Node.js in headers
    (re.compile(r'node\.js[/\s]+v?(\d+\.\d+[\.\d]*)', re.IGNORECASE), "node.js"),
    # IIS in server header: "Microsoft-IIS/10.0"
    (re.compile(r'Microsoft-IIS/(\d+\.\d+[\.\d]*)', re.IGNORECASE), "microsoft iis"),
    # Elasticsearch version in JSON body
    (re.compile(r'"number"\s*:\s*"(\d+\.\d+[\.\d]*)"'), "elasticsearch"),
    # Generic version pattern for unknown products
    (re.compile(r'/(\d+\.\d+\.\d+)'), None),   # None = use with known product context
]


def extract_version_from_response(html_body: str, headers: dict,
                                   known_product: str = "") -> dict:
    """
    Extract product/version pairs from HTTP response content.

    Returns dict: {normalised_product: version_string}

    Checks in order:
    1. Response headers (Server, X-Powered-By, X-Generator, X-AspNet-Version)
    2. HTML body (error pages, meta generator tags, framework signatures)
    3. JSON body (APIs that expose version in response)

    This supplements Nmap banner detection when banners are vague.
    """
    found = {}
    combined = str(html_body or "") + "\n" + " ".join(str(v) for v in (headers or {}).values())

    for pattern, product_hint in _VERSION_PATTERNS:
        match = pattern.search(combined)
        if not match:
            continue
        version = match.group(1)
        if not version:
            continue

        # Determine product
        if product_hint:
            norm = product_hint
        elif known_product:
            norm = normalize_product_name(known_product)
        else:
            continue   # generic pattern with no product context — skip

        if norm and version and len(version) >= 3:
            # Only update if we don't have a version yet or new one is more specific
            existing = found.get(norm, "")
            if not existing or len(version) > len(existing):
                found[norm] = version

    # Also check specific headers directly
    srv = headers.get("server", headers.get("Server", ""))
    xpb = headers.get("x-powered-by", headers.get("X-Powered-By", ""))
    asp = headers.get("x-aspnet-version", headers.get("X-AspNet-Version", ""))

    for raw in [srv, xpb]:
        if not raw:
            continue
        ver_m = re.search(r'[/\s](\d+\.\d+[\.\d]*)', raw)
        if ver_m:
            norm = normalize_product_name(raw)
            ver  = ver_m.group(1)
            if norm and len(norm) >= 3 and norm not in found:
                found[norm] = ver

    if asp:
        found["asp.net"] = asp.split(";")[0].strip()

    return found


def finding_confidence(cve: dict, detected_version: str,
                        port_matched: bool, service_matched: bool) -> str:
    """
    Point 3 — Strict confidence model for RCE_CANDIDATE leads.

    LOW    — CVE exists + port is open
    MEDIUM — CVE exists + service matches + version is POSSIBLE/CONFIRMED
    HIGH   — CVE exists + service matches + version CONFIRMED + EPSS >= 0.1

    Returns: "HIGH", "MEDIUM", or "LOW"
    """
    epss    = float(cve.get("epss", 0) or 0)
    cvss    = float(cve.get("cvss", 0) or 0)
    ver_rel = version_is_relevant(detected_version, cve.get("affected_versions", ""))

    if (service_matched and
            ver_rel == "CONFIRMED" and
            (epss >= 0.1 or cvss >= 9.0)):
        return "HIGH"

    if service_matched and ver_rel in ("CONFIRMED", "POSSIBLE"):
        return "MEDIUM"

    return "LOW"


def confidence_reason(cve: dict, detected_version: str,
                       port_matched: bool, service_matched: bool) -> str:
    """
    Human-readable explanation of why a lead has its confidence level.
    """
    parts = []
    epss  = float(cve.get("epss", 0) or 0)
    cvss  = float(cve.get("cvss", 0) or 0)
    ver_rel = version_is_relevant(detected_version, cve.get("affected_versions", ""))
    cve_id  = cve.get("cve", "")

    if service_matched:
        parts.append("service name matches product")
    else:
        parts.append("product matched by name only — service not confirmed")

    parts.append(f"version relevance: {ver_rel} (detected: {detected_version or 'unknown'})")

    if epss >= 0.3:
        parts.append(f"EPSS {epss:.3f} — high real-world exploitation probability")
    elif epss >= 0.1:
        parts.append(f"EPSS {epss:.3f} — moderate exploitation probability")
    elif epss > 0:
        parts.append(f"EPSS {epss:.3f} — low exploitation probability")

    if cvss >= 9.0:
        parts.append(f"CVSS {cvss:.1f} — critical severity")
    elif cvss >= 7.0:
        parts.append(f"CVSS {cvss:.1f} — high severity")

    return "; ".join(parts)
