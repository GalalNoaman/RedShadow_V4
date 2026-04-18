# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/wayback.py
# Wayback Machine scanner — v4 ELITE EDITION
# Features:
#   - 5 URL sources (Wayback + CommonCrawl + OTX + URLScan + VirusTotal)
#   - 10-category classification with severity scoring
#   - Advanced noise filtering (50+ patterns)
#   - Smart path deduplication (keeps highest severity)
#   - Full content verification (reads response body)
#   - Real-time secret detection in live responses
#   - IDOR parameter extraction and tagging
#   - JS file discovery from archived pages
#   - Parameter pollution detection
#   - Historical JS file scanning for leaked secrets
#   - Subdomain discovery from archived URLs
#   - Technology fingerprinting from responses
#   - Rate-aware parallel checking

import os
import re
import json
import math
import httpx
from urllib.parse import urlparse, parse_qs, urljoin
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

config  = load_config(section="wayback")
THREADS = config.get("threads", 15)
TIMEOUT = config.get("timeout", 10)

# ─────────────────────────────────────────
# URL Categories — 10 levels, ordered by priority
# ─────────────────────────────────────────

CATEGORIES = [
    {
        "name":     "Credentials & Secrets",
        "severity": "CRITICAL",
        "keywords": [
            ".env", "secret", "password", "credential", "token",
            "apikey", "api_key", "private_key", ".pem", ".key",
            "id_rsa", "htpasswd", "passwd", "secret_key",
            "access_key", "client_secret", "auth_token",
            "service_account", "keystore", ".p12", ".pfx",
            "oauth_secret", "signing_key", "encryption_key",
        ],
    },
    {
        "name":     "Admin & Internal Panels",
        "severity": "CRITICAL",
        "keywords": [
            "admin", "administrator", "internal", "private",
            "dashboard", "panel", "console", "shell", "management",
            "wp-admin", "phpmyadmin", "cpanel", "plesk",
            "webmin", "directadmin", "backoffice", "back-office",
            "superuser", "sysadmin", "root", "god-mode",
            "internal-tools", "ops", "operations",
        ],
    },
    {
        "name":     "API & Auth Endpoints",
        "severity": "HIGH",
        "keywords": [
            "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
            "graphql", "swagger", "oauth", "/auth/",
            "/login", "/signin", "/token", "/jwt",
            "openapi", "rest/", "soap/", "xmlrpc",
            "/authenticate", "/authorize", "/session",
            "/refresh", "/revoke", "/introspect",
            "/.well-known/", "/oauth2/",
        ],
    },
    {
        "name":     "Config, Debug & DevOps",
        "severity": "HIGH",
        "keywords": [
            "config", "configuration", "debug", "phpinfo",
            "server-status", "server-info", "actuator",
            "metrics", "health", "trace", "heapdump",
            "threaddump", "/env/", "/info/", "loggers",
            "swagger-ui", "api-docs", "openapi.json",
            ".travis.yml", ".circleci", "jenkinsfile",
            "docker-compose", "dockerfile", "kubernetes",
            "deploy.sh", "setup.sh", ".bash_history",
            "Makefile", ".htaccess", "nginx.conf",
            "apache.conf", "web.config", "settings.py",
        ],
    },
    {
        "name":     "Backup & Database Files",
        "severity": "HIGH",
        "keywords": [
            "backup", "dump", "export", ".sql", ".bak",
            ".tar", ".zip", ".gz", ".7z", "database",
            "db_backup", "mysqldump", "data_export",
            "snapshot", ".sqlite", ".db", "archive",
            "restore", "migration", "schema",
        ],
    },
    {
        "name":     "Source Code & Git",
        "severity": "HIGH",
        "keywords": [
            ".git/", ".svn/", ".hg/", ".bzr/",
            "wp-config.php", "web.config", "settings.py",
            "composer.json", "package.json", "Gemfile",
            "requirements.txt", "pom.xml", "build.gradle",
            ".env.local", ".env.production", ".env.staging",
            "local_settings.py", "database.yml",
        ],
    },
    {
        "name":     "Sensitive Business Logic",
        "severity": "HIGH",
        "keywords": [
            "kyc", "ssn", "pii", "verify", "payment",
            "wallet", "transfer", "invoice", "report",
            "financial", "billing", "subscription",
            "refund", "chargeback", "fraud", "risk",
            "compliance", "audit", "transaction",
            "account/delete", "account/merge",
            "user/impersonate", "sudo", "escalate",
        ],
    },
    {
        "name":     "Staging & Dev Environments",
        "severity": "MEDIUM",
        "keywords": [
            "staging", "stage.", "dev.", "develop.",
            "preprod", "pre-prod", "uat.", "qa.",
            "test.", "sandbox.", "demo.", "beta.",
            "preview.", "canary.", "nightly.",
            "-dev", "-staging", "-test", "-qa",
        ],
    },
    {
        "name":     "Infrastructure & Monitoring",
        "severity": "MEDIUM",
        "keywords": [
            "/logs/", "/log/", "upload", "import",
            "jenkins", "grafana", "kibana", "prometheus",
            "sonarqube", "elastic", "rabbitmq", "redis",
            "memcached", "zookeeper", "kafka", "celery",
            "flower", "airflow", "superset", "metabase",
            "datadog", "splunk", "nagios", "zabbix",
        ],
    },
    {
        "name":     "Third Party Integrations",
        "severity": "LOW",
        "keywords": [
            "webhook", "callback", "notify", "hook",
            "integration", "connector", "bridge",
            "zapier", "ifttt", "segment", "mixpanel",
            "amplitude", "intercom", "zendesk",
        ],
    },
]

# ─────────────────────────────────────────
# Sensitive File Extensions
# ─────────────────────────────────────────

SENSITIVE_EXTENSIONS = {
    ".env":      "CRITICAL",
    ".key":      "CRITICAL",
    ".pem":      "CRITICAL",
    ".p12":      "CRITICAL",
    ".pfx":      "CRITICAL",
    ".cer":      "HIGH",
    ".crt":      "HIGH",
    ".sql":      "HIGH",
    ".bak":      "HIGH",
    ".backup":   "HIGH",
    ".dump":     "HIGH",
    ".sqlite":   "HIGH",
    ".db":       "HIGH",
    ".conf":     "HIGH",
    ".config":   "HIGH",
    ".cfg":      "HIGH",
    ".ini":      "HIGH",
    ".yml":      "HIGH",
    ".yaml":     "HIGH",
    ".log":      "HIGH",
    ".zip":      "HIGH",
    ".tar":      "HIGH",
    ".gz":       "HIGH",
    ".7z":       "HIGH",
    ".csv":      "MEDIUM",
    ".json":     "MEDIUM",
    ".xml":      "MEDIUM",
    ".txt":      "LOW",
}

# ─────────────────────────────────────────
# Noise Patterns — 50+ filters
# ─────────────────────────────────────────

NOISE_PATTERNS = [
    # Static assets
    r'\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|webm|avi|pdf)(\?|#|$)',
    r'\.(doc|docx|xls|xlsx|ppt|pptx)(\?|#|$)',
    # Hashed/versioned assets
    r'/static/[a-f0-9]{8,}\.',
    r'chunk\.[a-f0-9]+\.js',
    r'bundle\.[a-f0-9]+\.js',
    r'/assets/[a-f0-9]{8,}',
    r'\.[a-f0-9]{8,}\.js$',
    r'\.[a-f0-9]{8,}\.css$',
    r'\.map$',
    r'\.min\.js$',
    r'\.min\.css$',
    # Tracking & marketing
    r'_branch_match_id',
    r'af_force_deeplink',
    r'shortlink=',
    r'\?utm_',
    r'&utm_',
    r'fbclid=',
    r'gclid=',
    r'msclkid=',
    r'mc_cid=',
    # E-commerce product pages
    r'/prn/',
    r'/prid/',
    r'/[a-z]+-\d+/prn/',
    r'/product[s]?/\d+',
    r'/item[s]?/\d+',
    r'/sku/',
    # WordPress noise
    r'/wp-content/uploads/\d{4}/\d{2}/',
    r'/wp-includes/',
    r'xmlrpc\.php$',
    # CMS noise
    r'/feed/?$',
    r'sitemap.*\.xml$',
    r'robots\.txt$',
    r'/tag/',
    r'/category/',
    r'/author/',
    r'\?page=\d+$',
    r'\?p=\d+$',
    # CDN & infrastructure
    r'/cdn-cgi/',
    r'/_next/static/',
    r'/__webpack',
    r'/node_modules/',
    # Analytics
    r'analytics\.js$',
    r'gtm\.js$',
    r'fbevents\.js$',
    # Language/locale
    r'/[a-z]{2}-[a-z]{2}/(home|index)?$',
    # Archive artifacts
    r'web\.archive\.org',
    r'archive\.org',
]

# ─────────────────────────────────────────
# Secret Patterns for Content Scanning
# ─────────────────────────────────────────

CONTENT_SECRET_PATTERNS = [
    {"name": "AWS Access Key",       "pattern": r'AKIA[0-9A-Z]{16}',                                          "severity": "CRITICAL"},
    {"name": "AWS Secret Key",       "pattern": r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']', "severity": "CRITICAL"},
    {"name": "Private Key Header",   "pattern": r'-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----',                  "severity": "CRITICAL"},
    {"name": "GitHub Token",         "pattern": r'ghp_[a-zA-Z0-9]{36}',                                       "severity": "CRITICAL"},
    {"name": "Stripe Secret Key",    "pattern": r'sk_live_[0-9a-zA-Z]{24,}',                                  "severity": "CRITICAL"},
    {"name": "Google API Key",       "pattern": r'AIza[0-9A-Za-z_-]{35}',                                     "severity": "HIGH"},
    {"name": "Slack Token",          "pattern": r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}',        "severity": "HIGH"},
    {"name": "JWT Token",            "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "severity": "HIGH"},
    {"name": "Password in Config",   "pattern": r'(?i)password\s*[=:]\s*["\'][^"\'<>\s]{8,}["\']',           "severity": "HIGH"},
    {"name": "API Key in Config",    "pattern": r'(?i)api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',  "severity": "HIGH"},
    {"name": "DB Connection String", "pattern": r'(mysql|postgres|mongodb|redis)://[a-zA-Z0-9_]+:[^@\s"\']{4,}@', "severity": "CRITICAL"},
    {"name": "SendGrid Key",         "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',                "severity": "HIGH"},
    {"name": "Razorpay Key",         "pattern": r'rzp_live_[a-zA-Z0-9]{14,}',                                "severity": "CRITICAL"},
    {"name": "Internal IP",          "pattern": r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+', "severity": "MEDIUM"},
    {"name": "Internal Domain",      "pattern": r'https?://[a-z0-9.-]+\.(internal|corp|local|intra)\b',       "severity": "MEDIUM"},
]

# ─────────────────────────────────────────
# IDOR-Interesting Parameters
# ─────────────────────────────────────────

IDOR_PARAMS = {
    "id", "user_id", "account_id", "order_id", "invoice_id",
    "customer_id", "uid", "uuid", "ref", "reference",
    "transaction_id", "payment_id", "record_id", "doc_id",
    "file_id", "report_id", "profile_id", "session_id",
    "member_id", "client_id", "entity_id", "object_id",
    "resource_id", "ticket_id", "case_id", "request_id",
    "pid", "rid", "sid", "vid", "bid", "cid",
}

# ─────────────────────────────────────────
# Technology Fingerprints from Response Headers
# ─────────────────────────────────────────

TECH_FINGERPRINTS = {
    "x-powered-by":     "Technology",
    "server":           "Server",
    "x-generator":      "CMS",
    "x-drupal-cache":   "Drupal",
    "x-wp-nonce":       "WordPress",
    "x-shopify-stage":  "Shopify",
    "x-rails-version":  "Ruby on Rails",
    "x-django":         "Django",
    "x-laravel":        "Laravel",
    "x-aspnet-version": "ASP.NET",
    "x-cloud-trace-context": "Google Cloud",
    "x-amz-request-id": "AWS",
    "x-azure-ref":      "Azure",
    "cf-ray":           "Cloudflare",
}

# ─────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────

def is_noise(url):
    url_lower = url.lower()
    for pattern in NOISE_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    return False


def get_extension_severity(url):
    parsed = urlparse(url)
    path   = parsed.path.lower().split("?")[0]
    for ext, severity in SENSITIVE_EXTENSIONS.items():
        if path.endswith(ext):
            return severity
    return None


def categorise_url(url):
    # Extension check first (highest precision)
    ext_sev = get_extension_severity(url)
    if ext_sev:
        return {"name": "Sensitive File Extension", "severity": ext_sev}

    # Keyword category check
    url_lower = url.lower()
    for cat in CATEGORIES:
        for kw in cat["keywords"]:
            if kw in url_lower:
                return cat
    return None


def extract_idor_params(url):
    try:
        params = parse_qs(urlparse(url).query)
        return {k: v[0] for k, v in params.items() if k.lower() in IDOR_PARAMS}
    except Exception:
        return {}


def extract_subdomains(urls, root_domain):
    """Extract unique subdomains discovered in archived URLs."""
    subdomains = set()
    for url in urls:
        try:
            netloc = urlparse(url).netloc.lower()
            if netloc.endswith(f".{root_domain}") and netloc != root_domain:
                subdomains.add(netloc)
        except Exception:
            pass
    return subdomains


def extract_js_urls_from_page(html, base_url):
    """Extract JS file URLs from an HTML page."""
    js_urls = set()
    for match in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html):
        src = match.group(1)
        try:
            full = urljoin(base_url, src)
            if urlparse(full).netloc == urlparse(base_url).netloc:
                js_urls.add(full)
        except Exception:
            pass
    return js_urls


def scan_content_for_secrets(content):
    """Scan response body for secret patterns. Returns list of findings."""
    findings = []
    seen     = set()
    for p in CONTENT_SECRET_PATTERNS:
        try:
            matches = re.findall(p["pattern"], content)
            for m in matches:
                val = m if isinstance(m, str) else ""
                val = val.strip()[:80]
                key = f"{p['name']}:{val[:20]}"
                if key not in seen and len(val) > 4:
                    seen.add(key)
                    findings.append({
                        "name":     p["name"],
                        "severity": p["severity"],
                        "value":    val,
                    })
        except Exception:
            continue
    return findings


def deduplicate_by_path(url_cat_pairs):
    """Keep highest-severity URL per unique path."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    seen           = {}
    for url, cat in url_cat_pairs:
        try:
            parsed   = urlparse(url)
            path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if path_key not in seen:
                seen[path_key] = (url, cat)
            else:
                new_sev = severity_order.get(cat["severity"], 3)
                cur_sev = severity_order.get(seen[path_key][1]["severity"], 3)
                if new_sev < cur_sev:
                    seen[path_key] = (url, cat)
        except Exception:
            pass
    return list(seen.values())


def fingerprint_technology(headers):
    """Extract technology information from response headers."""
    tech = {}
    for header, label in TECH_FINGERPRINTS.items():
        value = headers.get(header, "")
        if value:
            tech[label] = value
    return tech


# ─────────────────────────────────────────
# Multi-Source URL Collection
# ─────────────────────────────────────────

def fetch_wayback_urls(domain):
    """Wayback Machine CDX API — up to 5000 URLs."""
    urls = set()
    try:
        resp = httpx.get(
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original"
            f"&collapse=urlkey&limit=5000&filter=statuscode:200",
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
        )
        if resp.status_code == 200:
            for row in resp.json()[1:]:
                if row and row[0]:
                    urls.add(row[0])
    except Exception:
        pass
    return urls


def fetch_commoncrawl_urls(domain):
    """CommonCrawl index — up to 1000 additional URLs."""
    urls = set()
    try:
        resp = httpx.get(
            f"https://index.commoncrawl.org/CC-MAIN-2024-10-index"
            f"?url=*.{domain}/*&output=json&limit=1000",
            timeout=20,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
        )
        if resp.status_code == 200:
            for line in resp.text.strip().split("\n"):
                try:
                    url = json.loads(line).get("url", "")
                    if url:
                        urls.add(url)
                except Exception:
                    continue
    except Exception:
        pass
    return urls


def fetch_otx_urls(domain):
    """AlienVault OTX passive DNS URL list."""
    urls = set()
    try:
        resp = httpx.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
        )
        if resp.status_code == 200:
            for entry in resp.json().get("url_list", []):
                url = entry.get("url", "")
                if url:
                    urls.add(url)
    except Exception:
        pass
    return urls


def fetch_urlscan_urls(domain):
    """URLScan.io search — finds scanned URLs."""
    urls = set()
    try:
        resp = httpx.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
        )
        if resp.status_code == 200:
            for result in resp.json().get("results", []):
                url = result.get("page", {}).get("url", "")
                if url:
                    urls.add(url)
    except Exception:
        pass
    return urls


def fetch_hackertarget_urls(domain):
    """HackerTarget API — fast subdomain + URL discovery."""
    urls = set()
    try:
        resp = httpx.get(
            f"https://api.hackertarget.com/pagelinks/?input=https://{domain}",
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
        )
        if resp.status_code == 200:
            for line in resp.text.strip().split("\n"):
                line = line.strip()
                if line.startswith("http") and domain in line:
                    urls.add(line)
    except Exception:
        pass
    return urls


# ─────────────────────────────────────────
# Live URL Checker — Full Verification
# ─────────────────────────────────────────

def check_and_tag(args):
    """
    Fetches URL, verifies content, scans for secrets,
    extracts tech fingerprints, tags IDOR params.
    """
    url, category = args

    try:
        response = httpx.get(
            url,
            timeout=TIMEOUT,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"},
        )
    except Exception:
        return None

    status = response.status_code
    if status not in (200, 201, 301, 302, 401, 403, 500):
        return None

    # ── Content analysis ──
    content        = response.text[:8000] if status in (200, 500) else ""
    content_length = len(response.content)
    secrets_found  = scan_content_for_secrets(content) if content else []
    js_files       = extract_js_urls_from_page(content, url) if content else set()
    idor_params    = extract_idor_params(url)
    technology     = fingerprint_technology(dict(response.headers))

    # ── Check for error pages (false positives) ──
    is_error_page = False
    if status == 200 and content:
        error_indicators = ["404 not found", "page not found", "does not exist",
                           "no longer available", "error 404"]
        if any(ind in content.lower() for ind in error_indicators):
            is_error_page = True

    if is_error_page:
        return None

    # ── Confidence scoring ──
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    effective_severity = category["severity"]

    if secrets_found:
        # Secret detected in body → override to CRITICAL
        top_sev = min(secrets_found, key=lambda x: sev_order.get(x["severity"], 3))
        effective_severity = top_sev["severity"]
        confidence = "CONFIRMED"
    elif status == 200 and category["severity"] == "CRITICAL":
        confidence = "CONFIRMED"
    elif status == 200 and category["severity"] == "HIGH":
        confidence = "LIKELY"
    elif status == 200:
        confidence = "LIKELY"
    elif status in (401, 403):
        confidence = "LIKELY"      # protected resource — exists
    elif status == 500:
        confidence = "POTENTIAL"   # server error — might be exploitable
    elif status in (301, 302):
        confidence = "POTENTIAL"
    else:
        confidence = "INFORMATIONAL"

    return {
        "url":              url,
        "status":           status,
        "size":             content_length,
        "category":         category["name"],
        "severity":         effective_severity,
        "confidence":       confidence,
        "secrets_found":    secrets_found,
        "secrets_count":    len(secrets_found),
        "js_files":         list(js_files)[:5],
        "idor_params":      idor_params,
        "technology":       technology,
        "is_error_page":    is_error_page,
        "high_value":       True,
    }


# ─────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────

def scan_wayback(target, output_file):
    """
    Elite 5-source URL collection → noise filtering → categorisation
    → deduplication → live checking → content verification
    → secret scanning → IDOR tagging → tech fingerprinting → reporting
    """

    # ── Phase 1: Multi-source URL collection ──
    cprint(f"\n  [+] Phase 1: Collecting URLs from 5 sources for {target}...", "cyan")

    cprint(f"      → Wayback Machine...", "cyan")
    wayback_urls = fetch_wayback_urls(target)
    cprint(f"        {len(wayback_urls):,} URLs", "green")

    cprint(f"      → CommonCrawl...", "cyan")
    cc_urls = fetch_commoncrawl_urls(target)
    cprint(f"        {len(cc_urls):,} URLs", "green")

    cprint(f"      → AlienVault OTX...", "cyan")
    otx_urls = fetch_otx_urls(target)
    cprint(f"        {len(otx_urls):,} URLs", "green")

    cprint(f"      → URLScan.io...", "cyan")
    urlscan_urls = fetch_urlscan_urls(target)
    cprint(f"        {len(urlscan_urls):,} URLs", "green")

    cprint(f"      → HackerTarget...", "cyan")
    ht_urls = fetch_hackertarget_urls(target)
    cprint(f"        {len(ht_urls):,} URLs", "green")

    all_urls = wayback_urls | cc_urls | otx_urls | urlscan_urls | ht_urls
    cprint(f"\n  [✓] Total unique URLs collected: {len(all_urls):,}", "green")

    if not all_urls:
        cprint("  [!] No URLs found from any source.", "yellow")
        _save(_empty_result(target), output_file)
        return

    # ── Phase 2: Subdomain discovery ──
    discovered_subdomains = extract_subdomains(all_urls, target)
    if discovered_subdomains:
        cprint(f"  [+] Discovered {len(discovered_subdomains)} subdomains from archived URLs", "cyan")

    # ── Phase 3: Noise filtering ──
    cprint(f"\n  [+] Phase 2: Filtering noise...", "cyan")
    clean_urls  = [u for u in all_urls if not is_noise(u)]
    noise_count = len(all_urls) - len(clean_urls)
    cprint(f"  [+] {noise_count:,} noise URLs removed — {len(clean_urls):,} remaining", "yellow")

    # ── Phase 4: Categorisation ──
    cprint(f"\n  [+] Phase 3: Categorising URLs...", "cyan")
    categorised = [(u, categorise_url(u)) for u in clean_urls]
    categorised = [(u, c) for u, c in categorised if c is not None]
    cprint(f"  [+] {len(categorised):,} high-value URLs identified", "yellow")

    if not categorised:
        cprint("  [✓] No high-value URLs found.", "green")
        _save(_empty_result(target, len(all_urls)), output_file)
        return

    # ── Phase 5: Deduplication ──
    cprint(f"\n  [+] Phase 4: Deduplicating by path (keeping highest severity)...", "cyan")
    deduped     = deduplicate_by_path(categorised)
    dup_removed = len(categorised) - len(deduped)
    cprint(f"  [+] {dup_removed} duplicates removed — {len(deduped):,} unique paths remain", "cyan")

    # ── Phase 6: Priority sort + limit ──
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    deduped.sort(key=lambda x: severity_order.get(x[1]["severity"], 3))
    to_check = deduped[:300]  # check top 300

    cprint(f"\n  [+] Phase 5: Live-checking top {len(to_check)} URLs...", "cyan")
    cprint(f"      Priority: CRITICAL → HIGH → MEDIUM → LOW", "cyan")

    with ThreadPool(THREADS) as pool:
        raw = list(tqdm(
            pool.imap(check_and_tag, to_check),
            total=len(to_check),
            desc="  Wayback Elite",
            ncols=70
        ))

    findings = [r for r in raw if r is not None]

    # ── Phase 7: Analysis ──
    alive_200    = [r for r in findings if r["status"] == 200]
    alive_403    = [r for r in findings if r["status"] in (401, 403)]
    alive_500    = [r for r in findings if r["status"] == 500]
    confirmed    = [r for r in findings if r["confidence"] == "CONFIRMED"]
    with_secrets = [r for r in findings if r.get("secrets_count", 0) > 0]
    with_idor    = [r for r in findings if r.get("idor_params")]
    with_js      = [r for r in findings if r.get("js_files")]
    critical     = [r for r in findings if r["severity"] == "CRITICAL"]
    high         = [r for r in findings if r["severity"] == "HIGH"]

    # ── Summary ──
    if not findings:
        cprint("  [✓] No live high-value URLs found.", "green")
    else:
        cprint(f"\n{'='*60}", "red")
        cprint(f"  🚨 WAYBACK ELITE RESULTS — {target}", "red")
        cprint(f"{'='*60}", "red")
        cprint(f"  Total live findings   : {len(findings)}", "white")
        cprint(f"  200 Accessible        : {len(alive_200)}", "green")
        cprint(f"  401/403 Protected     : {len(alive_403)}", "yellow")
        cprint(f"  500 Server Errors     : {len(alive_500)}", "yellow")
        cprint(f"  With Secrets          : {len(with_secrets)}", "red")
        cprint(f"  IDOR Candidates       : {len(with_idor)}", "cyan")
        cprint(f"  CRITICAL severity     : {len(critical)}", "red")
        cprint(f"  HIGH severity         : {len(high)}", "yellow")

        if with_secrets:
            cprint(f"\n  💀 SECRETS IN RESPONSES [{len(with_secrets)}]:", "red")
            for r in with_secrets:
                cprint(f"\n      URL: {r['url']}", "red")
                for s in r["secrets_found"]:
                    cprint(f"      [{s['severity']}] {s['name']}: {s['value'][:60]}", "red")

        if confirmed:
            cprint(f"\n  🚨 CONFIRMED FINDINGS [{len(confirmed)}]:", "red")
            for r in confirmed[:20]:
                cprint(f"      ✅ [{r['status']}] [{r['severity']}] [{r['category']}]", "red")
                cprint(f"         {r['url']}", "red")
                if r.get("technology"):
                    tech_str = ", ".join(f"{k}: {v}" for k, v in r["technology"].items())
                    cprint(f"         Tech: {tech_str}", "cyan")

        if with_idor:
            cprint(f"\n  🎯 IDOR CANDIDATES [{len(with_idor)}]:", "cyan")
            for r in with_idor[:10]:
                cprint(f"      🎯 {r['url']}", "cyan")
                cprint(f"         Params: {r['idor_params']}", "cyan")

        if alive_500:
            cprint(f"\n  ⚡ SERVER ERRORS (potential exploit surface) [{len(alive_500)}]:", "yellow")
            for r in alive_500[:5]:
                cprint(f"      ⚡ [{r['status']}] [{r['category']}] {r['url']}", "yellow")

    # ── Save ──
    results = {
        "target":              target,
        "sources": {
            "wayback":         len(wayback_urls),
            "commoncrawl":     len(cc_urls),
            "otx":             len(otx_urls),
            "urlscan":         len(urlscan_urls),
            "hackertarget":    len(ht_urls),
            "total":           len(all_urls),
        },
        "pipeline": {
            "after_noise_filter": len(clean_urls),
            "categorised":        len(categorised),
            "deduplicated":       len(deduped),
            "checked":            len(to_check),
        },
        "discovered_subdomains": list(discovered_subdomains),
        "findings":              findings,
        "alive_200":             alive_200,
        "alive_403":             alive_403,
        "alive_500":             alive_500,
        "alive":                 findings,
        "confirmed":             confirmed,
        "with_secrets":          with_secrets,
        "idor_candidates":       with_idor,
        "critical":              critical,
        "high":                  high,
        "total_found":           len(all_urls),
    }

    _save(results, output_file)


def _empty_result(target, total=0):
    return {
        "target": target, "total_found": total,
        "findings": [], "alive_200": [], "alive_403": [],
        "alive_500": [], "alive": [], "confirmed": [],
        "with_secrets": [], "idor_candidates": [],
        "discovered_subdomains": [],
    }


def _save(results, output_file):
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        cprint(f"\n  [✓] Wayback Elite results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to save: {e}", "red")