# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/jsextractor.py
# JavaScript endpoint extractor — finds hidden API endpoints, paths, and parameters
# JavaScript endpoint extractor with source map support and parameter extraction.
#       GraphQL introspection detection, subdomain leakage, makedirs fix

import os
import re
import json
import httpx
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin, urlparse, parse_qs
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config
import warnings

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

config  = load_config(section="jsextractor")
THREADS = config.get("threads", 10)
TIMEOUT = config.get("timeout", 8)

# ─────────────────────────────────────────
# Endpoint Patterns
# Extended endpoint patterns including template literals and environment variable URLs.
#          GraphQL, WebSocket, and more HTTP method variants
# ─────────────────────────────────────────

ENDPOINT_PATTERNS = [
    # REST API paths
    r'["\'`](/api/v?\d*/[a-zA-Z0-9/_-]+)["\' `]',
    r'["\'`](/api/[a-zA-Z0-9/_-]+)["\' `]',
    r'["\'`](/v\d+/[a-zA-Z0-9/_-]+)["\' `]',

    # Common sensitive paths
    r'["\'`](/admin[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/internal[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/private[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/dashboard[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/graphql[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/swagger[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/health[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/metrics[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/debug[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/config[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/user[s]?/[a-zA-Z0-9/_-]+)["\' `]',
    r'["\'`](/account[s]?/[a-zA-Z0-9/_-]+)["\' `]',
    r'["\'`](/payment[s]?/[a-zA-Z0-9/_-]+)["\' `]',
    # Additional sensitive path indicators.
    r'["\'`](/actuator[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/console[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/shell[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/upload[s]?[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/export[s]?[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/backup[s]?[a-zA-Z0-9/_-]*)["\' `]',
    r'["\'`](/report[s]?[a-zA-Z0-9/_-]*)["\' `]',

    # Full URLs pointing to same domain or subdomains
    r'["\'`](https?://[a-zA-Z0-9._-]+/api/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'["\'`](https?://[a-zA-Z0-9._-]+/v\d+/[a-zA-Z0-9/_?&=-]+)["\' `]',

    # Fetch/axios/XHR calls
    r'fetch\(["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'axios\.[a-z]+\(["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'\.get\(["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'\.post\(["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'\.put\(["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'\.delete\(["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'\.patch\(["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    # XMLHttpRequest URL patterns.
    r'\.open\(["\'][A-Z]+["\'],\s*["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',

    # URL construction patterns
    r'url\s*[:=]\s*["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'endpoint\s*[:=]\s*["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'path\s*[:=]\s*["\' `](\/[a-zA-Z0-9/_?&=-]+)["\' `]',
    r'baseURL\s*[:=]\s*["\' `](https?://[a-zA-Z0-9._/-]+)["\' `]',
    r'baseUrl\s*[:=]\s*["\' `](https?://[a-zA-Z0-9._/-]+)["\' `]',
    r'API_URL\s*[:=]\s*["\' `](https?://[a-zA-Z0-9._/-]+)["\' `]',
    # Template literal URL patterns.
    r'`\$\{[^}]+\}(/api/[a-zA-Z0-9/_?&=-]+)`',
    r'`\$\{[^}]+\}(/v\d+/[a-zA-Z0-9/_?&=-]+)`',
    # CommonJS and ES module import URL patterns.
    r'(?:require|import)\(["\' `](https?://[a-zA-Z0-9._/-]+)["\' `]\)',
    # WebSocket endpoint patterns.
    r'new WebSocket\(["\' `](wss?://[a-zA-Z0-9._/-]+)["\' `]\)',
    # Environment variable URL patterns.
    r'process\.env\.[A-Z_]*URL[A-Z_]*\s*\|\|\s*["\' `](https?://[a-zA-Z0-9._/-]+)["\' `]',
]

# ─────────────────────────────────────────
# Parameter Patterns (Upgrade)
# Extract interesting query parameters from URLs found in JS
# ─────────────────────────────────────────

INTERESTING_PARAMS = {
    "id", "user_id", "account_id", "order_id", "token", "key",
    "secret", "api_key", "auth", "session", "callback", "redirect",
    "next", "url", "file", "path", "cmd", "exec", "query",
    "search", "filter", "sort", "page", "limit", "offset",
    "ref", "debug", "admin", "role", "access", "scope",
}

# ─────────────────────────────────────────
# High Value Keywords
# ─────────────────────────────────────────

HIGH_VALUE_KEYWORDS = [
    "admin", "internal", "private", "debug", "config",
    "secret", "token", "key", "password", "credential",
    "user", "account", "payment", "transfer", "wallet",
    "export", "import", "backup", "dump", "log",
    "graphql", "swagger", "metrics", "health", "actuator",
    "ssn", "pii", "kyc", "verify", "console", "shell",
    # High-value endpoint indicators.
    "upload", "report", "invoice", "billing", "impersonate",
    "sudo", "root", "superuser", "system", "exec",
]


def is_high_value(endpoint):
    ep_lower = endpoint.lower()
    return any(kw in ep_lower for kw in HIGH_VALUE_KEYWORDS)


# ─────────────────────────────────────────
# False Positive Filter
# ─────────────────────────────────────────

FALSE_POSITIVE_PATHS = [
    r'^/static/', r'^/assets/', r'^/images/', r'^/img/',
    r'^/css/', r'^/fonts/', r'^/icons/', r'^/svg/',
    r'\.png$', r'\.jpg$', r'\.jpeg$', r'\.gif$',
    r'\.css$', r'\.woff', r'\.ttf', r'\.eot',
    r'^/$', r'^//$',
    # Low-value paths excluded from results.
    r'^/favicon', r'\.map$', r'\.min\.js$',
    r'^/robots', r'^/sitemap',
]


def is_false_positive(endpoint):
    for pattern in FALSE_POSITIVE_PATHS:
        if re.search(pattern, endpoint, re.IGNORECASE):
            return True
    if len(endpoint) < 4 or len(endpoint) > 200:
        return True
    return False


# ─────────────────────────────────────────
# Parameter Extractor (Upgrade)
# ─────────────────────────────────────────

def extract_interesting_params(endpoints):
    """
    Upgrade: scans extracted endpoints for interesting query parameters.
    Returns a dict of {param: [example_values]}.
    """
    found_params = {}
    for ep in endpoints:
        if "?" not in ep:
            continue
        try:
            qs = ep.split("?", 1)[1]
            params = parse_qs(qs)
            for param in params:
                if param.lower() in INTERESTING_PARAMS:
                    if param not in found_params:
                        found_params[param] = []
                    found_params[param].extend(params[param])
        except Exception:  # URL param extraction - skip malformed URL
            continue
    return found_params


# ─────────────────────────────────────────
# GraphQL Introspection Detector (Upgrade)
# ─────────────────────────────────────────

def check_graphql_introspection(base_url):
    """
    Upgrade: if a /graphql endpoint is found, checks if introspection is enabled.
    Introspection enabled = schema fully exposed = HIGH severity finding.
    """
    graphql_url = base_url.rstrip("/") + "/graphql"
    query = '{"query":"{__schema{types{name}}}"}'
    try:
        resp = httpx.post(
            graphql_url,
            content=query,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)",
            },
            timeout=TIMEOUT,
            verify=False,
        )
        if resp.status_code == 200 and "__schema" in resp.text:
            return True
    except Exception:  # GraphQL introspection request failed - non-web service or timeout
        pass
    return False


# ─────────────────────────────────────────
# Source Map Fetcher (Upgrade)
# ─────────────────────────────────────────

def fetch_source_map(js_url, headers):
    """
    Upgrade: checks for .map file alongside each JS file.
    Source maps often contain original unminified source with more endpoints.
    Returns content string or empty string.
    """
    map_url = js_url + ".map"
    try:
        resp = httpx.get(
            map_url,
            headers=headers,
            timeout=TIMEOUT,
            verify=False,
        )
        if resp.status_code == 200 and "sourcesContent" in resp.text:
            # Extract source contents from the map
            data = resp.json()
            sources = data.get("sourcesContent", [])
            return "\n".join(s for s in sources if s)
    except Exception:  # Source map parse failed - not a valid sourcemap
        pass
    return ""


# ─────────────────────────────────────────
# Subdomain Leakage Detector (Upgrade)
# ─────────────────────────────────────────

def extract_subdomains_from_js(content, base_domain):
    """
    Upgrade: scans JS content for hardcoded subdomains of the target domain.
    Useful for discovering internal/staging endpoints referenced in frontend code.
    """
    pattern   = rf'https?://([a-zA-Z0-9._-]+\.{re.escape(base_domain)})'
    matches   = re.findall(pattern, content, re.IGNORECASE)
    subdomains = set()
    for m in matches:
        host = m.lower()
        if host != base_domain:
            subdomains.add(host)
    return subdomains


# ─────────────────────────────────────────
# Extract Endpoints from Content
# ─────────────────────────────────────────

def extract_endpoints(content, base_url):
    """Extract all API endpoints from JS/HTML content."""
    found = set()

    for pattern in ENDPOINT_PATTERNS:
        try:
            matches = re.findall(pattern, content)
            for match in matches:
                endpoint = match.strip().rstrip("'\"` ")
                if not endpoint:
                    continue
                if is_false_positive(endpoint):
                    continue
                found.add(endpoint)
        except Exception:  # Endpoint regex failed on this content chunk - skip
            continue

    return found


# ─────────────────────────────────────────
# Extract JS URLs from Page
# ─────────────────────────────────────────

def get_js_urls(html, base_url):
    """Get all JS file URLs from a page."""
    js_urls = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            if src:
                full        = urljoin(base_url, src)
                parsed      = urlparse(full)
                base_parsed = urlparse(base_url)
                if base_parsed.netloc in parsed.netloc or \
                   parsed.netloc.endswith("." + base_parsed.netloc):
                    js_urls.add(full)
    except Exception:  # URL normalisation failed - skip malformed URL
        pass
    return js_urls


# ─────────────────────────────────────────
# Inline Script Extractor (Upgrade)
# ─────────────────────────────────────────

def extract_inline_scripts(html):
    """
    Upgrade: extracts content from inline <script> tags (no src attribute).
    Inline scripts often contain hardcoded API URLs and config objects.
    """
    content = ""
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=False):
            text = tag.get_text()
            if text:
                content += text + "\n"
    except Exception:  # Inline script tag extraction failed - skip
        pass
    return content


# ─────────────────────────────────────────
# Single Host Extractor
# ─────────────────────────────────────────

def extract_from_host(args):
    """Extract endpoints from a single host and all its JS files."""
    url, = args
    all_endpoints    = set()
    all_subdomains   = set()
    js_files_scanned = 0
    graphql_exposed  = False

    # Try to extract base domain for subdomain leakage detection
    try:
        parsed      = urlparse(url)
        netloc      = parsed.netloc
        parts       = netloc.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else netloc
    except Exception:  # Domain parse failed - use empty base_domain
        base_domain = ""  # URL parse failed — use empty base domain

    ua_headers = {"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}

    try:
        resp     = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                             verify=False, headers=ua_headers)
        html     = resp.text
        base_url = str(resp.url)

        # ── Main page endpoints ──
        all_endpoints.update(extract_endpoints(html, base_url))

        # ── Upgrade: inline script scanning ──
        inline_content = extract_inline_scripts(html)
        if inline_content:
            all_endpoints.update(extract_endpoints(inline_content, base_url))

        # ── Subdomain leakage from main page ──
        if base_domain:
            all_subdomains.update(extract_subdomains_from_js(html, base_domain))

        # ── JS files ──
        js_urls = get_js_urls(html, base_url)

        for js_url in list(js_urls)[:30]:
            try:
                js_resp = httpx.get(js_url, timeout=TIMEOUT, follow_redirects=True,
                                    verify=False, headers=ua_headers)
                js_content = js_resp.text

                all_endpoints.update(extract_endpoints(js_content, base_url))

                # Subdomain references extracted from JavaScript content.
                if base_domain:
                    all_subdomains.update(
                        extract_subdomains_from_js(js_content, base_domain)
                    )

                # Source map file scanning for original source code references.
                map_content = fetch_source_map(js_url, ua_headers)
                if map_content:
                    all_endpoints.update(extract_endpoints(map_content, base_url))

                js_files_scanned += 1
            except Exception:  # Single JS file scan failed - skip file
                continue

        # GraphQL introspection endpoint detection.
        has_graphql = any("graphql" in ep.lower() for ep in all_endpoints)
        if has_graphql:
            graphql_exposed = check_graphql_introspection(base_url)

    except Exception:  # Per-host JS extraction failed - skip host
        pass

    # Parameter extraction from discovered endpoints.
    interesting_params = extract_interesting_params(all_endpoints)

    # Categorise findings
    high_value = sorted(e for e in all_endpoints if is_high_value(e))
    normal     = sorted(e for e in all_endpoints if not is_high_value(e))

    return {
        "url":               url,
        "js_files_scanned":  js_files_scanned,
        "total_endpoints":   len(all_endpoints),
        "high_value":        high_value,
        "endpoints":         normal,
        # Extended result fields.
        "interesting_params":   interesting_params,
        "graphql_introspection": graphql_exposed,
        "leaked_subdomains":    sorted(all_subdomains),
    }


# ─────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────

def extract_js_endpoints(input_file, output_file):
    """
    Extracts hidden API endpoints from JS files across all live hosts.
    """

    if not os.path.exists(input_file):
        cprint(f"  [!] Input file not found: {input_file}", "red")
        return

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            passive_data = json.load(f)
    except Exception as e:
        cprint(f"  [!] Failed to read passive results: {e}", "red")
        return

    # Deduplicate by hostname
    seen = set()
    urls = []
    for entry in passive_data:
        hostname = entry.get("hostname", "")
        if hostname and hostname not in seen:
            seen.add(hostname)
            urls.append(entry.get("url", ""))

    if not urls:
        cprint("  [!] No live hosts to scan.", "yellow")
        return

    cprint(f"  [+] Extracting JS endpoints from {len(urls)} hosts...", "cyan")

    args = [(url,) for url in urls]

    with ThreadPool(THREADS) as pool:
        results = list(tqdm(
            pool.imap(extract_from_host, args),
            total=len(args),
            desc="  JS Extract",
            ncols=70
        ))

    # ── Summary ──
    total_endpoints    = sum(r["total_endpoints"] for r in results)
    total_high_value   = sum(len(r["high_value"]) for r in results)
    total_js_files     = sum(r["js_files_scanned"] for r in results)
    total_params       = sum(len(r["interesting_params"]) for r in results)
    total_subdomains   = sum(len(r["leaked_subdomains"]) for r in results)
    graphql_hosts      = [r["url"] for r in results if r.get("graphql_introspection")]

    cprint(f"\n  [✓] Scanned {total_js_files} JS files across {len(urls)} hosts", "green")
    cprint(f"  [+] Found {total_endpoints} unique endpoints", "cyan")

    if total_params:
        cprint(f"  [+] Found {total_params} interesting parameter type(s)", "cyan")

    if total_subdomains:
        cprint(f"  [+] Found {total_subdomains} leaked subdomain(s) in JS", "cyan")

    if graphql_hosts:
        cprint(f"\n  🚨 GraphQL introspection ENABLED on {len(graphql_hosts)} host(s):", "red")
        for h in graphql_hosts:
            cprint(f"      ⚠️  {h}/graphql", "red")

    if total_high_value:
        cprint(f"\n  🚨 {total_high_value} HIGH VALUE endpoints found!", "red")
        for r in results:
            if r["high_value"]:
                cprint(f"\n  [→] {r['url']}", "cyan")
                for ep in r["high_value"]:
                    cprint(f"      ⭐ {ep}", "yellow")
                if r.get("interesting_params"):
                    cprint(f"      🎯 Params: {list(r['interesting_params'].keys())}", "cyan")
                if r.get("leaked_subdomains"):
                    cprint(f"      🌐 Leaked subdomains: {r['leaked_subdomains']}", "cyan")

    # ── Save ──
    # Ensure output directory exists.
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        cprint(f"\n  [✓] JS endpoint results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to write results: {e}", "red")