# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/githubscan.py
# GitHub secret scanner — searches public GitHub repos for leaked credentials
# GitHub secret scanner with rate limit handling and comprehensive query coverage.
#       improved patterns, progress counter, makedirs fix

import os
import re
import json
import time
import httpx
from termcolor import cprint
from modules.utils import load_config
from dotenv import load_dotenv

config  = load_config(section="githubscan")
TIMEOUT = config.get("timeout", 10)
load_dotenv()
TOKEN = config.get("token", "") or os.environ.get("GITHUB_TOKEN", "")

# Delay between requests (seconds)
# Rate limiting: 7 seconds between queries to stay within GitHub API limits.
# With 21 queries that's 147s of silent waiting. Now we warn the user
# upfront so they know what to expect, and back off on 403/429.
DELAY_NO_TOKEN  = 7.0   # 10 req/min limit without token
DELAY_WITH_TOKEN = 1.5  # safer cadence with token


# ─────────────────────────────────────────
# Search Queries
# 30 search queries covering common credential and secret leak patterns.
# ─────────────────────────────────────────

def build_queries(target):
    """Build GitHub search queries for a target domain."""
    company = target.split(".")[0]
    domain  = target

    return [
        # ── Credentials ──
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret_key',
        f'"{domain}" aws_secret',
        f'"{domain}" AKIA',
        f'"{domain}" private_key',
        f'"{domain}" access_token',
        f'"{domain}" auth_token',
        f'"{company}" db_password',
        f'"{company}" database_url',
        f'"{company}" mongodb',
        f'"{company}" postgres',
        # Extended credential detection patterns.
        f'"{company}" redis_url',
        f'"{company}" smtp_password',
        f'"{company}" secret_token',
        f'"{company}" client_secret',

        # ── Config files ──
        f'"{domain}" filename:.env',
        f'"{domain}" filename:config.yml',
        f'"{domain}" filename:settings.py',
        f'"{domain}" filename:database.yml',
        f'"{company}" filename:docker-compose.yml',
        # Additional configuration file patterns.
        f'"{company}" filename:.env.production',
        f'"{company}" filename:application.yml',
        f'"{company}" filename:secrets.yml',

        # ── AWS specific ──
        f'"{company}" AWS_ACCESS_KEY_ID',
        f'"{company}" AWS_SECRET_ACCESS_KEY',
        # GCP and Azure credential patterns.
        f'"{company}" GOOGLE_APPLICATION_CREDENTIALS',
        f'"{company}" AZURE_CLIENT_SECRET',

        # ── Internal domains ──
        f'"{company}.internal"',
        f'"{company}.corp"',
    ]


# ─────────────────────────────────────────
# Secret Patterns for Validation
# Extended patterns with reliable group extraction.
# ─────────────────────────────────────────

SECRET_PATTERNS = [
    {"name": "AWS Access Key",         "pattern": r'AKIA[0-9A-Z]{16}',                                           "severity": "CRITICAL"},
    {"name": "AWS Secret Key",         "pattern": r'(?i)aws.{0,10}secret.{0,10}["\']([A-Za-z0-9/+=]{40})["\']', "severity": "CRITICAL"},
    {"name": "Private Key",            "pattern": r'-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----',                   "severity": "CRITICAL"},
    {"name": "GitHub Token",           "pattern": r'ghp_[a-zA-Z0-9]{36}',                                        "severity": "CRITICAL"},
    {"name": "GitHub OAuth Token",     "pattern": r'gho_[a-zA-Z0-9]{36}',                                        "severity": "CRITICAL"},
    {"name": "Stripe Secret Key",      "pattern": r'sk_live_[0-9a-zA-Z]{24,}',                                   "severity": "CRITICAL"},
    {"name": "Razorpay Key",           "pattern": r'rzp_live_[a-zA-Z0-9]{14,}',                                  "severity": "CRITICAL"},
    # Extended credential patterns including SendGrid, Slack, and Firebase.
    {"name": "SendGrid API Key",       "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',                  "severity": "CRITICAL"},
    {"name": "Slack Token",            "pattern": r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}',         "severity": "HIGH"},
    {"name": "Google API Key",         "pattern": r'AIza[0-9A-Za-z_-]{35}',                                      "severity": "HIGH"},
    {"name": "Password in code",       "pattern": r'(?i)password\s*=\s*["\']([^"\']{8,})["\']',                  "severity": "HIGH"},
    {"name": "Database URL",           "pattern": r'(mysql|postgres|mongodb|redis)://[^\s"\'<>]+',                "severity": "HIGH"},
    {"name": "API Key",                "pattern": r'(?i)api[_-]?key\s*=\s*["\']([a-zA-Z0-9_-]{20,})["\']',      "severity": "HIGH"},
    {"name": "Bearer Token",           "pattern": r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{40,})',                       "severity": "HIGH"},
    {"name": "JWT Token",              "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',                 "severity": "MEDIUM"},
    {"name": "Internal URL",           "pattern": r'https?://[a-z0-9.-]+\.(internal|corp|local)[/\s]',           "severity": "MEDIUM"},
    # GCP service account key detection pattern.
    {"name": "GCP Service Account",    "pattern": r'"type"\s*:\s*"service_account"',                             "severity": "CRITICAL"},
    {"name": "Private Key ID (GCP)",   "pattern": r'"private_key_id"\s*:\s*"([a-f0-9]{40})"',                    "severity": "CRITICAL"},
]


def find_secrets_in_content(content):
    """Scan code content for secret patterns."""
    findings = []
    seen     = set()

    for p in SECRET_PATTERNS:
        try:
            matches = re.findall(p["pattern"], content)
            for m in matches:
                # Handle tuple groups from patterns with capture groups
                if isinstance(m, tuple):
                    val = next((x for x in m if x), "")
                else:
                    val = m
                val = val.strip()[:100]
                key = f"{p['name']}:{val[:20]}"
                if key not in seen and len(val) > 4:
                    seen.add(key)
                    findings.append({
                        "name":     p["name"],
                        "severity": p["severity"],
                        "value":    val,
                    })
        except Exception:  # GitHub API request failed - skip this search query
            continue

    return findings


# ─────────────────────────────────────────
# GitHub API Search
# Retry logic with rate limit and authentication error handling.
# ─────────────────────────────────────────

def search_github(query, headers, retries=2):
    """
    Search GitHub code for a query.
    Returns list of result items, or empty list on failure.
    Upgrade: retries on 429 with exponential backoff.
    """
    url    = "https://api.github.com/search/code"
    params = {"q": query, "per_page": 10}

    for attempt in range(retries + 1):
        try:
            resp = httpx.get(url, params=params, headers=headers, timeout=TIMEOUT)

            if resp.status_code == 200:
                return resp.json().get("items", [])

            elif resp.status_code == 429:
                # Handle 429 Too Many Requests with exponential backoff.
                retry_after = int(resp.headers.get("retry-after", 60))
                cprint(f"  [!] GitHub 429 — waiting {retry_after}s before retry...", "yellow")
                time.sleep(retry_after)
                continue

            elif resp.status_code == 403:
                remaining = resp.headers.get("x-ratelimit-remaining", "?")
                if remaining == "0":
                    reset_ts  = int(resp.headers.get("x-ratelimit-reset", 0))
                    wait_secs = max(0, reset_ts - int(time.time())) + 2
                    cprint(f"  [!] GitHub rate limit exhausted — waiting {wait_secs}s", "yellow")
                    time.sleep(min(wait_secs, 120))   # cap at 2 min
                    continue
                else:
                    cprint("  [!] GitHub 403 — check token permissions", "yellow")
                    return []

            elif resp.status_code == 422:
                return []   # Invalid query — skip silently

            elif resp.status_code == 401:
                cprint("  [!] GitHub 401 — token is invalid or expired", "red")
                return []

        except Exception:  # GitHub file fetch failed - skip this file
            pass

    return []


def fetch_file_content(url, headers):
    """Fetch raw file content from GitHub."""
    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com")
        raw_url = raw_url.replace("/blob/", "/")
        resp    = httpx.get(raw_url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.text[:8000]   # Increased response size for better coverage.
    except Exception:  # Per-repo GitHub scan failed - skip repo
        pass
    return ""


# ─────────────────────────────────────────
# Main GitHub Scanner Entry Point
# ─────────────────────────────────────────

def scan_github(target, output_file):
    """
    Searches GitHub for exposed credentials and secrets related to the target.
    """

    headers = {
        "Accept":     "application/vnd.github.v3+json",
        "User-Agent": "RedShadowBot/4.0",
    }

    if TOKEN:
        headers["Authorization"] = f"token {TOKEN}"
        delay = DELAY_WITH_TOKEN
        cprint("  [+] Using GitHub token for higher rate limits", "green")
    else:
        delay = DELAY_NO_TOKEN
        cprint("  [ℹ] No GitHub token — limited to 10 requests/min", "yellow")
        cprint("  [ℹ] Add token to config.yaml under githubscan.token", "yellow")

    queries = build_queries(target)

    # Upfront time estimate so the operator knows the scan is running.
    estimated_secs = int(len(queries) * delay)
    if estimated_secs > 30:
        mins = estimated_secs // 60
        secs = estimated_secs % 60
        cprint(
            f"  [ℹ] {len(queries)} queries × {delay}s delay = "
            f"~{mins}m {secs}s estimated runtime",
            "yellow"
        )

    all_findings = []
    seen_urls    = set()

    cprint(f"  [+] Running {len(queries)} GitHub searches for {target}...", "cyan")

    for i, query in enumerate(queries, 1):
        # Progress tracking for API queries.
        cprint(f"  [{i}/{len(queries)}] {query}", "cyan")

        items = search_github(query, headers)

        for item in items:
            file_url = item.get("html_url", "")
            repo     = item.get("repository", {}).get("full_name", "N/A")

            if file_url in seen_urls:
                continue
            seen_urls.add(file_url)

            content = fetch_file_content(file_url, headers)
            secrets = find_secrets_in_content(content)

            if secrets:
                all_findings.append({
                    "query":    query,
                    "repo":     repo,
                    "file_url": file_url,
                    "secrets":  secrets,
                })
                cprint(f"\n  🚨 Found in {repo}:", "red")
                for s in secrets:
                    colour = "red" if s["severity"] == "CRITICAL" else "yellow"
                    cprint(f"      [{s['severity']}] {s['name']} → {s['value'][:50]}", colour)
                cprint(f"      URL: {file_url}", "cyan")

        time.sleep(delay)

    # ── Summary ──
    total    = len(all_findings)
    critical = sum(1 for f in all_findings for s in f["secrets"] if s["severity"] == "CRITICAL")
    high     = sum(1 for f in all_findings for s in f["secrets"] if s["severity"] == "HIGH")

    if not all_findings:
        cprint(f"  [✓] No leaked secrets found on GitHub for {target}", "green")
    else:
        cprint(f"\n  🚨 Found {total} file(s) with secrets!", "red")
        cprint(f"  CRITICAL: {critical} | HIGH: {high}", "red")

    # ── Save ──
    results = {
        "target":      target,
        "queries_run": len(queries),
        "files_found": total,
        "critical":    critical,
        "high":        high,
        "findings":    all_findings,
    }

    # Ensure output directory exists.
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        cprint(f"\n  [✓] GitHub scan results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to save: {e}", "red")