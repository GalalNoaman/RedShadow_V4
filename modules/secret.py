# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/secret.py
# Secret scanner — finds exposed API keys, tokens, passwords in JS/HTML
# Secret and credential scanner with entropy checking and confidence scoring.

import os
import re
import json
import math
import httpx
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin, urlparse
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

# ── Suppress XML parsing warnings ──
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

config  = load_config(section="secret")
THREADS = config.get("threads", 10)
TIMEOUT = config.get("timeout", 8)

# ─────────────────────────────────────────
# Secret Patterns
# confidence: HIGH = strong pattern, specific format
# confidence: MEDIUM = generic pattern, needs review
# ─────────────────────────────────────────

PATTERNS = [
    # ── AWS ──
    {
        "name":       "AWS Access Key ID",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'AKIA[0-9A-Z]{16}',
        "min_length": 20,
        "entropy":    3.5,
    },
    {
        "name":       "AWS Secret Access Key",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
        "min_length": 40,
        "entropy":    4.0,
    },
    {
        "name":       "AWS Session Token",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'(?i)aws.{0,20}session.{0,20}["\']([A-Za-z0-9/+=]{100,})["\']',
        "min_length": 100,
        "entropy":    4.0,
    },

    # ── Private Keys ──
    {
        "name":       "RSA Private Key",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'-----BEGIN RSA PRIVATE KEY-----',
        "min_length": 0,
        "entropy":    0,
    },
    {
        "name":       "EC Private Key",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'-----BEGIN EC PRIVATE KEY-----',
        "min_length": 0,
        "entropy":    0,
    },
    {
        "name":       "Private Key (generic)",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'-----BEGIN PRIVATE KEY-----',
        "min_length": 0,
        "entropy":    0,
    },

    # ── GitHub Tokens ──
    {
        "name":       "GitHub Personal Access Token",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'ghp_[a-zA-Z0-9]{36}',
        "min_length": 40,
        "entropy":    4.0,
    },
    {
        "name":       "GitHub OAuth Token",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'gho_[a-zA-Z0-9]{36}',
        "min_length": 40,
        "entropy":    4.0,
    },
    {
        "name":       "GitHub App Token",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'ghs_[a-zA-Z0-9]{36}',
        "min_length": 40,
        "entropy":    4.0,
    },

    # ── Communication Tokens ──
    {
        "name":       "Slack Bot Token",
        "severity":   "HIGH",
        "confidence": "HIGH",
        "pattern":    r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}',
        "min_length": 50,
        "entropy":    3.5,
    },
    {
        "name":       "Slack Webhook URL",
        "severity":   "HIGH",
        "confidence": "HIGH",
        "pattern":    r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        "min_length": 60,
        "entropy":    3.0,
    },

    # ── Google ──
    {
        "name":       "Google API Key",
        "severity":   "HIGH",
        "confidence": "HIGH",
        "pattern":    r'AIza[0-9A-Za-z_-]{35}',
        "min_length": 39,
        "entropy":    3.5,
    },
    {
        "name":       "Firebase API Key",
        "severity":   "HIGH",
        "confidence": "HIGH",
        "pattern":    r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        "min_length": 150,
        "entropy":    4.0,
    },

    # ── Payment ──
    {
        "name":       "Stripe Secret Key",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'sk_live_[0-9a-zA-Z]{24,}',
        "min_length": 32,
        "entropy":    3.5,
    },
    {
        "name":       "Stripe Publishable Key",
        "severity":   "MEDIUM",
        "confidence": "HIGH",
        "pattern":    r'pk_live_[0-9a-zA-Z]{24,}',
        "min_length": 32,
        "entropy":    3.5,
    },
    {
        "name":       "Razorpay Live Key",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'rzp_live_[a-zA-Z0-9]{14,}',
        "min_length": 22,
        "entropy":    3.0,
    },
    {
        "name":       "PayPal Client ID",
        "severity":   "MEDIUM",
        "confidence": "MEDIUM",
        "pattern":    r'(?i)paypal.{0,20}client.{0,10}["\']([A-Za-z0-9_-]{50,})["\']',
        "min_length": 50,
        "entropy":    3.5,
    },

    # ── Email Services ──
    {
        "name":       "SendGrid API Key",
        "severity":   "HIGH",
        "confidence": "HIGH",
        "pattern":    r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        "min_length": 69,
        "entropy":    4.0,
    },
    {
        "name":       "Mailgun API Key",
        "severity":   "HIGH",
        "confidence": "HIGH",
        "pattern":    r'key-[0-9a-zA-Z]{32}',
        "min_length": 36,
        "entropy":    3.5,
    },
    {
        "name":       "Twilio API Key",
        "severity":   "HIGH",
        "confidence": "MEDIUM",
        "pattern":    r'SK[0-9a-fA-F]{32}',
        "min_length": 34,
        "entropy":    3.5,
    },

    # ── JWT ──
    {
        "name":       "JWT Token",
        "severity":   "HIGH",
        "confidence": "MEDIUM",
        "pattern":    r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "min_length": 50,
        "entropy":    3.5,
    },

    # ── Database URLs ──
    {
        "name":       "MySQL Connection String",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'mysql://[a-zA-Z0-9_-]+:[^@\s"\'<>]{4,}@[a-zA-Z0-9._-]+',
        "min_length": 20,
        "entropy":    2.5,
    },
    {
        "name":       "PostgreSQL Connection",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'postgres(?:ql)?://[a-zA-Z0-9_-]+:[^@\s"\'<>]{4,}@[a-zA-Z0-9._-]+',
        "min_length": 20,
        "entropy":    2.5,
    },
    {
        "name":       "MongoDB Connection",
        "severity":   "CRITICAL",
        "confidence": "HIGH",
        "pattern":    r'mongodb(\+srv)?://[a-zA-Z0-9_-]+:[^@\s"\'<>]{4,}@[a-zA-Z0-9._-]+',
        "min_length": 20,
        "entropy":    2.5,
    },
    {
        "name":       "Redis Connection",
        "severity":   "HIGH",
        "confidence": "HIGH",
        "pattern":    r'redis://[a-zA-Z0-9_-]+:[^@\s"\'<>]{4,}@[a-zA-Z0-9._-]+',
        "min_length": 15,
        "entropy":    2.5,
    },

    # ── Generic (MEDIUM confidence — needs review) ──
    {
        "name":       "Generic API Key",
        "severity":   "MEDIUM",
        "confidence": "MEDIUM",
        "pattern":    r'(?i)["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,})["\']',
        "min_length": 32,
        "entropy":    3.5,
    },
    {
        "name":       "Generic Secret Key",
        "severity":   "MEDIUM",
        "confidence": "MEDIUM",
        "pattern":    r'(?i)["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,})["\']',
        "min_length": 32,
        "entropy":    3.5,
    },
    {
        "name":       "Generic Password",
        "severity":   "MEDIUM",
        "confidence": "LOW",
        "pattern":    r'(?i)["\']?password["\']?\s*[:=]\s*["\']([^"\'<>\s]{12,})["\']',
        "min_length": 12,
        "entropy":    3.0,
    },
    {
        "name":       "Bearer Token",
        "severity":   "HIGH",
        "confidence": "MEDIUM",
        "pattern":    r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{40,})',
        "min_length": 40,
        "entropy":    3.5,
    },

    # ── Cloud Storage ──
    {
        "name":       "S3 Bucket URL",
        "severity":   "MEDIUM",
        "confidence": "HIGH",
        "pattern":    r'https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com',
        "min_length": 20,
        "entropy":    0,
    },
    {
        "name":       "Azure Blob Storage",
        "severity":   "MEDIUM",
        "confidence": "HIGH",
        "pattern":    r'https?://[a-z0-9]+\.blob\.core\.windows\.net',
        "min_length": 20,
        "entropy":    0,
    },
    {
        "name":       "GCP Storage Bucket",
        "severity":   "MEDIUM",
        "confidence": "HIGH",
        "pattern":    r'https?://storage\.googleapis\.com/[a-z0-9._-]+',
        "min_length": 20,
        "entropy":    0,
    },

    # ── Internal Infrastructure ──
    {
        "name":       "Internal URL",
        "severity":   "MEDIUM",
        "confidence": "MEDIUM",
        "pattern":    r'https?://[a-z0-9.-]+\.(internal|local|corp|intra)[/\s"\']',
        "min_length": 15,
        "entropy":    0,
    },
    {
        "name":       "Private IP Address",
        "severity":   "LOW",
        "confidence": "HIGH",
        "pattern":    r'(?:^|[^0-9])(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}(?:[^0-9]|$)',
        "min_length": 7,
        "entropy":    0,
    },
]

# ─────────────────────────────────────────
# False Positive Patterns
# These values are NEVER real secrets
# ─────────────────────────────────────────

FALSE_POSITIVE_EXACT = {
    "UPDATE_PASSWORD",
    "YOUR_PASSWORD",
    "YOUR_API_KEY",
    "YOUR_SECRET",
    "ENTER_YOUR",
    "ADD_YOUR",
    "password123",
    "changeme",
    "mustbeatleast",
    "Must be same",
    "set_cart_cancel_token",
    "access_token_secret",
    "your_token_here",
    "insert_token_here",
    "token_placeholder",
}

FALSE_POSITIVE_PATTERNS = [
    r'example\.com',
    r'localhost',
    # False positive filter patterns for common placeholder values.
    # had no word boundaries, so they matched real secrets containing those words anywhere
    # (e.g. a real API key like "ghp_Atest12345..." would be silently dropped).
    # Changed to \b word boundaries so only standalone words are filtered.
    r'\btest\b',
    r'\bdemo\b',
    r'\bsample\b',
    r'\bplaceholder\b',
    r'\bdummy\b',
    r'YOUR_',
    r'<YOUR',
    r'INSERT_',
    r'ENTER_',
    r'ADD_YOUR',
    r'xxxx+',
    r'0{6,}',
    r'1234567',
    r'abcdef',
    r'\bpassword\b',      # generic word "password" as a value (word boundary safe)
    r'\$\{',             # template variables like ${VAR}
    r'process\.env\.',   # Node.js env vars
    r'os\.environ',      # Python env vars
    r'must.{0,20}same',  # UI strings
    r'must.{0,20}match', # UI strings
    r'least.{0,5}\d+.{0,10}char', # password requirements
    r'hex\}',            # code fragments
    r'utf8tohex',        # code fragments
    r'rstrtohex',        # code fragments
    r'^[a-f0-9\.]+$',    # OIDs like 1.2.840.113549
    r'\.\d+\.\d+\.\d+',  # version numbers / OIDs
]

# Minimum entropy for random-looking secrets
ENTROPY_THRESHOLD = 2.5


# ─────────────────────────────────────────
# Entropy Calculator
# ─────────────────────────────────────────

def calculate_entropy(value):
    """
    Calculates Shannon entropy of a string.
    Real secrets have high entropy (>3.5).
    Readable strings have low entropy (<2.5).
    """
    if not value:
        return 0.0
    freq   = {}
    for c in value:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length  = len(value)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ─────────────────────────────────────────
# False Positive Checker
# ─────────────────────────────────────────

def is_false_positive(value, pattern_def):
    """
    Multi-layered false positive detection.
    Returns True if the value is likely NOT a real secret.
    """
    if not value:
        return True

    # ── Exact match against known false positives ──
    for fp in FALSE_POSITIVE_EXACT:
        if fp.lower() in value.lower():
            return True

    # ── Regex pattern matching ──
    for fp_pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(fp_pattern, value, re.IGNORECASE):
            return True

    # ── Minimum length check ──
    min_len = pattern_def.get("min_length", 8)
    if min_len > 0 and len(value) < min_len:
        return True

    # ── Entropy check (skip for URL patterns and key headers) ──
    required_entropy = pattern_def.get("entropy", 0)
    if required_entropy > 0:
        entropy = calculate_entropy(value)
        if entropy < required_entropy:
            return True

    # ── Repeated character check ──
    # Real secrets don't have 6+ repeated characters
    if re.search(r'(.)\1{5,}', value):
        return True

    # ── All same case with no digits = probably a word not a secret ──
    if value.isalpha() and len(value) < 20:
        return True

    return False


# ─────────────────────────────────────────
# JS File Extractor
# ─────────────────────────────────────────

def extract_js_urls(html, base_url):
    """Extracts all JS file URLs from a page."""
    js_urls = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            if src:
                full_url    = urljoin(base_url, src)
                parsed_full = urlparse(full_url)
                parsed_base = urlparse(base_url)
                if parsed_full.netloc == parsed_base.netloc:
                    js_urls.add(full_url)
    except Exception:  # URL parse failed - skip malformed URL
        pass
    return js_urls


# ─────────────────────────────────────────
# Content Scanner
# ─────────────────────────────────────────

def scan_content(content, source_url):
    """
    Scans content for secret patterns.
    Returns list of findings with confidence scores.
    """
    findings = []
    seen     = set()

    for pattern_def in PATTERNS:
        try:
            matches = re.findall(pattern_def["pattern"], content)
            for match in matches:
                # Extract value from group or full match
                if isinstance(match, tuple):
                    value = next((m for m in match if m), "")
                else:
                    value = match

                value = value.strip()

                if not value or len(value) < 6:
                    continue

                if is_false_positive(value, pattern_def):
                    continue

                # Deduplicate
                dedup_key = f"{pattern_def['name']}:{value[:30]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                entropy = calculate_entropy(value)

                findings.append({
                    "name":       pattern_def["name"],
                    "severity":   pattern_def["severity"],
                    "confidence": pattern_def["confidence"],
                    "value":      value[:120] + "..." if len(value) > 120 else value,
                    "url":        source_url,
                    "entropy":    round(entropy, 2),
                })

        except Exception:  # Pattern match failed on this finding - skip
            continue

    return findings


# ─────────────────────────────────────────
# Single Host Scanner
# ─────────────────────────────────────────

def scan_host(args):
    """Scans a single host — main page + all linked JS files."""
    url, = args
    all_findings = []
    scanned_urls = set()

    try:
        response = httpx.get(
            url,
            timeout=TIMEOUT,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
        )

        html     = response.text
        base_url = str(response.url)
        scanned_urls.add(url)

        all_findings.extend(scan_content(html, url))

        js_urls = extract_js_urls(html, base_url)

        for js_url in list(js_urls)[:20]:
            if js_url in scanned_urls:
                continue
            scanned_urls.add(js_url)
            try:
                js_resp = httpx.get(
                    js_url,
                    timeout=TIMEOUT,
                    follow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
                )
                all_findings.extend(scan_content(js_resp.text, js_url))
            except Exception:  # JS file fetch/scan failed - skip this URL
                continue

    except Exception:  # Per-host secret scan failed - skip host
        pass

    return {
        "url":           url,
        "findings":      all_findings,
        "files_scanned": len(scanned_urls),
    }


# ─────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────

def scan_secrets(input_file, output_file):
    """
    Scans all live hosts for exposed secrets in HTML and JS files.
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

    # ── Extract unique hosts ──
    seen_hosts = set()
    urls       = []
    for entry in passive_data:
        url      = entry.get("url", "")
        hostname = entry.get("hostname", "")
        if hostname and hostname not in seen_hosts:
            seen_hosts.add(hostname)
            urls.append(url)

    if not urls:
        cprint("  [!] No live hosts to scan.", "yellow")
        return

    cprint(f"  [+] Scanning {len(urls)} hosts for exposed secrets...", "cyan")

    args = [(url,) for url in urls]

    with ThreadPool(THREADS) as pool:
        raw = list(tqdm(
            pool.imap(scan_host, args),
            total=len(args),
            desc="  Secret Scan",
            ncols=70
        ))

    results   = [e for e in raw if e["findings"]]
    total     = sum(len(e["findings"]) for e in results)
    critical  = sum(1 for e in results for f in e["findings"] if f["severity"] == "CRITICAL")
    high      = sum(1 for e in results for f in e["findings"] if f["severity"] == "HIGH")
    med       = sum(1 for e in results for f in e["findings"] if f["severity"] == "MEDIUM")
    high_conf = sum(1 for e in results for f in e["findings"] if f["confidence"] == "HIGH")

    if not results:
        cprint("  [✓] No secrets found.", "green")
    else:
        cprint(f"\n  [!] Found {total} secret(s) across {len(results)} host(s)!", "red")
        cprint(f"  🚨 CRITICAL : {critical}", "red")
        cprint(f"  ⚠️  HIGH     : {high}", "yellow")
        cprint(f"  🔵 MEDIUM   : {med}", "cyan")
        cprint(f"  ✅ High confidence findings: {high_conf}", "green")

        for entry in results:
            if not entry["findings"]:
                continue
            cprint(f"\n  [→] {entry['url']}", "cyan")
            for f in entry["findings"]:
                colour    = "red" if f["severity"] == "CRITICAL" else \
                            "yellow" if f["severity"] == "HIGH" else "cyan"
                conf_icon = "✅" if f["confidence"] == "HIGH" else \
                            "⚠️ " if f["confidence"] == "MEDIUM" else "❓"
                cprint(f"      [{f['severity']}] {conf_icon} {f['name']}", colour)
                cprint(f"             Value      : {f['value']}", colour)
                cprint(f"             Confidence : {f['confidence']} (entropy: {f['entropy']})", colour)
                cprint(f"             Found      : {f['url']}", colour)

    # ── Save results ──
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        cprint(f"\n  [✓] Secret scan results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to write results: {e}", "red")