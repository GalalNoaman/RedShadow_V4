# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/redirect.py
# Open redirect detection module
# Tests common redirect parameters for unvalidated redirects

import os
import json
import httpx
import time
from urllib.parse import urlparse
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

config  = load_config(section="redirect")
THREADS = config.get("threads", 10)
TIMEOUT = config.get("timeout", 8)
DELAY   = config.get("delay", 0.2)

# ─────────────────────────────────────────
# Canary URL — what we inject to test redirects
# ─────────────────────────────────────────

CANARY        = "https://evil.com"
CANARY_DOMAIN = "evil.com"

# Pre-build all three quote variants once so we're not rebuilding them
# inside the hot path on every request.
# Tests multiple redirect parameter formats for comprehensive coverage.
# but missed url="https://evil.com" (double-quoted), which is the most common
# HTML form: <meta http-equiv="refresh" content="0; url="https://evil.com"">
_CANARY_LOWER         = CANARY.lower()
_META_UNQUOTED        = f"url={_CANARY_LOWER}"
_META_SINGLE_QUOTED   = f"url='{_CANARY_LOWER}'"
_META_DOUBLE_QUOTED   = f'url="{_CANARY_LOWER}"'

# ─────────────────────────────────────────
# Common redirect parameters to test
# ─────────────────────────────────────────

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "next_url", "return", "return_url", "returnUrl",
    "goto", "goto_url", "target", "target_url",
    "link", "link_url", "forward", "forward_url",
    "continue", "continue_url", "dest", "destination",
    "go", "out", "view", "ref", "redir",
    "location", "back", "callback", "callback_url",
    "success_url", "cancel_url", "login_url",
    "logout_url", "logout_redirect",
    "auth_redirect", "to", "path",
]

# ─────────────────────────────────────────
# Common paths that often have redirects
# ─────────────────────────────────────────

REDIRECT_PATHS = [
    "/",
    "/login",
    "/logout",
    "/signin",
    "/signout",
    "/auth",
    "/oauth",
    "/redirect",
    "/go",
    "/out",
    "/forward",
    "/track",
    "/click",
    "/link",
    "/api/redirect",
    "/api/auth",
]


# ─────────────────────────────────────────
# Redirect Validator
# ─────────────────────────────────────────

def is_real_redirect(location, original_host):
    """
    Validates that a redirect is genuinely going to an external domain.

    A real open redirect:
    - Goes to a completely different domain (evil.com)
    - Does NOT stay on the same host (http → https upgrade is NOT a redirect)
    - Does NOT just add our canary as a query param on the same domain
    """
    if not location:
        return False

    try:
        parsed_location = urlparse(location)
        location_host   = parsed_location.netloc.lower().lstrip("www.")
        original_clean  = original_host.lower().lstrip("www.")

        # Must redirect to a completely different domain
        if location_host == original_clean:
            return False

        # Must contain our canary domain
        if CANARY_DOMAIN not in location_host:
            return False

        return True

    except Exception:
        return False


# ─────────────────────────────────────────
# Meta Refresh Validator
# ─────────────────────────────────────────

def is_meta_redirect(body):
    """
    Checks whether a page body contains a meta refresh redirect to the canary.

    Fix: original only checked unquoted and single-quoted variants:
        url=https://evil.com
        url='https://evil.com'
    This missed the double-quoted form which is the most common in real HTML:
        url="https://evil.com"
    All three variants are now checked.
    """
    if "meta" not in body or "refresh" not in body or CANARY_DOMAIN not in body:
        return False

    return (
        _META_UNQUOTED      in body or
        _META_SINGLE_QUOTED in body or
        _META_DOUBLE_QUOTED in body
    )


# ─────────────────────────────────────────
# Single URL Redirect Test
# ─────────────────────────────────────────

def test_redirect(url, param, path="/"):
    """
    Tests a single URL + parameter combination for open redirect.
    Returns a finding dict if genuinely vulnerable, None otherwise.
    """
    test_url = f"{url.rstrip('/')}{path}?{param}={CANARY}"

    try:
        parsed      = urlparse(url)
        target_host = parsed.netloc

        response = httpx.get(
            test_url,
            timeout=TIMEOUT,
            follow_redirects=False,
            verify=False
        )

        # ── Header-based redirect ──
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "")
            if is_real_redirect(location, target_host):
                return {
                    "type":         "open_redirect",
                    "name":         f"Open Redirect via `{param}` parameter",
                    "severity":     "HIGH",
                    "url":          test_url,
                    "parameter":    param,
                    "path":         path,
                    "redirects_to": location,
                    "status":       response.status_code,
                    "confirmed":    True,
                }

        # ── Meta refresh redirect ──
        if response.status_code == 200:
            body = response.text.lower()
            if is_meta_redirect(body):
                return {
                    "type":         "open_redirect_meta",
                    "name":         f"Open Redirect (meta refresh) via `{param}` parameter",
                    "severity":     "MEDIUM",
                    "url":          test_url,
                    "parameter":    param,
                    "path":         path,
                    "redirects_to": CANARY,
                    "status":       response.status_code,
                    "confirmed":    True,
                }

    except Exception:
        pass

    return None


# ─────────────────────────────────────────
# Single Host Redirect Check
# ─────────────────────────────────────────

def check_host_redirects(args):
    """
    Tests all redirect parameter + path combinations for a single host.
    Returns list of findings.
    """
    url, = args
    findings = []

    for path in REDIRECT_PATHS:
        for param in REDIRECT_PARAMS:
            result = test_redirect(url, param, path)
            if result:
                findings.append(result)
                break  # Found one on this path — move to next path
            time.sleep(DELAY)

    return {"url": url, "findings": findings}


# ─────────────────────────────────────────
# Main Redirect Detection Entry Point
# ─────────────────────────────────────────

def check_redirects(input_file, output_file):
    """
    Checks all live hosts for open redirect vulnerabilities.
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

    # ── Extract base URLs (deduplicated by hostname) ──
    seen_hosts = set()
    urls       = []
    for entry in passive_data:
        url      = entry.get("url", "")
        hostname = entry.get("hostname", "")
        if hostname and hostname not in seen_hosts:
            seen_hosts.add(hostname)
            urls.append(url)

    if not urls:
        cprint("  [!] No live hosts found to test.", "yellow")
        return

    total_tests = len(urls) * len(REDIRECT_PATHS) * len(REDIRECT_PARAMS)
    cprint(f"  [+] Testing {len(urls)} hosts × {len(REDIRECT_PATHS)} paths × {len(REDIRECT_PARAMS)} params = {total_tests} checks...", "cyan")

    args = [(url,) for url in urls]

    with ThreadPool(THREADS) as pool:
        raw = list(tqdm(
            pool.imap(check_host_redirects, args),
            total=len(args),
            desc="  Redirect Check",
            ncols=70
        ))

    results        = [entry for entry in raw if entry["findings"]]
    total_findings = sum(len(e["findings"]) for e in results)

    if not results:
        cprint("  [✓] No open redirect vulnerabilities found.", "green")
    else:
        cprint(f"\n  [!] Found {total_findings} confirmed open redirect(s) across {len(results)} host(s)!", "red")
        for entry in results:
            cprint(f"\n  [→] {entry['url']}", "cyan")
            for f in entry["findings"]:
                cprint(f"      [HIGH] {f['name']}", "red")
                cprint(f"             URL          : {f['url']}", "yellow")
                cprint(f"             Redirects to : {f['redirects_to']}", "yellow")

    # ── Save results ──
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        cprint(f"\n  [✓] Redirect results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to write results: {e}", "red")