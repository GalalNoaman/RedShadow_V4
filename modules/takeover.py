# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/takeover.py
# Subdomain takeover detection — v2
# Improvements:
#   - Severity now reflects confirmation state (CRITICAL=confirmed, HIGH=potential)
#   - Multiple fingerprints per service for better detection
#   - NXDOMAIN detection (dangling DNS)
#   - Confidence scoring (CONFIRMED / LIKELY / POTENTIAL)
#   - Added more services (40 total)

import os
import json
import dns.resolver
import httpx
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

config  = load_config(section="takeover")
THREADS = config.get("threads", 20)
TIMEOUT = config.get("timeout", 8)

# ─────────────────────────────────────────
# Vulnerable Service Fingerprints
#
# Each entry:
#   cname        → string to match in CNAME record
#   service      → human readable service name
#   fingerprints → list of strings — ANY match confirms unclaimed
#   nxdomain     → True if NXDOMAIN alone confirms takeover
# ─────────────────────────────────────────

FINGERPRINTS = [
    # ── GitHub Pages ──
    {
        "cname":        "github.io",
        "service":      "GitHub Pages",
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index",
            "githubapp.com",
        ],
        "nxdomain": False,
    },
    # ── Heroku ──
    {
        "cname":        "herokuapp.com",
        "service":      "Heroku",
        "fingerprints": [
            "No such app",
            "there is no app here",
            "herokucdn.com/error-pages/no-such-app",
        ],
        "nxdomain": False,
    },
    {
        "cname":        "herokussl.com",
        "service":      "Heroku SSL",
        "fingerprints": ["No such app"],
        "nxdomain": False,
    },
    # ── Netlify ──
    {
        "cname":        "netlify.app",
        "service":      "Netlify",
        "fingerprints": [
            "Not Found - Request ID",
            "netlify",
        ],
        "nxdomain": False,
    },
    {
        "cname":        "netlify.com",
        "service":      "Netlify",
        "fingerprints": ["Not Found - Request ID"],
        "nxdomain": False,
    },
    # ── Shopify ──
    {
        "cname":        "myshopify.com",
        "service":      "Shopify",
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "only accessible to authorized users",
        ],
        "nxdomain": False,
    },
    # ── AWS S3 ──
    {
        "cname":        "s3.amazonaws.com",
        "service":      "AWS S3",
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "nxdomain": False,
    },
    {
        "cname":        ".s3-website",
        "service":      "AWS S3 Website",
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "nxdomain": False,
    },
    # ── Azure ──
    {
        "cname":        "azurewebsites.net",
        "service":      "Azure Web Apps",
        "fingerprints": [
            "404 Web Site not found",
            "Microsoft Azure App Service",
            "does not exist",
        ],
        "nxdomain": False,
    },
    {
        "cname":        "cloudapp.net",
        "service":      "Azure Cloud",
        "fingerprints": ["404 Web Site not found"],
        "nxdomain": True,
    },
    {
        "cname":        "trafficmanager.net",
        "service":      "Azure Traffic Manager",
        "fingerprints": ["404 Web Site not found"],
        "nxdomain": True,
    },
    {
        "cname":        "blob.core.windows.net",
        "service":      "Azure Blob Storage",
        "fingerprints": [
            "BlobNotFound",
            "The specified resource does not exist",
        ],
        "nxdomain": False,
    },
    # ── Fastly ──
    {
        "cname":        "fastly.net",
        "service":      "Fastly",
        "fingerprints": [
            "Fastly error: unknown domain",
            "please check that this domain has been added",
        ],
        "nxdomain": False,
    },
    # ── Ghost ──
    {
        "cname":        "ghost.io",
        "service":      "Ghost",
        "fingerprints": [
            "The thing you were looking for is no longer here",
            "Ghost error",
        ],
        "nxdomain": False,
    },
    # ── Surge.sh ──
    {
        "cname":        "surge.sh",
        "service":      "Surge",
        "fingerprints": [
            "project not found",
            "surge.sh",
        ],
        "nxdomain": False,
    },
    # ── Tumblr ──
    {
        "cname":        "tumblr.com",
        "service":      "Tumblr",
        "fingerprints": [
            "Whatever you were looking for doesn't currently exist",
            "There's nothing here",
        ],
        "nxdomain": False,
    },
    # ── Pantheon ──
    {
        "cname":        "pantheonsite.io",
        "service":      "Pantheon",
        "fingerprints": [
            "The gods are wise",
            "pantheon.io/404",
        ],
        "nxdomain": False,
    },
    # ── Zendesk ──
    {
        "cname":        "zendesk.com",
        "service":      "Zendesk",
        "fingerprints": [
            "Help Center Closed",
            "Oops, this help center no longer exists",
        ],
        "nxdomain": False,
    },
    # ── Unbounce ──
    {
        "cname":        "unbouncepages.com",
        "service":      "Unbounce",
        "fingerprints": [
            "The requested URL was not found on this server",
            "unbounce",
        ],
        "nxdomain": False,
    },
    # ── Webflow ──
    {
        "cname":        "webflow.io",
        "service":      "Webflow",
        "fingerprints": [
            "The page you are looking for doesn't exist",
            "page not found",
        ],
        "nxdomain": False,
    },
    # ── Squarespace ──
    {
        "cname":        "squarespace.com",
        "service":      "Squarespace",
        "fingerprints": [
            "No Such Account",
            "squarespace.com",
        ],
        "nxdomain": False,
    },
    # ── HubSpot ──
    {
        "cname":        "hubspot.net",
        "service":      "HubSpot",
        "fingerprints": [
            "does not exist in our system",
            "hubspot.com/404",
        ],
        "nxdomain": False,
    },
    # ── Intercom ──
    {
        "cname":        "intercom.io",
        "service":      "Intercom",
        "fingerprints": [
            "This page is reserved for artistic dogs",
            "intercom.io",
        ],
        "nxdomain": False,
    },
    # ── Cargo ──
    {
        "cname":        "cargocollective.com",
        "service":      "Cargo Collective",
        "fingerprints": ["404 Not Found"],
        "nxdomain": False,
    },
    # ── Readme.io ──
    {
        "cname":        "readme.io",
        "service":      "Readme.io",
        "fingerprints": [
            "Project doesnt exist",
            "readme.io",
        ],
        "nxdomain": False,
    },
    # ── WordPress.com ──
    {
        "cname":        "wordpress.com",
        "service":      "WordPress.com",
        "fingerprints": [
            "Do you want to register",
            "doesn't exist",
        ],
        "nxdomain": False,
    },
    # ── Strikingly ──
    {
        "cname":        "strikingly.com",
        "service":      "Strikingly",
        "fingerprints": [
            "But if you're looking to build your own website",
            "strikingly.com",
        ],
        "nxdomain": False,
    },
    # ── Fly.io ──
    {
        "cname":        "fly.dev",
        "service":      "Fly.io",
        "fingerprints": [
            "404 Not Found",
            "fly.io",
        ],
        "nxdomain": False,
    },
    # ── Render ──
    {
        "cname":        "onrender.com",
        "service":      "Render",
        "fingerprints": [
            "There's nothing here yet",
            "render.com",
        ],
        "nxdomain": False,
    },
    # ── Vercel ──
    {
        "cname":        "vercel.app",
        "service":      "Vercel",
        "fingerprints": [
            "The deployment could not be found",
            "vercel.com/404",
        ],
        "nxdomain": False,
    },
    # ── Notion ──
    {
        "cname":        "notion.site",
        "service":      "Notion",
        "fingerprints": ["notion.so/404"],
        "nxdomain": False,
    },
    # ── JetBrains ──
    {
        "cname":        "myjetbrains.com",
        "service":      "JetBrains YouTrack",
        "fingerprints": ["is not a registered InCloud YouTrack"],
        "nxdomain": False,
    },
    # ── Kinsta ──
    {
        "cname":        "kinsta.cloud",
        "service":      "Kinsta",
        "fingerprints": ["No Site For Domain"],
        "nxdomain": False,
    },
    # ── Launchrock ──
    {
        "cname":        "launchrock.com",
        "service":      "Launchrock",
        "fingerprints": ["It looks like you may have taken a wrong turn"],
        "nxdomain": False,
    },
    # ── Pingdom ──
    {
        "cname":        "stats.pingdom.com",
        "service":      "Pingdom",
        "fingerprints": ["This public report page has not been activated"],
        "nxdomain": False,
    },
    # ── UserVoice ──
    {
        "cname":        "uservoice.com",
        "service":      "UserVoice",
        "fingerprints": ["This UserVoice subdomain is currently available"],
        "nxdomain": False,
    },
    # ── Statuspage ──
    {
        "cname":        "statuspage.io",
        "service":      "Statuspage",
        "fingerprints": ["You are being redirected"],
        "nxdomain": False,
    },
    # ── Acquia ──
    {
        "cname":        "acquia-sites.com",
        "service":      "Acquia",
        "fingerprints": ["If you are an Acquia Cloud customer"],
        "nxdomain": False,
    },
    # ── WP Engine ──
    {
        "cname":        "wpengine.com",
        "service":      "WP Engine",
        "fingerprints": ["The site you were looking for couldn't be found"],
        "nxdomain": False,
    },
]


# ─────────────────────────────────────────
# DNS Helpers
# ─────────────────────────────────────────

def get_cname(subdomain):
    """Returns the CNAME target for a subdomain, or None."""
    try:
        resolver          = dns.resolver.Resolver()
        resolver.timeout  = 3
        resolver.lifetime = 5
        answers = resolver.resolve(subdomain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:  # Subdomain CNAME resolution failed - not taken over
        return None


def is_nxdomain(subdomain):
    """Returns True if the subdomain does not resolve at all."""
    try:
        resolver          = dns.resolver.Resolver()
        resolver.timeout  = 3
        resolver.lifetime = 5
        resolver.resolve(subdomain, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:  # HTTP probe failed for takeover check - skip
        return False


# ─────────────────────────────────────────
# HTTP Fingerprint Check
# ─────────────────────────────────────────

def check_fingerprints(subdomain, fingerprints):
    """
    Fetches the subdomain and checks if ANY fingerprint appears
    in the response — confirming unclaimed service.

    Returns (confirmed: bool, matched_fingerprint: str)
    """
    for scheme in ["https://", "http://"]:
        try:
            response = httpx.get(
                scheme + subdomain,
                timeout=TIMEOUT,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; RedShadowBot/4.0)"}
            )
            body = response.text.lower()
            for fp in fingerprints:
                if fp.lower() in body:
                    return True, fp
        except Exception:  # Single subdomain takeover check failed - skip
            continue
    return False, ""


# ─────────────────────────────────────────
# Single Subdomain Check
# ─────────────────────────────────────────

def check_subdomain(subdomain):
    """
    Checks a single subdomain for takeover vulnerability.

    Confidence levels:
      CONFIRMED  → CNAME matches + HTTP fingerprint confirms unclaimed
      LIKELY     → CNAME matches + service is NXDOMAIN-vulnerable
      POTENTIAL  → CNAME matches + HTTP check inconclusive

    Severity:
      CRITICAL   → CONFIRMED
      HIGH       → LIKELY or POTENTIAL
    """
    cname = get_cname(subdomain)
    if not cname:
        return None

    for fp in FINGERPRINTS:
        if fp["cname"].lower() not in cname.lower():
            continue

        # ── Check HTTP fingerprint ──
        confirmed, matched_fp = check_fingerprints(subdomain, fp["fingerprints"])

        if confirmed:
            return {
                "subdomain":   subdomain,
                "cname":       cname,
                "service":     fp["service"],
                "severity":    "CRITICAL",
                "confidence":  "CONFIRMED",
                "confirmed":   True,
                "status":      "CONFIRMED VULNERABLE — fingerprint matched",
                "fingerprint": matched_fp,
            }

        # ── Check NXDOMAIN (dangling DNS) ──
        if fp.get("nxdomain") and is_nxdomain(cname):
            return {
                "subdomain":   subdomain,
                "cname":       cname,
                "service":     fp["service"],
                "severity":    "HIGH",
                "confidence":  "LIKELY",
                "confirmed":   False,
                "status":      "LIKELY VULNERABLE — CNAME target does not resolve (dangling DNS)",
                "fingerprint": "",
            }

        # ── CNAME match but fingerprint not found ──
        return {
            "subdomain":   subdomain,
            "cname":       cname,
            "service":     fp["service"],
            "severity":    "HIGH",
            "confidence":  "POTENTIAL",
            "confirmed":   False,
            "status":      "POTENTIAL — CNAME matches service, needs manual verification",
            "fingerprint": "",
        }

    return None


# ─────────────────────────────────────────
# Main Takeover Entry Point
# ─────────────────────────────────────────

def check_takeovers(input_file, output_file):
    """
    Checks all subdomains for takeover vulnerabilities.
    """

    if not os.path.exists(input_file):
        cprint(f"  [!] Subdomain file not found: {input_file}", "red")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        subdomains = [line.strip() for line in f if line.strip()]

    if not subdomains:
        cprint("  [!] No subdomains to check.", "yellow")
        return

    cprint(f"  [+] Checking {len(subdomains)} subdomains for takeover ({len(FINGERPRINTS)} services)...", "cyan")

    with ThreadPool(THREADS) as pool:
        results = list(tqdm(
            pool.imap(check_subdomain, subdomains),
            total=len(subdomains),
            desc="  Takeover Check",
            ncols=70
        ))

    findings  = [r for r in results if r is not None]
    confirmed = [f for f in findings if f["confidence"] == "CONFIRMED"]
    likely    = [f for f in findings if f["confidence"] == "LIKELY"]
    potential = [f for f in findings if f["confidence"] == "POTENTIAL"]

    if not findings:
        cprint("  [✓] No subdomain takeover vulnerabilities found.", "green")
    else:
        cprint(f"\n  [!] Found {len(findings)} takeover candidate(s)!", "red")

        if confirmed:
            cprint(f"\n  🚨 CONFIRMED VULNERABLE [{len(confirmed)}] — CRITICAL:", "red")
            for f in confirmed:
                cprint(f"      [CRITICAL] {f['subdomain']}", "red")
                cprint(f"              CNAME       → {f['cname']}", "red")
                cprint(f"              Service     → {f['service']}", "red")
                cprint(f"              Fingerprint → {f['fingerprint']}", "red")

        if likely:
            cprint(f"\n  ⚠️  LIKELY VULNERABLE [{len(likely)}] — HIGH (dangling DNS):", "yellow")
            for f in likely:
                cprint(f"      [HIGH] {f['subdomain']}", "yellow")
                cprint(f"              CNAME   → {f['cname']}", "yellow")
                cprint(f"              Service → {f['service']}", "yellow")
                cprint(f"              Status  → {f['status']}", "yellow")

        if potential:
            cprint(f"\n  🔵 POTENTIAL [{len(potential)}] — needs manual verification:", "cyan")
            for f in potential:
                cprint(f"      [HIGH] {f['subdomain']}", "cyan")
                cprint(f"              CNAME   → {f['cname']}", "cyan")
                cprint(f"              Service → {f['service']}", "cyan")

    # ── Save results ──
    # Safe directory creation for output files.
    # if output_file has no directory component. Using the consistent pattern.
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        cprint(f"\n  [✓] Takeover results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to write results: {e}", "red")