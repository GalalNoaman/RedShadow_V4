# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/bruteforce.py
# DNS bruteforce subdomain discovery
# v3 — deep wildcard detection (multi-probe, A+AAAA+CNAME), thread-local resolvers,
#       real retry logic, rich DNS results (IP + record type + CNAME target),
#       dual output (txt + JSON), clean permutation signature, live stats

import os
import json
import time
import random
import string
import threading
import dns.resolver
from tqdm import tqdm
from termcolor import cprint
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import load_config

config      = load_config(section="bruteforce")
THREADS     = config.get("threads", 30)
TIMEOUT     = config.get("timeout", 2)
DNS_SERVERS = config.get("dns_servers", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])

# Retry settings
MAX_RETRIES = 2      # retries per record type on SERVFAIL / timeout
RETRY_DELAY = 0.1    # seconds between retries

# ─────────────────────────────────────────
# Thread-local Resolver Pool (Fix)
# Shared resolver instance for efficient DNS lookups.
# With 30 threads × thousands of words that's thousands of object creations.
# Thread-local storage gives each thread one persistent pre-configured resolver.
# ─────────────────────────────────────────

_thread_local = threading.local()


def get_resolver():
    """Returns a thread-local pre-configured resolver (created once per thread)."""
    if not hasattr(_thread_local, "resolver"):
        r             = dns.resolver.Resolver()
        r.nameservers = DNS_SERVERS
        r.timeout     = TIMEOUT
        r.lifetime    = TIMEOUT * (MAX_RETRIES + 1)
        _thread_local.resolver = r
    return _thread_local.resolver


# ─────────────────────────────────────────
# Wordlist Paths — in priority order
# ─────────────────────────────────────────

WORDLIST_PATHS = [
    os.path.expanduser("~/RedShadow_V4/data/wordlists/redshadow_dns_wordlist.txt"),
    os.path.expanduser("~/RedShadow_V4/data/wordlists/subdomains-top1million-5000.txt"),
    os.path.expanduser("~/RedShadow_V4/data/wordlists/dns-Jhaddix.txt"),
]

# ─────────────────────────────────────────
# Built-in Wordlist (expanded)
# ─────────────────────────────────────────

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "mx", "mx1", "mx2",
    "api", "dev", "staging", "stage", "test", "qa", "uat", "demo", "beta",
    "app", "apps", "web", "portal", "admin", "administrator", "dashboard",
    "login", "auth", "sso", "oauth", "ldap", "vpn", "ssh", "remote",
    "cdn", "static", "assets", "img", "images", "media", "files", "upload",
    "blog", "news", "shop", "store", "cart", "payment", "checkout",
    "support", "help", "docs", "documentation", "wiki", "kb", "status",
    "monitor", "metrics", "grafana", "kibana", "jenkins", "ci", "git",
    "gitlab", "github", "bitbucket", "jira", "confluence", "slack",
    "aws", "s3", "gcp", "azure", "cloud", "k8s", "kubernetes", "docker",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "internal", "intranet", "corp", "corporate", "office", "hr", "finance",
    "sandbox", "preview", "preprod", "pre-prod", "production", "prod",
    "v1", "v2", "v3", "v4", "api-v1", "api-v2", "api-v3",
    "mobile", "m", "wap", "android", "ios", "app-api",
    "analytics", "tracking", "reports", "reporting", "data",
    "email", "smtp2", "imap", "webmail", "mail2", "mta",
    "secure", "ssl", "tls", "gateway", "proxy", "load-balancer",
    "backup", "bak", "archive", "old", "new", "tmp", "temp",
    "search", "autocomplete", "suggest", "recommend",
    "user", "users", "account", "accounts", "profile", "profiles",
    "notifications", "alerts", "webhooks", "callback", "events",
    "ws", "websocket", "socket", "stream", "live", "realtime",
    "health", "ping", "echo", "info", "version", "release",
    "download", "downloads", "releases", "update", "updates",
    "partner", "partners", "affiliate", "affiliates", "vendor", "vendors",
    "contractor", "contractors", "supplier", "suppliers", "client", "clients",
    "customer", "customers", "member", "members", "subscriber", "subscribers",
    "blog2", "forum", "community", "social", "chat", "messaging",
    "dev2", "dev3", "test2", "test3", "staging2", "uat2",
    "exchange", "hub", "central", "core", "base", "platform",
    "connect", "integration", "webhook", "hook", "trigger",
    "report", "invoice", "billing", "subscription", "plan", "pricing",
    "public", "private", "share", "shared", "global",
    "east", "west", "north", "south", "us", "eu", "uk", "ap",
    "us-east", "us-west", "eu-west", "ap-southeast", "ap-northeast",
    "origin", "edge", "node", "worker", "compute", "server",
    "jumbo", "lambda", "function", "serverless",
    "console", "panel", "manage", "management", "ops", "operations",
    "infra", "infrastructure", "network", "net", "vpn2",
    "devops", "sre", "deploy", "build",
    "airflow", "celery", "rabbitmq", "kafka", "nats",
    "vault", "secrets", "keys", "certs", "pki",
    "prometheus", "alertmanager", "loki", "jaeger", "zipkin",
    "sonar", "sonarqube", "nexus", "artifactory",
    "registry", "containers", "pods",
    "test-api", "dev-api", "staging-api", "prod-api",
    "api2", "api3", "rest", "graphql", "grpc",
    "crm", "erp", "hrms", "itsm", "cms",
    "partner-api", "vendor-api", "external", "public-api",
    "onboarding", "signup", "register",
    "pay", "payments", "wallet", "transfer", "fx",
    "audit", "compliance", "legal", "risk",
    "ds", "ml", "ai", "model", "inference",
]


# ─────────────────────────────────────────
# Deep Wildcard Detection (Fix + Upgrade)
# Multi-probe wildcard detection using multiple random labels.
# Problems solved:
#   - wildcards can return multiple rotating IPs
#   - wildcards may exist only for AAAA (IPv6)
#   - CNAME-based wildcards were missed entirely
# Now: probes 5 random labels across A + AAAA + CNAME,
#      builds a complete set of wildcard answers for each type.
# ─────────────────────────────────────────

def detect_wildcard(target, probes=5):
    """
    Deep wildcard detection using multiple random probes across A, AAAA, CNAME.

    Returns:
        {
          "A":      set of wildcard IPv4 addresses,
          "AAAA":   set of wildcard IPv6 addresses,
          "CNAME":  set of wildcard CNAME targets,
          "active": bool
        }
    """
    wildcard = {"A": set(), "AAAA": set(), "CNAME": set(), "active": False}
    resolver = get_resolver()

    for _ in range(probes):
        label    = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        hostname = f"{label}.{target}"

        for rtype in ("A", "AAAA", "CNAME"):
            try:
                answers = resolver.resolve(hostname, rtype)
                for rdata in answers:
                    value = str(rdata).rstrip(".")
                    wildcard[rtype].add(value)
                    wildcard["active"] = True
            except Exception:
                pass

    return wildcard


def is_wildcard_match(result, wildcard):
    """
    Returns True if a resolved result matches any known wildcard answer.
    Checks the resolved value against the correct record-type wildcard set.
    """
    if not wildcard["active"]:
        return False
    rtype = result.get("record_type", "")
    value = result.get("value", "")
    # Also check all_values in case primary differs from wildcard set
    all_values = result.get("all_values", [value])
    return bool(wildcard.get(rtype, set()) & set(all_values))


# ─────────────────────────────────────────
# Permutation Generator (Fix)
# Generates permutations from the target domain components.
# misleading signature. Now just takes target, which is all it needs.
# ─────────────────────────────────────────

def generate_permutations(target):
    """
    Generates company-name permutation candidates.
    e.g. target=acme.com → "acme-api", "api-acme", "acme-dev", ...
    """
    company = target.split(".")[0].lower()
    combos  = [
        "api", "dev", "staging", "prod", "internal",
        "admin", "app", "web", "mobile", "portal",
        "backend", "frontend", "service", "services",
        "data", "db", "auth", "sso", "cdn",
        "test", "qa", "uat", "sandbox", "demo",
        "ops", "devops", "infra", "platform", "cloud",
        "secure", "vpn", "remote", "gateway",
        "backup", "archive", "logs", "monitor",
    ]
    perms = set()
    for word in combos:
        perms.add(f"{company}-{word}")
        perms.add(f"{word}-{company}")
    return perms


# ─────────────────────────────────────────
# Load Wordlist
# ─────────────────────────────────────────

def load_wordlist(custom_path=None):
    """Priority: custom → downloaded → built-in"""
    if custom_path and os.path.exists(custom_path):
        with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        cprint(f"  [+] Using custom wordlist: {len(words):,} words from {custom_path}", "cyan")
        return words

    for path in WORDLIST_PATHS:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if words:
                cprint(f"  [+] Using downloaded wordlist: {len(words):,} words from {os.path.basename(path)}", "cyan")
                return words

    cprint(f"  [+] Using built-in wordlist ({len(BUILTIN_WORDLIST)} entries)", "yellow")
    cprint(f"  [ℹ] Run data/wordlists/update_wordlist.sh for 10,000+ words", "yellow")
    return BUILTIN_WORDLIST


# ─────────────────────────────────────────
# DNS Resolver with Real Retry Logic (Fix + Upgrade)
# DNS resolution with retry logic and exponential backoff.
# Returns full CNAME chain target for takeover analysis.
# Now:
#   - retries MAX_RETRIES times on SERVFAIL / timeout with RETRY_DELAY between
#   - returns rich dict with all DNS details
#   - CNAME stores the actual target and resolves it to an IP if possible
#   - uses thread-local resolver (no per-call object creation)
# ─────────────────────────────────────────

def resolve_subdomain(args):
    """
    Resolves a subdomain using A → AAAA → CNAME with real retry logic.

    Returns rich result dict:
        {
          "hostname":     "api.target.com",
          "record_type":  "A" | "AAAA" | "CNAME",
          "value":        "1.2.3.4",
          "all_values":   ["1.2.3.4", "5.6.7.8"],
          "cname_target": "api.cdn.net"   ← only present for CNAME
        }
    Returns None if unresolvable.
    """
    subdomain, target = args
    hostname = f"{subdomain}.{target}"
    resolver = get_resolver()

    for rtype in ("A", "AAAA", "CNAME"):
        for attempt in range(MAX_RETRIES + 1):
            try:
                answers    = resolver.resolve(hostname, rtype)
                all_values = [str(r).rstrip(".") for r in answers]
                primary    = all_values[0] if all_values else ""

                result = {
                    "hostname":    hostname,
                    "record_type": rtype,
                    "value":       primary,
                    "all_values":  all_values,
                }

                # Store CNAME target and resolve to IP for takeover validation.
                if rtype == "CNAME":
                    result["cname_target"] = primary
                    try:
                        a_answers         = resolver.resolve(primary, "A")
                        result["value"]      = a_answers[0].to_text()
                        result["all_values"] = [r.to_text() for r in a_answers]
                    except Exception:
                        result["value"] = primary   # keep CNAME as value if A fails

                return result

            except dns.resolver.NXDOMAIN:
                break   # definitive non-existence — no point retrying
            except dns.resolver.NoAnswer:
                break   # this record type doesn't exist for this host
            except (dns.resolver.Timeout, dns.resolver.NoNameservers):
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)
                    continue
                break   # exhausted retries for this record type
            except Exception:
                break

    return None


# ─────────────────────────────────────────
# Main DNS Bruteforce Entry Point
# ─────────────────────────────────────────

def dns_bruteforce(target, output_file, wordlist=None):
    """
    Bruteforces subdomains using DNS resolution.

    Outputs:
      - subdomains.txt       (simple hostname list, pipeline-compatible)
      - subdomains_dns.json  (rich DNS data: IPs, record types, CNAME targets)

    Args:
        target (str):      Root domain to bruteforce
        output_file (str): Path to write/append subdomains to (.txt)
        wordlist (str):    Optional path to custom wordlist
    """

    # ── Deep wildcard detection ──
    cprint(f"  [+] Running deep wildcard detection (5 probes × A + AAAA + CNAME)...", "cyan")
    wildcard = detect_wildcard(target, probes=5)

    if wildcard["active"]:
        cprint(f"  [!] Wildcard DNS active on {target}!", "yellow")
        if wildcard["A"]:
            cprint(f"      A     wildcard IPs    : {wildcard['A']}", "yellow")
        if wildcard["AAAA"]:
            cprint(f"      AAAA  wildcard IPs    : {wildcard['AAAA']}", "yellow")
        if wildcard["CNAME"]:
            cprint(f"      CNAME wildcard targets: {wildcard['CNAME']}", "yellow")
        cprint(f"  [!] Wildcard results will be filtered automatically", "yellow")
    else:
        cprint(f"  [✓] No wildcard DNS detected — results will be reliable", "green")

    # ── Load existing subdomains ──
    existing = set()
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            existing = {line.strip() for line in f if line.strip()}

    # ── Load wordlist + permutations ──
    words     = load_wordlist(wordlist)
    perms     = generate_permutations(target)   
    all_words = list(dict.fromkeys(list(words) + list(perms)))
    cprint(
        f"  [+] {len(words):,} wordlist + {len(perms)} permutations "
        f"= {len(all_words):,} total candidates",
        "cyan"
    )

    candidates = [w for w in all_words if f"{w}.{target}" not in existing]

    if not candidates:
        cprint(f"  [!] No new candidates to bruteforce.", "yellow")
        return

    cprint(f"  [+] Bruteforcing {len(candidates):,} new candidates against {target}...", "cyan")

    args           = [(word, target) for word in candidates]
    found_results  = []
    wildcard_hits  = 0
    total_resolved = 0
    lock           = threading.Lock()

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(resolve_subdomain, arg): arg for arg in args}
        with tqdm(total=len(args), desc="  DNS Bruteforce", ncols=70) as pbar:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    if is_wildcard_match(result, wildcard):
                        with lock:
                            wildcard_hits += 1
                    else:
                        with lock:
                            found_results.append(result)
                            total_resolved += 1
                            pbar.set_postfix({"found": total_resolved}, refresh=False)
                pbar.update(1)

    # ── Filter already-existing ──
    new_results = [r for r in found_results if r["hostname"] not in existing]

    if not new_results:
        cprint(f"  [!] No new subdomains discovered.", "yellow")
        if wildcard_hits:
            cprint(f"  [ℹ] {wildcard_hits} wildcard matches were filtered", "yellow")
        return

    # ── Save simple .txt (pipeline-compatible) ──
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    with open(output_file, "a", encoding="utf-8") as f:
        for r in sorted(new_results, key=lambda x: x["hostname"]):
            f.write(r["hostname"] + "\n")

    # ── Save rich DNS JSON alongside .txt (Fix: preserves all DNS detail) ──
    json_output = output_file.replace(".txt", "_dns.json")
    try:
        existing_json  = []
        if os.path.exists(json_output):
            with open(json_output, "r", encoding="utf-8") as f:
                existing_json = json.load(f)
        existing_hosts = {e["hostname"] for e in existing_json}
        merged = existing_json + [r for r in new_results if r["hostname"] not in existing_hosts]
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)
    except Exception as e:
        cprint(f"  [!] Could not save DNS JSON: {e}", "yellow")

    # ── Summary ──
    by_type = {}
    for r in new_results:
        rtype = r["record_type"]
        by_type[rtype] = by_type.get(rtype, 0) + 1

    cprint(f"\n  [✓] Found {len(new_results)} new subdomains → {output_file}", "green")
    for rtype, count in sorted(by_type.items()):
        cprint(f"      {rtype:6s} records  : {count}", "cyan")
    if wildcard_hits:
        cprint(f"      Wildcard filtered : {wildcard_hits}", "yellow")
    cprint(f"      Rich DNS data     : {json_output}", "cyan")

    # ── Preview top findings ──
    cprint(f"\n  Discovered subdomains (top 20):", "cyan")
    for r in sorted(new_results, key=lambda x: x["hostname"])[:20]:
        cname_tag = f" → CNAME:{r['cname_target']}" if r.get("cname_target") else ""
        cprint(f"      [{r['record_type']}] {r['hostname']} ({r['value']}){cname_tag}", "green")
    if len(new_results) > 20:
        cprint(f"      ... and {len(new_results) - 20} more (see {output_file})", "cyan")