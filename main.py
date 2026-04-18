# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/main.py
# Main entry point — command routing for all pipeline modes.
#       new standalone commands: probe, takeover, secret, s3, wayback,
#       github, js, redirect, cache
#       hardened path validation, startup banner, graceful keyboard interrupt

import argparse
import re
import sys
import os
from termcolor import cprint

TOOL_VERSION = "4.0"

# ─────────────────────────────────────────
# Validation Helpers
# ─────────────────────────────────────────

def is_valid_domain(domain: str) -> bool:
    """Validates a root domain name."""
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain))


def is_valid_ip(value: str) -> bool:
    """
    Validates a single IPv4 address using Python's ipaddress module.
    Rejects values like 999.999.999.999 that regex would accept.
    """
    import ipaddress
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_cidr(value: str) -> bool:
    """
    Validates an IPv4 CIDR block using Python's ipaddress module.
    Requires "/" to be present — bare IPs like "10.0.0.0" are rejected.
    Rejects invalid prefixes like /99 that regex would accept.
    """
    import ipaddress
    value = str(value).strip()
    if "/" not in value:
        return False   # bare IPs are not CIDRs
    try:
        ipaddress.IPv4Network(value, strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False


def is_ip_target(value: str) -> bool:
    """True for IPs or CIDR blocks (not domains)."""
    return is_valid_ip(value) or is_valid_cidr(value)


def expand_cidr(cidr: str):
    """
    Expand a CIDR block to individual IP strings.
    Capped at /16 (65534 hosts) to prevent accidental huge expansions.
    Uses ipaddress module — invalid CIDRs raise ValueError immediately.
    """
    import ipaddress
    try:
        net = ipaddress.IPv4Network(cidr.strip(), strict=False)
        if net.num_addresses > 65536:
            raise ValueError(f"CIDR {cidr} is too large (max /16 = 65536 hosts)")
        return [str(ip) for ip in net.hosts()]
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as ex:
        raise ValueError(f"Invalid CIDR {cidr!r}: {ex}") from ex


def load_targets_file(path: str):
    """
    Load targets from a plain-text file — one per line.
    Accepts: IPv4 addresses, CIDR blocks, domain names.
    Comments (#) and blank lines are skipped.
    CIDR blocks are expanded to individual IPs.
    Returns (ip_list, domain_list) sorted and deduplicated.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Targets file not found: {path!r}")
    ips     = set()
    domains = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            val = line.strip()
            if not val or val.startswith("#"):
                continue
            if is_valid_cidr(val):
                ips.update(expand_cidr(val))
            elif is_valid_ip(val):
                ips.add(val)
            elif is_valid_domain(val):
                domains.add(val)
            else:
                cprint(f"  [!] Skipping unrecognised target: {val!r}", "yellow")
    return sorted(ips), sorted(domains)


def is_safe_path(path: str) -> bool:
    """
    Hardened path safety check.
    Rejects: path traversal (..), absolute paths, null bytes, shell metacharacters.
    """
    if not path:
        return True
    if ".." in path:
        return False
    if path.startswith("/") or path.startswith("\\"):
        return False
    if "\x00" in path:
        return False
    # Reject shell metacharacters that shouldn't appear in file paths
    if re.search(r'[;&|`$<>]', path):
        return False
    return True


def validate_path(path: str, name: str):
    """Raises ValueError if path is unsafe."""
    if path and not is_safe_path(path):
        raise ValueError(f"Unsafe path detected for {name}: {path!r}")


# ─────────────────────────────────────────
# Banner
# ─────────────────────────────────────────

def print_banner():
    cprint(r"""
  ██████╗ ███████╗██████╗ ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ██████╔╝█████╗  ██║  ██║███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ██║  ██║███████╗██████╔╝███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
""", "red")
    cprint(f"  🛡️  RedShadow V{TOOL_VERSION} — Red Team Recon Framework", "cyan")
    cprint(f"  Developed by Galal Noaman | For lawful use only\n", "white")


# ─────────────────────────────────────────
# Argument Parser
# ─────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redshadow",
        description="🛡️ RedShadow V4 — Red Team Reconnaissance and CVE Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  auto        Full 14-stage recon pipeline (recommended)
  domain      Subdomain enumeration via crt.sh
  bruteforce  DNS bruteforce subdomain discovery
  passive     Passive recon (headers, tech, status)
  probe       Active HTTP vulnerability probing
  takeover    Subdomain takeover detection
  secret      Secret & credential scanner
  s3          S3/GCS/Azure bucket scanner
  js          JavaScript endpoint extractor
  wayback     Wayback Machine archived URL scanner
  github      GitHub secret scanner
  redirect    Open redirect detection
  scan        Nmap port scanner
  analyse     CVE analysis from scan results
  report      Generate HTML + Markdown report
  cache       Manage NVD CVE cache

Examples:
  python main.py auto --target example.com
  python main.py auto --target example.com --resume
  python main.py auto --target example.com --no-bruteforce --insecure
  python main.py probe --input outputs/passive_results.json
  python main.py cache --clear
        """
    )
    parser.add_argument("-v", "--version", action="version", version=f"RedShadow V{TOOL_VERSION}")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-banner", action="store_true", help="Suppress startup banner")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── auto ──
    p = sub.add_parser("auto", help="Run full 15-stage recon pipeline")
    # Target: domain OR IP/CIDR. Exactly one of --target / --targets / --ips required.
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target",  help="Single domain target (e.g. hackerone.com)")
    tgt.add_argument("--targets", help="File of targets — one domain/IP/CIDR per line")
    tgt.add_argument("--ips",     help="Comma-separated IPs or CIDRs (e.g. 10.0.0.1,10.0.1.0/24)")
    p.add_argument("--output-dir",    default="outputs",         help="Output directory (default: outputs)")
    p.add_argument("--wordlist",      default=None,              help="Path to custom DNS wordlist")
    p.add_argument("--insecure",      action="store_true",       help="Disable TLS verification")
    p.add_argument("--no-bruteforce", action="store_true",       help="Skip DNS bruteforce stage")
    p.add_argument("--resume",        action="store_true",       help="Resume from last completed stage")
    p.add_argument("--debug",         action="store_true",       help="Enable debug logging")
    p.add_argument("--quiet",         action="store_true",       help="Suppress non-essential output")

    # Dedicated IP-mode command (alias for auto with IP targets)
    p2 = sub.add_parser("scan-ips", help="IP-mode pipeline — port scan + probe + CVE + report (no domain stages)")
    tgt2 = p2.add_mutually_exclusive_group(required=True)
    tgt2.add_argument("--targets", help="File of IPs/CIDRs — one per line")
    tgt2.add_argument("--ips",     help="Comma-separated IPs or CIDRs")
    p2.add_argument("--output-dir", default="outputs", help="Output directory (default: outputs)")
    p2.add_argument("--insecure",   action="store_true", help="Disable TLS verification")
    p2.add_argument("--resume",     action="store_true", help="Resume from last completed stage")
    p2.add_argument("--triage",     action="store_true",
                    help="Fast triage mode — skips open redirect and S3 scanning (~70%% faster). "
                         "Use for quick first-pass on many IPs.")
    p2.add_argument("--debug",      action="store_true", help="Enable debug logging (verbose stage details)")
    p2.add_argument("--quiet",      action="store_true", help="Suppress non-essential console output")
    p2.add_argument("--fast",       action="store_true",
                    help="Alias for --triage. Fast first-pass: skips redirect and S3.")
    p2.add_argument("--deep",       action="store_true",
                    help="Deep mode: runs all stages including redirect and S3 (default without --triage/--fast).")
    p2.add_argument("--format",     default="all", choices=["all", "html", "md", "json"],
                    help="Report output format (default: all — HTML + Markdown)")
    p2.add_argument("--threads",    type=int, default=None,
                    help="Override thread count for all scanning stages")
    p2.add_argument("--timeout",    type=int, default=None,
                    help="Override timeout (seconds) for HTTP stages")
    p2.add_argument("--ports",      default=None,
                    help="Comma-separated port list to scan (overrides config.yaml). "
                         "Example: --ports 443,8080,8443,7999  "
                         "Use this to stay within authorised scope.")

    # ── domain ──
    p = sub.add_parser("domain", help="Enumerate subdomains via crt.sh")
    p.add_argument("--target",  required=True,                   help="Target root domain")
    p.add_argument("--output",  default="outputs/subdomains.txt",help="Output path")

    # ── bruteforce ──
    p = sub.add_parser("bruteforce", help="DNS bruteforce subdomain discovery")
    p.add_argument("--target",   required=True,                   help="Target root domain")
    p.add_argument("--output",   default="outputs/subdomains.txt",help="Output path (appends to existing)")
    p.add_argument("--wordlist", default=None,                    help="Path to custom wordlist")

    # ── passive ──
    p = sub.add_parser("passive", help="Passive recon — headers, tech stack, status codes")
    p.add_argument("--input",    default="outputs/subdomains.txt",      help="Subdomains file")
    p.add_argument("--output",   default="outputs/passive_results.json",help="Output path")
    p.add_argument("--insecure", action="store_true",                   help="Disable TLS verification")
    p.add_argument("--verbose",  action="store_true",                   help="Show connection errors")

    # ── probe ──
    p = sub.add_parser("probe", help="Active HTTP vulnerability probing (100+ checks)")
    p.add_argument("--input",    default="outputs/passive_results.json",help="passive_results.json path")
    p.add_argument("--output",   default="outputs/probe_results.json",  help="Output path")
    p.add_argument("--insecure", action="store_true",                   help="Disable TLS verification")

    # ── takeover ──
    p = sub.add_parser("takeover", help="Subdomain takeover detection (40 services)")
    p.add_argument("--input",  default="outputs/subdomains.txt",         help="Subdomains file")
    p.add_argument("--output", default="outputs/takeover_results.json",  help="Output path")

    # ── secret ──
    p = sub.add_parser("secret", help="Secret & credential scanner (JS + HTML)")
    p.add_argument("--input",  default="outputs/passive_results.json",   help="passive_results.json path")
    p.add_argument("--output", default="outputs/secret_results.json",    help="Output path")

    # ── s3 ──
    p = sub.add_parser("s3", help="S3/GCS/Azure bucket scanner")
    p.add_argument("--target",      required=True,                   help="Target root domain")
    p.add_argument("--output",      default="outputs/s3_results.json",help="Output path")
    p.add_argument("--secret-file", default=None,                    help="secret_results.json (enriches bucket names)")

    # ── js ──
    p = sub.add_parser("js", help="JavaScript endpoint extractor")
    p.add_argument("--input",  default="outputs/passive_results.json",   help="passive_results.json path")
    p.add_argument("--output", default="outputs/js_results.json",        help="Output path")

    # ── wayback ──
    p = sub.add_parser("wayback", help="Wayback Machine archived URL scanner")
    p.add_argument("--target", required=True,                           help="Target root domain")
    p.add_argument("--output", default="outputs/wayback_results.json",  help="Output path")

    # ── github ──
    p = sub.add_parser("github", help="GitHub secret scanner")
    p.add_argument("--target", required=True,                           help="Target root domain")
    p.add_argument("--output", default="outputs/github_results.json",   help="Output path")

    # ── redirect ──
    p = sub.add_parser("redirect", help="Open redirect vulnerability detection")
    p.add_argument("--input",  default="outputs/passive_results.json",   help="passive_results.json path")
    p.add_argument("--output", default="outputs/redirect_results.json",  help="Output path")

    # ── scan ──
    p = sub.add_parser("scan", help="Nmap port scan with service detection")
    p.add_argument("--input",  required=True,                           help="Input file with domains")
    p.add_argument("--output", default="outputs/scan_results.json",     help="Output path")

    # ── analyse ──
    p = sub.add_parser("analyse", help="CVE analysis from scan results (NVD + EPSS)")
    p.add_argument("--input",  default="outputs/scan_results.json",     help="scan_results.json path")
    p.add_argument("--output", default="outputs/analysis_results.json", help="Output path")

    # ── report ──
    p = sub.add_parser("report", help="Generate Markdown + HTML report")
    p.add_argument("--input",       default="outputs/analysis_results.json", help="analysis_results.json path")
    p.add_argument("--output",      default="outputs/redshadow_report.md",   help="Markdown output path")
    p.add_argument("--html",        default="outputs/redshadow_report.html", help="HTML output path")
    p.add_argument("--output-dir",  default="outputs",                       help="Directory for all input files")

    # ── cache (new) ──
    p = sub.add_parser("cache", help="Manage NVD CVE cache")
    p.add_argument("--clear", action="store_true", help="Clear expired cache entries")
    p.add_argument("--stats", action="store_true", help="Show cache statistics")
    p.add_argument("--purge", action="store_true", help="Delete ALL cache entries (forces fresh lookup)")

    # ── correlate ──
    p = sub.add_parser("correlate", help="Run attack path correlation on existing outputs (Stage 14)")
    p.add_argument("--output-dir", default="outputs", help="Directory containing stage output files (default: outputs)")

    return parser


# ─────────────────────────────────────────
# Command Dispatch
# ─────────────────────────────────────────

def dispatch(args):

    # ── auto ──
    if args.command in ("auto", "scan-ips"):
        validate_path(args.output_dir, "--output-dir")

        # Resolve what targets were given
        ip_list     = []
        domain_list = []

        if getattr(args, "targets", None):
            validate_path(args.targets, "--targets")
            ip_list, domain_list = load_targets_file(args.targets)
        elif getattr(args, "ips", None):
            for raw in args.ips.split(","):
                val = raw.strip()
                if is_valid_cidr(val):
                    ip_list.extend(expand_cidr(val))
                elif is_valid_ip(val):
                    ip_list.append(val)
                else:
                    raise ValueError(f"Not a valid IP or CIDR: {val!r}")
        elif getattr(args, "target", None):
            t = args.target
            if is_valid_ip(t) or is_valid_cidr(t):
                if is_valid_cidr(t):
                    ip_list = expand_cidr(t)
                else:
                    ip_list = [t]
            elif is_valid_domain(t):
                domain_list = [t]
            else:
                raise ValueError(f"Not a valid domain, IP, or CIDR: {t!r}")

        # Deduplicate
        ip_list     = sorted(set(ip_list))
        domain_list = sorted(set(domain_list))

        # Route to correct pipeline
        if ip_list and not domain_list:
            # Pure IP mode
            from modules.pipeline_ip import run_pipeline_ip
            # --fast is an alias for --triage
            use_triage = getattr(args, "triage", False) or getattr(args, "fast", False)
            # --deep explicitly disables triage even if triage_by_default is set
            if getattr(args, "deep", False):
                use_triage = False

            run_pipeline_ip(
                ip_list=ip_list,
                output_dir=args.output_dir,
                insecure=getattr(args, "insecure", False),
                resume=getattr(args, "resume", False),
                triage=use_triage,
                debug=getattr(args, "debug", False),
                quiet=getattr(args, "quiet", False),
                report_format=getattr(args, "format", "all"),
                thread_override=getattr(args, "threads", None),
                timeout_override=getattr(args, "timeout", None),
                port_override=getattr(args, "ports", None),
            )
        elif domain_list and not ip_list:
            # Standard domain mode
            validate_path(getattr(args, "wordlist", None), "--wordlist")
            from modules.pipeline import run_pipeline
            run_pipeline(
                target=domain_list[0],
                output_dir=args.output_dir,
                wordlist=getattr(args, "wordlist", None),
                insecure=getattr(args, "insecure", False),
                verbose=getattr(args, "verbose", False),
                skip_bruteforce=getattr(args, "no_bruteforce", False),
                resume=getattr(args, "resume", False),
            )
        elif ip_list and domain_list:
            raise ValueError(
                "Mixed IP and domain targets are not supported in one run. "
                "Run domain mode first, then IP mode separately."
            )
        else:
            raise ValueError("No valid targets provided.")

    # ── domain ──
    elif args.command == "domain":
        validate_path(args.output, "--output")
        if not is_valid_domain(args.target):
            raise ValueError(f"Invalid domain: {args.target!r}")
        from modules.domain import enumerate_subdomains
        enumerate_subdomains(args.target, args.output)

    # ── bruteforce ──
    elif args.command == "bruteforce":
        validate_path(args.output,   "--output")
        validate_path(args.wordlist, "--wordlist")
        if not is_valid_domain(args.target):
            raise ValueError(f"Invalid domain: {args.target!r}")
        from modules.bruteforce import dns_bruteforce
        dns_bruteforce(args.target, args.output, wordlist=args.wordlist)

    # ── passive ──
    elif args.command == "passive":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.passive import passive_recon
        passive_recon(
            input_file=args.input,
            output_file=args.output,
            insecure=args.insecure,
            verbose=args.verbose,
        )

    # ── probe ──
    elif args.command == "probe":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.probe import run_probes
        run_probes(input_file=args.input, output_file=args.output, insecure=args.insecure)

    # ── takeover ──
    elif args.command == "takeover":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.takeover import check_takeovers
        check_takeovers(args.input, args.output)

    # ── secret ──
    elif args.command == "secret":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.secret import scan_secrets
        scan_secrets(args.input, args.output)

    # ── s3 ──
    elif args.command == "s3":
        validate_path(args.output,      "--output")
        validate_path(args.secret_file, "--secret-file")
        if not is_valid_domain(args.target):
            raise ValueError(f"Invalid domain: {args.target!r}")
        from modules.s3scanner import scan_s3
        scan_s3(args.target, args.output, secret_file=args.secret_file)

    # ── js ──
    elif args.command == "js":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.jsextractor import extract_js_endpoints
        extract_js_endpoints(args.input, args.output)

    # ── wayback ──
    elif args.command == "wayback":
        validate_path(args.output, "--output")
        if not is_valid_domain(args.target):
            raise ValueError(f"Invalid domain: {args.target!r}")
        from modules.wayback import scan_wayback
        scan_wayback(args.target, args.output)

    # ── github ──
    elif args.command == "github":
        validate_path(args.output, "--output")
        if not is_valid_domain(args.target):
            raise ValueError(f"Invalid domain: {args.target!r}")
        from modules.githubscan import scan_github
        scan_github(args.target, args.output)

    # ── redirect ──
    elif args.command == "redirect":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.redirect import check_redirects
        check_redirects(args.input, args.output)

    # ── scan ──
    elif args.command == "scan":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.scan import run_scan
        run_scan(args.input, args.output)

    # ── analyse ──
    elif args.command == "analyse":
        validate_path(args.input,  "--input")
        validate_path(args.output, "--output")
        from modules.analyse import analyse_scan_results
        analyse_scan_results(args.input, args.output)

    # ── report ──
    elif args.command == "report":
        validate_path(args.input,      "--input")
        validate_path(args.output,     "--output")
        validate_path(args.html,       "--html")
        validate_path(args.output_dir, "--output-dir")
        output_dir = args.output_dir
        from modules.report import generate_report
        generate_report(
            args.input,
            args.output,
            html_output=args.html,
            probe_file=os.path.join(output_dir, "probe_results.json"),
            takeover_file=os.path.join(output_dir, "takeover_results.json"),
            redirect_file=os.path.join(output_dir, "redirect_results.json"),
            secret_file=os.path.join(output_dir, "secret_results.json"),
            s3_file=os.path.join(output_dir, "s3_results.json"),
            js_file=os.path.join(output_dir, "js_results.json"),
            wayback_file=os.path.join(output_dir, "wayback_results.json"),
            github_file=os.path.join(output_dir, "github_results.json"),
            attack_paths_file=os.path.join(output_dir, "attack_paths.json"),
        )

    # ── correlate ──
    elif args.command == "correlate":
        validate_path(args.output_dir, "--output-dir")
        output_dir = args.output_dir
        from modules.correlate import correlate
        correlate(
            os.path.join(output_dir, "attack_paths.json"),
            passive_file=os.path.join(output_dir, "passive_results.json"),
            probe_file=os.path.join(output_dir, "probe_results.json"),
            secret_file=os.path.join(output_dir, "secret_results.json"),
            js_file=os.path.join(output_dir, "js_results.json"),
            wayback_file=os.path.join(output_dir, "wayback_results.json"),
            github_file=os.path.join(output_dir, "github_results.json"),
            redirect_file=os.path.join(output_dir, "redirect_results.json"),
            takeover_file=os.path.join(output_dir, "takeover_results.json"),
            s3_file=os.path.join(output_dir, "s3_results.json"),
            scan_file=os.path.join(output_dir, "scan_results.json"),
            analysis_file=os.path.join(output_dir, "analysis_results.json"),
        )

    # ── cache ──
    elif args.command == "cache":
        from modules.nvd import clear_expired_cache, cache_stats
        import shutil

        if args.stats or (not args.clear and not args.purge):
            stats = cache_stats()
            cprint(f"\n  NVD Cache Statistics:", "cyan")
            cprint(f"    Total entries   : {stats['total']}", "white")
            cprint(f"    Valid (fresh)   : {stats['valid']}", "green")
            cprint(f"    Expired         : {stats['expired']}", "yellow")

        if args.clear:
            removed = clear_expired_cache()
            cprint(f"  [✓] Removed {removed} expired cache entries", "green")

        if args.purge:
            cache_dir = "data/nvd_cache"
            if os.path.exists(cache_dir):
                shutil.rmtree(cache_dir)
                cprint(f"  [✓] Entire NVD cache purged — all future lookups will query live API", "yellow")
            else:
                cprint(f"  [ℹ] Cache directory does not exist — nothing to purge", "cyan")


# ─────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not getattr(args, "no_banner", False):
        print_banner()

    try:
        dispatch(args)
    except KeyboardInterrupt:
        cprint("\n\n  [!] Interrupted by user — exiting cleanly.", "yellow")
        sys.exit(0)
    except ValueError as e:
        cprint(f"\n  [!] Input error: {e}", "red")
        sys.exit(1)
    except Exception as e:
        cprint(f"\n  [!] Unexpected error: {e}", "red")
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()