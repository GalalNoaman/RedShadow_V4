# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/scan.py
# Port scanner — v2
# Improvements:
#   - Confidence scoring on findings
#   - Better error handling and logging
#   - Cleaner output structure
#   - Removed hardcoded paths

#   - Added service confidence tagging
#   - Only open ports are reported

#             (original would crash the entire pipeline at import time)

import re
import json
import os
import sys
import socket
import subprocess
import dns.resolver
import nmap
from datetime import datetime
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

# ─────────────────────────────────────────
# Config
# Falls back to safe defaults if config cannot be loaded.
# silently during Stage 12. Now falls back to safe defaults and continues.
# ─────────────────────────────────────────

try:
    config        = load_config()
    scan_cfg      = config.get("scan", {}) if isinstance(config, dict) else {}
    DEFAULT_PORTS = scan_cfg.get("nmap_ports", "21-25,53,80,443,8080,8443")
    MAX_THREADS   = int(scan_cfg.get("max_threads", 10))
    DNS_SERVERS   = scan_cfg.get("dns_servers", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    NMAP_ARGS     = scan_cfg.get("nmap_args", "-sS -sV -T4 -Pn -n")
except Exception as err:
    cprint(f"[!] Failed to load scan config: {err} — using defaults", "yellow")
    DEFAULT_PORTS = "21-25,53,80,443,8080,8443"
    MAX_THREADS   = 10
    DNS_SERVERS   = ["8.8.8.8", "1.1.1.1"]
    NMAP_ARGS     = "-sS -sV -T4 -Pn -n"

FALLBACK_DNS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]

# ─────────────────────────────────────────
# Target Validation
# ─────────────────────────────────────────

def is_valid_target(target):
    """Validates that a target is a domain name or IP address."""
    is_domain = bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target))
    is_ip     = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    return is_domain or is_ip


# ─────────────────────────────────────────
# DNS Resolution
# ─────────────────────────────────────────

def resolve_domain(domain, log_file=None):
    """
    Resolves a domain to an IP address using multiple fallback methods.
    Returns (domain, ip) — ip is None if all methods fail.
    """
    reasons = []
    servers = DNS_SERVERS or FALLBACK_DNS

    # ── Method 1: DNS A record ──
    try:
        resolver             = dns.resolver.Resolver()
        resolver.nameservers = servers
        resolver.timeout     = 3
        resolver.lifetime    = 5
        answer = resolver.resolve(domain, "A")
        return domain, answer[0].to_text()
    except Exception as e:
        reasons.append(f"A record: {e}")

    # ── Method 2: CNAME → A fallback ──
    try:
        resolver             = dns.resolver.Resolver()
        resolver.nameservers = servers
        resolver.timeout     = 3
        resolver.lifetime    = 5
        cname  = resolver.resolve(domain, "CNAME")
        target = str(cname[0].target)
        answer = resolver.resolve(target, "A")
        return domain, answer[0].to_text()
    except Exception as e:
        reasons.append(f"CNAME: {e}")

    # ── Method 3: AAAA (IPv6) ──
    try:
        resolver             = dns.resolver.Resolver()
        resolver.nameservers = servers
        resolver.timeout     = 3
        resolver.lifetime    = 5
        answer = resolver.resolve(domain, "AAAA")
        return domain, answer[0].to_text()
    except Exception as e:
        reasons.append(f"AAAA: {e}")

    # ── Method 4: dig ──
    try:
        result = subprocess.check_output(
            ["dig", "+short", domain],
            stderr=subprocess.DEVNULL,
            timeout=5
        ).decode().strip()
        if result:
            ip = result.split("\n")[0]
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return domain, ip
    except Exception as e:
        reasons.append(f"dig: {e}")

    # ── Method 5: socket fallback ──
    try:
        ip = socket.gethostbyname(domain)
        return domain, ip
    except Exception as e:
        reasons.append(f"socket: {e}")

    # ── All failed — log it ──
    if log_file:
        dirpath = os.path.dirname(log_file)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{domain}:\n")
            for r in reasons:
                f.write(f"  {r}\n")

    return domain, None


def retry_resolve(args):
    """Resolves a domain with up to 3 attempts."""
    domain, log_file = args
    for _ in range(3):
        d, ip = resolve_domain(domain, log_file)
        if ip:
            return d, ip
    return domain, None


# ─────────────────────────────────────────
# Nmap Scanner
# ─────────────────────────────────────────

def scan_target(args):
    """
    Scans a single target with Nmap.
    Returns structured results with confidence tagging.
    Accepts (domain, ip) or (domain, ip, port_list) tuple.
    """
    domain   = args[0]
    ip       = args[1]
    port_list = args[2] if len(args) > 2 else DEFAULT_PORTS

    scanner = nmap.PortScanner()

    try:
        scanner.scan(
            hosts=ip,
            arguments=f"{NMAP_ARGS} -p {port_list}"
        )
    except Exception as error:
        return {
            domain: {
                "ip":         ip,
                "hostname":   domain,
                "state":      "error",
                "error":      str(error),
                "protocols":  {},
                "confidence": "ERROR",
            }
        }

    for host in scanner.all_hosts():
        protocols = {}

        for proto in scanner[host].all_protocols():
            ports_data  = scanner[host][proto]
            proto_ports = {}

            for port, port_info in ports_data.items():
                state = port_info.get("state", "unknown")

                # Only report open ports
                if state not in ("open", "open|filtered"):
                    continue

                product = port_info.get("product", "")
                version = port_info.get("version", "")
                service = port_info.get("name", "")

                # Confidence based on service detection quality
                if product and version:
                    confidence = "HIGH"
                elif product:
                    confidence = "MEDIUM"
                elif service:
                    confidence = "LOW"
                else:
                    confidence = "LOW"

                proto_ports[port] = {
                    "state":      state,
                    "service":    service,
                    "product":    product,
                    "version":    version or "unknown",
                    "extrainfo":  port_info.get("extrainfo", ""),
                    "confidence": confidence,
                }

            if proto_ports:
                protocols[proto] = proto_ports

        return {
            domain: {
                "ip":            ip,
                "hostname":      scanner[host].hostname() or domain,
                "state":         scanner[host].state(),
                "protocols":     protocols,
                "ports_scanned": DEFAULT_PORTS,
                "confidence":    "SCANNED",
            }
        }

    # Host responded but no open ports found
    return {
        domain: {
            "ip":            ip,
            "hostname":      domain,
            "state":         "up",
            "protocols":     {},
            "ports_scanned": DEFAULT_PORTS,
            "confidence":    "SCANNED",
            "note":          "No open ports found in scanned range",
        }
    }


# ─────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────

def run_scan(input_file, output_file, port_override=None):
    """
    Reads targets from input_file, resolves them,
    runs Nmap scans, and saves structured JSON results.

    port_override: comma-separated ports e.g. "22,80,443,7999"
                   If None, uses DEFAULT_PORTS from config.yaml.
    """
    _ports = port_override.strip() if port_override else DEFAULT_PORTS

    cprint(f"[+] Reading targets from {input_file}", "cyan")

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            raw_targets = sorted(set(
                line.strip().lower()
                for line in f
                if line.strip()
                and not line.startswith("*.")
                and not line.startswith("#")
            ))
    except Exception as error:
        cprint(f"[!] Failed to read input file: {error}", "red")
        return

    # Validate targets
    valid_targets = [t for t in raw_targets if is_valid_target(t)]
    invalid       = len(raw_targets) - len(valid_targets)

    if invalid:
        cprint(f"  [ℹ] Skipped {invalid} invalid target(s)", "yellow")

    if not valid_targets:
        cprint("[!] No valid domains or IPs to scan.", "yellow")
        return

    # Resolve DNS
    cprint("[+] Resolving targets...", "cyan")

    output_dir = os.path.dirname(output_file) if os.path.dirname(output_file) else "outputs"
    log_file   = os.path.join(output_dir, "scan_dns_failures.txt")

    if os.path.exists(log_file):
        os.remove(log_file)

    resolve_args = [(t, log_file) for t in valid_targets]

    with ThreadPool(MAX_THREADS) as pool:
        resolved = pool.map(retry_resolve, resolve_args)

    failed  = [d for d, ip in resolved if not ip]
    targets = [(d, ip, _ports) for d, ip in resolved if ip]

    if failed:
        cprint(f"[!] {len(failed)} domain(s) failed DNS resolution (see {log_file})", "yellow")

    if not targets:
        cprint("[!] No live targets to scan.", "red")
        return

    # Run Nmap
    cprint(f"[+] Starting Nmap scans on {len(targets)} target(s)...", "cyan")

    with ThreadPool(MAX_THREADS) as pool:
        results = pool.map(scan_target, targets)

    # Build output
    final_output = {
        "scan_timestamp":  datetime.utcnow().isoformat() + "Z",
        "targets_scanned": len(targets),
        "targets_failed":  len(failed),
        "ports_scanned":   _ports,
        "results":         {},
    }

    open_port_count = 0
    for entry in results:
        if isinstance(entry, dict):
            final_output["results"].update(entry)
            for domain_data in entry.values():
                for proto in domain_data.get("protocols", {}).values():
                    open_port_count += len(proto)

    final_output["total_open_ports"] = open_port_count

    # Save
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_output, f, indent=2)
        cprint(f"[✓] Scan complete — {len(targets)} targets, {open_port_count} open ports. Saved to {output_file}", "green")
    except Exception as error:
        cprint(f"[!] Failed to write output: {error}", "red")


# ─────────────────────────────────────────
# CLI Support
# ─────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py <input_file.txt> <output_file.json>")
        sys.exit(1)
    run_scan(sys.argv[1], sys.argv[2])