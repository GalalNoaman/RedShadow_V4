# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/domain.py

import httpx
import time
import os
import re
import json
from termcolor import cprint
from modules.utils import load_config


class SubdomainEnumerationError(Exception):
    pass


def validate_domain(domain):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain) is not None


def enumerate_subdomains(domain, output_file, output_format="txt"):
    config = load_config(section="domain")

    if not validate_domain(domain):
        raise ValueError(f"[!] Invalid domain format: {domain}")

    cprint(f"[+] Enumerating subdomains for: {domain}", "cyan")

    crtsh_url  = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    headers = config.get("headers", {"User-Agent": "RedShadowBot/1.0"})
    timeout = config.get("timeout", 20)
    retries = config.get("retries", 2)
    delay   = config.get("delay", 0)

    # ──── Try crt.sh ────
    for attempt in range(retries):
        try:
            response = httpx.get(crtsh_url, timeout=timeout, headers=headers)
            response.raise_for_status()
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.splitlines():
                    if domain in sub:
                        cleaned = sub.strip().lstrip("*.")
                        subdomains.add(cleaned.lower())
            cprint(f"[✓] Found {len(subdomains)} from crt.sh", "green")
            break
        except (httpx.RequestError, ValueError) as error:
            cprint(f"[!] crt.sh attempt {attempt + 1} failed: {error}", "red")
            time.sleep(delay)
    else:
        cprint("[!] crt.sh failed. Trying backup API...", "yellow")

        # ──── Fallback: dns.bufferover.run ────
        try:
            alt_url      = f"https://dns.bufferover.run/dns?q=.{domain}"
            alt_response = httpx.get(alt_url, timeout=10, headers=headers)
            alt_response.raise_for_status()
            alt_data = alt_response.json()
            if 'FDNS_A' in alt_data:
                for entry in alt_data['FDNS_A']:
                    parts = entry.split(',')
                    if len(parts) == 2 and domain in parts[1]:
                        cleaned = parts[1].strip().lstrip("*.").lower()
                        subdomains.add(cleaned)
            cprint(f"[✓] Found {len(subdomains)} from bufferover.run", "green")
        except Exception as backup_error:
            cprint(f"[!] Backup API also failed: {backup_error}", "red")
            raise SubdomainEnumerationError("All subdomain enumeration methods failed.")

    # ──── Save Results ────
    if subdomains:
        # Safe directory creation that handles bare filenames without a path component.
        # output_file has no directory component (e.g. "subdomains.txt"),
        # because dirname returns "" and makedirs("") raises FileNotFoundError.
        dirpath = os.path.dirname(output_file)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)

        try:
            if output_format == "json":
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(sorted(list(subdomains)), f, indent=2)
            else:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for sub in sorted(subdomains):
                        f.write(sub + '\n')
            cprint(f"[✓] Saved {len(subdomains)} subdomains to {output_file}", "green")
        except Exception as write_error:
            cprint(f"[!] Failed to write output: {write_error}", "red")
    else:
        cprint("[!] No subdomains found.", "yellow")