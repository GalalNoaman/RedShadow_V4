# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/s3scanner.py
# S3 bucket discovery and misconfiguration detection
# S3, GCS, and Azure bucket scanner with configurable write test and expanded name generation.
#       region-aware URLs, improved sensitivity detection

import os
import re
import json
import httpx
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

config        = load_config(section="s3scanner")
THREADS       = config.get("threads", 20)
TIMEOUT       = config.get("timeout", 8)
# Write test requires explicit opt-in via config — disabled by default.

# belonging to someone else. Set enable_write_check: true in config.yaml to enable.
ENABLE_WRITE_CHECK = config.get("enable_write_check", False)

# ─────────────────────────────────────────
# AWS S3 Regions — for region-aware URL checking
# ─────────────────────────────────────────

AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "sa-east-1", "ca-central-1",
]

# ─────────────────────────────────────────
# Bucket Name Generator
# ─────────────────────────────────────────

def generate_bucket_names(company):
    """
    Generates a list of likely S3/GCS/Azure bucket names for a company.
    Upgrade: expanded suffixes, GCP and Azure naming patterns added.
    """
    name     = company.lower().replace(".com", "").replace(".io", "").replace(".", "-")
    alt_name = name.replace("-", "")   # no-hyphen variant e.g. "acmecorp"

    suffixes = [
        "", "-prod", "-production", "-dev", "-development", "-staging", "-stage",
        "-test", "-testing", "-qa", "-uat", "-demo", "-sandbox",
        "-backup", "-backups", "-bak", "-archive", "-archives",
        "-data", "-database", "-db",
        "-logs", "-log", "-logging",
        "-assets", "-static", "-media", "-images", "-img",
        "-uploads", "-upload", "-files", "-file",
        "-public", "-private", "-internal",
        "-api", "-apis", "-backend",
        "-config", "-configs", "-configuration",
        "-build", "-builds", "-deploy", "-deployments",
        "-lambda", "-functions", "-serverless",
        "-export", "-exports", "-import", "-imports",
        "-report", "-reports", "-analytics",
        "-email", "-mail", "-emails",
        "-cdn", "-content",
        "-mobile", "-ios", "-android",
        "-web", "-webapp", "-frontend",
        "-temp", "-tmp", "-cache",
        "-secrets", "-credentials", "-keys",
        "-2023", "-2024", "-2025", "-2026",
        # Extended bucket name patterns for broader coverage.
        "-infra", "-infrastructure", "-platform",
        "-release", "-releases", "-artifact", "-artifacts",
        "-terraform", "-tfstate",
        "-airflow", "-mlflow", "-datalake", "-warehouse",
        "-raw", "-processed", "-curated",
    ]

    prefixes = [
        "", "prod-", "dev-", "staging-", "test-", "backup-",
        "data-", "static-", "assets-", "media-",
        # Cloud provider prefix patterns.
        "s3-", "gcs-", "blob-", "storage-",
    ]

    buckets = set()

    for suffix in suffixes:
        buckets.add(f"{name}{suffix}")
        buckets.add(f"{alt_name}{suffix}")

    for prefix in prefixes:
        buckets.add(f"{prefix}{name}")
        buckets.add(f"{prefix}{alt_name}")

    return sorted(buckets)


# ─────────────────────────────────────────
# S3 Bucket Checker
# ─────────────────────────────────────────

def check_bucket(bucket_name):
    """
    Checks a single S3 bucket for public access.
    Upgrade: checks both path-style and virtual-hosted URLs,
             plus a sample of regional endpoints.

    Status codes:
    - 200 → Public read access (CRITICAL)
    - 403 → Bucket exists but private (INFO)
    - 404 → Bucket doesn't exist
    """

    # Virtual-hosted + path-style URLs
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]

    # Regional endpoint URLs for buckets that only respond on region-specific hostnames.
    for region in AWS_REGIONS[:4]:   # check top 4 regions to keep it fast
        urls.append(f"https://{bucket_name}.s3.{region}.amazonaws.com")

    for url in urls:
        try:
            response = httpx.get(
                url,
                timeout=TIMEOUT,
                follow_redirects=False,
                verify=True
            )

            # ── Public bucket — can list contents ──
            if response.status_code == 200:
                content = response.text

                if "<ListBucketResult" in content or "<?xml" in content:
                    file_count    = content.count("<Key>")
                    # Sensitive filename keywords for flagging high-risk bucket contents.
                    sensitive_keywords = [
                        "password", "passwd", "secret", "key", "token", "credential",
                        "backup", "dump", "private", "config", "database", "db",
                        "id_rsa", ".pem", ".env", "aws_access", "api_key",
                    ]
                    has_sensitive = any(w in content.lower() for w in sensitive_keywords)

                    return {
                        "bucket":    bucket_name,
                        "url":       url,
                        "status":    "PUBLIC_READABLE",
                        "severity":  "CRITICAL",
                        "files":     file_count,
                        "sensitive": has_sensitive,
                        "note":      (
                            f"Bucket is publicly readable — {file_count} files listed"
                            + (" — SENSITIVE FILENAMES DETECTED!" if has_sensitive else "")
                        ),
                    }
                else:
                    return {
                        "bucket":    bucket_name,
                        "url":       url,
                        "status":    "PUBLIC_ACCESS",
                        "severity":  "HIGH",
                        "files":     0,
                        "sensitive": False,
                        "note":      "Bucket returns 200 — may have public access",
                    }

            # ── Bucket exists but access denied ──
            elif response.status_code == 403:
                if (
                    "x-amz-bucket-region" in response.headers
                    or "AmazonS3" in response.headers.get("server", "")
                    or "AccessDenied" in response.text
                    or "AllAccessDisabled" in response.text
                ):
                    # Write test is behind ENABLE_WRITE_CHECK flag.
                    
                    # real buckets that happen to share a guessed name.
                    if ENABLE_WRITE_CHECK:
                        try:
                            write_resp = httpx.put(
                                f"{url}/redshadow-test.txt",
                                content=b"RedShadow security test",
                                timeout=TIMEOUT,
                                verify=True,
                            )
                            if write_resp.status_code in (200, 201):
                                httpx.delete(f"{url}/redshadow-test.txt", timeout=TIMEOUT)
                                return {
                                    "bucket":    bucket_name,
                                    "url":       url,
                                    "status":    "PUBLIC_WRITABLE",
                                    "severity":  "CRITICAL",
                                    "files":     0,
                                    "sensitive": True,
                                    "note":      "Bucket allows ANONYMOUS WRITE ACCESS — critical!",
                                }
                        except Exception:
                            pass

                    return {
                        "bucket":    bucket_name,
                        "url":       url,
                        "status":    "EXISTS_PRIVATE",
                        "severity":  "INFO",
                        "files":     0,
                        "sensitive": False,
                        "note":      "Bucket exists but access is restricted",
                    }

        except (httpx.ConnectTimeout, httpx.ReadTimeout):
            continue
        except Exception:
            continue

    return None


# ─────────────────────────────────────────
# GCP Bucket Checker (Upgrade)
# ─────────────────────────────────────────

def check_gcp_bucket(bucket_name):
    """
    Upgrade: checks Google Cloud Storage buckets for public access.
    GCS uses storage.googleapis.com — same misconfiguration patterns as S3.
    """
    url = f"https://storage.googleapis.com/{bucket_name}"
    try:
        response = httpx.get(url, timeout=TIMEOUT, follow_redirects=False, verify=True)

        if response.status_code == 200:
            content    = response.text
            file_count = content.count("<Key>") + content.count("<Name>")
            return {
                "bucket":    bucket_name,
                "url":       url,
                "status":    "GCS_PUBLIC_READABLE",
                "severity":  "CRITICAL",
                "files":     file_count,
                "sensitive": False,
                "note":      f"GCS bucket publicly readable — {file_count} objects listed",
                "provider":  "GCP",
            }

        if response.status_code == 403:
            if "storage.googleapis.com" in response.text or "AccessDenied" in response.text:
                return {
                    "bucket":    bucket_name,
                    "url":       url,
                    "status":    "GCS_EXISTS_PRIVATE",
                    "severity":  "INFO",
                    "files":     0,
                    "sensitive": False,
                    "note":      "GCS bucket exists but access is restricted",
                    "provider":  "GCP",
                }
    except Exception:
        pass
    return None


# ─────────────────────────────────────────
# Azure Blob Checker (Upgrade)
# ─────────────────────────────────────────

def check_azure_blob(account_name, container_name):
    """
    Upgrade: checks Azure Blob Storage containers for public access.
    """
    url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"
    try:
        response = httpx.get(url, timeout=TIMEOUT, follow_redirects=False, verify=True)

        if response.status_code == 200:
            file_count = response.text.count("<Name>")
            return {
                "bucket":    f"{account_name}/{container_name}",
                "url":       url,
                "status":    "AZURE_PUBLIC_READABLE",
                "severity":  "CRITICAL",
                "files":     file_count,
                "sensitive": False,
                "note":      f"Azure blob container publicly readable — {file_count} blobs listed",
                "provider":  "Azure",
            }

        if response.status_code == 403:
            return {
                "bucket":    f"{account_name}/{container_name}",
                "url":       url,
                "status":    "AZURE_EXISTS_PRIVATE",
                "severity":  "INFO",
                "files":     0,
                "sensitive": False,
                "note":      "Azure container exists but access is restricted",
                "provider":  "Azure",
            }
    except Exception:
        pass
    return None


# ─────────────────────────────────────────
# Extract Bucket Names from Secret Scan Results
# ─────────────────────────────────────────

def extract_buckets_from_secrets(secret_file):
    """Extract any S3/GCS/Azure bucket names found by the secret scanner."""
    buckets = set()
    if not secret_file or not os.path.exists(secret_file):
        return buckets

    try:
        with open(secret_file, "r") as f:
            data = json.load(f)
        for entry in data:
            for finding in entry.get("findings", []):
                value = finding.get("value", "")
                # S3 virtual-hosted
                matches = re.findall(
                    r'https?://([a-z0-9.-]+)\.s3[.-][a-z0-9-]*\.amazonaws\.com',
                    value
                )
                buckets.update(matches)
                # S3 path-style
                matches2 = re.findall(r's3://([a-z0-9.-]+)', value)
                buckets.update(matches2)
                # GCS
                matches3 = re.findall(
                    r'https?://storage\.googleapis\.com/([a-z0-9._-]+)',
                    value
                )
                buckets.update(matches3)
    except Exception:
        pass

    return buckets


# ─────────────────────────────────────────
# Main S3 Scanner Entry Point
# ─────────────────────────────────────────

def scan_s3(target, output_file, secret_file=None):
    """
    Discovers and checks S3/GCS/Azure buckets related to the target domain.
    """

    company = target.split(".")[0]
    buckets = generate_bucket_names(company)

    # Add buckets found by secret scanner
    known_buckets = extract_buckets_from_secrets(secret_file)
    if known_buckets:
        cprint(f"  [+] Adding {len(known_buckets)} buckets from secret scanner", "cyan")
        buckets = sorted(set(buckets) | known_buckets)

    cprint(f"  [+] Checking {len(buckets)} possible S3 buckets for {target}...", "cyan")
    if ENABLE_WRITE_CHECK:
        cprint(f"  [⚠] Write check enabled — PUT test will run on existing buckets", "yellow")
    else:
        cprint(f"  [ℹ] Write check disabled (set enable_write_check: true in config to enable)", "cyan")

    # ── S3 checks ──
    with ThreadPool(THREADS) as pool:
        raw_s3 = list(tqdm(
            pool.imap(check_bucket, buckets),
            total=len(buckets),
            desc="  S3 Scan",
            ncols=70
        ))

    # ── GCP checks (Upgrade) ──
    cprint(f"  [+] Checking {len(buckets)} possible GCS buckets...", "cyan")
    with ThreadPool(THREADS) as pool:
        raw_gcs = list(tqdm(
            pool.imap(check_gcp_bucket, buckets),
            total=len(buckets),
            desc="  GCS Scan",
            ncols=70
        ))

    # ── Azure checks (Upgrade) — use company name as both account and container ──
    cprint(f"  [+] Checking Azure blob containers...", "cyan")
    azure_pairs = [(company, b) for b in buckets[:50]]   # limit to top 50 for speed
    with ThreadPool(THREADS) as pool:
        raw_azure = list(tqdm(
            pool.imap(lambda args: check_azure_blob(*args), azure_pairs),
            total=len(azure_pairs),
            desc="  Azure Scan",
            ncols=70
        ))

    # ── Combine all findings ──
    all_findings   = [r for r in (raw_s3 + raw_gcs + raw_azure) if r is not None]
    critical       = [r for r in all_findings if r["severity"] == "CRITICAL"]
    high           = [r for r in all_findings if r["severity"] == "HIGH"]
    exists_private = [r for r in all_findings if "EXISTS_PRIVATE" in r.get("status", "")]

    # ── Summary ──
    if not all_findings:
        cprint("  [✓] No misconfigured buckets found.", "green")
    else:
        if critical:
            cprint(f"\n  🚨 CRITICAL — {len(critical)} publicly accessible bucket(s)!", "red")
            for f in critical:
                provider = f.get("provider", "AWS")
                cprint(f"      [{f['severity']}] [{provider}] {f['bucket']}", "red")
                cprint(f"             URL    : {f['url']}", "red")
                cprint(f"             Status : {f['status']}", "red")
                cprint(f"             Note   : {f['note']}", "red")

        if high:
            cprint(f"\n  ⚠️  HIGH — {len(high)} bucket(s) with potential access", "yellow")
            for f in high:
                cprint(f"      [{f['severity']}] {f['bucket']} → {f['url']}", "yellow")

        if exists_private:
            cprint(f"\n  [ℹ] {len(exists_private)} private bucket(s) discovered (exist but locked)", "cyan")
            for f in exists_private[:5]:
                provider = f.get("provider", "AWS")
                cprint(f"      [INFO] [{provider}] {f['bucket']}", "cyan")

    # ── Save results ──
    results = {
        "target":         target,
        "total_checked":  len(buckets),
        "write_check":    ENABLE_WRITE_CHECK,
        "critical":       critical,
        "high":           high,
        "exists_private": exists_private,
    }

    # Ensure output directory exists before writing.
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        cprint(f"\n  [✓] S3/GCS/Azure scan results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to write results: {e}", "red")