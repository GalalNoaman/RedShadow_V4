# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/pipeline.py
# Orchestrates the full auto recon pipeline
# v3 — all feedback addressed:
#   Fix 1: Explicit stage states (PASSED / FAILED / SKIPPED / RESUMED)
#           no longer overloads (True, None) for skipped stages
#   Fix 2: Per-stage ETA weights (replaces misleading global average)
#   Fix 3: Parallel stages expanded — 5/6/7/9 run in parallel
#           since they all depend on passive_file but not each other
#   Fix 4: Resume backed by metadata file (timestamp + version + checksum)
#           not just "file exists" check
#   Fix 5: Report stage checks BOTH HTML and markdown outputs
#   Fix 6: ETA records parallel block as 3 separate stage credits
#   Fix 7: Summary counts use explicit PASSED/FAILED/SKIPPED states

import os
import sys
import time
import json
import hashlib
import threading
from datetime import datetime
from termcolor import cprint
from modules.logger import init_logger

# ─────────────────────────────────────────
# Stage State Constants (Fix 1)
# Replaces overloaded (True/False/None, result) tuples
# ─────────────────────────────────────────

STATE_PASSED  = "PASSED"
STATE_FAILED  = "FAILED"
STATE_SKIPPED = "SKIPPED"   # intentionally skipped (--no-bruteforce, empty passive, etc.)
STATE_RESUMED = "RESUMED"   # skipped because resume mode found valid output

# ─────────────────────────────────────────
# Stage State Record
# ─────────────────────────────────────────

class StageRecord:
    def __init__(self, name, state, elapsed=0.0, error=""):
        self.name    = name
        self.state   = state
        self.elapsed = elapsed
        self.error   = error

    def passed(self):  return self.state == STATE_PASSED
    def failed(self):  return self.state == STATE_FAILED
    def skipped(self): return self.state in (STATE_SKIPPED, STATE_RESUMED)


# ─────────────────────────────────────────
# Stage Runner (Fix 1 applied)
# Returns StageRecord, never raises
# ─────────────────────────────────────────

def run_stage(stage_name, func, *args, **kwargs):
    cprint(f"\n{'='*60}", "cyan")
    cprint(f"  [►] {stage_name}", "cyan")
    cprint(f"{'='*60}", "cyan")
    start = time.time()
    try:
        func(*args, **kwargs)
        elapsed = round(time.time() - start, 2)
        cprint(f"  [✓] {stage_name} — {elapsed}s", "green")
        return StageRecord(stage_name, STATE_PASSED, elapsed)
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        cprint(f"  [✗] {stage_name} failed after {elapsed}s: {e}", "red")
        import traceback
        cprint(f"  [→] {traceback.format_exc().splitlines()[-1]}", "yellow")
        cprint(f"  [→] Skipping to next stage...", "yellow")
        return StageRecord(stage_name, STATE_FAILED, elapsed, str(e))


# ─────────────────────────────────────────
# Parallel Stage Runner (Fix 3 + Fix 6)
# Parallel execution group — these stages share passive recon input but are independent.
#        so they are now run in parallel too
# Each stage records timing individually for accurate ETA calculation.
# ─────────────────────────────────────────

def run_stages_parallel(stage_triplets, eta_tracker=None):
    """
    Runs a list of (name, func, args, kwargs) tuples in parallel threads.
    Returns dict {name: StageRecord}.
    Fix 6: records each stage's time individually into eta_tracker.
    """
    records = {}
    lock    = threading.Lock()

    def _worker(name, func, args, kwargs):
        record = run_stage(name, func, *args, **kwargs)
        with lock:
            records[name] = record
            if eta_tracker:
                eta_tracker.record(name, record.elapsed)

    threads = []
    for name, func, args, kwargs in stage_triplets:
        t = threading.Thread(target=_worker, args=(name, func, args, kwargs), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return records


# ─────────────────────────────────────────
# Per-Stage ETA Tracker (Fix 2)
# Per-stage ETA tracking based on historical elapsed times.
# The stages have wildly different runtimes (report = seconds, Nmap = minutes).
# Now uses per-stage type weights derived from empirical timing.
# Falls back to running average when no prior data is available.
# ─────────────────────────────────────────

# Estimated relative weights per stage (tuned from real runs)
# Higher = slower. Used to weight the ETA calculation.
STAGE_WEIGHTS = {
    "1. Subdomain Enumeration":   1.0,
    "2. DNS Bruteforce":          3.0,
    "3. Takeover Check":          2.0,
    "4. Passive Recon":           2.0,
    "5. HTTP Probing":            3.5,
    "6. Open Redirect":           3.5,
    "7. Secret Scanner":          2.5,
    "8. S3 Bucket Scanner":       2.0,
    "9. JS Extractor":            2.5,
    "10. Wayback Scanner":        2.0,
    "11. GitHub Secret Scanner":  4.0,   # slowest — rate-limited
    "12. Port Scan (Nmap)":       4.5,   # slowest — nmap
    "13. CVE Analysis":           2.0,
    "14. Attack Path Correlation": 0.5,
    "15. Report Generation":      0.5,
}


class ETATracker:
    """
    Fix 2: per-stage weighted ETA.
    Records actual time per stage and calibrates remaining estimate
    using relative weights from STAGE_WEIGHTS.
    """
    def __init__(self, all_stage_names):
        self.all_stages    = all_stage_names
        self.done          = {}   # stage_name → elapsed_seconds
        self.start         = time.time()

    def record(self, stage_name, elapsed):
        self.done[stage_name] = elapsed

    def eta_str(self):
        if not self.done:
            return ""
        remaining_stages = [s for s in self.all_stages if s not in self.done]
        if not remaining_stages:
            return "almost done"

        # Compute seconds-per-weight-unit from completed stages
        total_elapsed = sum(self.done.values())
        total_weight  = sum(STAGE_WEIGHTS.get(s, 1.0) for s in self.done)
        if total_weight == 0:
            return ""
        secs_per_unit = total_elapsed / total_weight

        # Estimate remaining
        remaining_weight = sum(STAGE_WEIGHTS.get(s, 1.0) for s in remaining_stages)
        remaining_secs   = int(remaining_weight * secs_per_unit)
        mins, secs       = divmod(remaining_secs, 60)
        return f"~{mins}m {secs}s remaining ({len(remaining_stages)} stages left)"


# ─────────────────────────────────────────
# Resume Metadata (Fix 4)
# Stage completion verified by checksum — detects truncated or corrupted output.
# Problems: partial writes, stale files, schema changes all pass that check.
# Now: writes a .meta.json alongside each output file recording:
#   timestamp, file_size, sha256 checksum, tool_version
# Resume check validates all four fields.
# ─────────────────────────────────────────

TOOL_VERSION = "4.0"
META_SUFFIX  = ".meta.json"


def _write_meta(output_file):
    """Writes a metadata sidecar for a completed stage output file."""
    if not os.path.exists(output_file):
        return
    try:
        size = os.path.getsize(output_file)
        with open(output_file, "rb") as f:
            checksum = hashlib.sha256(f.read()).hexdigest()
        meta = {
            "file":       output_file,
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "size":       size,
            "sha256":     checksum,
            "version":    TOOL_VERSION,
        }
        with open(output_file + META_SUFFIX, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:  # Metadata sidecar write failed - non-critical, resume will re-run stage
        pass


def _meta_valid(output_file):
    """
    Fix 4: validates a stage output using its metadata sidecar.
    Returns True only if:
      - output file exists and matches recorded size + checksum
      - metadata was written by the current tool version
    """
    meta_path = output_file + META_SUFFIX
    if not os.path.exists(output_file) or not os.path.exists(meta_path):
        return False
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        # Version check
        if meta.get("version") != TOOL_VERSION:
            return False

        # Size check
        current_size = os.path.getsize(output_file)
        if current_size != meta.get("size", -1):
            return False

        # Checksum check (catches partial writes and corruption)
        with open(output_file, "rb") as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        if current_hash != meta.get("sha256", ""):
            return False

        return True

    except Exception:  # Metadata validation failed - treat as invalid (safe default)
        return False


def stage_already_done(output_files, resume):
    """
    Fix 4 + Fix 5: checks ALL output files for a stage (not just one).
    Returns True only if every output file passes metadata validation.
    output_files can be a single path or a list of paths.
    """
    if not resume:
        return False
    if isinstance(output_files, str):
        output_files = [output_files]
    for fpath in output_files:
        if not _meta_valid(fpath):
            return False
    cprint(f"  [→] Resume: valid output found — stage skipped", "yellow")
    return True


def mark_stage_done(output_files):
    """Writes metadata sidecars for all output files of a completed stage."""
    if isinstance(output_files, str):
        output_files = [output_files]
    for fpath in output_files:
        _write_meta(fpath)


# ─────────────────────────────────────────
# File Helpers
# ─────────────────────────────────────────

def count_subdomains(filepath):
    try:
        with open(filepath, "r") as f:
            return sum(1 for line in f if line.strip())
    except Exception:  # Subdomain file read failed - return 0
        return 0


def file_has_content(filepath, min_bytes=10):
    return os.path.exists(filepath) and os.path.getsize(filepath) >= min_bytes


def _load_json_list(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:  # JSON list load failed - return empty list
        return []


def _load_json_dict(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:  # JSON dict load failed - return empty dict
        return {}


# ─────────────────────────────────────────
# Summary Printer (Fix 1 + Fix 7 applied)
# Explicit stage state tracking: PASSED, FAILED, SKIPPED, RESUMED.
# Stage counts derived from explicit state records.
# ─────────────────────────────────────────

def print_summary(target, stage_map, output_dir, start_time):
    """
    stage_map: dict {stage_name: StageRecord}
    """
    elapsed      = round(time.time() - start_time, 2)
    mins, secs   = divmod(int(elapsed), 60)
    total        = len(stage_map)
    # Explicit state-based counting.
    passed_count  = sum(1 for r in stage_map.values() if r.state == STATE_PASSED)
    failed_count  = sum(1 for r in stage_map.values() if r.state == STATE_FAILED)
    skipped_count = sum(1 for r in stage_map.values() if r.state in (STATE_SKIPPED, STATE_RESUMED))
    resumed_count = sum(1 for r in stage_map.values() if r.state == STATE_RESUMED)

    cprint(f"\n{'='*60}", "magenta")
    cprint(f"  🛡️  RedShadow V4 — Scan Complete", "magenta")
    cprint(f"{'='*60}", "magenta")
    cprint(f"  Target   : {target}", "white")
    cprint(f"  Duration : {mins}m {secs}s", "white")
    cprint(f"  Stages   : {passed_count} passed | {failed_count} failed | {skipped_count} skipped ({resumed_count} resumed)", "white")

    # Stage results with timing
    cprint(f"\n  Stage Results:", "white")
    for name, record in stage_map.items():
        if record.state == STATE_PASSED:
            cprint(f"    [✓] {name}  ({record.elapsed}s)", "green")
        elif record.state == STATE_RESUMED:
            cprint(f"    [~] {name}  (resumed from cache)", "yellow")
        elif record.state == STATE_SKIPPED:
            cprint(f"    [–] {name}  (skipped)", "yellow")
        else:
            cprint(f"    [✗] {name}  ({record.elapsed}s) — {record.error[:60]}", "red")

    # Findings summary
    cprint(f"\n  Findings Summary:", "white")
    sub_count = count_subdomains(os.path.join(output_dir, "subdomains.txt"))
    cprint(f"    Subdomains discovered     : {sub_count}", "cyan")

    takeover_file = os.path.join(output_dir, "takeover_results.json")
    conf_takeovers = sum(1 for t in _load_json_list(takeover_file) if t.get("confidence") == "CONFIRMED")
    pot_takeovers  = sum(1 for t in _load_json_list(takeover_file) if t.get("confidence") != "CONFIRMED")
    if conf_takeovers: cprint(f"    🚨 Confirmed takeovers     : {conf_takeovers}", "red")
    if pot_takeovers:  cprint(f"    ⚠️  Potential takeovers     : {pot_takeovers}", "yellow")

    secret_count = sum(len(e.get("findings", [])) for e in _load_json_list(os.path.join(output_dir, "secret_results.json")))
    if secret_count: cprint(f"    🔑 Secrets found           : {secret_count}", "red")

    gh_data = _load_json_dict(os.path.join(output_dir, "github_results.json"))
    if gh_data.get("critical"): cprint(f"    🐙 GitHub critical secrets : {gh_data['critical']}", "red")

    s3_data = _load_json_dict(os.path.join(output_dir, "s3_results.json"))
    s3_crit = len(s3_data.get("critical", []))
    if s3_crit: cprint(f"    🪣 Public S3 buckets       : {s3_crit}", "red")

    probe_vulns = sum(
        1 for e in _load_json_list(os.path.join(output_dir, "probe_results.json"))
        for f in e.get("findings", [])
        if f.get("finding_type") == "vulnerability" and f.get("severity") in ("CRITICAL", "HIGH")
    )
    if probe_vulns: cprint(f"    🔍 Critical/High probe hits: {probe_vulns}", "yellow")

    redirect_count = sum(len(e.get("findings", [])) for e in _load_json_list(os.path.join(output_dir, "redirect_results.json")))
    if redirect_count: cprint(f"    🔀 Open redirects          : {redirect_count}", "yellow")

    wb_alive = len(_load_json_dict(os.path.join(output_dir, "wayback_results.json")).get("alive_200", []))
    if wb_alive: cprint(f"    🕰️  Wayback live URLs        : {wb_alive}", "cyan")

    js_data    = _load_json_list(os.path.join(output_dir, "js_results.json"))
    js_high    = sum(len(e.get("high_value", [])) for e in js_data)
    gql_hosts  = sum(1 for e in js_data if e.get("graphql_introspection"))
    if js_high:   cprint(f"    🔎 High-value JS endpoints : {js_high}", "cyan")
    if gql_hosts: cprint(f"    ⚠️  GraphQL introspection   : {gql_hosts} host(s)", "yellow")

    analysis_data = _load_json_list(os.path.join(output_dir, "analysis_results.json"))
    cve_total = sum(len(m.get("cves", [])) for e in analysis_data for m in e.get("tech_matches", []))
    rce_count = sum(1 for e in analysis_data for m in e.get("tech_matches", [])
                    for c in m.get("cves", []) if "RCE" in c.get("attack_surface", []))
    if cve_total: cprint(f"    🛡️  CVEs matched             : {cve_total} ({rce_count} RCE)", "yellow")

    # Attack path correlation summary
    atk_paths = _load_json_list(os.path.join(output_dir, "attack_paths.json"))
    if atk_paths:
        crit_paths = [p for p in atk_paths if p.get("score", 0) >= 9.0]
        cprint(f"    🎯 Attack paths ranked       : {len(atk_paths)} ({len(crit_paths)} critical ≥9.0)", "red" if crit_paths else "yellow")
        for p in atk_paths[:3]:
            score = p.get("score", 0)
            col = "red" if score >= 9.0 else "yellow"
            cprint(f"       #{p.get('rank','')} [{score:.1f}] {p.get('type','')}: {p.get('title','')[:60]}", col)

    # Output files
    cprint(f"\n  Output Files:", "white")
    expected = [
        "subdomains.txt", "subdomains_dns.json",
        "takeover_results.json", "passive_results.json",
        "probe_results.json", "secret_results.json",
        "s3_results.json", "js_results.json",
        "wayback_results.json", "github_results.json",
        "redirect_results.json", "scan_results.json",
        "analysis_results.json", "attack_paths.json",
        "redshadow_report.md", "redshadow_report.html",
    ]
    for fname in expected:
        fpath = os.path.join(output_dir, fname)
        if os.path.exists(fpath):
            size = os.path.getsize(fpath)
            validated = "✅" if _meta_valid(fpath) else "📄"
            cprint(f"    {validated} {fpath} ({size:,} bytes)", "green")
        else:
            cprint(f"    [✗] {fpath}", "yellow")

    cprint(f"\n{'='*60}\n", "magenta")


# ─────────────────────────────────────────
# Main Pipeline Entry Point
# ─────────────────────────────────────────

def run_pipeline(target, output_dir="outputs", wordlist=None, insecure=False,
                 verbose=False, skip_bruteforce=False, resume=False):
    """
    Runs the full RedShadow recon pipeline.

    Args:
        target (str):          Root domain to scan
        output_dir (str):      Directory for all output files
        wordlist (str):        Path to custom DNS wordlist
        insecure (bool):       Skip TLS verification
        verbose (bool):        Verbose output
        skip_bruteforce (bool): Skip DNS bruteforce stage
        resume (bool):         Resume from last successful stage
    """

    os.makedirs(output_dir, exist_ok=True)
    start_time = time.time()
    stage_map  = {}   # str → StageRecord
    log        = init_logger(output_dir=output_dir)

    # ── All stage names for ETA weight lookup ──
    ALL_STAGE_NAMES = list(STAGE_WEIGHTS.keys())
    eta = ETATracker(ALL_STAGE_NAMES)

    # ── File paths ──
    subdomains_file  = os.path.join(output_dir, "subdomains.txt")
    passive_file     = os.path.join(output_dir, "passive_results.json")
    scan_file        = os.path.join(output_dir, "scan_results.json")
    analysis_file    = os.path.join(output_dir, "analysis_results.json")
    report_md_file   = os.path.join(output_dir, "redshadow_report.md")
    report_html_file = os.path.join(output_dir, "redshadow_report.html")
    correlate_file   = os.path.join(output_dir, "attack_paths.json")
    probe_file       = os.path.join(output_dir, "probe_results.json")
    takeover_file    = os.path.join(output_dir, "takeover_results.json")
    redirect_file    = os.path.join(output_dir, "redirect_results.json")
    secret_file      = os.path.join(output_dir, "secret_results.json")
    s3_file          = os.path.join(output_dir, "s3_results.json")
    js_file          = os.path.join(output_dir, "js_results.json")
    wayback_file     = os.path.join(output_dir, "wayback_results.json")
    github_file      = os.path.join(output_dir, "github_results.json")

    cprint(f"\n{'='*60}", "magenta")
    cprint(f"  🛡️  RedShadow V4 — Auto Pipeline", "magenta")
    cprint(f"  Target  : {target}", "white")
    cprint(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "white")
    cprint(f"  Output  : {output_dir}", "white")
    if resume:
        cprint(f"  Mode    : RESUME (checksum-validated cache)", "yellow")
    cprint(f"{'='*60}", "magenta")

    def _record(name, record):
        stage_map[name] = record
        eta.record(name, record.elapsed)
        log.stage_end(name, elapsed=record.elapsed, state=record.state, error=record.error)
        if record.state not in (STATE_SKIPPED, STATE_RESUMED):
            cprint(f"  [⏱] {eta.eta_str()}", "cyan")

    # ─────────────────────────────────────
    # Stage 1: Subdomain Enumeration
    # ─────────────────────────────────────
    name = "1. Subdomain Enumeration"
    if stage_already_done(subdomains_file, resume):
        _record(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.domain import enumerate_subdomains
        rec = run_stage(name, enumerate_subdomains, target, subdomains_file)
        if rec.passed(): mark_stage_done(subdomains_file)
        _record(name, rec)

    # ─────────────────────────────────────
    # Stage 2: DNS Bruteforce
    # ─────────────────────────────────────
    name = "2. DNS Bruteforce"
    if skip_bruteforce:
        cprint("\n  [→] DNS bruteforce skipped (--no-bruteforce)", "yellow")
        _record(name, StageRecord(name, STATE_SKIPPED))
    elif stage_already_done(subdomains_file, resume):
        _record(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.bruteforce import dns_bruteforce
        rec = run_stage(name, dns_bruteforce, target, subdomains_file, wordlist=wordlist)
        if rec.passed(): mark_stage_done(subdomains_file)
        _record(name, rec)

    found = count_subdomains(subdomains_file)
    cprint(f"\n  [ℹ] Total unique subdomains: {found}", "cyan")

    if found == 0:
        cprint("  [!] No subdomains found — aborting pipeline.", "red")
        for remaining in ALL_STAGE_NAMES[2:]:
            stage_map[remaining] = StageRecord(remaining, STATE_SKIPPED)
        log.run_summary()
        print_summary(target, stage_map, output_dir, start_time)
        return

    # ─────────────────────────────────────
    # Stage 3: Subdomain Takeover
    # ─────────────────────────────────────
    name = "3. Takeover Check"
    if stage_already_done(takeover_file, resume):
        _record(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.takeover import check_takeovers
        rec = run_stage(name, check_takeovers, subdomains_file, takeover_file)
        if rec.passed(): mark_stage_done(takeover_file)
        _record(name, rec)

    # ─────────────────────────────────────
    # Stage 4: Passive Recon
    # ─────────────────────────────────────
    name = "4. Passive Recon"
    if stage_already_done(passive_file, resume):
        _record(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.passive import passive_recon
        rec = run_stage(name, passive_recon,
                        input_file=subdomains_file, output_file=passive_file,
                        insecure=insecure, verbose=verbose)
        if rec.passed(): mark_stage_done(passive_file)
        _record(name, rec)

    # Early exit when passive recon returns no results.
    if not file_has_content(passive_file):
        cprint("  [!] Passive recon found no live hosts — skipping host-dependent stages.", "yellow")
        for skip_name in ["5. HTTP Probing", "6. Open Redirect", "7. Secret Scanner", "9. JS Extractor"]:
            stage_map[skip_name] = StageRecord(skip_name, STATE_SKIPPED)
    else:
        # ─────────────────────────────────
        # Stages 5, 6, 7, 9 — Parallel (Fix 3)
        # All depend on passive_file but NOT on each other.
        # Running them concurrently cuts this block from ~4 sequential waits
        # down to the time of the slowest one.
        # ─────────────────────────────────
        parallel_group = []

        n5 = "5. HTTP Probing"
        if stage_already_done(probe_file, resume):
            stage_map[n5] = StageRecord(n5, STATE_RESUMED)
        else:
            from modules.probe import run_probes
            parallel_group.append((n5, run_probes,
                                    (), {"input_file": passive_file, "output_file": probe_file, "insecure": insecure}))

        n6 = "6. Open Redirect"
        if stage_already_done(redirect_file, resume):
            stage_map[n6] = StageRecord(n6, STATE_RESUMED)
        else:
            from modules.redirect import check_redirects
            parallel_group.append((n6, check_redirects, (passive_file, redirect_file), {}))

        n7 = "7. Secret Scanner"
        if stage_already_done(secret_file, resume):
            stage_map[n7] = StageRecord(n7, STATE_RESUMED)
        else:
            from modules.secret import scan_secrets
            parallel_group.append((n7, scan_secrets, (passive_file, secret_file), {}))

        n9 = "9. JS Extractor"
        if stage_already_done(js_file, resume):
            stage_map[n9] = StageRecord(n9, STATE_RESUMED)
        else:
            from modules.jsextractor import extract_js_endpoints
            parallel_group.append((n9, extract_js_endpoints, (passive_file, js_file), {}))

        if parallel_group:
            cprint(f"\n{'='*60}", "cyan")
            cprint(f"  [►] Stages 5/6/7/9 running in parallel ({len(parallel_group)} active)...", "cyan")
            cprint(f"{'='*60}", "cyan")
            results = run_stages_parallel(parallel_group, eta_tracker=eta)
            for rname, rec in results.items():
                stage_map[rname] = rec
                if rec.passed():
                    out = {n5: probe_file, n6: redirect_file, n7: secret_file, n9: js_file}.get(rname)
                    if out: mark_stage_done(out)
            cprint(f"  [⏱] {eta.eta_str()}", "cyan")

    # ─────────────────────────────────────
    # Stages 8, 10, 11 — Parallel (target-only, no dependencies)
    # ─────────────────────────────────────
    parallel_group2 = []

    n8 = "8. S3 Bucket Scanner"
    if stage_already_done(s3_file, resume):
        stage_map[n8] = StageRecord(n8, STATE_RESUMED)
    else:
        from modules.s3scanner import scan_s3
        parallel_group2.append((n8, scan_s3, (target, s3_file), {"secret_file": secret_file}))

    n10 = "10. Wayback Scanner"
    if stage_already_done(wayback_file, resume):
        stage_map[n10] = StageRecord(n10, STATE_RESUMED)
    else:
        from modules.wayback import scan_wayback
        parallel_group2.append((n10, scan_wayback, (target, wayback_file), {}))

    n11 = "11. GitHub Secret Scanner"
    if stage_already_done(github_file, resume):
        stage_map[n11] = StageRecord(n11, STATE_RESUMED)
    else:
        from modules.githubscan import scan_github
        parallel_group2.append((n11, scan_github, (target, github_file), {}))

    if parallel_group2:
        cprint(f"\n{'='*60}", "cyan")
        cprint(f"  [►] Stages 8/10/11 running in parallel ({len(parallel_group2)} active)...", "cyan")
        cprint(f"{'='*60}", "cyan")
        results2 = run_stages_parallel(parallel_group2, eta_tracker=eta)
        output_map2 = {n8: s3_file, n10: wayback_file, n11: github_file}
        for rname, rec in results2.items():
            stage_map[rname] = rec
            if rec.passed(): mark_stage_done(output_map2[rname])
        cprint(f"  [⏱] {eta.eta_str()}", "cyan")

    # ─────────────────────────────────────
    # Stage 12: Port Scan (Nmap)
    # ─────────────────────────────────────
    name = "12. Port Scan (Nmap)"
    if stage_already_done(scan_file, resume):
        _record(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.scan import run_scan
        rec = run_stage(name, run_scan, subdomains_file, scan_file)
        if rec.passed(): mark_stage_done(scan_file)
        _record(name, rec)

    # ─────────────────────────────────────
    # Stage 13: CVE Analysis
    # ─────────────────────────────────────
    name = "13. CVE Analysis"
    if stage_already_done(analysis_file, resume):
        _record(name, StageRecord(name, STATE_RESUMED))
    elif not file_has_content(scan_file):
        cprint("  [!] No scan results — skipping CVE analysis.", "yellow")
        _record(name, StageRecord(name, STATE_SKIPPED))
    else:
        # Clear stale NVD cache entries before analysis
        try:
            from modules.nvd import clear_expired_cache
            cleared = clear_expired_cache()
            if cleared:
                cprint(f"  [ℹ] Cleared {cleared} expired NVD cache entries", "cyan")
        except Exception:  # NVD cache clear failed - non-critical
            pass
        from modules.analyse import analyse_scan_results
        rec = run_stage(name, analyse_scan_results, scan_file, analysis_file,
                        passive_file=passive_file if file_has_content(passive_file) else None,
                        probe_file=probe_file   if file_has_content(probe_file)   else None)
        if rec.passed(): mark_stage_done(analysis_file)
        _record(name, rec)

    # ─────────────────────────────────────
    # Stage 14: Attack Path Correlation
    # Must run BEFORE report so report can include attack paths.
    # Reads all prior stage outputs, cross-references findings,
    # produces ranked attack paths in attack_paths.json
    # ─────────────────────────────────────
    name = "14. Attack Path Correlation"
    if stage_already_done(correlate_file, resume):
        _record(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.correlate import correlate
        rec = run_stage(
            name, correlate,
            correlate_file,
            passive_file=passive_file,
            probe_file=probe_file,
            secret_file=secret_file,
            js_file=js_file,
            wayback_file=wayback_file,
            github_file=github_file,
            redirect_file=redirect_file,
            takeover_file=takeover_file,
            s3_file=s3_file,
            scan_file=scan_file,
            analysis_file=analysis_file,
        )
        if rec.passed(): mark_stage_done(correlate_file)
        _record(name, rec)

    # ─────────────────────────────────────
    # Stage 15: Report Generation
    # Runs last — includes attack paths from Stage 14
    # Verifies both HTML and Markdown report outputs.
    # ─────────────────────────────────────
    name = "15. Report Generation"
    if stage_already_done([report_html_file, report_md_file], resume):   
        _record(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.report import generate_report
        rec = run_stage(
            name, generate_report,
            analysis_file, report_md_file,
            html_output=report_html_file,
            probe_file=probe_file,
            takeover_file=takeover_file,
            redirect_file=redirect_file,
            secret_file=secret_file,
            s3_file=s3_file,
            js_file=js_file,
            wayback_file=wayback_file,
            github_file=github_file,
            attack_paths_file=correlate_file,
        )
        if rec.passed(): mark_stage_done([report_html_file, report_md_file])
        _record(name, rec)

    # ─────────────────────────────────────
    # Final Summary
    # ─────────────────────────────────────
    print_summary(target, stage_map, output_dir, start_time)