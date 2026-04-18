# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/report.py
# Report generator — v2

#   - HTML injection fix (html.escape on all user-controlled data)
#   - Consumes new fields from upgraded modules:
#       probe:      finding_type, confidence, matched_snippet, header_evidence
#       analyse:    risk_score, epss, attack_surface, cwe_ids, vector_string
#       jsextractor: graphql_introspection, leaked_subdomains, interesting_params
#       takeover:   confidence field (CONFIRMED/LIKELY/POTENTIAL)
#       s3scanner:  provider field (AWS/GCP/Azure)
#   - Risk-scored CVE target table (sorted by risk_score)
#   - Separate probe sections by finding_type
#   - EPSS column in CVE table
#   - Attack surface tag badges
#   - GraphQL introspection section
#   - Leaked subdomain section
#   - CORS findings section
#   - Cookie audit section
#   - Consistent makedirs fix

import json
import os
from html import escape
from datetime import datetime


# ─────────────────────────────────────────
# Badge Helpers
# ─────────────────────────────────────────

def _cvss_badge(score):
    try:
        s = float(score)
        if s >= 9.0:   return "critical"
        elif s >= 7.0: return "high"
        elif s >= 4.0: return "medium"
        else:          return "low"
    except Exception:
        return "unknown"


def _severity_badge(severity):
    return {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "INFO":     "info",
    }.get(str(severity).upper(), "info")


def _confidence_badge(confidence):
    return {
        "CONFIRMED": "confirmed",
        "LIKELY":    "likely",
        "POTENTIAL": "potential",
        "HIGH":      "confirmed",
        "MEDIUM":    "likely",
        "LOW":       "potential",
    }.get(str(confidence).upper(), "info")


def _version_relevance_badge(relevance):
    """
    Returns (css_class, display_text) for version_relevance field.
    Uses "Banner Matched" not "Version Confirmed" — the version comes
    from the Nmap/HTTP banner which is not independently verified.
    Ubuntu/Debian distributions may backport fixes without changing
    the upstream version string shown in banners.
    """
    mapping = {
        "CONFIRMED": ("confirmed",  "~ Banner Matched"),
        "POSSIBLE":  ("likely",     "~ Possibly Affected"),
        "UNLIKELY":  ("info",       "✗ Version Unlikely"),
        "UNKNOWN":   ("info",       "? Unknown"),
        "":          ("info",       "? Unknown"),
    }
    return mapping.get(str(relevance).upper(), ("info", "? Unknown"))


def _epss_badge(epss):
    """Returns CSS class based on EPSS exploitation probability."""
    if epss is None:
        return "info", "N/A"
    try:
        p = float(epss)
        if p >= 0.5:   return "critical", f"{p:.3f}"
        elif p >= 0.1: return "high",     f"{p:.3f}"
        elif p >= 0.01: return "medium",  f"{p:.3f}"
        else:           return "low",     f"{p:.3f}"
    except Exception:
        return "info", "N/A"


def e(text):
    """Escape HTML — prevents XSS in report from attacker-controlled response data."""
    return escape(str(text or ""), quote=True)


def _build_priority_actions_html(priority_actions):
    """Render ranked priority actions as an HTML block for the exec summary card."""
    if not priority_actions:
        return ""
    PRIORITY_STYLES = {
        "CRITICAL": ("background:#ff444422;color:#ff4444;", "#ff444444"),
        "HIGH":     ("background:#f0883e22;color:#f0883e;", "#f0883e44"),
        "MEDIUM":   ("background:#d2992222;color:#d29922;", "#d2992244"),
    }
    items = ""
    for priority, action in priority_actions:
        badge_style, _ = PRIORITY_STYLES.get(priority, ("background:#30363d;color:#8b949e;", "#30363d"))
        items += (
            f'<li style="margin-bottom:0.4rem">'
            f'<span style="{badge_style}padding:1px 7px;border-radius:3px;'
            f'font-size:0.73rem;font-weight:700;margin-right:0.5rem">{e(priority)}</span>'
            f'{e(action)}</li>'
        )
    return (
        f'<div style="margin-top:0.8rem;padding:0.7rem 1rem;'
        f'background:#0d1117;border-radius:6px;border-left:3px solid #ff4444">'
        f'<p style="color:#ff4444;font-size:0.83rem;font-weight:700;margin-bottom:0.5rem">'
        f'🚨 Priority Actions</p>'
        f'<ol style="margin:0 0 0 1rem;padding:0;color:#c9d1d9;font-size:0.84rem;line-height:1.85">'
        f'{items}</ol></div>'
    )


# ─────────────────────────────────────────
# Data Loaders
# ─────────────────────────────────────────

def _load(path):
    """Load JSON from path. Returns [] or {} on failure."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _load_dict(path):
    data = _load(path)
    return data if isinstance(data, dict) else {}


def _load_list(path):
    data = _load(path)
    return data if isinstance(data, list) else []


# ─────────────────────────────────────────
# Main Report Generator
# ─────────────────────────────────────────

def generate_report(input_file, output_file, html_output=None,
                    probe_file=None, takeover_file=None, redirect_file=None,
                    secret_file=None, s3_file=None, js_file=None,
                    wayback_file=None, github_file=None,
                    attack_paths_file=None):

    generated_on = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Load CVE analysis (primary input) ──
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            cve_data = json.load(f)
        if not isinstance(cve_data, list):
            cve_data = []
    except Exception as _load_err:
        print(f"[!] Failed to read analysis file: {_load_err}")
        cve_data = []

    # ── Load all module outputs ──
    probe_data    = _load_list(probe_file)
    takeover_data = _load_list(takeover_file)
    redirect_data = _load_list(redirect_file)
    secret_data   = _load_list(secret_file)
    js_data       = _load_list(js_file)

    s3_raw        = _load_dict(s3_file)
    s3_critical   = s3_raw.get("critical", [])
    s3_high       = s3_raw.get("high", [])
    s3_private    = s3_raw.get("exists_private", [])
    s3_all        = s3_critical + s3_high

    wb_raw        = _load_dict(wayback_file)
    wb_alive200   = wb_raw.get("alive_200", [])
    wb_alive403   = wb_raw.get("alive_403", [])
    wb_total      = wb_raw.get("total_found", 0)
    wb_alive      = wb_raw.get("alive", [])

    gh_raw        = _load_dict(github_file)
    gh_findings   = gh_raw.get("findings", [])
    gh_critical   = gh_raw.get("critical", 0)
    gh_high       = gh_raw.get("high", 0)
    gh_total      = gh_raw.get("files_found", 0)

    # ── Aggregate stats ──
    total_cves       = sum(len(m.get("cves", [])) for e in cve_data for m in e.get("tech_matches", []))
    high_cves        = sum(1 for e in cve_data for m in e.get("tech_matches", [])
                           for c in m.get("cves", []) if _cvss_badge(c.get("cvss")) in ("critical", "high"))
    rce_cves         = sum(1 for e in cve_data for m in e.get("tech_matches", [])
                           for c in m.get("cves", []) if "RCE" in c.get("attack_surface", []))
    total_probes     = sum(len(e.get("findings", [])) for e in probe_data)
    probe_vulns      = sum(1 for e in probe_data for f in e.get("findings", [])
                           if f.get("finding_type") == "vulnerability")
    probe_hardening  = sum(1 for e in probe_data for f in e.get("findings", [])
                           if f.get("finding_type") == "hardening")
    total_redirects  = sum(len(e.get("findings", [])) for e in redirect_data)
    total_secrets    = sum(len(e.get("findings", [])) for e in secret_data)
    secret_critical  = sum(1 for e in secret_data for f in e.get("findings", [])
                           if f.get("severity") == "CRITICAL")
    takeover_confirmed = [t for t in takeover_data if t.get("confidence") == "CONFIRMED" or t.get("confirmed")]
    takeover_likely    = [t for t in takeover_data if t.get("confidence") == "LIKELY"]
    takeover_potential = [t for t in takeover_data if t.get("confidence") == "POTENTIAL"
                          and not t.get("confirmed")]
    total_js_endpoints  = sum(r.get("total_endpoints", 0) for r in js_data)
    total_js_high_value = sum(len(r.get("high_value", [])) for r in js_data)
    total_js_files      = sum(r.get("js_files_scanned", 0) for r in js_data)
    graphql_hosts       = [r for r in js_data if r.get("graphql_introspection")]
    leaked_subdomains   = [(r["url"], sub) for r in js_data for sub in r.get("leaked_subdomains", [])]
    cors_findings       = [f for e in probe_data for f in e.get("findings", []) if f.get("type") == "cors"]
    cookie_findings     = [f for e in probe_data for f in e.get("findings", []) if f.get("type") == "cookie"]
    attack_paths        = _load_list(attack_paths_file) if attack_paths_file else []

    # ─────────────────────────────────────
    # Executive Summary + Priority Actions (auto-generated)
    # ─────────────────────────────────────

    def _build_exec_summary():
        """
        Builds a crisp executive summary paragraph and a ranked
        Priority Actions list. The actions list is the key addition —
        it surfaces the top 3-5 concrete things an operator should do next,
        making the report decision-focused not just data-rich.
        """
        parts = []

        # Scope
        n_hosts = len(set(
            e.get("ip", e.get("url", ""))
            for e in cve_data
        ))
        if n_hosts:
            parts.append(f"Scan covered {n_hosts} host(s).")

        # Services found
        services = []
        for entry in cve_data:
            for m in entry.get("tech_matches", []):
                tech  = m.get("tech", "")
                ver   = m.get("version", "")
                ports = m.get("ports", [])
                if tech:
                    label = f"{tech} {ver}".strip()
                    if ports:
                        label += f" on port {ports[0]}"
                    services.append(label)
        if services:
            parts.append(f"Detected: {', '.join(services[:6])}.")

        # Highest risk CVE
        top_cve = None
        top_score = 0.0
        top_cve_tech = ""
        for entry in cve_data:
            for m in entry.get("tech_matches", []):
                for c in m.get("cves", []):
                    if c.get("version_relevance") == "UNLIKELY":
                        continue
                    sc = float(c.get("cvss", 0) or 0) * 0.6 + float(c.get("epss", 0) or 0) * 10 * 0.4
                    if sc > top_score:
                        top_score    = sc
                        top_cve      = c
                        top_cve_tech = m.get("tech", "")
        if top_cve:
            epss = float(top_cve.get("epss", 0) or 0)
            parts.append(
                f"Highest-priority CVE: {top_cve.get('cve','')} ({top_cve_tech}, "
                f"CVSS {top_cve.get('cvss','N/A')}, EPSS {epss:.3f} — "
                f"{'actively exploited in the wild' if epss >= 0.3 else 'patch validation required'})."
            )

        if secret_critical:
            parts.append(f"{secret_critical} critical credential(s) exposed — rotation required immediately.")
        elif total_secrets:
            parts.append(f"{total_secrets} potential credential(s) identified — validate and rotate if confirmed.")

        if takeover_confirmed:
            parts.append(f"{len(takeover_confirmed)} subdomain takeover candidate(s) confirmed.")

        if s3_critical:
            parts.append(f"{len(s3_critical)} publicly readable storage bucket(s) found.")

        if attack_paths:
            high = sum(1 for p in attack_paths if p.get("confidence") == "HIGH")
            parts.append(
                f"Correlation engine: {len(attack_paths)} lead(s), {high} HIGH confidence. "
                f"All require manual validation."
            )

        if not parts:
            return "Scan completed. No high-priority findings identified in this run.", []

        # Build Priority Actions — ranked, concrete, decision-focused
        actions = []

        # 1. Critical credentials
        if secret_critical:
            actions.append(("CRITICAL", "Rotate exposed credentials immediately — do not wait for patch cycle"))
        elif total_secrets:
            actions.append(("HIGH", f"Review {total_secrets} credential finding(s) and validate with a safe read-only API call"))

        # 2. Takeovers
        for t in takeover_confirmed[:2]:
            svc = t.get("service", "unknown")
            sub = t.get("subdomain", "")
            actions.append(("CRITICAL", f"Remove or reclaim dangling DNS record for {sub} ({svc})"))

        # 3. Top CVE
        if top_cve:
            epss = float(top_cve.get("epss", 0) or 0)
            priority = "CRITICAL" if epss >= 0.3 else "HIGH"
            actions.append((priority,
                f"Confirm {top_cve.get('cve','')} patch status on {top_cve_tech} — "
                f"EPSS {epss:.3f} {'(actively exploited)' if epss >= 0.3 else ''}"))

        # 4. Public storage
        for bucket in s3_critical[:2]:
            name = bucket.get("bucket", bucket.get("name", ""))
            actions.append(("HIGH", f"Review public bucket '{name}' contents for sensitive data"))

        # 5. Hardening gaps (batch)
        if probe_hardening:
            actions.append(("MEDIUM", f"Add missing security headers ({probe_hardening} gap(s)) — CSP, X-Frame-Options, etc."))

        # 6. High-confidence leads
        for lead in [p for p in attack_paths if p.get("confidence") == "HIGH"][:2]:
            actions.append(("HIGH", f"Validate lead: {lead.get('title','')[:80]}"))

        # Sort: CRITICAL first, then HIGH, then MEDIUM
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        actions.sort(key=lambda x: priority_order.get(x[0], 3))

        return " ".join(parts), actions[:6]  # cap at 6 actions

    exec_summary, priority_actions = _build_exec_summary()

    # ─────────────────────────────────────
    # Markdown Report
    # ─────────────────────────────────────
    lines = [
        "# 🛡️ RedShadow V4 Reconnaissance Report",
        f"\n**Generated:** `{generated_on}`\n",
        f"**Total CVEs:** {total_cves} | **RCE:** {rce_cves} | **Secrets:** {total_secrets} | **Takeovers:** {len(takeover_confirmed)} confirmed | **Correlated Leads:** {len(attack_paths)}\n",
        "## 📋 Executive Summary\n",
        f"> {exec_summary}\n",
    ]

    if priority_actions:
        lines += ["## 🚨 Priority Actions\n"]
        for i, (priority, action) in enumerate(priority_actions, 1):
            lines.append(f"{i}. **[{priority}]** {action}")
        lines.append("")

    lines += [
        "## 🔬 Recommended Validation Steps\n",
        "> 1. Confirm exact service versions via banner grabbing or response headers",
        "> 2. Validate CVE applicability against detected version ranges",
        "> 3. Check patch status with vendor advisories before treating as exploitable",
        "> 4. Validate correlated leads manually — engine output is not proof\n",
    ]

    if attack_paths:
        lines += ["## 🎯 Correlated Leads — Prioritised for Review\n"]
        lines.append("> Cross-stage correlation — each lead requires manual validation before being treated as a confirmed finding.\n")
        for p in attack_paths:
            score      = p.get("score", 0)
            rank       = p.get("rank", "")
            ptype      = p.get("type", "")
            title      = p.get("title", "")
            hosts      = ", ".join(p.get("hosts", []))
            confidence = p.get("confidence", "")
            src_mods   = ", ".join(p.get("source_modules", []))
            narrative  = p.get("narrative", "")
            checks     = p.get("validation_checks", [])
            lines.append(f"### #{rank} [{score:.1f}] [{confidence}] `{ptype}` — {title}\n")
            lines.append(f"**Hosts:** `{hosts}` | **Sources:** {src_mods}\n")
            if narrative:
                lines.append(f"> {narrative}\n")
            if checks:
                lines.append("**Validation Checks:**")
                for i, c in enumerate(checks, 1):
                    lines.append(f"{i}. {c}")
                lines.append("")

    if takeover_data:
        lines += ["## 🚨 Subdomain Takeover\n"]
        for t in takeover_confirmed:
            lines.append(f"- **[CONFIRMED]** `{t.get('subdomain','')}` → `{t.get('cname','')}` ({t.get('service','')})")
        for t in takeover_likely:
            lines.append(f"- **[LIKELY]** `{t.get('subdomain','')}` → `{t.get('cname','')}` ({t.get('service','')})")
        for t in takeover_potential:
            lines.append(f"- **[POTENTIAL]** `{t.get('subdomain','')}` → `{t.get('cname','')}` ({t.get('service','')})")
        lines.append("")

    if s3_all:
        lines += ["## 🪣 S3/Cloud Storage Findings\n"]
        for b in s3_all:
            provider = b.get("provider", "AWS")
            lines.append(f"- **[{b['severity']}]** `{b['bucket']}` [{provider}] → {b['status']}")
            lines.append(f"  - {b['note']}")
        lines.append("")

    if secret_data:
        lines += ["## 🔑 Secrets & Credentials\n"]
        for entry in secret_data:
            for f in entry.get("findings", []):
                lines.append(f"- [{f['severity']}] **{f['name']}** → `{f['value']}`")
                lines.append(f"  - Source: `{f['url']}`")
                if f.get("entropy"):
                    lines.append(f"  - Entropy: {f['entropy']}")
        lines.append("")

    if gh_findings:
        lines += ["## 🐙 GitHub Leaked Secrets\n"]
        for f in gh_findings:
            lines.append(f"### {f['repo']}")
            lines.append(f"- File: {f['file_url']}")
            for s in f.get("secrets", []):
                lines.append(f"  - [{s['severity']}] {s['name']} → `{s['value']}`")
        lines.append("")

    if graphql_hosts:
        lines += ["## ⚠️ GraphQL Introspection Enabled\n"]
        for r in graphql_hosts:
            lines.append(f"- `{r['url']}/graphql` — schema fully exposed")
        lines.append("")

    if leaked_subdomains:
        lines += ["## 🌐 Subdomain Leakage in JS\n"]
        for host_url, sub in leaked_subdomains[:20]:
            lines.append(f"- `{sub}` (found in JS of `{host_url}`)")
        lines.append("")

    if cors_findings:
        lines += ["## 🔓 Hardening Gaps — CORS Policy Issues\n"]
        for f in cors_findings:
            lines.append(f"- [{f['severity']}] {f['name']} → `{f['url']}`")
            if f.get("header_evidence"):
                lines.append(f"  - Evidence: `{f['header_evidence']}`")
        lines.append("")

    if wb_alive200:
        lines += ["## 🕰️ Wayback — Live Archived URLs\n"]
        for r in wb_alive200:
            lines.append(f"- [200] `{r['url']}`")
        lines.append("")

    if js_data:
        lines += ["## 🔎 JS High-Value Endpoints\n"]
        for r in js_data:
            if r.get("high_value"):
                lines.append(f"### {r['url']}")
                for ep in r["high_value"]:
                    lines.append(f"  - ⭐ `{ep}`")
        lines.append("")

    if redirect_data:
        lines += ["## 🔀 Open Redirects\n"]
        for entry in redirect_data:
            for f in entry.get("findings", []):
                lines.append(f"- {f['name']} → `{f['url']}`")
        lines.append("")

    # Probe — split by finding_type
    probe_vuln_list = [f for e in probe_data for f in e.get("findings", [])
                       if f.get("finding_type") == "vulnerability"]
    if probe_vuln_list:
        lines += ["## 🔍 Exposed Services — HTTP Probe Findings\n"]
        for f in probe_vuln_list:
            lines.append(f"- [{f['severity']}] {f['name']} → `{f['url']}`")
            if f.get("matched_snippet"):
                lines.append(f"  - Proof: `{f['matched_snippet']}`")
        lines.append("")

    lines += ["## 🛡️ Version-Matched CVE Candidates\n"]
    lines.append("> ⚠️ CVEs below are historically associated with detected service versions. "
                 "Sorted by EPSS × CVSS priority. Requires version confirmation before treating "
                 "as confirmed vulnerabilities.\n")
    for entry in sorted(cve_data, key=lambda x: x.get("risk_score", 0), reverse=True):
        url   = entry.get("url", "N/A")
        ip    = entry.get("ip", "N/A")
        score = entry.get("risk_score", 0)
        lines.append(f"### `{url}` (IP: {ip}) — Risk: {score}/10")
        for match in entry.get("tech_matches", []):
            for cve in match.get("cves", []):
                cvss  = cve.get("cvss", "N/A")
                epss  = cve.get("epss")
                tags  = ", ".join(cve.get("attack_surface", []))
                epss_str = f" | EPSS: {epss:.3f}" if epss is not None else ""
                tags_str = f" | {tags}" if tags else ""
                lines.append(f"  - [{cve.get('cve')}]({cve.get('url','#')}) CVSS: {cvss}{epss_str}{tags_str}")
        lines.append("")

    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[✓] Markdown report: {output_file}")
    except Exception as ex:
        print(f"[!] Could not write markdown: {ex}")

    if not html_output:
        return

    # ─────────────────────────────────────
    # HTML Section Builders
    # All output is HTML-escaped to prevent XSS from attacker-controlled data.
    # ─────────────────────────────────────

    # ── Attack Path Correlation (Stage 15) ──
    attack_paths_html = ""
    if attack_paths:
        crit_count = sum(1 for p in attack_paths if p.get("score", 0) >= 9.0)
        high_count = sum(1 for p in attack_paths if 7.5 <= p.get("score", 0) < 9.0)

        TYPE_ICONS = {
            # Lead type icons
            "CRITICAL_CHAIN":          "🔗",
            "AUTH_BYPASS":             "🔓",
            "TAKEOVER_CHAIN":          "🏴",
            "RCE_PATH":                "💥",
            "SECRET_REUSE":            "🔑",
            "IDOR_SURFACE":            "🪪",
            "GRAPHQL_EXPOSED":         "⚡",
            "OPEN_REDIRECT":           "↪️",
            "S3_CHAIN":                "🪣",
            "WAYBACK_PARAM":           "🕰️",
            # New rule types
            "MULTI_SOURCE_SECRET":     "🔑",
            "TAKEOVER_LIVE":           "🏴",
            "RCE_CANDIDATE":           "💥",
            "TOKEN_WITH_SURFACE":      "🔐",
            "STORAGE_EXPOSURE":        "🪣",
            "IDOR_CANDIDATE":          "🪪",
            "CORS_CREDENTIALED":       "🔓",
            "REDIRECT_SENSITIVE":      "↪️",
            "FORGOTTEN_ENDPOINT":      "🕰️",
            "GRAPHQL_RECON":           "⚡",
            "EXPOSED_ADMIN_PANEL":     "🚪",
            "DEBUG_ENDPOINT":          "🐛",
            "VERSION_CHAIN":           "📦",
            # Chain types
            "CREDENTIAL_RCE_CHAIN":    "⛓️",
            "CORS_TOKEN_CHAIN":        "⛓️",
            "TAKEOVER_CREDENTIAL_CHAIN": "⛓️",
            "IDOR_FORGOTTEN_CHAIN":    "⛓️",
            "STORAGE_CREDENTIAL_CHAIN":"⛓️",
        }

        cards = ""
        for p in attack_paths:
            score     = p.get("score", 0)
            ptype     = p.get("type", "")
            icon      = TYPE_ICONS.get(ptype, "🎯")
            rank      = p.get("rank", "")
            title      = e(p.get("title", ""))
            action     = e(p.get("action", ""))
            hosts      = ", ".join(e(h) for h in p.get("hosts", []))
            steps_html = "".join(f"<li>{e(s)}</li>" for s in p.get("steps", []))
            narrative  = e(p.get("narrative", ""))
            # validation_checks from correlate.py (more operator-focused than steps)
            checks_html = "".join(f"<li>{e(c)}</li>" for c in p.get("validation_checks", []))
            confidence   = p.get("confidence", "")
            conf_color   = "#3fb950" if confidence == "HIGH" else "#f0883e" if confidence == "MEDIUM" else "#8b949e"
            src_mods_str = e(", ".join(p.get("source_modules", [])))

            is_chain   = p.get("is_chain", False)
            if score >= 9.0:
                score_col  = "#ff4444"
                border_col = "#ff4444aa" if is_chain else "#ff444444"
            elif score >= 7.5:
                score_col  = "#f0883e"
                border_col = "#f0883eaa" if is_chain else "#f0883e44"
            else:
                score_col  = "#d29922"
                border_col = "#d29922aa" if is_chain else "#d2992244"

            cards += f"""
            <div style="background:#161b22;border:1px solid {border_col};border-radius:8px;
                        padding:1.2rem 1.4rem;margin-bottom:1rem;">
                <div style="display:flex;align-items:center;gap:0.7rem;margin-bottom:0.8rem;flex-wrap:wrap">
                    <span style="font-size:1.4rem;font-weight:700;color:{score_col}">#{rank}</span>
                    <span style="font-size:1.1rem">{icon}</span>
                    <span style="background:{score_col}22;color:{score_col};padding:2px 10px;
                                 border-radius:4px;font-size:0.78rem;font-weight:600;
                                 letter-spacing:0.05em">{e(ptype)}</span>
                    <span style="background:{conf_color}22;color:{conf_color};padding:2px 8px;
                                 border-radius:4px;font-size:0.75rem;font-weight:600">{confidence}</span>
                    {"<span style='background:#388bfd22;color:#58a6ff;padding:2px 8px;border-radius:4px;font-size:0.72rem;font-weight:600'>⛓️ CHAIN</span>" if is_chain else ""}
                    <span style="font-size:1rem;font-weight:600;color:#e6edf3;flex:1">{title}</span>
                    <span style="font-size:1.3rem;font-weight:700;color:{score_col}">{score:.1f}</span>
                </div>
                <div style="font-size:0.82rem;color:#8b949e;margin-bottom:0.8rem">
                    Hosts: <code style="color:#58a6ff">{hosts}</code>
                    &nbsp;·&nbsp; Sources: <code style="color:#8b949e">{src_mods_str}</code>
                </div>
                {"<p style='font-size:0.88rem;color:#c9d1d9;line-height:1.6;margin-bottom:0.8rem;padding:0.6rem 0.8rem;background:#0d1117;border-radius:4px;border-left:3px solid " + border_col + "'>" + narrative + "</p>" if narrative else ""}
                {"<details style='margin-bottom:0.8rem'><summary style='color:#8b949e;font-size:0.82rem;cursor:pointer'>▶ Validation Checks (" + str(len(p.get("validation_checks",[]))) + ")</summary><ol style='margin:0.5rem 0 0 1.2rem;color:#c9d1d9;font-size:0.84rem;line-height:1.7'>" + checks_html + "</ol></details>" if checks_html else ""}
            </div>"""

        attack_paths_html = f"""
        <h2 style="color:#ff4444;margin:2rem 0 0.5rem">🎯 Correlated Leads
            <span style="font-size:0.9rem;color:#8b949e;font-weight:normal;margin-left:1rem">
                {len(attack_paths)} total &nbsp;·&nbsp;
                <span style="color:#ff4444">{crit_count} critical ≥9.0</span> &nbsp;·&nbsp;
                <span style="color:#f0883e">{high_count} high ≥7.5</span>
            </span>
        </h2>
        <p style="color:#8b949e;font-size:0.88rem;margin:0 0 1rem">
            Cross-stage correlation — each lead combines signals from multiple modules. All leads require manual validation before being treated as confirmed findings.
        </p>
        {cards}"""

    # ── Takeover ──
    takeover_html = ""
    if takeover_data:
        rows = ""
        for t in takeover_confirmed + takeover_likely + takeover_potential:
            conf  = t.get("confidence", "CONFIRMED" if t.get("confirmed") else "POTENTIAL")
            badge = _confidence_badge(conf)
            rows += f"""<tr>
                <td><code>{e(t.get('subdomain',''))}</code></td>
                <td><code>{e(t.get('cname',''))}</code></td>
                <td>{e(t.get('service',''))}</td>
                <td>{e(t.get('fingerprint',''))}</td>
                <td><span class="badge {badge}">{e(conf)}</span></td>
            </tr>"""
        takeover_html = f"""
        <h2 style="color:#ff4444;margin:2rem 0 1rem">🚨 Subdomain Takeover
            <span style="font-size:0.9rem;color:#8b949e;font-weight:normal;margin-left:1rem">
                {len(takeover_confirmed)} confirmed · {len(takeover_likely)} likely · {len(takeover_potential)} potential
            </span>
        </h2>
        <div class="target-card"><table>
        <thead><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Fingerprint</th><th>Status</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── S3 / Cloud Storage ──
    s3_html = ""
    if s3_all or s3_private:
        rows = ""
        for b in s3_all:
            badge    = _severity_badge(b["severity"])
            provider = e(b.get("provider", "AWS"))
            sensitive_flag = "🔴 SENSITIVE" if b.get("sensitive") else ""
            rows += f"""<tr>
                <td><code>{e(b['bucket'])}</code></td>
                <td><span class="badge info">{provider}</span></td>
                <td><a href="{e(b['url'])}" target="_blank">{e(b['url'])}</a></td>
                <td><span class="badge {badge}">{e(b['status'])}</span></td>
                <td>{b.get('files', 0)} {sensitive_flag}</td>
                <td>{e(b['note'][:80])}</td>
            </tr>"""
        for b in s3_private[:10]:
            provider = e(b.get("provider", "AWS"))
            rows += f"""<tr>
                <td><code>{e(b['bucket'])}</code></td>
                <td><span class="badge info">{provider}</span></td>
                <td><a href="{e(b['url'])}" target="_blank">{e(b['url'])}</a></td>
                <td><span class="badge info">EXISTS_PRIVATE</span></td>
                <td>—</td><td>{e(b['note'])}</td>
            </tr>"""
        s3_html = f"""
        <h2 style="color:#f85149;margin:2rem 0 1rem">🪣 Cloud Storage Findings</h2>
        <div class="target-card"><table>
        <thead><tr><th>Bucket</th><th>Provider</th><th>URL</th><th>Status</th><th>Files</th><th>Note</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── Secrets ──
    secret_html = ""
    if secret_data:
        rows = ""
        for entry in secret_data:
            for f in entry.get("findings", []):
                badge = _severity_badge(f.get("severity", "INFO"))
                conf  = _confidence_badge(f.get("confidence", "HIGH"))
                entropy = f"Entropy: {f['entropy']}" if f.get("entropy") else ""
                rows += f"""<tr>
                    <td><a href="{e(entry.get('url',''))}" target="_blank">{e(entry.get('url',''))}</a></td>
                    <td>{e(f.get('name',''))}</td>
                    <td><code style="word-break:break-all">{e(f.get('value',''))}</code></td>
                    <td><span class="badge {badge}">{e(f.get('severity',''))}</span></td>
                    <td><span class="badge {conf}">{e(f.get('confidence',''))}</span></td>
                    <td style="font-size:0.8rem;color:#8b949e">{entropy}</td>
                </tr>"""
        secret_html = f"""
        <h2 style="color:#ff4444;margin:2rem 0 1rem">🔑 Secrets & Credentials</h2>
        <div class="target-card"><table>
        <thead><tr><th>Host</th><th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th><th>Entropy</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── GitHub ──
    github_html = ""
    if gh_findings:
        rows = ""
        for f in gh_findings:
            repo     = f.get("repo", "N/A")
            file_url = f.get("file_url", "#")
            for s in f.get("secrets", []):
                badge = _severity_badge(s.get("severity", "INFO"))
                rows += f"""<tr>
                    <td><a href="https://github.com/{e(repo)}" target="_blank">{e(repo)}</a></td>
                    <td><a href="{e(file_url)}" target="_blank">{e(file_url.split('/')[-1])}</a></td>
                    <td>{e(s.get('name',''))}</td>
                    <td><code style="word-break:break-all">{e(s.get('value',''))}</code></td>
                    <td><span class="badge {badge}">{e(s.get('severity',''))}</span></td>
                </tr>"""
        github_html = f"""
        <h2 style="color:#ff6b6b;margin:2rem 0 1rem">🐙 GitHub Leaked Secrets
            <span style="font-size:0.9rem;color:#8b949e;font-weight:normal;margin-left:1rem">
                {gh_total} files · {gh_critical} critical · {gh_high} high
            </span>
        </h2>
        <div class="target-card"><table>
        <thead><tr><th>Repository</th><th>File</th><th>Secret Type</th><th>Value</th><th>Severity</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── GraphQL Introspection (new) ──
    graphql_html = ""
    if graphql_hosts:
        rows = "".join(f"""<tr>
            <td><a href="{e(r['url'])}/graphql" target="_blank">{e(r['url'])}/graphql</a></td>
            <td><span class="badge high">SCHEMA EXPOSED</span></td>
            <td>Introspection query returned __schema — full API schema accessible</td>
        </tr>""" for r in graphql_hosts)
        graphql_html = f"""
        <h2 style="color:#f85149;margin:2rem 0 1rem">⚠️ GraphQL Introspection Enabled ({len(graphql_hosts)} host(s))</h2>
        <div class="target-card"><table>
        <thead><tr><th>Endpoint</th><th>Status</th><th>Impact</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── Leaked Subdomains (new) ──
    leaked_html = ""
    if leaked_subdomains:
        rows = "".join(f"""<tr>
            <td><code>{e(sub)}</code></td>
            <td><a href="{e(host_url)}" target="_blank">{e(host_url)}</a></td>
        </tr>""" for host_url, sub in leaked_subdomains[:50])
        leaked_html = f"""
        <h2 style="color:#79c0ff;margin:2rem 0 1rem">🌐 Subdomains Leaked in JS ({len(leaked_subdomains)} found)</h2>
        <div class="target-card"><table>
        <thead><tr><th>Leaked Subdomain</th><th>Discovered in</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── CORS Misconfigurations (new) ──
    cors_html = ""
    if cors_findings:
        rows = ""
        for f in cors_findings:
            badge = _severity_badge(f.get("severity", "MEDIUM"))
            rows += f"""<tr>
                <td><a href="{e(f.get('url',''))}" target="_blank">{e(f.get('url',''))}</a></td>
                <td>{e(f.get('name',''))}</td>
                <td><code>{e(f.get('header_evidence',''))}</code></td>
                <td><span class="badge {badge}">{e(f.get('severity',''))}</span></td>
            </tr>"""
        cors_html = f"""
        <h2 style="color:#f85149;margin:2rem 0 1rem">🔓 CORS Misconfigurations ({len(cors_findings)} findings)</h2>
        <div class="target-card"><table>
        <thead><tr><th>Host</th><th>Finding</th><th>Evidence</th><th>Severity</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── Wayback ──
    wayback_html = ""
    if wb_alive:
        rows = ""
        for r in wb_alive200:
            cat = e(r.get("category", ""))
            rows += f"""<tr>
                <td><a href="{e(r['url'])}" target="_blank">{e(r['url'])}</a></td>
                <td><span class="badge high">200 LIVE</span></td>
                <td>{cat}</td>
            </tr>"""
        for r in wb_alive403[:20]:
            rows += f"""<tr>
                <td><a href="{e(r['url'])}" target="_blank">{e(r['url'])}</a></td>
                <td><span class="badge medium">403 EXISTS</span></td>
                <td></td>
            </tr>"""
        wayback_html = f"""
        <h2 style="color:#e3b341;margin:2rem 0 1rem">🕰️ Wayback Machine
            <span style="font-size:0.9rem;color:#8b949e;font-weight:normal;margin-left:1rem">
                {wb_total:,} archived · {len(wb_alive200)} live · {len(wb_alive403)} exist
            </span>
        </h2>
        <div class="target-card"><table>
        <thead><tr><th>URL</th><th>Status</th><th>Category</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── JS Endpoints ──
    js_html = ""
    if total_js_endpoints > 0:
        rows = ""
        for r in js_data:
            host = r.get("url", "")
            for ep in r.get("high_value", []):
                rows += f"""<tr>
                    <td><a href="{e(host)}" target="_blank">{e(host)}</a></td>
                    <td><code>{e(ep)}</code></td>
                    <td><span class="badge high">⭐ HIGH VALUE</span></td>
                </tr>"""
            for ep in r.get("endpoints", [])[:10]:
                rows += f"""<tr>
                    <td><a href="{e(host)}" target="_blank">{e(host)}</a></td>
                    <td><code>{e(ep)}</code></td>
                    <td><span class="badge info">ENDPOINT</span></td>
                </tr>"""
        if rows:
            js_html = f"""
            <h2 style="color:#79c0ff;margin:2rem 0 1rem">🔎 JS Endpoint Extraction
                <span style="font-size:0.9rem;color:#8b949e;font-weight:normal;margin-left:1rem">
                    {total_js_files} files · {total_js_endpoints} endpoints · {total_js_high_value} high value
                </span>
            </h2>
            <div class="target-card"><table>
            <thead><tr><th>Host</th><th>Endpoint</th><th>Type</th></tr></thead>
            <tbody>{rows}</tbody></table></div>"""

    # ── Open Redirects ──
    redirect_html = ""
    if redirect_data:
        rows = ""
        for entry in redirect_data:
            for f in entry.get("findings", []):
                rows += f"""<tr>
                    <td><a href="{e(entry.get('url',''))}">{e(entry.get('url',''))}</a></td>
                    <td>{e(f.get('name',''))}</td>
                    <td><code>{e(f.get('parameter',''))}</code></td>
                    <td><a href="{e(f.get('redirects_to',''))}">{e(f.get('redirects_to',''))}</a></td>
                    <td><span class="badge high">HIGH</span></td>
                </tr>"""
        redirect_html = f"""
        <h2 style="color:#f85149;margin:2rem 0 1rem">🔀 Open Redirects ({total_redirects})</h2>
        <div class="target-card"><table>
        <thead><tr><th>Host</th><th>Finding</th><th>Param</th><th>Redirects To</th><th>Severity</th></tr></thead>
        <tbody>{rows}</tbody></table></div>"""

    # ── HTTP Probe — split by finding_type ──
    probe_html = ""
    if probe_data:
        def _probe_section(title, ftype, colour):
            findings = [(e_entry, f) for e_entry in probe_data
                        for f in e_entry.get("findings", [])
                        if f.get("finding_type") == ftype]
            if not findings:
                return ""
            rows = ""
            for e_entry, f in findings:
                badge   = _severity_badge(f.get("severity", "INFO"))
                conf    = _confidence_badge(f.get("confidence", ""))
                snippet = f.get("matched_snippet") or f.get("header_evidence") or ""
                rows += f"""<tr>
                    <td><a href="{e(e_entry.get('url',''))}">{e(e_entry.get('url',''))}</a></td>
                    <td>{e(f.get('name',''))}</td>
                    <td><a href="{e(f.get('url',''))}">{e(f.get('url',''))}</a></td>
                    <td><span class="badge {badge}">{e(f.get('severity',''))}</span></td>
                    <td><span class="badge {conf}">{e(f.get('confidence',''))}</span></td>
                    <td style="font-size:0.8rem;color:#8b949e;max-width:200px;overflow:hidden">{e(snippet[:80])}</td>
                </tr>"""
            return f"""
            <h2 style="color:{colour};margin:2rem 0 1rem">{title} ({len(findings)})</h2>
            <div class="target-card"><table>
            <thead><tr><th>Host</th><th>Finding</th><th>URL</th><th>Severity</th><th>Confidence</th><th>Proof</th></tr></thead>
            <tbody>{rows}</tbody></table></div>"""

        probe_html = (
            _probe_section("🔍 HTTP Probe — Vulnerabilities",  "vulnerability", "#f85149") +
            _probe_section("🔍 HTTP Probe — Recon Findings",   "recon",         "#58a6ff")
        )
        # Hardening gaps rendered as collapsed details section to reduce noise
        hardening_items = [
            f for e in probe_data
            for f in e.get("findings", [])
            if f.get("finding_type") == "hardening"
        ]
        if hardening_items:
            harden_rows = ""
            for hf in hardening_items:
                host_url = next((e.get("url","") for e in probe_data if hf in e.get("findings",[])), "")
                harden_rows += f"""<tr>
                    <td style="font-size:0.82rem"><code>{e(host_url)}</code></td>
                    <td style="font-size:0.82rem">{e(hf.get('name',''))}</td>
                    <td><span class="badge {_severity_badge(hf.get('severity',''))}">{e(hf.get('severity',''))}</span></td>
                    <td style="font-size:0.78rem;color:#8b949e">{e(hf.get('description','') or hf.get('header',''))}</td>
                </tr>"""
            probe_html += f"""
            <details style="margin-top:1rem">
            <summary style="cursor:pointer;color:#8b949e;font-size:0.85rem;padding:0.4rem 0;
                             border-top:1px solid #30363d;list-style:none">
                ▶ Hardening Gaps ({len(hardening_items)}) — click to expand
                <span style="font-size:0.75rem;color:#555;margin-left:0.5rem">
                    (missing security headers — lower priority than vulnerabilities)
                </span>
            </summary>
            <table style="margin-top:0.5rem"><thead><tr>
                <th>Host</th><th>Gap</th><th>Severity</th><th>Detail</th>
            </tr></thead><tbody>{harden_rows}</tbody></table>
            </details>"""

    # ── CVE Analysis (with risk score + EPSS + attack surface) ──
    # CVEs are sorted by combined EPSS+CVSS score so highest-priority items
    # appear first. The report explicitly frames these as historically associated
    # CVEs requiring version validation — not confirmed vulnerabilities.
    cve_html = ""
    for entry in sorted(cve_data, key=lambda x: x.get("risk_score", 0), reverse=True):
        url        = entry.get("url", "N/A")
        ip         = entry.get("ip", "N/A")
        hostname   = entry.get("hostname", "N/A")
        risk_score = entry.get("risk_score", 0)
        risk_badge = _cvss_badge(risk_score)
        techs      = entry.get("tech_matches", [])
        rows       = ""
        total_cves_this_target = sum(len(m.get("cves", [])) for m in techs)

        for match in techs:
            # Sort CVEs by combined EPSS+CVSS — highest risk first
            # Filter out UNLIKELY version matches from display — they add noise
            all_cves     = match.get("cves", [])
            display_cves = [c for c in all_cves
                            if c.get("version_relevance", "POSSIBLE") != "UNLIKELY"]
            if not display_cves:
                display_cves = all_cves   # fallback: show all if all filtered

            sorted_cves = sorted(
                display_cves,
                key=lambda c: (
                    float(c.get("epss", 0) or 0) * 10 * 0.4 +
                    float(c.get("cvss", 0) or 0) * 0.6
                ),
                reverse=True
            )
            unlikely_count = len(all_cves) - len(display_cves)

            for cve in sorted_cves:
                cvss_badge   = _cvss_badge(cve.get("cvss", "N/A"))
                epss_cls, epss_val = _epss_badge(cve.get("epss"))
                tags         = cve.get("attack_surface", [])
                cwe_ids      = cve.get("cwe_ids", [])
                ver_rel      = cve.get("version_relevance", "")
                ver_rel_cls, ver_rel_txt = _version_relevance_badge(ver_rel)
                tag_badges   = "".join(f'<span class="badge high" style="margin:1px;font-size:0.7rem">{e(t)}</span>' for t in tags)
                cwe_str      = ", ".join(e(c) for c in cwe_ids[:3]) if cwe_ids else ""
                # Build context flag warnings
                ctx_flags = []
                if cve.get("forwarded_agent_only"):
                    ctx_flags.append(("⚠️ Agent-forwarding condition", cve["forwarded_agent_only"]))
                if cve.get("requires_component"):
                    ctx_flags.append(("⚠️ Non-default component", cve["requires_component"]))
                if cve.get("auth_rate_only"):
                    ctx_flags.append(("ℹ️ Auth rate / brute-force", cve["auth_rate_only"]))
                if cve.get("backport_risk"):
                    ctx_flags.append(("ℹ️ Backport risk", "Distro package may contain backported fix not reflected in version string"))

                ctx_html = ""
                if ctx_flags:
                    ctx_html = "".join(
                        f'<div style="font-size:0.72rem;color:#8b949e;margin-top:2px" title="{e(detail)}">{e(label)}</div>'
                        for label, detail in ctx_flags
                    )

                rows += f"""<tr>
                    <td><code>{e(match.get('tech',''))}</code> <span style="color:#8b949e;font-size:0.8rem">{e(match.get('version',''))}</span></td>
                    <td>{', '.join(e(p) for p in match.get('ports',[]))}</td>
                    <td><a href="{e(cve.get('url','#'))}" target="_blank">{e(cve.get('cve',''))}</a>{ctx_html}</td>
                    <td><span class="badge {cvss_badge}">{e(str(cve.get('cvss','N/A')))}</span></td>
                    <td><span class="badge {epss_cls}">{epss_val}</span></td>
                    <td><span class="badge {ver_rel_cls}" style="font-size:0.72rem">{e(ver_rel_txt)}</span></td>
                    <td>{tag_badges}</td>
                    <td style="font-size:0.75rem;color:#8b949e">{cwe_str}</td>
                </tr>"""
            if unlikely_count > 0:
                rows += f"""<tr><td colspan="8" style="color:#555;font-size:0.78rem;text-align:center;padding:0.4rem">
                    {unlikely_count} CVE(s) with unlikely version relevance hidden — run with --debug to see all
                </td></tr>"""
        if not rows:
            rows = "<tr><td colspan='7' style='color:#888;text-align:center'>No CVEs detected</td></tr>"
        cve_html += f"""
        <div class="target-card">
            <div class="target-header">
                <span class="target-url">🔗 {e(url)}</span>
                <span class="target-meta">
                    IP: {e(ip)} | Host: {e(hostname)}
                    &nbsp;|&nbsp; <span class="badge {risk_badge}">Risk: {risk_score}/10</span>
                    &nbsp;|&nbsp; {total_cves_this_target} historically associated CVE(s)
                </span>
            </div>
            <p style="padding:0.6rem 1.2rem 0;font-size:0.82rem;color:#8b949e">
                ⚠️ These CVEs are matched against the detected service banner version.
                Banner versions from Nmap may not reflect backported patches in Ubuntu/Debian/RHEL packages —
                always verify patch status at the package level, not just the version string.
                CVEs marked ⚠️ Agent-forwarding or ⚠️ Non-default component require specific
                conditions beyond a plain version match. Sorted by EPSS × CVSS priority.
            </p>
            <table><thead><tr>
                <th>Technology</th><th>Ports</th><th>CVE</th>
                <th>CVSS</th><th>EPSS</th><th>Version Match</th><th>Attack Surface</th><th>CWE</th>
            </tr></thead>
            <tbody>{rows}</tbody></table>
        </div>"""

    # ─────────────────────────────────────
    # Full HTML Document
    # ─────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedShadow V4 — {e(generated_on)}</title>
    <style>
        *{{box-sizing:border-box;margin:0;padding:0}}
        body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem;line-height:1.6}}
        header{{border-bottom:1px solid #30363d;padding-bottom:1.5rem;margin-bottom:2rem}}
        header h1{{font-size:1.8rem;color:#58a6ff}}
        header p{{color:#8b949e;margin-top:0.3rem;font-size:0.9rem}}
        .summary{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
        .stat-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;min-width:110px;text-align:center}}
        .stat-box .num{{font-size:2rem;font-weight:bold;display:block}}
        .stat-box .label{{font-size:0.75rem;color:#8b949e}}
        .stat-box.blue .num{{color:#58a6ff}}
        .stat-box.red .num{{color:#ff4444}}
        .stat-box.orange .num{{color:#f85149}}
        .stat-box.yellow .num{{color:#e3b341}}
        .stat-box.green .num{{color:#3fb950}}
        .stat-box.purple .num{{color:#bc8cff}}
        .stat-box.pink .num{{color:#ff6b6b}}
        .stat-box.amber .num{{color:#ffa657}}
        .target-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:1.5rem;overflow:hidden}}
        .target-header{{background:#1c2128;padding:0.8rem 1.2rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;border-bottom:1px solid #30363d}}
        .target-url{{font-weight:bold;color:#58a6ff}}
        .target-meta{{font-size:0.8rem;color:#8b949e}}
        table{{width:100%;border-collapse:collapse}}
        th{{background:#1c2128;text-align:left;padding:0.6rem 1rem;font-size:0.8rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid #30363d}}
        td{{padding:0.6rem 1rem;border-bottom:1px solid #21262d;font-size:0.9rem;vertical-align:top}}
        tr:last-child td{{border-bottom:none}}
        a{{color:#58a6ff;text-decoration:none}}
        a:hover{{text-decoration:underline}}
        code{{background:#21262d;padding:0.1em 0.4em;border-radius:4px;font-size:0.85em;word-break:break-all}}
        .badge{{display:inline-block;padding:0.15em 0.6em;border-radius:4px;font-size:0.78rem;font-weight:bold}}
        .badge.critical{{background:#4a0000;color:#ff4444}}
        .badge.high{{background:#3d1c1c;color:#f85149}}
        .badge.medium{{background:#2d2200;color:#e3b341}}
        .badge.low{{background:#0d2a17;color:#3fb950}}
        .badge.info{{background:#1c2128;color:#8b949e}}
        .badge.unknown{{background:#21262d;color:#8b949e}}
        .badge.confirmed{{background:#0d2a17;color:#3fb950}}
        .badge.likely{{background:#2d2200;color:#e3b341}}
        .badge.potential{{background:#21262d;color:#8b949e}}
        h2{{margin:2rem 0 1rem}}
        footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid #30363d;font-size:0.8rem;color:#8b949e;text-align:center}}
    </style>
</head>
<body>
<header>
    <h1>🛡️ RedShadow V4 Reconnaissance Report</h1>
    <p>Generated: {e(generated_on)}</p>
</header>

<div class="summary">
    <div class="stat-box blue"><span class="num">{len(cve_data)}</span><span class="label">Targets</span></div>
    <div class="stat-box blue"><span class="num">{total_cves}</span><span class="label">CVEs</span></div>
    <div class="stat-box red"><span class="num">{rce_cves}</span><span class="label">RCE CVEs</span></div>
    <div class="stat-box orange"><span class="num">{high_cves}</span><span class="label">High CVEs</span></div>
    <div class="stat-box pink"><span class="num">{total_secrets}</span><span class="label">Secrets</span></div>
    <div class="stat-box red"><span class="num">{secret_critical}</span><span class="label">Critical Secrets</span></div>
    <div class="stat-box amber"><span class="num">{len(s3_critical)}</span><span class="label">Public Buckets</span></div>
    <div class="stat-box pink"><span class="num">{gh_critical}</span><span class="label">GitHub Critical</span></div>
    <div class="stat-box yellow"><span class="num">{len(wb_alive200)}</span><span class="label">Wayback Live</span></div>
    <div class="stat-box blue"><span class="num">{total_js_high_value}</span><span class="label">JS High Value</span></div>
    <div class="stat-box purple"><span class="num">{probe_vulns}</span><span class="label">Probe Vulns</span></div>
    <div class="stat-box yellow"><span class="num">{probe_hardening}</span><span class="label">Hardening Gaps</span></div>
    <div class="stat-box orange"><span class="num">{total_redirects}</span><span class="label">Open Redirects</span></div>
    <div class="stat-box red"><span class="num">{len(takeover_confirmed)}</span><span class="label">Takeovers</span></div>
    <div class="stat-box yellow"><span class="num">{len(cors_findings)}</span><span class="label">CORS Issues</span></div>
    <div class="stat-box blue"><span class="num">{len(graphql_hosts)}</span><span class="label">GraphQL Exposed</span></div>
    <div class="stat-box red"><span class="num">{len(attack_paths)}</span><span class="label">Correlated Leads</span></div>
</div>

<div style="background:#161b22;border:1px solid #388bfd44;border-radius:8px;padding:1.2rem 1.5rem;margin-bottom:1.5rem">
    <h2 style="color:#58a6ff;font-size:1.1rem;margin-bottom:0.6rem">📋 Executive Summary</h2>
    <p style="color:#c9d1d9;line-height:1.7;font-size:0.92rem">{e(exec_summary)}</p>
    {_build_priority_actions_html(priority_actions)}
    <div style="margin-top:0.8rem;padding-top:0.8rem;border-top:1px solid #30363d">
        <p style="color:#8b949e;font-size:0.82rem;font-weight:600;margin-bottom:0.4rem">Validation Approach</p>
        <ol style="color:#8b949e;font-size:0.82rem;margin-left:1.2rem;line-height:1.8">
            <li>Confirm exact service versions via banner grabbing or response headers</li>
            <li>Validate CVE applicability against detected version ranges using vendor advisories</li>
            <li>Check patch status before treating any CVE association as confirmed exploitable</li>
            <li>Test hardening gaps in a controlled environment</li>
            <li>Validate all correlated leads manually — engine output is not proof of exploitation</li>
        </ol>
    </div>
</div>
{attack_paths_html}
{takeover_html}
{s3_html}
{secret_html}
{github_html}
{graphql_html}
{leaked_html}
{cors_html}
{wayback_html}
{js_html}
{redirect_html}
{probe_html}

<h2 style="color:#58a6ff;margin:2rem 0 1rem">🛡️ Version-Matched CVE Candidates — Requires Configuration &amp; Patch Validation</h2>
{cve_html}

<footer>RedShadow V4 &nbsp;|&nbsp; Developed by Galal Noaman &nbsp;|&nbsp; For lawful use only</footer>
</body>
</html>"""

    dirpath = os.path.dirname(html_output)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    try:
        with open(html_output, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[✓] HTML report: {html_output}")
    except Exception as ex:
        print(f"[!] Could not write HTML report: {ex}")