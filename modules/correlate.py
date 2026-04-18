# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/correlate.py
# Stage 14 — Correlation and Prioritisation Engine  v2
#
# Role:
#   Reads all prior stage outputs, cross-references findings across modules,
#   and produces RANKED CORRELATED LEADS — not confirmed exploits.
#   Each lead explains WHY two or more signals point at the same surface,
#   what an operator should verify next, and how confident the correlation is.
#
# Design decisions (v2 — all reviewer feedback addressed):
#
#   1. FRAMING: output is "correlated lead" not "attack path" or "exploit chain"
#      Rules never claim confirmed exploitation — only candidate surfaces.
#
#   2. SCORING: evidence-driven, not hardcoded constants.
#      score = base (per type) + confidence_bonus + source_count_bonus
#      Base scores are intentionally conservative vs v1.
#
#   3. action FIELD REMOVED: replaced with validation_checks[] — operator
#      guidance only. No exploit commands, no payload strings, no curl replays.
#
#   4. URL/HOST NORMALISATION: urllib.parse throughout. No lstrip() hacks.
#      One canonical layer (_parse_host, _parse_url, _hosts_match) used everywhere.
#
#   5. EVIDENCE SHAPE: every rule emits the same _evidence() structure:
#      sources[], source_modules[], primary_artifact{}, secondary_artifact{}
#
#   6. DEDUPLICATION: richer key = type + canonical hosts + resource identifier.
#      No longer collapses distinct leads sharing only type + host.
#
#   7. CONFIDENCE: per-lead field (HIGH/MEDIUM/LOW) + confidence_reason string.
#      Score is not doing double duty.
#
#   8. OVERCONFIDENT RULES DOWNGRADED:
#      - GRAPHQL_RECON: always LOW, lowest base score, framed as recon only
#      - CORS_CREDENTIALED: requires PoC to confirm, base score 5.0
#      - TOKEN_WITH_SURFACE: spatial correlation only, base score 6.0
#
# Lead types (ordered by base score):
#   MULTI_SOURCE_SECRET   7.5 — same credential in 2+ independent modules
#   TAKEOVER_LIVE         7.0 — confirmed/likely takeover + live traffic
#   RCE_CANDIDATE         6.5 — RCE CVE + open port on matching service
#   TOKEN_WITH_SURFACE    6.0 — credential + endpoint on same host
#   STORAGE_EXPOSURE      6.0 — public cloud bucket (+ optional credentials)
#   IDOR_CANDIDATE        5.5 — IDOR param in historic URL + endpoint live
#   CORS_CREDENTIALED     5.0 — CORS issue + credentialed endpoint
#   REDIRECT_SENSITIVE    4.5 — redirect on auth/SSO or secret host
#   FORGOTTEN_ENDPOINT    4.5 — historic param endpoint still alive today
#   GRAPHQL_RECON         4.0 — introspection open (recon lead only)

import json
import os
import re
import hashlib
from urllib.parse import urlparse, parse_qs
from termcolor import cprint
from modules.matchers import (
    normalize_product_name, normalize_version,
    service_matches_product, version_is_relevant,
    finding_confidence, confidence_reason,
)


# ─────────────────────────────────────────
# Data Loaders
# ─────────────────────────────────────────

def _load_list(path):
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError as ex:
        cprint(f"  [!] Correlate: JSON parse error in {path}: {ex}", "yellow")
        return []
    except Exception as ex:
        cprint(f"  [!] Correlate: could not load {path}: {ex}", "yellow")
        return []


def _load_dict(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError as ex:
        cprint(f"  [!] Correlate: JSON parse error in {path}: {ex}", "yellow")
        return {}
    except Exception as ex:
        cprint(f"  [!] Correlate: could not load {path}: {ex}", "yellow")
        return {}


def _load_scan_as_list(path):
    """
    Load scan_results.json into a flat list of host entries.
    scan.py writes: {"results": {"ip": {"ip": ..., "protocols": {"tcp": {port: {...}}}}}}
    This converts it to: [{"host": "ip", "ports": [{"port": N, "service": ..., ...}]}]
    """
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as ex:
        cprint(f"  [!] Correlate: scan results JSON parse error in {path}: {ex}", "yellow")
        return []
    except Exception as ex:
        cprint(f"  [!] Correlate: could not load scan results {path}: {ex}", "yellow")
        return []

    if isinstance(raw, list):
        return raw  # already flat list format

    results_block = raw.get("results", raw) if isinstance(raw, dict) else {}
    parsed = []
    for host_key, host_data in results_block.items():
        if not isinstance(host_data, dict):
            continue
        host = host_data.get("ip", host_data.get("hostname", host_key))
        protocols = host_data.get("protocols", {})
        flat_ports = []
        for proto, port_dict in protocols.items():
            if not isinstance(port_dict, dict):
                continue
            for port_num, port_info in port_dict.items():
                if not isinstance(port_info, dict):
                    continue
                state = port_info.get("state", "")
                if state not in ("open", "open|filtered"):
                    continue
                flat_ports.append({
                    "port":    int(port_num),
                    "proto":   proto,
                    "state":   state,
                    "service": port_info.get("service", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                })
        parsed.append({"host": host, "ip": host, "ports": flat_ports})
    return parsed


# ─────────────────────────────────────────
# Canonical URL / Host Normalisation
# All normalisation uses urllib.parse — no lstrip() hacks (reviewer fix #4).
# ─────────────────────────────────────────

def _parse_host(value):
    """
    Extract canonical lowercase hostname from any URL or bare hostname.
    Returns empty string on failure — never raises.
    """
    if not value:
        return ""
    value = str(value).strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    try:
        parsed = urlparse(value)
        return parsed.hostname.lower() if parsed.hostname else ""
    except Exception as ex:
        cprint(f"  [!] Correlate: host parse failed for {value!r}: {ex}", "yellow")
        return ""


def _parse_url(value):
    """Return a normalised URL string. Returns original on failure."""
    if not value:
        return ""
    value = str(value).strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    try:
        p = urlparse(value)
        scheme = p.scheme.lower()
        host   = (p.hostname or "").lower()
        port   = f":{p.port}" if p.port else ""
        path   = p.path or "/"
        query  = f"?{p.query}" if p.query else ""
        return f"{scheme}://{host}{port}{path}{query}"
    except Exception:  # URL parse failed - return empty host
        return value


def _hosts_match(a, b):
    """True if two values refer to the same host or direct subdomain relationship."""
    ha = _parse_host(a)
    hb = _parse_host(b)
    if not ha or not hb:
        return False
    return ha == hb or ha.endswith("." + hb) or hb.endswith("." + ha)


def _dedup_key(lead_type, hosts, resource=""):
    """
    Canonical dedup key: type + sorted hosts + resource.
    Richer than v1 (type + hosts only) — prevents collapsing distinct leads
    that share only type and host (reviewer fix #6).
    """
    host_part = ",".join(sorted(_parse_host(h) or h for h in hosts))
    res_part  = str(resource)[:80]
    raw       = f"{lead_type}|{host_part}|{res_part}"
    return hashlib.md5(raw.encode()).hexdigest()


# ─────────────────────────────────────────
# Evidence Builder
# Every rule uses this — guarantees consistent evidence shape (reviewer fix #5).
# ─────────────────────────────────────────

def _evidence(source_modules, primary=None, secondary=None, extra=None):
    sources = []
    if primary:
        sources.append(primary)
    if secondary:
        sources.append(secondary)
    if extra:
        sources.extend(extra if isinstance(extra, list) else [extra])
    return {
        "sources":            sources,
        "source_modules":     source_modules,
        "primary_artifact":   primary or {},
        "secondary_artifact": secondary or {},
    }


# ─────────────────────────────────────────
# Scoring Model (reviewer fix #2)
# score = base + confidence_bonus + source_bonus
# Base scores are conservative — not inflated.
# ─────────────────────────────────────────

BASE_SCORES = {
    "MULTI_SOURCE_SECRET":  7.5,
    "TAKEOVER_LIVE":        7.0,
    "RCE_CANDIDATE":        6.5,
    "TOKEN_WITH_SURFACE":   6.0,
    "STORAGE_EXPOSURE":     6.0,
    "IDOR_CANDIDATE":       5.5,
    "CORS_CREDENTIALED":    5.0,
    "REDIRECT_SENSITIVE":   4.5,
    "FORGOTTEN_ENDPOINT":   4.5,
    "GRAPHQL_RECON":        4.0,
}

_CONF_BONUS   = {"HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.0}
_SRC_BONUS_EA = 0.3   # per source beyond first, capped at 1.2


def _score(lead_type, confidence, source_count):
    base    = BASE_SCORES.get(lead_type, 5.0)
    c_bonus = _CONF_BONUS.get(confidence, 0.0)
    s_bonus = min((max(source_count, 1) - 1) * _SRC_BONUS_EA, 1.2)
    return round(min(base + c_bonus + s_bonus, 10.0), 2)


def _confidence_from(source_count, live_validated=False):
    if live_validated or source_count >= 3:
        return "HIGH"
    if source_count >= 2:
        return "MEDIUM"
    return "LOW"


def _conf_reason(source_count, live_validated=False, extra=""):
    parts = []
    if live_validated:
        parts.append("live HTTP confirmation present")
    if source_count >= 3:
        parts.append(f"{source_count} independent modules agree")
    elif source_count == 2:
        parts.append("2 independent modules agree")
    else:
        parts.append("single source — relationship is inferred, not validated")
    if extra:
        parts.append(extra)
    return "; ".join(parts)


# ─────────────────────────────────────────
# Secret type labels
# ─────────────────────────────────────────

_SECRET_LABELS = {
    "aws_access_key": "AWS Access Key", "aws_secret_key": "AWS Secret Key",
    "github_token":   "GitHub Token",   "google_api_key": "Google API Key",
    "stripe_key":     "Stripe Key",     "jwt":            "JWT Token",
    "slack_token":    "Slack Token",    "sendgrid_key":   "SendGrid Key",
    "twilio_key":     "Twilio Key",     "heroku_key":     "Heroku API Key",
    "private_key":    "Private Key",    "generic_secret": "Generic Secret",
}

def _slabel(stype):
    return _SECRET_LABELS.get(str(stype).lower(), str(stype))


# ─────────────────────────────────────────
# Correlation Rules
# Rules return a list of lead dicts or [].
# Every lead includes: type, confidence, confidence_reason, score, title,
#   what_was_found, why_it_matters, validation_checks, source_modules,
#   source_count, evidence, hosts, validation_state, _dedup_key.
# No rule includes exploit commands or payload strings (reviewer fix #3).
# ─────────────────────────────────────────

def _rule_multi_source_secret(secret_data, github_data):
    """
    MULTI_SOURCE_SECRET
    Same credential TYPE found in both the secret scanner (live HTTP response)
    and the GitHub scanner. Two independent sources agreeing is the strongest
    corroboration this engine can produce for a credential finding.
    """
    leads = []

    page_by_type = {}
    for entry in secret_data:
        h = _parse_host(entry.get("url", ""))
        for f in entry.get("findings", []):
            stype = f.get("type", "")
            if stype:
                page_by_type.setdefault(stype, []).append({
                    "host": h, "severity": f.get("severity", ""),
                    "confidence": f.get("confidence", ""), "module": "secret",
                })

    gh_by_type = {}
    for f in github_data.get("findings", []):
        stype = f.get("secret_type", f.get("type", ""))
        if stype:
            gh_by_type.setdefault(stype, []).append({
                "repo_url": f.get("repo_url", ""), "file": f.get("file", ""),
                "module": "githubscan",
            })

    for stype, pg_recs in page_by_type.items():
        if stype not in gh_by_type:
            continue
        pg  = pg_recs[0]
        gh  = gh_by_type[stype][0]
        sev = pg.get("severity", "")
        h   = pg.get("host", "")

        if sev == "CRITICAL":
            conf   = "HIGH"
            reason = "CRITICAL severity in live HTTP response + same type in GitHub"
        elif sev == "HIGH":
            conf   = "MEDIUM"
            reason = "HIGH severity in live HTTP response + same type in GitHub"
        else:
            conf   = "MEDIUM"
            reason = "credential type confirmed in both live scan and GitHub"

        leads.append({
            "type":              "MULTI_SOURCE_SECRET",
            "confidence":        conf,
            "confidence_reason": reason,
            "score":             _score("MULTI_SOURCE_SECRET", conf, 2),
            "title":             f"{_slabel(stype)} confirmed in live response and GitHub",
            "what_was_found": [
                f"{_slabel(stype)} ({sev}) found in live HTTP response on {h}",
                f"Same type in GitHub: {gh.get('repo_url', 'unknown')}",
            ],
            "why_it_matters": (
                "Two independent modules found the same credential type. "
                "This significantly increases probability the credential is real and active. "
                "This is the strongest corroboration signal this engine produces."
            ),
            "validation_checks": [
                "Verify the credential value (not just type) matches between sources",
                "Check GitHub commit history for when it was introduced and whether it was ever rotated",
                "Validate the credential is still active using a safe read-only API call",
                "If valid, report immediately — do not use beyond validation",
            ],
            "source_modules":   ["secret", "githubscan"],
            "source_count":     2,
            "evidence":         _evidence(["secret", "githubscan"], primary=pg, secondary=gh),
            "hosts":            [h] if h else [],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("MULTI_SOURCE_SECRET", [h], stype),
        })

    return leads


def _rule_takeover_live(takeover_data, passive_data, probe_data):
    """
    TAKEOVER_LIVE
    Subdomain takeover candidate (CONFIRMED or LIKELY from takeover module)
    where the subdomain also shows live HTTP traffic in passive/probe results.
    Live traffic = real users or services potentially exposed.
    """
    leads = []

    live_hosts = set()
    for p in passive_data:
        if p.get("status") in (200, 301, 302, 403):
            h = _parse_host(p.get("url", ""))
            if h:
                live_hosts.add(h)
    for p in probe_data:
        h = _parse_host(p.get("url", ""))
        if h:
            live_hosts.add(h)

    for t in takeover_data:
        t_conf = t.get("confidence", "")
        if t_conf not in ("CONFIRMED", "LIKELY"):
            continue

        sub   = _parse_host(t.get("subdomain", ""))
        svc   = t.get("service", "unknown service")
        cname = t.get("cname", "")
        is_live = any(_hosts_match(sub, lh) for lh in live_hosts)

        if t_conf == "CONFIRMED" and is_live:
            conf   = "HIGH"
            reason = "takeover CONFIRMED + live HTTP traffic present"
        elif t_conf == "CONFIRMED":
            conf   = "MEDIUM"
            reason = "takeover CONFIRMED — no live HTTP traffic confirmed yet"
        elif is_live:
            conf   = "MEDIUM"
            reason = "takeover LIKELY + live HTTP traffic present"
        else:
            conf   = "LOW"
            reason = "takeover LIKELY — no live HTTP traffic confirmed"

        src_mods = ["takeover"] + (["passive"] if is_live else [])
        leads.append({
            "type":              "TAKEOVER_LIVE",
            "confidence":        conf,
            "confidence_reason": reason,
            "score":             _score("TAKEOVER_LIVE", conf, len(src_mods)),
            "title":             f"[{t_conf}] Takeover candidate: {sub} ({svc})",
            "what_was_found": [
                f"Dangling CNAME on {sub} → {cname}",
                f"Service: {svc} — target resource appears unclaimed",
                f"Live HTTP traffic: {'confirmed' if is_live else 'not confirmed'}",
            ],
            "why_it_matters": (
                f"If the {svc} resource is unclaimed, an attacker can register it and serve "
                f"arbitrary content from {sub}. Live traffic means real users or services "
                f"may send cookies or tokens here."
            ),
            "validation_checks": [
                f"Manually verify {cname} is still unclaimed on {svc}",
                "Confirm whether real user traffic reaches this subdomain",
                "Check cookie scope: are parent-domain cookies sent to this subdomain?",
                "Do not register the resource without explicit written scope authorisation",
            ],
            "source_modules":   src_mods,
            "source_count":     len(src_mods),
            "evidence":         _evidence(
                src_mods,
                primary={"module": "takeover", "subdomain": sub, "cname": cname,
                         "service": svc, "confidence": t_conf},
                secondary={"module": "passive", "live": is_live} if is_live else None,
            ),
            "hosts":            [sub],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("TAKEOVER_LIVE", [sub], cname),
        })

    return leads


def _rule_rce_candidate(analysis_data, scan_data):
    """
    RCE_CANDIDATE
    A CVE tagged RCE exists for a product AND an open port on the same host
    matches the expected service. Version accuracy from Nmap is not guaranteed.
    Confidence is driven by EPSS and port confirmation.
    """
    leads = []

    # scan_results.json is a dict-wrapped format from scan.py — parse it properly
    port_map = {}
    # scan_data may be a list (if _load_list worked on a flat structure)
    # or we need to handle the dict-wrapped format
    raw_scan = scan_data  # already loaded by correlate() via _load_list
    if isinstance(raw_scan, list):
        for entry in raw_scan:
            h = _parse_host(entry.get("host", entry.get("ip", "")))
            if not h:
                continue
            for pi in entry.get("ports", []):
                port_map.setdefault(h, []).append({
                    "port":    pi.get("port"),
                    "service": str(pi.get("service", "")).lower(),
                    "product": str(pi.get("product", "")).lower(),
                    "version": str(pi.get("version", "")).lower(),
                })

    for entry in analysis_data:
        h = _parse_host(entry.get("url", entry.get("host", "")))
        for match in entry.get("tech_matches", []):
            product  = match.get("tech", match.get("product", ""))
            version  = str(match.get("version", "")).lower()
            ver_rel  = match.get("version_relevance", "")

            for cve in match.get("cves", []):
                if "RCE" not in cve.get("attack_surface", []):
                    continue

                cve_id   = cve.get("cve", cve.get("cve_id", ""))
                cvss     = float(cve.get("cvss", 0) or 0)
                epss     = float(cve.get("epss", 0) or 0)
                tags     = cve.get("attack_surface", [])
                cve_ver_rel = cve.get("version_relevance", ver_rel)

                # Skip leads where CVE version relevance is UNLIKELY
                if cve_ver_rel == "UNLIKELY":
                    continue

                # Guard: skip if critical fields are empty
                if not cve_id or not product or not h:
                    continue

                # Skip forwarded-agent-only CVEs from RCE_CANDIDATE leads
                # These require the victim to forward their ssh-agent to an
                # attacker-controlled server — not an internet-facing SSH risk.
                # They are still shown in the CVE table with a context flag.
                if cve.get("forwarded_agent_only"):
                    continue

                # Skip component-specific CVEs unless the component is evidenced
                # e.g. mod_authnz_external, mod_mime — not default Apache installs
                if cve.get("requires_component"):
                    continue

                host_ports    = port_map.get(h, [])
                port_match    = False
                service_match = False

                for p in host_ports:
                    if service_matches_product(product, p.get("service",""), p.get("product","")):
                        port_match    = True
                        service_match = True
                        break

                # Secondary port match: port is open but service name doesn't align
                if not port_match and host_ports:
                    port_match = True   # port open — LOW confidence minimum

                src_mods = ["analyse"] + (["scan"] if port_match else [])

                # Use strict three-tier confidence from matchers.py
                conf   = finding_confidence(cve, version, port_match, service_match)
                reason = confidence_reason(cve, version, port_match, service_match)

                # Add version_relevance context to reason
                if cve_ver_rel and cve_ver_rel != "UNKNOWN":
                    reason += f"; version relevance: {cve_ver_rel}"

                leads.append({
                    "type":              "RCE_CANDIDATE",
                    "confidence":        conf,
                    "confidence_reason": reason,
                    "score":             _score("RCE_CANDIDATE", conf, len(src_mods)),
                    "title":             f"RCE candidate: {cve_id} on {product} at {h}",
                    "what_was_found": [
                        f"{product} (version: {version or 'unknown'}) on {h}",
                        f"{cve_id} — CVSS {cvss:.1f}, EPSS {epss:.3f}, tags: {', '.join(tags)}",
                        f"Port confirmation: {'yes' if port_match else 'no'}",
                    ],
                    "why_it_matters": (
                        f"{cve_id} is tagged RCE. If this is the affected version and the "
                        f"service is reachable, this may represent remote code execution surface. "
                        f"EPSS {epss:.3f} reflects real-world exploitation probability."
                    ),
                    "validation_checks": [
                        "Confirm the exact service version via banner grabbing or response headers",
                        "Verify the CVE applies to this specific configuration and version range",
                        "Check NVD and vendor advisories for patch status",
                        "Confirm the affected port is reachable from an external network",
                        "Do not run exploit code without explicit written scope authorisation",
                    ],
                    "source_modules":   src_mods,
                    "source_count":     len(src_mods),
                    "evidence":         _evidence(
                        src_mods,
                        primary={"module": "analyse", "host": h, "cve_id": cve_id,
                                 "cvss": cvss, "epss": epss, "tech": product, "version": version},
                        secondary={"module": "scan", "ports": host_ports} if host_ports else None,
                    ),
                    "hosts":            [h],
                    "validation_state": "UNVALIDATED",
                    "_dedup_key":       _dedup_key("RCE_CANDIDATE", [h], cve_id),
                })

    return leads


def _rule_token_with_surface(secret_data, js_data, probe_data, wayback_data):
    """
    TOKEN_WITH_SURFACE
    A credential exists in a live HTTP response AND a high-value endpoint
    exists on the same host. Relationship is SPATIAL — not validated.
    Downgraded from v1: this is a candidate, not a confirmed exploit.
    """
    leads = []

    ep_by_host = {}
    for js in js_data:
        h = _parse_host(js.get("url", ""))
        if not h:
            continue
        r = ep_by_host.setdefault(h, {"endpoints": set(), "modules": set()})
        for ep in js.get("high_value", []):
            r["endpoints"].add(ep); r["modules"].add("jsextractor")

    for pe in probe_data:
        h = _parse_host(pe.get("url", ""))
        if not h:
            continue
        r = ep_by_host.setdefault(h, {"endpoints": set(), "modules": set()})
        for f in pe.get("findings", []):
            if f.get("finding_type") == "vulnerability" and f.get("path"):
                r["endpoints"].add(f["path"]); r["modules"].add("probe")

    wb_raw = wayback_data if isinstance(wayback_data, dict) else {}
    for wb_url in wb_raw.get("alive_200", []):
        h = _parse_host(wb_url)
        if not h:
            continue
        r = ep_by_host.setdefault(h, {"endpoints": set(), "modules": set()})
        r["endpoints"].add(_parse_url(wb_url)); r["modules"].add("wayback")

    for secret_entry in secret_data:
        sh = _parse_host(secret_entry.get("url", ""))
        for finding in secret_entry.get("findings", []):
            sev   = finding.get("severity", "")
            stype = finding.get("type", "unknown")
            if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
                continue

            for ep_host, ep_data in ep_by_host.items():
                if not _hosts_match(sh, ep_host):
                    continue
                endpoints  = list(ep_data["endpoints"])
                ep_mods    = list(ep_data["modules"])
                if not endpoints:
                    continue

                src_mods   = list({"secret"} | set(ep_mods))
                live_valid = ("probe" in ep_mods or "wayback" in ep_mods) and sev == "CRITICAL"
                conf       = _confidence_from(len(src_mods), live_validated=live_valid)
                reason     = _conf_reason(len(src_mods), live_validated=live_valid,
                                          extra=f"credential severity: {sev}")

                leads.append({
                    "type":              "TOKEN_WITH_SURFACE",
                    "confidence":        conf,
                    "confidence_reason": reason,
                    "score":             _score("TOKEN_WITH_SURFACE", conf, len(src_mods)),
                    "title":             f"{_slabel(stype)} on {sh} — high-value endpoint on same host",
                    "what_was_found": [
                        f"{_slabel(stype)} ({sev}) in HTTP response on {sh}",
                        f"{len(endpoints)} high-value endpoint(s) on {ep_host} "
                        f"(confirmed by: {', '.join(ep_mods)})",
                    ],
                    "why_it_matters": (
                        "A credential and a high-value endpoint share the same host. "
                        "This is a spatial correlation — it does not confirm the credential "
                        "is valid for that endpoint. Manual validation is required."
                    ),
                    "validation_checks": [
                        "Confirm the credential type matches the authentication mechanism on the endpoint",
                        "Check whether the credential is still active before testing the endpoint",
                        "Manually test the endpoint in a controlled environment with explicit scope",
                        "Determine whether the endpoint enforces rate-limiting or account lockout",
                    ],
                    "source_modules":   src_mods,
                    "source_count":     len(src_mods),
                    "evidence":         _evidence(
                        src_mods,
                        primary={"module": "secret", "host": sh, "type": stype, "severity": sev},
                        secondary={"module": ep_mods[0] if ep_mods else "unknown",
                                   "host": ep_host, "endpoint_sample": endpoints[0],
                                   "total_endpoints": len(endpoints)},
                    ),
                    "hosts":            list({sh, ep_host}),
                    "validation_state": "UNVALIDATED",
                    "_dedup_key":       _dedup_key("TOKEN_WITH_SURFACE", [sh, ep_host], stype),
                })

    return leads


def _rule_storage_exposure(s3_data, secret_data):
    """
    STORAGE_EXPOSURE
    Public cloud bucket found. If AWS credentials also found in secret scan,
    confidence increases — credentials + public bucket = broader access risk.
    """
    leads = []

    s3_raw  = s3_data if isinstance(s3_data, dict) else {}
    buckets = s3_raw.get("critical", []) + s3_raw.get("high", [])
    if not buckets:
        return leads

    aws_creds = []
    for entry in secret_data:
        for f in entry.get("findings", []):
            if "aws" in f.get("type", "").lower():
                aws_creds.append({
                    "host": _parse_host(entry.get("url", "")),
                    "type": f.get("type", ""),
                    "severity": f.get("severity", ""),
                    "module": "secret",
                })

    for bucket in buckets:
        name     = bucket.get("bucket", bucket.get("name", ""))
        provider = bucket.get("provider", "AWS")
        burl     = bucket.get("url", f"https://{name}.s3.amazonaws.com")
        h        = _parse_host(burl) or name

        has_creds = bool(aws_creds) and provider == "AWS"
        src_mods  = ["s3scanner"] + (["secret"] if has_creds else [])
        conf      = "HIGH" if has_creds else "MEDIUM"
        reason    = (
            "public bucket + AWS credentials found in secret scan"
            if has_creds else
            "bucket confirmed publicly accessible without authentication"
        )

        leads.append({
            "type":              "STORAGE_EXPOSURE",
            "confidence":        conf,
            "confidence_reason": reason,
            "score":             _score("STORAGE_EXPOSURE", conf, len(src_mods)),
            "title":             f"Public {provider} bucket: {name}"
                                 + (" + AWS credentials corroborated" if has_creds else ""),
            "what_was_found": [
                f"{provider} bucket '{name}' publicly accessible ({burl})",
            ] + ([f"AWS credentials on {aws_creds[0]['host']}"] if has_creds else []),
            "why_it_matters": (
                f"The bucket '{name}' requires no authentication to list or read. "
                + ("AWS credentials were also found — if valid, this may allow access to "
                   "additional resources beyond this bucket. " if has_creds else "")
                + "Public buckets commonly contain backups, configs, or user data."
            ),
            "validation_checks": [
                f"List bucket contents without credentials: aws s3 ls s3://{name}/ --no-sign-request",
                "Check for sensitive files: .env, backup, config, db, credentials, source",
            ] + ([
                "Validate AWS credentials are active using a safe read-only call (sts get-caller-identity)",
                "Do not use credentials beyond read-only validation without explicit scope",
            ] if has_creds else []),
            "source_modules":   src_mods,
            "source_count":     len(src_mods),
            "evidence":         _evidence(
                src_mods,
                primary={"module": "s3scanner", "bucket": name, "provider": provider, "url": burl},
                secondary={"module": "secret", "aws_credentials": aws_creds[0]} if has_creds else None,
            ),
            "hosts":            [h],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("STORAGE_EXPOSURE", [h], name),
        })

    return leads


def _rule_idor_candidate(wayback_data, js_data, probe_data):
    """
    IDOR_CANDIDATE
    Wayback URL with object-reference parameters + host confirmed live today.
    Requires manual testing to determine whether access controls exist.
    """
    leads = []

    IDOR_RE = re.compile(
        r'[?&](id|user_id|account_id|uid|order_id|item_id|record_id|'
        r'document_id|invoice_id|ticket_id|customer_id|profile_id)=\d+',
        re.IGNORECASE
    )

    wb_raw    = wayback_data if isinstance(wayback_data, dict) else {}
    idor_items = [r for r in wb_raw.get("findings", []) if r.get("idor_params")]

    seen = {item.get("url", "") for item in idor_items}
    for url in wb_raw.get("alive_200", []):
        if url not in seen and IDOR_RE.search(url):
            idor_items.append({"url": url, "idor_params": {"detected": True}})

    live_hosts = set()
    for p in probe_data:
        h = _parse_host(p.get("url", "")); live_hosts.add(h) if h else None
    for j in js_data:
        h = _parse_host(j.get("url", "")); live_hosts.add(h) if h else None

    for item in idor_items[:8]:
        url    = item.get("url", "")
        params = item.get("idor_params", {})
        h      = _parse_host(url)
        is_live = any(_hosts_match(h, lh) for lh in live_hosts)

        m          = IDOR_RE.search(url)
        param_name = m.group(1) if m else (list(params.keys())[0] if params else "param")

        src_mods = ["wayback"] + (["probe"] if is_live else [])
        conf     = "MEDIUM" if is_live else "LOW"
        reason   = (
            "IDOR parameter in archived URL + host confirmed live today"
            if is_live else
            "IDOR parameter in archived URL — host liveness not confirmed"
        )

        leads.append({
            "type":              "IDOR_CANDIDATE",
            "confidence":        conf,
            "confidence_reason": reason,
            "score":             _score("IDOR_CANDIDATE", conf, len(src_mods)),
            "title":             f"IDOR candidate: '{param_name}' parameter on {h}",
            "what_was_found": [
                f"Archived URL with IDOR parameter '{param_name}': {url[:120]}",
                f"Host {h} is {'confirmed live' if is_live else 'not confirmed live — verify first'}",
            ],
            "why_it_matters": (
                f"This endpoint historically accepted object reference parameters. "
                f"If access controls are missing or weak, an attacker may access "
                f"another user's resources by modifying the '{param_name}' value."
            ),
            "validation_checks": [
                "Confirm the endpoint still exists and returns data today",
                "Determine whether authentication is required",
                "Compare responses for different parameter values using two test accounts",
                "Check whether the response leaks another user's data with a modified ID",
                "Use only test account IDs — do not use real user IDs",
            ],
            "source_modules":   src_mods,
            "source_count":     len(src_mods),
            "evidence":         _evidence(
                src_mods,
                primary={"module": "wayback", "url": url, "idor_params": list(params.keys())},
                secondary={"module": "probe", "host": h, "is_live": is_live} if is_live else None,
            ),
            "hosts":            [h],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("IDOR_CANDIDATE", [h], param_name),
        })

    return leads


def _rule_cors_credentialed(probe_data, js_data):
    """
    CORS_CREDENTIALED
    CORS misconfiguration + credentialed endpoints on same host.
    Downgraded from v1: a PoC is always required to confirm exploitability.
    Low confidence unless CORS is CRITICAL + 2+ credentialed endpoints found.
    """
    leads = []

    AUTH_KW = frozenset(["auth", "login", "token", "user", "account", "admin",
                          "profile", "me", "session", "password", "oauth", "sso"])

    cors_by_host = {}
    for pe in probe_data:
        h = _parse_host(pe.get("url", ""))
        if not h:
            continue
        for f in pe.get("findings", []):
            if f.get("type") == "cors" and f.get("severity") in ("CRITICAL", "HIGH"):
                cors_by_host.setdefault(h, []).append(f)

    cred_by_host = {}
    for js in js_data:
        h = _parse_host(js.get("url", ""))
        if h not in cors_by_host:
            continue
        cred = [ep for ep in js.get("high_value", [])
                if any(kw in ep.lower() for kw in AUTH_KW)]
        if cred:
            cred_by_host.setdefault(h, []).extend(cred)

    for host, cors_findings in cors_by_host.items():
        cred_eps = cred_by_host.get(host, [])
        cors_sev = cors_findings[0].get("severity", "HIGH")
        src_mods = ["probe"] + (["jsextractor"] if cred_eps else [])

        if not cred_eps:
            conf   = "LOW"
            reason = "CORS issue found — no credentialed endpoint confirmed on this host"
        elif cors_sev == "CRITICAL" and len(cred_eps) >= 2:
            conf   = "HIGH"
            reason = "CORS severity CRITICAL + 2+ credentialed endpoints confirmed"
        else:
            conf   = "MEDIUM"
            reason = f"CORS severity {cors_sev} + credentialed endpoint confirmed"

        leads.append({
            "type":              "CORS_CREDENTIALED",
            "confidence":        conf,
            "confidence_reason": reason,
            "score":             _score("CORS_CREDENTIALED", conf, len(src_mods)),
            "title":             f"CORS misconfiguration + credentialed endpoints on {host}",
            "what_was_found": [
                f"CORS policy allows arbitrary/reflective origins on {host} (severity: {cors_sev})",
                f"{len(cred_eps)} credentialed endpoint(s): {cred_eps[:3]}",
            ],
            "why_it_matters": (
                "If the CORS policy accepts an attacker-controlled origin with credentials, "
                "it may allow cross-origin reads of authenticated API responses. "
                "A PoC is required to confirm — CORS headers alone do not confirm exploitation."
            ),
            "validation_checks": [
                "Confirm Access-Control-Allow-Origin reflects the request Origin header",
                "Confirm Access-Control-Allow-Credentials: true is present",
                "Build a minimal PoC that fetches an endpoint with credentials:include from an external origin",
                "Verify the response contains user-specific data before reporting",
                "Check SameSite cookie attributes — they may restrict the attack",
            ],
            "source_modules":   src_mods,
            "source_count":     len(src_mods),
            "evidence":         _evidence(
                src_mods,
                primary={"module": "probe", "host": host, "cors_finding": cors_findings[0]},
                secondary={"module": "jsextractor", "credentialed_endpoints": cred_eps[:5]} if cred_eps else None,
            ),
            "hosts":            [host],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("CORS_CREDENTIALED", [host]),
        })

    return leads


def _rule_redirect_sensitive(redirect_data, secret_data, passive_data):
    """
    REDIRECT_SENSITIVE
    Open redirect on an auth/SSO host or a host with exposed secrets.
    This elevates a standard open redirect to a social engineering / token theft risk.
    """
    leads = []

    AUTH_KW = frozenset(["auth", "login", "sso", "signin", "id.", "account", "oauth"])

    secret_hosts = set()
    for e in secret_data:
        if e.get("findings"):
            h = _parse_host(e.get("url", ""))
            if h:
                secret_hosts.add(h)

    auth_hosts = set()
    for p in passive_data:
        h = _parse_host(p.get("url", ""))
        if h and any(kw in h for kw in AUTH_KW):
            auth_hosts.add(h)

    for entry in redirect_data:
        h = _parse_host(entry.get("url", ""))
        for f in entry.get("findings", []):
            is_auth = h in auth_hosts
            has_sec = h in secret_hosts
            if not is_auth and not has_sec:
                continue

            if is_auth and has_sec:
                conf   = "HIGH"
                reason = "auth/SSO domain + secrets on same host + open redirect confirmed"
            else:
                conf   = "MEDIUM"
                reason = ("auth/SSO domain with open redirect"
                          if is_auth else "open redirect on host with exposed secrets")

            src_mods = (["redirect"]
                        + (["passive"] if is_auth else [])
                        + (["secret"] if has_sec else []))

            leads.append({
                "type":              "REDIRECT_SENSITIVE",
                "confidence":        conf,
                "confidence_reason": reason,
                "score":             _score("REDIRECT_SENSITIVE", conf, len(src_mods)),
                "title":             f"Open redirect on sensitive host: {h}",
                "what_was_found": [
                    f"Open redirect on {h}: {f.get('path', '')} → {f.get('redirect_to', '')}",
                    f"Host context: {'auth/SSO domain' if is_auth else ''}"
                    f"{' + secrets exposed' if has_sec else ''}".strip(),
                ],
                "why_it_matters": (
                    "An open redirect on a trusted domain enables phishing attacks where the "
                    "browser shows a legitimate domain. On auth/SSO hosts this may allow "
                    "token theft mid-authentication flow."
                ),
                "validation_checks": [
                    "Confirm the redirect triggers without authentication",
                    "Determine whether the application uses this parameter in OAuth redirect_uri flows",
                    "Check whether tokens or session data appear in the redirect URL",
                    "Verify whether redirect_uri is validated server-side",
                ],
                "source_modules":   src_mods,
                "source_count":     len(src_mods),
                "evidence":         _evidence(
                    src_mods,
                    primary={"module": "redirect", "host": h, "finding": f},
                    secondary={"module": "passive", "is_auth_host": is_auth, "has_secrets": has_sec},
                ),
                "hosts":            [h],
                "validation_state": "UNVALIDATED",
                "_dedup_key":       _dedup_key("REDIRECT_SENSITIVE", [h], f.get("path", "")),
            })

    return leads


def _rule_forgotten_endpoint(wayback_data, probe_data):
    """
    FORGOTTEN_ENDPOINT
    Wayback URL with injection-relevant parameters still returning HTTP 200 today.
    Forgotten endpoints often miss WAF coverage and recent security reviews.
    """
    leads = []

    INJ_RE = re.compile(
        r'[?&](q|search|query|cmd|exec|file|path|url|redirect|include|page|template)=',
        re.IGNORECASE
    )

    wb_raw      = wayback_data if isinstance(wayback_data, dict) else {}
    interesting = [u for u in wb_raw.get("alive_200", []) if INJ_RE.search(u)][:6]

    for url in interesting:
        h = _parse_host(url)
        try:
            parsed = urlparse(url)
            qs     = parse_qs(parsed.query)
            params = [k for k in qs if INJ_RE.search(f"?{k}=")]
        except Exception as ex:
            cprint(f"  [!] Correlate: URL parse failed for {url!r}: {ex}", "yellow")
            parsed = None
            params = []

        param_label = params[0] if params else "unknown"

        leads.append({
            "type":              "FORGOTTEN_ENDPOINT",
            "confidence":        "MEDIUM",
            "confidence_reason": "Wayback archive confirms historic existence; alive_200 confirms HTTP 200 today",
            "score":             _score("FORGOTTEN_ENDPOINT", "MEDIUM", 2),
            "title":             f"Forgotten endpoint still live — param: {param_label} on {h}",
            "what_was_found": [
                f"Archived URL: {url[:120]}",
                "Still returning HTTP 200 today",
                f"Injection-relevant parameter(s): {params}",
            ],
            "why_it_matters": (
                "Forgotten endpoints may not be covered by current WAF rules or recent "
                "security reviews. Injection-relevant parameters warrant testing for "
                "SQLi, SSRF, LFI, open redirect, and XSS."
            ),
            "validation_checks": [
                "Confirm the endpoint requires no authentication to reach",
                "Review the parameter's purpose from historical page content",
                "Test with benign inputs first (empty string, integer boundary values)",
                "Do not send attack payloads until scope is confirmed in writing",
            ],
            "source_modules":   ["wayback"],
            "source_count":     2,
            "evidence":         _evidence(
                ["wayback"],
                primary={"module": "wayback", "url": url,
                         "injection_params": params, "status": 200},
            ),
            "hosts":            [h],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("FORGOTTEN_ENDPOINT", [h], param_label + url[:40]),
        })

    return leads


def _rule_exposed_admin(probe_data, passive_data):
    """
    EXPOSED_ADMIN_PANEL
    An admin or management interface was confirmed accessible (HTTP 200)
    on a path that should require authentication or network restriction.
    Elevated when the host is internet-facing (not RFC1918).
    """
    leads = []
    import ipaddress as _ip

    ADMIN_PATHS = {
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/manager/html", "/phpmyadmin", "/adminer", "/console",
        "/actuator", "/actuator/env", "/actuator/health",
        "/kibana", "/grafana", "/jenkins", "/_cluster/health",
        "/solr", "/mongo-express", "/.env",
    }

    for entry in probe_data:
        host = _parse_host(entry.get("url", ""))
        for f in entry.get("findings", []):
            path = f.get("path", "")
            if path.lower() not in ADMIN_PATHS:
                continue
            if f.get("severity") not in ("CRITICAL", "HIGH"):
                continue
            if f.get("confidence") not in ("CONFIRMED", "LIKELY"):
                continue

            # Check if host is internet-facing (not RFC1918)
            is_public = True
            try:
                addr = _ip.ip_address(host)
                is_public = not addr.is_private
            except ValueError:
                pass   # hostname — assume public

            score_base = 8.5 if is_public else 6.5
            conf       = "HIGH" if is_public and f.get("confidence") == "CONFIRMED" else "MEDIUM"

            leads.append({
                "type":              "EXPOSED_ADMIN_PANEL",
                "confidence":        conf,
                "confidence_reason": f"Admin path {path!r} returned {f.get('severity','')} finding; host is {'internet-facing' if is_public else 'private network'}",
                "score":             score_base,
                "title":             f"Admin/management interface accessible: {path} on {host}",
                "what_was_found": [
                    f"Path {path!r} on {host} returned a confirmed finding (severity: {f.get('severity','')})",
                    f"Host appears to be {'internet-facing' if is_public else 'on a private network'}",
                ],
                "why_it_matters": (
                    f"An administrative or management interface at {path} is accessible without "
                    f"triggering an authentication wall at the network level. "
                    f"{'Internet-facing admin panels are a primary target for credential stuffing and brute force attacks.' if is_public else 'Even on private networks, exposed admin panels expand the blast radius of any initial access.'}"
                ),
                "narrative": (
                    f"An administrative panel at {path} on {host} was confirmed accessible by the HTTP probe. "
                    f"If authentication is weak or default, this gives an attacker direct access to management functions. "
                    f"Default credentials should be tested in a controlled environment before reporting."
                ),
                "validation_checks": [
                    f"Confirm {path} is not protected by IP allowlist or network-level restriction",
                    "Attempt login with common default credentials in a controlled lab environment only",
                    "Check whether the interface exposes sensitive configuration or user data",
                    "Verify whether the interface is intended to be publicly reachable",
                ],
                "source_modules":   ["probe"],
                "source_count":     1,
                "evidence":         _evidence(
                    ["probe"],
                    primary={"module": "probe", "host": host, "path": path,
                             "severity": f.get("severity"), "confidence": f.get("confidence")},
                ),
                "hosts":            [host],
                "validation_state": "UNVALIDATED",
                "_dedup_key":       _dedup_key("EXPOSED_ADMIN_PANEL", [host], path),
            })

    return leads


def _rule_debug_endpoint(probe_data):
    """
    DEBUG_ENDPOINT
    A debug, diagnostic, or framework-internal endpoint is accessible.
    These endpoints often expose server internals, environment variables,
    heap dumps, or dependency trees without authentication.
    """
    leads = []

    DEBUG_PATHS = {
        "/actuator/env":         "Spring Boot environment (credentials in plaintext)",
        "/actuator/heapdump":    "Spring Boot heap dump (may contain credentials/tokens)",
        "/actuator/trace":       "Spring Boot HTTP request trace",
        "/__debug/":             "Flask/Django debug console",
        "/debug/pprof/":         "Go pprof profiling endpoint",
        "/_profiler/":           "Symfony profiler (full request/response history)",
        "/server-status":        "Apache server-status (live connection data)",
        "/server-info":          "Apache server-info (module configuration)",
        "/phpinfo.php":          "PHP configuration info (server environment variables)",
        "/info.php":             "PHP info page",
        "/telescope":            "Laravel Telescope (full request debug log)",
        "/horizon":              "Laravel Horizon (queue monitor)",
        "/.git/config":          "Git repository configuration (may expose remote URLs with credentials)",
        "/.git/HEAD":            "Git HEAD reference (confirms .git exposure)",
        "/config.php.bak":       "PHP config backup file",
        "/wp-config.php.bak":    "WordPress config backup",
    }

    for entry in probe_data:
        host = _parse_host(entry.get("url", ""))
        for f in entry.get("findings", []):
            path     = f.get("path", "")
            desc     = DEBUG_PATHS.get(path.lower(), "")
            if not desc:
                continue
            if f.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM"):
                continue

            conf = "HIGH" if f.get("confidence") == "CONFIRMED" and f.get("severity") in ("CRITICAL","HIGH") else "MEDIUM"

            leads.append({
                "type":              "DEBUG_ENDPOINT",
                "confidence":        conf,
                "confidence_reason": f"Debug path {path!r} confirmed accessible (confidence: {f.get('confidence','')})",
                "score":             7.5 if conf == "HIGH" else 5.5,
                "title":             f"Debug/diagnostic endpoint accessible: {path} on {host}",
                "what_was_found": [
                    f"Path {path!r} on {host} — {desc}",
                    f"HTTP probe severity: {f.get('severity','')} | Confidence: {f.get('confidence','')}",
                ],
                "why_it_matters": (
                    f"The endpoint {path!r} is a debug or diagnostic interface: {desc}. "
                    f"These endpoints are designed for developer use and frequently expose "
                    f"environment variables, credentials, internal configuration, or request history "
                    f"without requiring authentication."
                ),
                "narrative": (
                    f"A debug endpoint at {path} on {host} was confirmed accessible. "
                    f"This type of endpoint ({desc}) is designed for internal diagnostic use "
                    f"and should never be reachable from external networks. "
                    f"Review the response body carefully — it may contain credentials, API keys, "
                    f"or internal hostnames."
                ),
                "validation_checks": [
                    f"Fetch {path} and inspect the response body for credentials, API keys, or hostnames",
                    "Confirm the endpoint is not protected by network-level controls",
                    "Check whether the response includes environment variables or configuration data",
                    "Do not use any discovered credentials beyond read-only validation",
                ],
                "source_modules":   ["probe"],
                "source_count":     1,
                "evidence":         _evidence(
                    ["probe"],
                    primary={"module": "probe", "host": host, "path": path,
                             "description": desc, "severity": f.get("severity"),
                             "confidence": f.get("confidence")},
                ),
                "hosts":            [host],
                "validation_state": "UNVALIDATED",
                "_dedup_key":       _dedup_key("DEBUG_ENDPOINT", [host], path),
            })

    return leads


def _rule_version_chain(analysis_data, probe_data, passive_data):
    """
    VERSION_CHAIN
    A service was detected with a version that is multiple major/minor versions
    behind the current stable release — indicating a pattern of delayed patching
    rather than a single missed update. This is a systemic risk indicator.

    Multiple severely outdated services on the same host compound the risk.
    """
    leads = []

    # Known current stable versions (approximate — used for relative comparison)
    CURRENT_VERSIONS = {
        "apache":         (2, 4, 59),
        "nginx":          (1, 25, 3),
        "openssh":        (9, 7),
        "openssl":        (3, 3, 0),
        "php":            (8, 3, 0),
        "mysql":          (8, 4, 0),
        "postgresql":     (16, 0),
        "redis":          (7, 2, 0),
        "elasticsearch":  (8, 13, 0),
        "jenkins":        (2, 452),
        "gitlab":         (16, 11, 0),
        "wordpress":      (6, 5, 0),
    }

    from modules.matchers import normalize_version

    host_outdated = {}  # host → [(product, detected_ver, current_ver, gap_str)]

    for entry in analysis_data:
        h = _parse_host(entry.get("url", entry.get("host", "")))
        for match in entry.get("tech_matches", []):
            product = match.get("tech", "")
            version = match.get("version", "")
            if not product or not version or version in ("unknown", "x"):
                continue

            current = CURRENT_VERSIONS.get(product.lower())
            if not current:
                continue

            detected = normalize_version(version)
            if not detected:
                continue

            # Check if significantly behind (2+ minor versions or 1+ major)
            if detected[0] < current[0]:
                gap = f"major version behind ({detected[0]}.x vs {current[0]}.x)"
            elif len(detected) >= 2 and len(current) >= 2 and detected[1] < current[1] - 1:
                gap = f"{current[1] - detected[1]} minor versions behind"
            else:
                continue   # close enough — skip

            host_outdated.setdefault(h, []).append((product, version, ".".join(str(x) for x in current), gap))

    for host, outdated_list in host_outdated.items():
        if not outdated_list:
            continue

        conf   = "HIGH" if len(outdated_list) >= 2 else "MEDIUM"
        score  = 7.0 if len(outdated_list) >= 2 else 5.5

        found_strs = [f"{p} {v} (current: {c}, gap: {g})" for p, v, c, g in outdated_list]

        leads.append({
            "type":              "VERSION_CHAIN",
            "confidence":        conf,
            "confidence_reason": f"{len(outdated_list)} significantly outdated service(s) on {host} — indicates pattern of delayed patching",
            "score":             score,
            "title":             f"{'Multiple outdated' if len(outdated_list) > 1 else 'Outdated'} service version(s) on {host} — systemic patching gap",
            "what_was_found":    [f"Outdated: {s}" for s in found_strs],
            "why_it_matters": (
                f"{len(outdated_list)} service(s) on {host} are significantly behind current stable versions. "
                f"This is not just a single missed patch — it indicates a pattern of delayed or "
                f"absent patch management. Hosts with delayed patching patterns are more likely to "
                f"have multiple unpatched CVEs across their entire stack."
            ),
            "narrative": (
                f"Version analysis found {len(outdated_list)} service(s) on {host} that are "
                f"significantly behind current stable releases. "
                f"The specific services are: {', '.join(p + ' ' + v for p,v,_,_ in outdated_list)}. "
                f"This pattern suggests systematic under-patching rather than isolated gaps. "
                f"Each outdated service should be cross-referenced against its CVE history "
                f"for the version range between detected and current."
            ),
            "validation_checks": [
                "Confirm exact versions via service banners or response headers",
                "Cross-reference the full CVE history for the version range (detected → current)",
                "Verify whether the host has a patching schedule or is unmanaged",
                "Check whether the outdated versions are behind a WAF or network control that mitigates exposure",
            ],
            "source_modules":   ["analyse"],
            "source_count":     1,
            "evidence":         _evidence(
                ["analyse"],
                primary={"module": "analyse", "host": host, "outdated_services": found_strs},
            ),
            "hosts":            [host],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("VERSION_CHAIN", [host], "version_gap"),
        })

    return leads


def _rule_graphql_recon(js_data):
    """
    GRAPHQL_RECON
    GraphQL introspection enabled. RECON LEAD ONLY — not an exploit.
    Always LOW confidence and lowest base score in the engine.
    Downgraded from v1 which overclaimed this as a high-value attack path.
    """
    leads = []

    for js_entry in js_data:
        if not js_entry.get("graphql_introspection"):
            continue
        h = _parse_host(js_entry.get("url", ""))
        if not h:
            continue

        leads.append({
            "type":              "GRAPHQL_RECON",
            "confidence":        "LOW",
            "confidence_reason": "single module signal — introspection flag from jsextractor; schema review needed",
            "score":             _score("GRAPHQL_RECON", "LOW", 1),
            "title":             f"GraphQL introspection enabled on {h}",
            "what_was_found": [
                f"GraphQL endpoint at https://{h}/graphql returned schema data",
                "Introspection confirmed by jsextractor",
            ],
            "why_it_matters": (
                "Introspection exposes the full API schema including all types, queries, "
                "and mutations. An operator can use this to identify high-risk mutations "
                "and test them for missing authentication or authorisation. "
                "Introspection being open is a misconfiguration — it is not itself an exploit."
            ),
            "validation_checks": [
                "Query __schema to retrieve all type and mutation names",
                "Identify mutations involving sensitive operations (payment, delete, admin, role change)",
                "Confirm whether introspection works without any authentication token",
                "Test sensitive mutations for missing auth — introspection alone is not a finding",
            ],
            "source_modules":   ["jsextractor"],
            "source_count":     1,
            "evidence":         _evidence(
                ["jsextractor"],
                primary={"module": "jsextractor", "host": h, "graphql_introspection": True},
            ),
            "hosts":            [h],
            "validation_state": "UNVALIDATED",
            "_dedup_key":       _dedup_key("GRAPHQL_RECON", [h]),
        })

    return leads


# ─────────────────────────────────────────
# Multi-Stage Chain Engine
# Finds pairs/triplets of leads that share hosts or evidence
# and creates "chain" leads showing how they connect end-to-end.
# This is what turns isolated findings into attack narratives.
# ─────────────────────────────────────────

# Chain type definitions — which lead combinations make meaningful chains
_CHAIN_PATTERNS = [
    # Secret + RCE on same host = credential-assisted code execution path
    {
        "a": "MULTI_SOURCE_SECRET",
        "b": "RCE_CANDIDATE",
        "type": "CREDENTIAL_RCE_CHAIN",
        "title_fn": lambda a, b: f"Exposed credential + RCE surface on {b['hosts'][0] if b.get('hosts') else 'same host'}",
        "score_boost": 1.5,
        "narrative": (
            "A confirmed credential was found AND a remote code execution candidate "
            "exists on an overlapping host. If the credential is valid for the affected "
            "service, it may allow authenticated exploitation or privilege escalation "
            "beyond what unauthenticated RCE alone would provide."
        ),
    },
    # CORS + Token = cross-origin credential theft
    {
        "a": "CORS_CREDENTIALED",
        "b": "TOKEN_WITH_SURFACE",
        "type": "CORS_TOKEN_CHAIN",
        "title_fn": lambda a, b: f"CORS bypass enables cross-origin token theft on {a['hosts'][0] if a.get('hosts') else 'same host'}",
        "score_boost": 1.2,
        "narrative": (
            "A CORS misconfiguration and a credential on the same host were both found. "
            "An attacker controlling another origin may be able to read the credential "
            "via cross-origin request, bypassing any same-origin protection."
        ),
    },
    # Takeover + Secret on same subdomain = full subdomain compromise
    {
        "a": "TAKEOVER_LIVE",
        "b": "TOKEN_WITH_SURFACE",
        "type": "TAKEOVER_CREDENTIAL_CHAIN",
        "title_fn": lambda a, b: f"Takeover candidate + credential exposure compound risk on {a['hosts'][0] if a.get('hosts') else 'same host'}",
        "score_boost": 1.3,
        "narrative": (
            "A subdomain takeover candidate and credential exposure share a host. "
            "If the takeover is achieved, the attacker serves content from a trusted "
            "subdomain — and the exposed credential may also be harvestable from users "
            "who interact with that subdomain."
        ),
    },
    # IDOR + forgotten endpoint on same host = object access via old path
    {
        "a": "IDOR_CANDIDATE",
        "b": "FORGOTTEN_ENDPOINT",
        "type": "IDOR_FORGOTTEN_CHAIN",
        "title_fn": lambda a, b: f"IDOR parameter + forgotten endpoint co-located on {a['hosts'][0] if a.get('hosts') else 'same host'}",
        "score_boost": 0.8,
        "narrative": (
            "An IDOR-susceptible parameter and a forgotten endpoint were both found "
            "on the same host. Forgotten endpoints often lack the access controls "
            "applied to current endpoints — the IDOR risk may be higher here than "
            "on actively-maintained paths."
        ),
    },
    # Storage exposure + secret = credential-assisted bucket access
    {
        "a": "STORAGE_EXPOSURE",
        "b": "MULTI_SOURCE_SECRET",
        "type": "STORAGE_CREDENTIAL_CHAIN",
        "title_fn": lambda a, b: f"Public storage bucket + confirmed credential — authenticated access risk",
        "score_boost": 1.4,
        "narrative": (
            "A publicly accessible storage bucket and a confirmed credential were both "
            "found. If the credential grants access to the same cloud account, "
            "the attacker may access not just the public bucket contents but also "
            "private resources in the same account."
        ),
    },
]


def _build_chains(leads: list) -> list:
    """
    Find pairs of leads that match chain patterns and share at least one host.
    Returns new chain leads — does not modify originals.
    Chains are scored as: max(a.score, b.score) + score_boost.
    """
    chain_leads = []
    seen_pairs  = set()

    by_type = {}
    for lead in leads:
        by_type.setdefault(lead["type"], []).append(lead)

    for pattern in _CHAIN_PATTERNS:
        type_a = pattern["a"]
        type_b = pattern["b"]
        leads_a = by_type.get(type_a, [])
        leads_b = by_type.get(type_b, [])

        if not leads_a or not leads_b:
            continue

        for la in leads_a:
            for lb in leads_b:
                hosts_a = set(_parse_host(h) for h in la.get("hosts", []))
                hosts_b = set(_parse_host(h) for h in lb.get("hosts", []))

                # Chain requires shared host OR both have no host (global findings)
                shared = hosts_a & hosts_b
                if not shared and hosts_a and hosts_b:
                    continue

                pair_key = (type_a, type_b, tuple(sorted(shared or hosts_a)))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                base_score    = max(la.get("score", 0), lb.get("score", 0))
                chain_score   = round(min(base_score + pattern["score_boost"], 10.0), 2)
                chain_conf    = la.get("confidence") if la.get("confidence") == "HIGH" or lb.get("confidence") == "HIGH" else "MEDIUM"
                chain_hosts   = sorted(shared or (hosts_a | hosts_b))
                chain_src_mods = sorted(set(la.get("source_modules", [])) | set(lb.get("source_modules", [])))

                chain_leads.append({
                    "type":              pattern["type"],
                    "confidence":        chain_conf,
                    "confidence_reason": f"Two correlated leads ({type_a} + {type_b}) share host(s): {', '.join(chain_hosts)}",
                    "score":             chain_score,
                    "title":             pattern["title_fn"](la, lb),
                    "what_was_found": [
                        f"Lead A: [{la.get('confidence','')}] {la.get('title','')}",
                        f"Lead B: [{lb.get('confidence','')}] {lb.get('title','')}",
                        f"Shared host(s): {', '.join(chain_hosts) or 'global finding'}",
                    ],
                    "why_it_matters": pattern["narrative"],
                    "narrative":      pattern["narrative"],
                    "validation_checks": [
                        "Validate each component lead independently before treating the chain as confirmed",
                        "Confirm shared host relationship is accurate (not just IP overlap)",
                        f"Start with the higher-confidence component: {type_a if la.get('confidence','') >= lb.get('confidence','') else type_b}",
                    ],
                    "source_modules":   chain_src_mods,
                    "source_count":     len(chain_src_mods),
                    "evidence": {
                        "sources":            [la.get("evidence", {}), lb.get("evidence", {})],
                        "source_modules":     chain_src_mods,
                        "primary_artifact":   {"lead_a_type": type_a, "lead_b_type": type_b},
                        "secondary_artifact": {},
                        "chain_components":   [
                            {"rank": la.get("rank"), "type": type_a, "score": la.get("score"), "title": la.get("title","")},
                            {"rank": lb.get("rank"), "type": type_b, "score": lb.get("score"), "title": lb.get("title","")},
                        ],
                    },
                    "hosts":            list(chain_hosts) or list(hosts_a | hosts_b),
                    "validation_state": "UNVALIDATED",
                    "is_chain":         True,
                    "_dedup_key":       _dedup_key(pattern["type"], list(chain_hosts), f"{type_a}+{type_b}"),
                })

    return chain_leads


# ─────────────────────────────────────────
# Deduplication v2 (reviewer fix #6)
# Key is set on each lead by its rule using _dedup_key().
# Removes _dedup_key from output — it is internal only.
# ─────────────────────────────────────────

def _dedup(leads):
    seen    = set()
    deduped = []
    for lead in leads:
        key = lead.pop("_dedup_key", None)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        deduped.append(lead)
    return deduped


# ─────────────────────────────────────────
# Narrative Chain Builder
# Builds a human-readable attack scenario from lead evidence
# explaining HOW the signals connect and WHAT the operator should do.
# ─────────────────────────────────────────

def _build_narrative(lead: dict) -> str:
    """
    Builds a multi-step narrative string that explains:
    1. What combination of signals triggered this lead
    2. Why that combination is meaningful
    3. What the realistic attack scenario looks like
    4. What evidence is still missing

    This is what turns a correlation engine output into something
    an operator can actually reason about.
    """
    lead_type  = lead.get("type", "")
    confidence = lead.get("confidence", "LOW")
    src_mods   = lead.get("source_modules", [])
    hosts      = lead.get("hosts", [])
    evidence   = lead.get("evidence", {})
    host_str   = hosts[0] if hosts else "unknown host"
    src_str    = " + ".join(src_mods) if src_mods else "unknown source"

    narratives = {

        "MULTI_SOURCE_SECRET": (
            f"A credential of the same type was independently discovered by two modules "
            f"({src_str}): once in live HTTP response content, and once in a public GitHub repository. "
            f"Cross-source agreement is the strongest corroboration this engine produces — "
            f"it significantly increases the probability the credential is real, active, and not rotated. "
            f"The next step is to verify whether the value matches between sources "
            f"and test validity with a safe read-only API call."
        ),

        "TAKEOVER_LIVE": (
            f"A dangling DNS record pointing to an unclaimed third-party service was detected on {host_str}. "
            f"{'Active HTTP traffic confirms real users or services reach this subdomain. ' if evidence.get('secondary_artifact', {}).get('live') else ''}"
            f"If the target resource is registered by an attacker, they can serve arbitrary content "
            f"from a subdomain that users trust. Depending on cookie scope, session tokens may be captured."
        ),

        "RCE_CANDIDATE": (
            f"A CVE tagged for remote code execution was matched against a service detected on {host_str} "
            f"by {src_str}. "
            f"{'Service name and version both align with the CVE affected range. ' if confidence in ('HIGH','MEDIUM') else 'Match is based on product name only — version not confirmed. '}"
            f"If the version is accurate and the service is reachable, this represents a potential "
            f"unauthenticated code execution surface. Version banner accuracy from Nmap is not guaranteed — "
            f"confirm via response headers or error pages before treating as exploitable."
        ),

        "TOKEN_WITH_SURFACE": (
            f"A credential was found in an HTTP response on {host_str}, and a high-value endpoint "
            f"was confirmed on the same host by {src_str}. "
            f"This is a spatial correlation — both signals share a host but the credential has not been "
            f"tested against the endpoint. The attack scenario is: if the credential type matches "
            f"the endpoint's authentication mechanism, it may grant authenticated access. "
            f"Manual validation is required before this can be treated as anything stronger than a lead."
        ),

        "STORAGE_EXPOSURE": (
            f"A cloud storage bucket was confirmed publicly accessible without credentials. "
            f"{'AWS credentials were also found in HTTP responses — if valid, this may allow authenticated access to additional resources beyond this bucket. ' if len(src_mods) > 1 else ''}"
            f"Public buckets frequently contain backup files, configuration archives, source code, "
            f"or user-uploaded content. The immediate next step is to list bucket contents "
            f"and identify any sensitive files before reporting."
        ),

        "IDOR_CANDIDATE": (
            f"A URL with object-reference parameters was archived by the Wayback Machine and is "
            f"still returning HTTP 200 today on {host_str}. "
            f"Forgotten endpoints frequently miss modern WAF rules and may not have been reviewed "
            f"in recent security assessments. The attack scenario is: if the endpoint lacks "
            f"access controls, modifying the ID parameter may expose another user's data. "
            f"Two test accounts are required to validate this properly."
        ),

        "CORS_CREDENTIALED": (
            f"A CORS misconfiguration was detected on {host_str} where the policy accepts "
            f"arbitrary or reflective origins. Credentialed endpoints were also confirmed on this host. "
            f"The attack scenario requires: an attacker-controlled page making a cross-origin request "
            f"with credentials:include, and the browser sending the victim's cookies. "
            f"This requires building a proof-of-concept page to confirm — CORS headers alone are not proof."
        ),

        "REDIRECT_SENSITIVE": (
            f"An open redirect was confirmed on {host_str}, which is classified as a sensitive host "
            f"({'auth/SSO domain' if 'auth' in host_str or 'sso' in host_str or 'login' in host_str else 'host with exposed secrets'}). "
            f"The attack scenario is social engineering: a phishing email containing a URL that shows "
            f"the trusted domain in the browser bar, redirecting to an attacker-controlled page. "
            f"On SSO hosts, this may also interfere with OAuth redirect_uri validation."
        ),

        "FORGOTTEN_ENDPOINT": (
            f"A historically accessible endpoint was archived by the Wayback Machine and confirmed "
            f"still live on {host_str} today. The endpoint accepts injection-relevant parameters. "
            f"Forgotten endpoints often predate current WAF rules and security reviews. "
            f"The attack surface covers: SQL injection, SSRF, LFI, path traversal, and open redirect. "
            f"Test with benign payloads in a controlled environment first."
        ),

        "GRAPHQL_RECON": (
            f"GraphQL introspection is enabled on {host_str}, exposing the complete API schema. "
            f"This is a recon lead, not an exploit. The value is: the schema reveals all query and "
            f"mutation names, including potentially sensitive operations involving payments, users, "
            f"admin functions, or deletion. Each sensitive mutation should be tested individually "
            f"for missing authentication or authorisation checks."
        ),
    }

    base = narratives.get(lead_type, (
        f"Signals from {src_str} were correlated on {host_str}. "
        f"Manual investigation required to determine impact."
    ))

    # Append confidence context
    conf_context = {
        "HIGH":   " Evidence from multiple independent sources supports this lead.",
        "MEDIUM": " Evidence is suggestive but requires validation before treating as confirmed.",
        "LOW":    " This is an inferred lead based on limited evidence — treat with caution.",
    }
    return base + conf_context.get(confidence, "")


# ─────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────

def correlate(
    output_file,
    passive_file=None,
    probe_file=None,
    secret_file=None,
    js_file=None,
    wayback_file=None,
    github_file=None,
    redirect_file=None,
    takeover_file=None,
    s3_file=None,
    scan_file=None,
    analysis_file=None,
):
    cprint("\n  [≈] Loading stage outputs for correlation...", "cyan")

    passive_data  = _load_list(passive_file)
    probe_data    = _load_list(probe_file)
    secret_data   = _load_list(secret_file)
    js_data       = _load_list(js_file)
    wayback_data  = _load_dict(wayback_file)
    github_data   = _load_dict(github_file)
    redirect_data = _load_list(redirect_file)
    takeover_data = _load_list(takeover_file)
    s3_data       = _load_dict(s3_file)
    scan_data     = _load_scan_as_list(scan_file)
    analysis_data = _load_list(analysis_file)

    cprint("  [≈] Running correlation rules...", "cyan")

    all_leads = []

    # Rules ordered: strongest first (MULTI_SOURCE_SECRET), weakest last (GRAPHQL_RECON)
    rules = [
        # Tier 1 — Strongest signals (multi-source, confirmed)
        ("MULTI_SOURCE_SECRET", lambda: _rule_multi_source_secret(secret_data, github_data)),
        ("TAKEOVER_LIVE",       lambda: _rule_takeover_live(takeover_data, passive_data, probe_data)),
        ("RCE_CANDIDATE",       lambda: _rule_rce_candidate(analysis_data, scan_data)),
        ("VERSION_CHAIN",       lambda: _rule_version_chain(analysis_data, probe_data, passive_data)),
        # Tier 2 — Exposed surfaces
        ("EXPOSED_ADMIN_PANEL", lambda: _rule_exposed_admin(probe_data, passive_data)),
        ("DEBUG_ENDPOINT",      lambda: _rule_debug_endpoint(probe_data)),
        ("STORAGE_EXPOSURE",    lambda: _rule_storage_exposure(s3_data, secret_data)),
        # Tier 3 — Corroborated signals
        ("TOKEN_WITH_SURFACE",  lambda: _rule_token_with_surface(secret_data, js_data, probe_data, wayback_data)),
        ("IDOR_CANDIDATE",      lambda: _rule_idor_candidate(wayback_data, js_data, probe_data)),
        ("CORS_CREDENTIALED",   lambda: _rule_cors_credentialed(probe_data, js_data)),
        ("REDIRECT_SENSITIVE",  lambda: _rule_redirect_sensitive(redirect_data, secret_data, passive_data)),
        ("FORGOTTEN_ENDPOINT",  lambda: _rule_forgotten_endpoint(wayback_data, probe_data)),
        # Tier 4 — Recon leads
        ("GRAPHQL_RECON",       lambda: _rule_graphql_recon(js_data)),
    ]

    for rule_name, rule_fn in rules:
        try:
            results = rule_fn()
            if results:
                cprint(f"  [+] {rule_name}: {len(results)} lead(s)", "yellow")
            all_leads.extend(results)
        except Exception as ex:
            import traceback
            cprint(f"  [!] Rule {rule_name} failed — skipped. Error: {ex}", "red")
            cprint(f"      {traceback.format_exc().splitlines()[-1]}", "yellow")

    all_leads = _dedup(all_leads)
    all_leads.sort(key=lambda p: p["score"], reverse=True)
    for i, lead in enumerate(all_leads, 1):
        lead["rank"] = i
        if not lead.get("narrative"):
            lead["narrative"] = _build_narrative(lead)

    # ── Multi-stage chain detection ──
    # Run after primary leads are deduplicated and ranked.
    # Chains reference existing lead ranks for traceability.
    try:
        chains = _build_chains(all_leads)
        if chains:
            cprint(f"  [+] Chain detection: {len(chains)} multi-stage chain(s) found", "yellow")
            # Dedup chains against existing leads
            existing_keys = {lead.get("_dedup_key", "") for lead in all_leads}
            new_chains = []
            for chain in chains:
                key = chain.pop("_dedup_key", None)
                if key and key not in existing_keys:
                    existing_keys.add(key)
                    new_chains.append(chain)
            # Add chains to lead list and re-rank everything
            all_leads.extend(new_chains)
            all_leads.sort(key=lambda p: p["score"], reverse=True)
            for i, lead in enumerate(all_leads, 1):
                lead["rank"] = i
    except Exception as ex:
        cprint(f"  [!] Chain detection failed — skipped: {ex}", "yellow")

    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_leads, f, indent=2)

    # Summary
    cprint(f"\n  [✓] Correlation complete — {len(all_leads)} lead(s) ranked", "green")

    by_conf = {}
    for lead in all_leads:
        c = lead.get("confidence", "LOW")
        by_conf[c] = by_conf.get(c, 0) + 1

    cprint(
        f"  [→] Confidence: "
        f"{by_conf.get('HIGH',0)} HIGH · "
        f"{by_conf.get('MEDIUM',0)} MEDIUM · "
        f"{by_conf.get('LOW',0)} LOW",
        "white"
    )

    if all_leads:
        cprint("\n  Top Correlated Leads:", "white")
        for lead in all_leads[:5]:
            conf  = lead.get("confidence", "")
            score = lead.get("score", 0)
            col   = "red" if conf == "HIGH" else "yellow" if conf == "MEDIUM" else "cyan"
            cprint(
                f"    #{lead['rank']} [{score:.1f}] [{conf}] "
                f"{lead['type']}: {lead['title'][:65]}",
                col
            )

    cprint(f"\n  [→] Saved: {output_file}", "cyan")
    return all_leads