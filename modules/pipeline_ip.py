# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/pipeline_ip.py
# IP-mode pipeline — for scanning raw IP addresses or CIDR ranges
# where domain-based stages (subdomain enum, DNS bruteforce, takeover,
# Wayback, GitHub) are not applicable.
#
# Stages run in IP mode:
#   1.  Port Scan (Nmap)           — all IPs in parallel batches
#   2.  Passive HTTP Recon         — HTTP fingerprint on every live web port
#   3.  HTTP Probing               — 100+ path/header/CORS/cookie checks
#   4.  Secret Scanner             — credential patterns in HTTP responses
#   5.  JS Endpoint Extractor      — endpoints + GraphQL from JS files
#   6.  Open Redirect Detection    — redirect chains on live hosts
#   7.  S3 Bucket Scanner          — cloud bucket names derived from responses
#   8.  CVE Analysis               — NVD + EPSS against Nmap service banners
#   9.  Correlation Engine         — cross-stage lead ranking
#   10. Report Generation          — HTML + Markdown report
#
# Stages NOT run (require a root domain):
#   Subdomain Enumeration, DNS Bruteforce, Takeover Detection,
#   Wayback Machine Scanner, GitHub Secret Scanner
#
# Usage:
#   python3 main.py scan-ips --ips 51.104.59.194,51.141.1.28
#   python3 main.py scan-ips --targets ips.txt
#   python3 main.py auto     --ips 51.104.59.194

import os
import time
import json
import hashlib
import threading
from datetime import datetime
from termcolor import cprint
from modules.logger import init_logger, get_logger

from modules.pipeline import (
    StageRecord, STATE_PASSED, STATE_FAILED, STATE_SKIPPED, STATE_RESUMED,
    run_stage, run_stages_parallel,
    stage_already_done, mark_stage_done,
    _write_meta, _meta_valid,
    file_has_content, _load_json_list, _load_json_dict,
    TOOL_VERSION,
)

# ─────────────────────────────────────────
# IP-mode stage weights for ETA tracker
# ─────────────────────────────────────────

IP_STAGE_WEIGHTS = {
    "1. Port Scan (Nmap)":        5.0,   # slowest — depends on IP count + port range
    "2. Passive HTTP Recon":      2.0,
    "3. HTTP Probing":            3.5,   # parallel with 4/5/6
    "4. Secret Scanner":          2.5,   # parallel with 3/5/6
    "5. JS Extractor":            2.5,   # parallel with 3/4/6
    "6. Open Redirect":           2.0,   # parallel with 3/4/5
    "7. S3 Bucket Scanner":       2.0,
    "8. CVE Analysis":            2.0,
    "9. Correlation Engine":      0.5,
    "10. Report Generation":      0.5,
}


class IPETATracker:
    def __init__(self):
        self.done  = {}
        self.start = time.time()

    def record(self, name, elapsed):
        self.done[name] = elapsed

    def eta_str(self):
        remaining = [s for s in IP_STAGE_WEIGHTS if s not in self.done]
        if not remaining:
            return "almost done"
        completed = list(self.done.keys())
        if not completed:
            return ""
        total_elapsed = sum(self.done.values())
        total_weight  = sum(IP_STAGE_WEIGHTS.get(s, 1.0) for s in completed)
        if total_weight == 0:
            return ""
        spu = total_elapsed / total_weight
        rem_secs = int(sum(IP_STAGE_WEIGHTS.get(s, 1.0) for s in remaining) * spu)
        m, s = divmod(rem_secs, 60)
        return f"~{m}m {s}s remaining ({len(remaining)} stages left)"


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _write_ip_list(ip_list, path):
    """Write IPs to a text file (one per line) — compatible with scan.py."""
    dirpath = os.path.dirname(path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(ip_list) + "\n")


def _is_likely_http_service(port, service, product):
    """
    Determine whether an open port is likely to speak HTTP or HTTPS.
    Uses three signals: port number, Nmap service name, Nmap product banner.
    Does NOT use a fixed allowlist — instead uses exclusion of known
    non-HTTP protocols so any unknown port gets probed (fail-open).

    Returns: "https", "http", "both", or None (skip this port).
    """
    port    = int(port)
    svc     = str(service).lower()
    prod    = str(product).lower()
    combined = svc + " " + prod

    # ── Ports that are definitively NOT HTTP ──
    # These are well-known protocols that will never speak HTTP.
    # Everything not in this list gets probed.
    DEFINITELY_NOT_HTTP = {
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP (plain)
        53,    # DNS
        110,   # POP3
        111,   # RPC portmapper
        119,   # NNTP
        135,   # MS RPC
        137,   # NetBIOS
        138,   # NetBIOS
        139,   # NetBIOS/SMB
        143,   # IMAP
        161,   # SNMP
        162,   # SNMP trap
        179,   # BGP (Border Gateway Protocol — not HTTP)
        389,   # LDAP
        445,   # SMB
        465,   # SMTPS (well-known)
        514,   # Syslog
        515,   # LPD
        587,   # SMTP submission
        636,   # LDAPS
        873,   # rsync
        993,   # IMAPS
        995,   # POP3S
        1194,  # OpenVPN
        1433,  # MSSQL
        1521,  # Oracle DB
        2049,  # NFS
        3306,  # MySQL
        3389,  # RDP
        4369,  # Erlang EPMD (RabbitMQ)
        5432,  # PostgreSQL
        5671,  # AMQP TLS (RabbitMQ)
        5672,  # AMQP (RabbitMQ)
        5900,  # VNC
        6379,  # Redis
        9042,  # Cassandra
        9092,  # Kafka
        9093,  # Kafka TLS
        9200,  # Elasticsearch HTTP — actually IS HTTP, handle below
        11211, # Memcached
        27017, # MongoDB
        27018, # MongoDB
        50000, # DB2 / Java JPDA
        61613, # STOMP (ActiveMQ)
        61616, # OpenWire (ActiveMQ)
    }

    # ── Known HTTP service names from Nmap ──
    HTTP_SERVICE_NAMES = {
        "http", "https", "http-alt", "http-proxy",
        "https-alt", "ssl/http", "ssl/https",
        "http?", "https?", "www", "webcache",
        "nagios", "jetty", "tomcat", "apache",
        "kubernetes", "docker",
    }

    # ── Ports that ALWAYS speak HTTP(S) regardless of banner ──
    ALWAYS_HTTP  = {80, 8080, 8008, 8000}
    ALWAYS_HTTPS = {443, 8443, 4443, 8444}
    TRY_BOTH     = {
        # Management, dev, API, monitoring ports
        3000, 4000, 4848, 5000, 7000, 7001, 7077, 7443,
        7999, 8001, 8009, 8081, 8082, 8083, 8085, 8086,
        8088, 8090, 8161, 8181, 8500, 8600, 8888, 8983,
        9000, 9001, 9090, 9200, 9300, 9418, 9999,
        10000, 10001, 10002, 10250, 10255, 15672,
        20000, 28017, 50070,
    }

    if port in DEFINITELY_NOT_HTTP:
        # Double-check: if Nmap says it's http despite the port, trust Nmap
        if any(s in combined for s in ["http", "www", "web"]):
            return "both"
        return None   # skip — not HTTP

    if port in ALWAYS_HTTPS:
        return "https"
    if port in ALWAYS_HTTP:
        return "http"
    if port in TRY_BOTH:
        return "both"

    # ── Use Nmap service name as primary signal ──
    if any(s in svc for s in ["ssl", "tls", "https"]):
        return "https"
    if any(s in svc for s in HTTP_SERVICE_NAMES):
        return "http"

    # ── Use product banner as fallback signal ──
    HTTP_PRODUCT_HINTS = [
        "apache", "nginx", "iis", "tomcat", "jetty", "lighttpd",
        "caddy", "gunicorn", "uvicorn", "express", "node",
        "spring", "django", "flask", "rails", "php",
        "kubernetes", "docker", "grafana", "kibana", "jenkins",
        "gitlab", "gitea", "prometheus", "consul", "vault",
        "swagger", "api", "web", "http", "rest",
    ]
    if any(h in prod for h in HTTP_PRODUCT_HINTS):
        return "both"

    # ── Fail-open: unknown port/service — probe it ──
    # Better to try and fail than to miss something.
    return "both"


def _parse_scan_results(scan_file):
    """
    Parse scan_results.json into a flat list of port entries.

    scan.py writes this structure:
    {
      "results": {
        "45.33.32.156": {
          "ip": "45.33.32.156",
          "protocols": {
            "tcp": {
              22: {"state": "open", "service": "ssh", "product": "OpenSSH", "version": "6.6.1p1"},
              80: {"state": "open", "service": "http", "product": "Apache httpd", "version": "2.4.7"}
            }
          }
        }
      }
    }

    Returns a list of dicts, one per host, each with a flat "ports" list:
    [
      {
        "host": "45.33.32.156",
        "ip":   "45.33.32.156",
        "ports": [
          {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "6.6.1p1"},
          {"port": 80, "state": "open", "service": "http", "product": "Apache httpd", "version": "2.4.7"}
        ]
      }
    ]
    """
    try:
        with open(scan_file, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as ex:
        cprint(f"  [!] Failed to read scan file: {ex}", "red")
        return []

    # Handle both dict-with-results wrapper and plain list
    if isinstance(raw, dict):
        results_block = raw.get("results", raw)
    elif isinstance(raw, list):
        # Already a flat list — normalise below
        results_block = {str(i): entry for i, entry in enumerate(raw)}
    else:
        return []

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

        parsed.append({
            "host":  host,
            "ip":    host,
            "ports": flat_ports,
        })

    return parsed


def _build_passive_from_scan(scan_file, passive_file, insecure=False):
    """
    IP mode has no subdomain list to feed passive.py.
    Instead we probe every open port from Nmap that could speak HTTP/HTTPS.

    Key design decisions:
    - Does NOT use a fixed WEB_PORTS allowlist — uses exclusion of known
      non-HTTP protocols instead (fail-open: unknown ports get probed)
    - Scheme detection uses port + Nmap service name + product banner
    - Tries both HTTP and HTTPS on ambiguous ports
    - Both successful responses are kept (same port may respond differently)
    - All real Nmap service data is preserved in passive output for CVE analysis
    """
    import httpx

    scan_data = _parse_scan_results(scan_file)
    if not scan_data:
        cprint("  [!] No scan results to build passive recon from.", "yellow")
        return

    UA = "Mozilla/5.0 (compatible; RedShadowBot/4.0)"
    results   = []
    attempted = 0
    skipped   = 0

    # One shared session — timeouts are tight to avoid hanging on non-HTTP ports
    session = httpx.Client(
        verify=not insecure,
        timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0),
        follow_redirects=True,
        headers={"User-Agent": UA},
    )

    for entry in scan_data:
        # scan.py stores results keyed by host under "results" or as a list
        host  = entry.get("host", entry.get("ip", ""))
        ports = entry.get("ports", [])

        if not host or not ports:
            continue

        for port_info in ports:
            # Only process open ports
            if str(port_info.get("state", "")).lower() != "open":
                continue

            port    = port_info.get("port", 0)
            service = port_info.get("service", "")
            product = port_info.get("product", "")
            version = port_info.get("version", "")

            probe_mode = _is_likely_http_service(port, service, product)
            if probe_mode is None:
                skipped += 1
                continue

            # Build list of URLs to try based on probe_mode
            if probe_mode == "https":
                urls_to_try = [f"https://{host}:{port}"]
            elif probe_mode == "http":
                urls_to_try = [f"http://{host}:{port}"]
            else:  # "both"
                urls_to_try = [f"https://{host}:{port}", f"http://{host}:{port}"]

            for try_url in urls_to_try:
                attempted += 1
                try:
                    resp = session.get(try_url)

                    # Detect tech from response
                    tech = _detect_tech_simple(resp.text, resp.headers, service, product)

                    # Merge Nmap-detected product into tech list if not already there
                    if product and product not in tech:
                        norm = product.strip().title()
                        if norm:
                            tech.append(norm)

                    results.append({
                        "url":          try_url,
                        "ip":           host,
                        "hostname":     host,
                        "status":       resp.status_code,
                        "title":        _extract_title(resp.text),
                        "tech_matches": [{"tech": t, "cves": []} for t in tech],
                        "headers":      dict(resp.headers),
                        "port":         port,
                        "service":      service,
                        "product":      product,
                        "version":      version,
                        # Preserve raw Nmap data for CVE analysis
                        "nmap_service": {
                            "port":    port,
                            "service": service,
                            "product": product,
                            "version": version,
                        },
                    })
                    # Got a response — if we got HTTPS working, skip HTTP
                    if try_url.startswith("https://"):
                        break

                except httpx.ConnectError:
                    # Port doesn't speak HTTP — silently skip
                    continue
                except httpx.TimeoutException:
                    # Slow port — skip, don't block the whole scan
                    continue
                except Exception:  # HTTP probe failed for this port - not an HTTP service
                    continue

    session.close()

    cprint(f"  [ℹ] Probed {attempted} port(s), skipped {skipped} non-HTTP port(s)", "cyan")

    if not results:
        cprint("  [!] No live web ports responded to HTTP/HTTPS.", "yellow")
        return

    dirpath = os.path.dirname(passive_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    with open(passive_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    cprint(f"  [✓] Passive HTTP recon: {len(results)} live web service(s) found across {attempted} probed ports", "green")


def _extract_title(html):
    try:
        s = html.lower().find("<title>")
        e = html.lower().find("</title>")
        if s != -1 and e > s:
            return html[s + 7:e].strip()
    except Exception:  # Passive HTTP session close failed - non-critical
        pass
    return "N/A"


def _detect_tech_simple(html, headers, nmap_service="", nmap_product=""):
    """
    HTTP response tech detection for IP mode.
    Uses four signal sources:
      1. Server / X-Powered-By / Via / X-Generator response headers
      2. HTML content patterns (meta tags, JS paths, class names)
      3. Cookie names (framework fingerprints)
      4. Nmap service/product banner passed through from scan results

    Returns a deduplicated list of technology name strings compatible
    with PRODUCT_MAPPINGS in analyse.py.
    """
    tech  = set()
    h     = str(html).lower()
    hdr   = {k.lower(): str(v).lower() for k, v in headers.items()}
    srv   = hdr.get("server", "")
    xpb   = hdr.get("x-powered-by", "")
    via   = hdr.get("via", "")
    gen   = hdr.get("x-generator", "")
    cook  = hdr.get("set-cookie", "")
    nmap  = (str(nmap_service) + " " + str(nmap_product)).lower()

    # ── Web servers (from Server header + Nmap) ──
    if "nginx" in srv or "nginx" in nmap:
        tech.add("nginx")
    if "apache" in srv and "tomcat" not in srv:
        tech.add("Apache")
    if "apache" in nmap and "tomcat" not in nmap and "activemq" not in nmap:
        tech.add("Apache")
    if "microsoft-iis" in srv or "microsoft iis" in srv or "iis" in nmap:
        tech.add("Microsoft IIS")
    if "lighttpd" in srv or "lighttpd" in nmap:
        tech.add("lighttpd")
    if "caddy" in srv or "caddy" in nmap:
        tech.add("caddy")
    if "openresty" in srv:
        tech.add("nginx")  # OpenResty is nginx-based
    if "gunicorn" in srv or "gunicorn" in nmap:
        tech.add("gunicorn")
    if "uvicorn" in srv or "uvicorn" in nmap:
        tech.add("uvicorn")

    # ── App servers ──
    if "tomcat" in srv or "tomcat" in nmap or "tomcat" in h:
        tech.add("Apache Tomcat")
    if "jetty" in srv or "jetty" in nmap:
        tech.add("Eclipse Jetty")
    if "jboss" in srv or "jboss" in nmap or "jboss" in h:
        tech.add("JBoss")
    if "wildfly" in srv or "wildfly" in nmap:
        tech.add("WildFly")
    if "glassfish" in srv or "glassfish" in nmap:
        tech.add("GlassFish")
    if "weblogic" in srv or "weblogic" in nmap:
        tech.add("WebLogic")
    if "websphere" in srv or "websphere" in nmap:
        tech.add("WebSphere")

    # ── Proxies / CDN ──
    if "cloudflare" in srv or "cloudflare" in hdr.get("cf-ray", "") or "cloudflare" in via:
        tech.add("cloudflare")
    if "varnish" in via or "varnish" in srv or "x-varnish" in hdr:
        tech.add("varnish")
    if "squid" in via or "squid" in srv:
        tech.add("squid")
    if "haproxy" in srv or "haproxy" in via:
        tech.add("haproxy")
    if "envoy" in srv or "x-envoy-upstream" in hdr:
        tech.add("envoy")
    if "traefik" in srv or "x-traefik" in hdr:
        tech.add("traefik")
    if "akamai" in via or "akamaighost" in srv or "akamai" in hdr.get("x-check-cacheable",""):
        tech.add("akamai")

    # ── Language runtimes (X-Powered-By) ──
    if "php" in xpb or "php" in srv or "php" in nmap:
        tech.add("PHP")
    if "asp.net" in xpb or "aspnet" in h or ".aspx" in h:
        tech.add("ASP.NET")
    if "express" in xpb or "express" in nmap:
        tech.add("Express.js")
    if "node" in xpb or "node.js" in nmap:
        tech.add("node.js")
    if "python" in xpb or "python" in srv or "python" in nmap:
        tech.add("python")
    if "ruby" in xpb or "ruby" in nmap:
        tech.add("ruby")
    if "java" in xpb or ("java" in nmap and "javascript" not in nmap):
        tech.add("java")

    # ── Frameworks (HTML content + cookies) ──
    if "wp-content" in h or "wp-includes" in h or "wordpress" in h:
        tech.add("WordPress")
    if "drupal" in h or "drupal" in cook:
        tech.add("Drupal")
    if "joomla" in h:
        tech.add("Joomla")
    if "magento" in h or "mage" in cook:
        tech.add("Magento")
    if "typo3" in h:
        tech.add("TYPO3")
    if "strapi" in h or "strapi" in hdr.get("x-powered-by", ""):
        tech.add("Strapi")
    if "/_next/" in h or "next.js" in gen:
        tech.add("Next.js")
    if "csrfmiddlewaretoken" in h or "django" in cook:
        tech.add("Django")
    if "laravel" in cook or "laravel" in h:
        tech.add("Laravel")
    if "symfony" in cook or "symfony" in h:
        tech.add("Symfony")
    if "rails" in cook or "ruby on rails" in h:
        tech.add("ruby on rails")
    if "spring" in h and "springframework" in h:
        tech.add("Spring Framework")
    if "flask" in h or "werkzeug" in srv:
        tech.add("Flask")
    if "react" in h and ("react-dom" in h or "_react" in h):
        tech.add("React")

    # ── Databases / storage exposed via HTTP ──
    if "elasticsearch" in h or "elasticsearch" in nmap or '"version":{"number"' in h:
        tech.add("Elasticsearch")
    if "kibana" in h or "kibana" in nmap:
        tech.add("kibana")
    if "grafana" in h or "grafana" in nmap:
        tech.add("grafana")
    if "prometheus" in h or "prometheus" in nmap:
        tech.add("prometheus")
    if "influxdb" in h or "influxdb" in nmap:
        tech.add("influxdb")
    if "couchdb" in h or "couchdb" in nmap or '"couchdb"' in h:
        tech.add("couchdb")

    # ── DevOps / infrastructure ──
    if "jenkins" in h or "jenkins" in nmap or "x-jenkins" in hdr:
        tech.add("Jenkins")
    if "gitlab" in h or "gitlab" in nmap:
        tech.add("GitLab")
    if "gitea" in h or "gitea" in nmap:
        tech.add("Gitea")
    if "sonarqube" in h or "sonarqube" in nmap:
        tech.add("SonarQube")
    if "nexus" in h or "nexus" in nmap:
        tech.add("sonatype nexus")
    if "artifactory" in h or "artifactory" in nmap:
        tech.add("jfrog artifactory")
    if "kubernetes" in h or "kubernetes" in nmap or "k8s" in h:
        tech.add("kubernetes")
    if "docker" in h or "docker" in nmap:
        tech.add("docker")
    if "consul" in h or "consul" in nmap:
        tech.add("consul")
    if "vault" in h or "hashicorp vault" in nmap:
        tech.add("vault")
    if "rabbitmq" in h or "rabbitmq" in nmap or "rabbitmq" in srv:
        tech.add("rabbitmq")
    if "activemq" in h or "activemq" in nmap:
        tech.add("apache activemq")
    if "kafka" in h or "kafka" in nmap:
        tech.add("apache kafka")
    if "zabbix" in h or "zabbix" in nmap:
        tech.add("zabbix")
    if "nagios" in h or "nagios" in nmap:
        tech.add("nagios")
    if "splunk" in h or "splunk" in nmap or "x-splunk" in hdr:
        tech.add("splunk")

    # ── OpenSSL / OpenSSH from Nmap banners ──
    if "openssl" in nmap:
        tech.add("openssl")
    if "openssh" in nmap:
        tech.add("openssh")

    # ── Catch-all: X-Powered-By value not already matched ──
    if xpb and not any(t.lower() in xpb for t in tech):
        clean = xpb.split("/")[0].strip()
        if clean and len(clean) > 1 and clean not in ("the", "a", "an"):
            tech.add(clean.title())

    return sorted(tech)


def _calculate_run_quality(stage_map, output_dir, ip_list=None):
    """
    Point 15: Calculate a run quality score based on:
    - Stage completion rate
    - Fingerprint confidence (did services get version banners?)
    - HTTP coverage (did passive recon find web services?)
    - CVE match quality (are there version-confirmed matches?)
    - Correlation strength (any HIGH confidence leads?)

    Returns a dict with overall grade and per-dimension scores.
    """
    passed  = sum(1 for r in stage_map.values() if r.state == "PASSED")
    total   = len(stage_map)
    skipped = sum(1 for r in stage_map.values() if r.state in ("SKIPPED", "RESUMED"))

    # Stage completion (0-30 points)
    stage_score = round((passed / max(total - skipped, 1)) * 30)

    # Fingerprint confidence — were service versions detected? (0-20 points)
    scan_data    = _parse_scan_results(os.path.join(output_dir, "scan_results.json"))
    total_ports  = sum(len(e.get("ports", [])) for e in scan_data)
    versioned    = sum(1 for e in scan_data for p in e.get("ports", []) if p.get("version") and p["version"] != "unknown")
    fp_score     = round((versioned / max(total_ports, 1)) * 20) if total_ports > 0 else 0

    # HTTP coverage — what fraction of IPs had web services? (0-20 points)
    # Score is relative: all IPs got HTTP coverage = 20pts, none = 0pts
    passive_data  = _load_json_list(os.path.join(output_dir, "passive_results.json"))
    n_targets     = len(ip_list) if ip_list else 1
    http_covered  = len(set(e.get("ip", e.get("url", "")) for e in passive_data if e))
    http_score    = round((http_covered / n_targets) * 20) if n_targets > 0 else 0

    # CVE quality — any version-confirmed matches? (0-20 points)
    analysis_data = _load_json_list(os.path.join(output_dir, "analysis_results.json"))
    confirmed_cve = sum(1 for e in analysis_data for m in e.get("tech_matches", [])
                        for c in m.get("cves", []) if c.get("version_relevance") == "CONFIRMED")
    cve_score = min(confirmed_cve * 5, 20)

    # Correlation strength — any HIGH leads? (0-10 points)
    leads      = _load_json_list(os.path.join(output_dir, "attack_paths.json"))
    high_leads = sum(1 for l in leads if l.get("confidence") == "HIGH")
    med_leads  = sum(1 for l in leads if l.get("confidence") == "MEDIUM")
    cor_score  = min(high_leads * 5 + med_leads * 2, 10)

    total_score = stage_score + fp_score + http_score + cve_score + cor_score

    if total_score >= 80:
        grade = "Excellent"
        grade_color = "green"
    elif total_score >= 60:
        grade = "Good"
        grade_color = "green"
    elif total_score >= 40:
        grade = "Moderate"
        grade_color = "yellow"
    else:
        grade = "Limited"
        grade_color = "yellow"

    return {
        "total": total_score,
        "grade": grade,
        "grade_color": grade_color,
        "dimensions": {
            "stage_completion":       stage_score,
            "fingerprint_confidence": fp_score,
            "http_coverage":          http_score,
            "cve_quality":            cve_score,
            "correlation_strength":   cor_score,
        }
    }


def _ip_summary(ip_list, stage_map, output_dir, start_time):
    """Print final summary for IP-mode scans."""
    elapsed    = round(time.time() - start_time, 2)
    mins, secs = divmod(int(elapsed), 60)
    passed  = sum(1 for r in stage_map.values() if r.state == STATE_PASSED)
    failed  = sum(1 for r in stage_map.values() if r.state == STATE_FAILED)
    skipped = sum(1 for r in stage_map.values() if r.state in (STATE_SKIPPED, STATE_RESUMED))

    cprint(f"\n{'='*60}", "magenta")
    cprint(f"  🛡️  RedShadow V4 — IP Scan Complete", "magenta")
    cprint(f"{'='*60}", "magenta")
    cprint(f"  Targets  : {len(ip_list)} IP(s)", "white")
    cprint(f"  Duration : {mins}m {secs}s", "white")
    cprint(f"  Stages   : {passed} passed | {failed} failed | {skipped} skipped", "white")

    cprint(f"\n  Stage Results:", "white")
    # Sort by stage number for clean sequential display
    import re as _re
    def _skey(n):
        m = _re.match(r"(\d+)\.", n)
        return int(m.group(1)) if m else 99
    for name, record in sorted(stage_map.items(), key=lambda x: _skey(x[0])):
        if record.state == STATE_PASSED:
            cprint(f"    [✓] {name}  ({record.elapsed}s)", "green")
        elif record.state == STATE_RESUMED:
            cprint(f"    [~] {name}  (resumed from cache)", "yellow")
        elif record.state == STATE_SKIPPED:
            cprint(f"    [–] {name}  (skipped)", "yellow")
        else:
            cprint(f"    [✗] {name}  ({record.elapsed}s) — {record.error[:60]}", "red")

    cprint(f"\n  Findings Summary:", "white")

    scan_data  = _parse_scan_results(os.path.join(output_dir, "scan_results.json"))
    open_ports = sum(len(entry.get("ports", [])) for entry in scan_data)
    cprint(f"    Open ports discovered    : {open_ports}", "cyan")

    secret_count = sum(
        len(e.get("findings", []))
        for e in _load_json_list(os.path.join(output_dir, "secret_results.json"))
    )
    if secret_count:
        cprint(f"    🔑 Secrets found         : {secret_count}", "red")

    probe_data  = _load_json_list(os.path.join(output_dir, "probe_results.json"))
    probe_vulns = sum(
        1 for e in probe_data for f in e.get("findings", [])
        if f.get("finding_type") == "vulnerability" and f.get("severity") in ("CRITICAL", "HIGH")
    )
    if probe_vulns:
        cprint(f"    🔍 Critical/High probes  : {probe_vulns}", "yellow")

    analysis_data = _load_json_list(os.path.join(output_dir, "analysis_results.json"))
    cve_total = sum(len(m.get("cves", [])) for e in analysis_data for m in e.get("tech_matches", []))
    rce_count = sum(
        1 for e in analysis_data for m in e.get("tech_matches", [])
        for c in m.get("cves", []) if "RCE" in c.get("attack_surface", [])
    )
    if cve_total:
        cprint(f"    🛡️  CVEs matched          : {cve_total} ({rce_count} RCE)", "yellow")

    leads = _load_json_list(os.path.join(output_dir, "attack_paths.json"))
    if leads:
        high_leads = sum(1 for l in leads if l.get("confidence") == "HIGH")
        cprint(f"    🎯 Correlated leads      : {len(leads)} ({high_leads} HIGH confidence)", "red" if high_leads else "yellow")

    # Output files
    cprint(f"\n  Output Files:", "white")
    for fname in ["scan_results.json", "passive_results.json", "probe_results.json",
                  "secret_results.json", "js_results.json", "redirect_results.json",
                  "s3_results.json", "analysis_results.json", "attack_paths.json",
                  "redshadow_report.md", "redshadow_report.html"]:
        fpath = os.path.join(output_dir, fname)
        if os.path.exists(fpath):
            size      = os.path.getsize(fpath)
            validated = "✅" if _meta_valid(fpath) else "📄"
            cprint(f"    {validated} {fpath} ({size:,} bytes)", "green")
        else:
            cprint(f"    [✗] {fpath}", "yellow")

    # Run quality score
    try:
        quality = _calculate_run_quality(stage_map, output_dir, ip_list=ip_list)
        cprint(f"\n  Run Quality Score:", "white")
        cprint(f"    Overall  : {quality['total']}/100 — {quality['grade']}", quality["grade_color"])
        dims = quality["dimensions"]
        cprint(f"    Stages   : {dims['stage_completion']}/30", "white")
        cprint(f"    Banners  : {dims['fingerprint_confidence']}/20", "white")
        cprint(f"    HTTP Cov : {dims['http_coverage']}/20", "white")
        cprint(f"    CVE Qual : {dims['cve_quality']}/20", "white")
        cprint(f"    Leads    : {dims['correlation_strength']}/10", "white")
    except Exception as ex:
        cprint(f"  [!] Quality score calculation failed: {ex}", "yellow")

    cprint(f"\n{'='*60}\n", "magenta")


# ─────────────────────────────────────────
# Main IP Pipeline Entry Point
# ─────────────────────────────────────────

def run_pipeline_ip(ip_list, output_dir="outputs", insecure=False, resume=False,
                    triage=False, debug=False, quiet=False,
                    report_format="all", thread_override=None, timeout_override=None,
                    port_override=None):
    """
    Run the IP-mode recon pipeline against a list of IP addresses.

    Args:
        ip_list (list):        List of IPv4 address strings
        output_dir (str):      Directory for all output files
        insecure (bool):       Skip TLS verification
        resume (bool):         Resume from last valid stage output
        triage (bool):         Fast triage mode — skips redirect and S3 (~70%% faster)
        debug (bool):          Enable verbose debug logging to log file
        quiet (bool):          Suppress non-essential console output
        report_format (str):   Output format: "all", "html", "md", "json"
        thread_override (int): Override thread count for all stages
        timeout_override (int):Override HTTP timeout for all stages
    """
    os.makedirs(output_dir, exist_ok=True)
    start_time = time.time()
    stage_map  = {}
    eta        = IPETATracker()
    log        = init_logger(output_dir=output_dir, debug=debug, quiet=quiet)

    # File paths
    ip_list_file  = os.path.join(output_dir, "ip_targets.txt")
    scan_file     = os.path.join(output_dir, "scan_results.json")
    passive_file  = os.path.join(output_dir, "passive_results.json")
    probe_file    = os.path.join(output_dir, "probe_results.json")
    secret_file   = os.path.join(output_dir, "secret_results.json")
    js_file       = os.path.join(output_dir, "js_results.json")
    redirect_file = os.path.join(output_dir, "redirect_results.json")
    s3_file       = os.path.join(output_dir, "s3_results.json")
    analysis_file = os.path.join(output_dir, "analysis_results.json")
    correlate_file = os.path.join(output_dir, "attack_paths.json")
    report_md     = os.path.join(output_dir, "redshadow_report.md")
    report_html   = os.path.join(output_dir, "redshadow_report.html")

    # Write IP list for scan.py
    _write_ip_list(ip_list, ip_list_file)

    cprint(f"\n{'='*60}", "magenta")
    cprint(f"  🛡️  RedShadow V4 — IP Mode Pipeline", "magenta")
    cprint(f"  Targets : {len(ip_list)} IP(s) — {', '.join(ip_list[:5])}"
           f"{'...' if len(ip_list) > 5 else ''}", "white")
    cprint(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "white")
    cprint(f"  Output  : {output_dir}", "white")
    # Read triage recommendation from config
    from modules.utils import load_config as _lc
    _ip_cfg = _lc(section="ip_mode") if True else {}
    triage_recommended = _ip_cfg.get("triage_by_default", True)

    mode_label = "IP (domain stages skipped)"
    if report_format != "all":
        cprint(f"  Format  : {report_format.upper()} only", "cyan")
    if thread_override:
        cprint(f"  Threads : {thread_override} (override)", "cyan")
    if timeout_override:
        cprint(f"  Timeout : {timeout_override}s (override)", "cyan")
    if triage:
        mode_label += " — TRIAGE MODE (redirect+S3 skipped)"
    elif triage_recommended and not triage:
        mode_label += " — FULL MODE"

    cprint(f"  Mode    : {mode_label}", "cyan")
    if triage_recommended and not triage:
        cprint(f"  Tip     : Add --triage for ~70% faster first-pass scan", "yellow")
    if resume:
        cprint(f"  Resume  : ON (checksum-validated cache)", "yellow")
    cprint(f"{'='*60}", "magenta")

    cprint(f"\n  [ℹ] Stages skipped in IP mode: Subdomain Enum, DNS Bruteforce, "
           f"Takeover, Wayback, GitHub", "yellow")

    def _rec(name, record):
        stage_map[name] = record
        eta.record(name, record.elapsed)
        log.stage_end(name, elapsed=record.elapsed, state=record.state, error=record.error)
        if record.state not in (STATE_SKIPPED, STATE_RESUMED):
            cprint(f"  [⏱] {eta.eta_str()}", "cyan")

    # ── Port scope override ──
    # Validate and clean the --ports argument before passing to scan.py
    import re as _re2
    if port_override:
        _clean_ports = ",".join(
            p.strip() for p in port_override.split(",")
            if _re2.match(r"^[0-9]+(-[0-9]+)?$", p.strip())
        )
        if _clean_ports:
            cprint(f"  [→] Port scope: {_clean_ports} (--ports override)", "cyan")
        else:
            cprint("  [!] --ports value invalid — using config.yaml defaults", "yellow")
            _clean_ports = None
    else:
        _clean_ports = None

    # ─────────────────────────────────────
    # Stage 1: Port Scan
    # Nmap already handles both domains and IPs — no changes needed.
    # ip_list_file is a plain text file with one IP per line.
    # ─────────────────────────────────────
    name = "1. Port Scan (Nmap)"
    if stage_already_done(scan_file, resume):
        _rec(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.scan import run_scan
        rec = run_stage(name, run_scan, ip_list_file, scan_file,
                        port_override=_clean_ports)
        if rec.passed():
            mark_stage_done(scan_file)
        _rec(name, rec)

    if not file_has_content(scan_file):
        cprint("  [!] Port scan produced no results — aborting pipeline.", "red")
        for remaining in list(IP_STAGE_WEIGHTS.keys())[1:]:
            stage_map[remaining] = StageRecord(remaining, STATE_SKIPPED)
        _ip_summary(ip_list, stage_map, output_dir, start_time)
        log.run_summary()
        return

    # ─────────────────────────────────────
    # Stage 2: Passive HTTP Recon (IP mode)
    # Not calling passive.py directly — it reads a subdomain text file.
    # Instead we call _build_passive_from_scan() which probes every open
    # web port found by Nmap and writes passive_results.json in the same
    # schema that probe.py, secret.py, etc. expect.
    # ─────────────────────────────────────
    name = "2. Passive HTTP Recon"
    if stage_already_done(passive_file, resume):
        _rec(name, StageRecord(name, STATE_RESUMED))
    else:
        rec = run_stage(name, _build_passive_from_scan, scan_file, passive_file, insecure)
        if rec.passed():
            mark_stage_done(passive_file)
        _rec(name, rec)

    if not file_has_content(passive_file):
        cprint("  [!] No live web ports found — skipping HTTP stages.", "yellow")
        for skip in ["3. HTTP Probing", "4. Secret Scanner",
                     "5. JS Extractor", "6. Open Redirect"]:
            stage_map[skip] = StageRecord(skip, STATE_SKIPPED)
    else:
        # ─────────────────────────────────
        # Stages 3/4/5/6 — Parallel
        # All depend on passive_file but not on each other.
        # Same pattern as domain pipeline stages 5/6/7/9.
        # ─────────────────────────────────
        parallel_group = []

        n3 = "3. HTTP Probing"
        if stage_already_done(probe_file, resume):
            stage_map[n3] = StageRecord(n3, STATE_RESUMED)
        else:
            from modules.probe import run_probes
            parallel_group.append((n3, run_probes, (),
                                   {"input_file": passive_file, "output_file": probe_file,
                                    "insecure": insecure}))

        n4 = "4. Secret Scanner"
        if stage_already_done(secret_file, resume):
            stage_map[n4] = StageRecord(n4, STATE_RESUMED)
        else:
            from modules.secret import scan_secrets
            parallel_group.append((n4, scan_secrets, (passive_file, secret_file), {}))

        n5 = "5. JS Extractor"
        if stage_already_done(js_file, resume):
            stage_map[n5] = StageRecord(n5, STATE_RESUMED)
        else:
            from modules.jsextractor import extract_js_endpoints
            parallel_group.append((n5, extract_js_endpoints, (passive_file, js_file), {}))

        n6 = "6. Open Redirect"
        if triage:
            cprint("  [→] Open redirect skipped (triage mode)", "yellow")
            stage_map[n6] = StageRecord(n6, STATE_SKIPPED)
        elif stage_already_done(redirect_file, resume):
            stage_map[n6] = StageRecord(n6, STATE_RESUMED)
        else:
            from modules.redirect import check_redirects
            parallel_group.append((n6, check_redirects, (passive_file, redirect_file), {}))

        if parallel_group:
            cprint(f"\n{'='*60}", "cyan")
            cprint(f"  [►] Stages 3/4/5/6 running in parallel ({len(parallel_group)} active)...", "cyan")
            cprint(f"{'='*60}", "cyan")
            results = run_stages_parallel(parallel_group, eta_tracker=eta)
            out_map  = {n3: probe_file, n4: secret_file, n5: js_file, n6: redirect_file}
            for rname, rec in results.items():
                stage_map[rname] = rec
                if rec.passed() and rname in out_map:
                    mark_stage_done(out_map[rname])
            cprint(f"  [⏱] {eta.eta_str()}", "cyan")

    # ─────────────────────────────────────
    # Stage 7: S3 Bucket Scanner
    # In IP mode, deriving bucket names from a raw IP produces noisy
    # low-quality guesses. Only run if passive recon found a real hostname
    # hint (e.g. from Host headers or HTML titles in HTTP responses).
    # If no hint exists, skip with a clear message.
    # ─────────────────────────────────────
    name = "7. S3 Bucket Scanner"
    if stage_already_done(s3_file, resume):
        _rec(name, StageRecord(name, STATE_RESUMED))
    else:
        if triage:
            cprint("  [→] S3 scan skipped (triage mode)", "yellow")
            _rec(name, StageRecord(name, STATE_SKIPPED))
        else:
            s3_target = _guess_org_name_from_passive(passive_file) if file_has_content(passive_file) else None
            if not s3_target:
                cprint("  [→] S3 scan skipped — no hostname hint from HTTP responses (raw IP mode)", "yellow")
                cprint("  [→] Tip: run standalone if you know the org name:", "yellow")
                cprint("           python3 main.py s3 --target <orgname>", "yellow")
                _rec(name, StageRecord(name, STATE_SKIPPED))
            else:
                cprint(f"  [→] S3 scan using hostname hint from HTTP responses: {s3_target!r}", "cyan")
                from modules.s3scanner import scan_s3
                rec = run_stage(name, scan_s3, s3_target, s3_file,
                                secret_file=secret_file if file_has_content(secret_file) else None)
                if rec.passed():
                    mark_stage_done(s3_file)
                _rec(name, rec)

    # ─────────────────────────────────────
    # Stage 8: CVE Analysis
    # scan.py already outputs service + version per port — analyse.py
    # reads scan_results.json directly and works identically in IP mode.
    # ─────────────────────────────────────
    name = "8. CVE Analysis"
    if stage_already_done(analysis_file, resume):
        _rec(name, StageRecord(name, STATE_RESUMED))
    elif not file_has_content(scan_file):
        cprint("  [!] No scan results — skipping CVE analysis.", "yellow")
        _rec(name, StageRecord(name, STATE_SKIPPED))
    else:
        try:
            from modules.nvd import clear_expired_cache
            cleared = clear_expired_cache()
            if cleared:
                cprint(f"  [ℹ] Cleared {cleared} expired NVD cache entries", "cyan")
        except Exception:
            pass
        from modules.analyse import analyse_scan_results
        rec = run_stage(name, analyse_scan_results, scan_file, analysis_file,
                        passive_file=passive_file if file_has_content(passive_file) else None,
                        probe_file=probe_file   if file_has_content(probe_file)   else None)
        if rec.passed():
            mark_stage_done(analysis_file)
        _rec(name, rec)

    # ─────────────────────────────────────
    # Stage 9: Correlation Engine
    # Same as domain pipeline — reads whatever stage outputs exist.
    # In IP mode wayback/github/takeover files won't exist — correlate.py
    # handles missing files gracefully (returns [] per missing source).
    # ─────────────────────────────────────
    name = "9. Correlation Engine"
    if stage_already_done(correlate_file, resume):
        _rec(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.correlate import correlate
        rec = run_stage(
            name, correlate,
            correlate_file,
            passive_file=passive_file,
            probe_file=probe_file,
            secret_file=secret_file,
            js_file=js_file,
            wayback_file=None,        # not run in IP mode
            github_file=None,         # not run in IP mode
            redirect_file=redirect_file,
            takeover_file=None,       # not run in IP mode
            s3_file=s3_file,
            scan_file=scan_file,
            analysis_file=analysis_file,
        )
        if rec.passed():
            mark_stage_done(correlate_file)
        _rec(name, rec)

    # ─────────────────────────────────────
    # Stage 10: Report Generation
    # Same report.py — attack_paths_file wired in.
    # ─────────────────────────────────────
    name = "10. Report Generation"
    if stage_already_done([report_html, report_md], resume):
        _rec(name, StageRecord(name, STATE_RESUMED))
    else:
        from modules.report import generate_report
        # Respect --format flag: skip HTML or MD output as requested
        _html_out = report_html if report_format in ("all", "html") else None
        _md_out   = report_md   if report_format in ("all", "md")   else None
        # If only JSON requested, still generate MD as minimum
        if not _md_out:
            _md_out = report_md
        rec = run_stage(
            name, generate_report,
            analysis_file, _md_out,
            html_output=_html_out,
            probe_file=probe_file,
            takeover_file=None,
            redirect_file=redirect_file,
            secret_file=secret_file,
            s3_file=s3_file,
            js_file=js_file,
            wayback_file=None,
            github_file=None,
            attack_paths_file=correlate_file,
        )
        if rec.passed():
            mark_stage_done([report_html, report_md])
        _rec(name, rec)

    _ip_summary(ip_list, stage_map, output_dir, start_time)


# ─────────────────────────────────────────
# Helper: Guess org name from passive results
# Used to seed S3 bucket name guesses in IP mode
# ─────────────────────────────────────────

def _guess_org_name_from_passive(passive_file):
    """
    Try to derive an organisation name from HTTP response data.
    Looks at: Server header, X-Powered-By, HTML title, hostname in URL.
    Returns a simple lowercase string suitable for bucket name guessing,
    or None if nothing useful is found.
    """
    data = _load_json_list(passive_file)
    for entry in data:
        # Try Host header or URL hostname
        from urllib.parse import urlparse
        url = entry.get("url", "")
        try:
            h = urlparse(url).hostname or ""
            # If it's an IP, skip
            if h and not h.replace(".", "").isdigit():
                # Strip port — use first label as org hint
                return h.split(".")[0].lower()
        except Exception:
            pass
        # Try title
        title = entry.get("title", "")
        if title and title != "N/A" and len(title) > 2:
            # Normalise: lowercase, keep alphanumeric only
            import re
            clean = re.sub(r"[^a-z0-9]", "-", title.lower().strip())[:32]
            if clean and clean != "-":
                return clean.strip("-")
    return None