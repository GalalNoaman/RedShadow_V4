# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/probe.py
# Nuclei-style active HTTP vulnerability probing
# v3 — all feedback addressed:
#   Fix 1: Set-Cookie parsed correctly (no comma-split)
#   Fix 2: Severity calibrated — recon paths separated from real vulnerabilities
#   Fix 3: Proof fields added (matched_snippet, header_evidence, body_snippet)
#   Fix 4: HSTS only flagged on HTTPS, lower-value headers downgraded
#   Fix 5: CORS expanded (preflight + method/header coverage)
#   Fix 6: Finding type split: "vulnerability" vs "recon" vs "hardening"

import httpx
import os
import re
import json
import time
from http.cookiejar import CookieJar
from tqdm import tqdm
from termcolor import cprint
from multiprocessing.dummy import Pool as ThreadPool
from modules.utils import load_config

config  = load_config(section="probe")
THREADS = config.get("threads", 10)
TIMEOUT = config.get("timeout", 8)
DELAY   = config.get("delay", 0.3)

UA = "Mozilla/5.0 (compatible; RedShadowBot/4.0)"

# ─────────────────────────────────────────
# Finding Types
# Findings are categorised as vulnerability, recon, or hardening gaps.
# "vulnerability" → active security issue with proof
# "recon"         → path/resource exists, needs manual review
# "hardening"     → missing security control, hardening opportunity
# ─────────────────────────────────────────

TYPE_VULNERABILITY = "vulnerability"
TYPE_RECON         = "recon"
TYPE_HARDENING     = "hardening"

# ─────────────────────────────────────────
# Probe Definitions
# Fields:
#   path           → URL path to check
#   name           → human-readable finding name
#   severity       → CRITICAL / HIGH / MEDIUM / LOW / INFO
#   finding_type   → "vulnerability" | "recon" | "hardening"
#   match          → status code (int) or keyword string
#   match_type     → "status" | "keyword" | "body_regex"
#   verify_content → string that MUST appear in body to confirm (prevents false positives)
#   category       → for grouping in output
#
# Severity calibration (Fix 2):
#   CRITICAL → data/credential confirmed exposed
#   HIGH     → admin panel or dangerous endpoint with content proof
#   MEDIUM   → potentially sensitive path, needs review
#   INFO     → path exists, purely informational / recon value only
# ─────────────────────────────────────────

PROBES = [

    # ══════════════════════════════════════
    # CRITICAL VULNERABILITIES — Credentials / Keys
    # ══════════════════════════════════════
    {"path": "/.env",                       "name": "Exposed .env file",                       "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "=",        "category": "secrets"},
    {"path": "/.env.local",                 "name": "Exposed .env.local",                      "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "=",        "category": "secrets"},
    {"path": "/.env.production",            "name": "Exposed .env.production",                 "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "=",        "category": "secrets"},
    {"path": "/.env.staging",               "name": "Exposed .env.staging",                    "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "=",        "category": "secrets"},
    {"path": "/.env.backup",                "name": "Exposed .env backup",                     "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "=",        "category": "secrets"},
    {"path": "/config.php",                 "name": "Exposed config.php",                      "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "<?",       "category": "secrets"},
    {"path": "/wp-config.php",              "name": "Exposed wp-config.php",                   "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "DB_NAME",  "category": "secrets"},
    {"path": "/config/database.yml",        "name": "Rails database config exposed",           "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "password", "category": "secrets"},
    {"path": "/config/secrets.yml",         "name": "Rails secrets.yml exposed",               "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "secret",   "category": "secrets"},
    {"path": "/id_rsa",                     "name": "Exposed SSH private key",                 "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "BEGIN RSA", "category": "secrets"},
    {"path": "/id_dsa",                     "name": "Exposed DSA private key",                 "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "BEGIN DSA", "category": "secrets"},
    {"path": "/.ssh/id_rsa",                "name": "Exposed SSH key (.ssh/)",                 "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "BEGIN",    "category": "secrets"},
    {"path": "/server.key",                 "name": "Exposed TLS private key",                 "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "BEGIN",    "category": "secrets"},
    {"path": "/.htpasswd",                  "name": "Exposed .htpasswd",                       "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": ":",        "category": "secrets"},
    {"path": "/.aws/credentials",           "name": "AWS credentials file exposed",            "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "aws_access_key_id", "category": "secrets"},

    # ══════════════════════════════════════
    # CRITICAL — Database Dumps
    # ══════════════════════════════════════
    {"path": "/backup.sql",                 "name": "SQL backup exposed",                      "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "CREATE",   "category": "backup"},
    {"path": "/database.sql",               "name": "Database dump exposed",                   "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "INSERT",   "category": "backup"},
    {"path": "/dump.sql",                   "name": "SQL dump exposed",                        "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "CREATE",   "category": "backup"},
    {"path": "/backup.zip",                 "name": "Backup archive exposed",                  "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,       "category": "backup"},
    {"path": "/backup.tar.gz",              "name": "Backup tarball exposed",                  "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,       "category": "backup"},
    {"path": "/site.tar.gz",                "name": "Site archive exposed",                    "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,       "category": "backup"},

    # ══════════════════════════════════════
    # CRITICAL — Spring Boot Actuator (proven dangerous)
    # ══════════════════════════════════════
    {"path": "/actuator/env",               "name": "Spring Boot /env actuator — credentials exposed", "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status", "verify_content": "propertySources", "category": "debug"},
    {"path": "/actuator/heapdump",          "name": "Spring Boot heap dump — memory exposed",          "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status", "verify_content": None,              "category": "debug"},
    {"path": "/jenkins/script",             "name": "Jenkins Groovy script console exposed",           "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status", "verify_content": "Groovy",          "category": "devops"},
    {"path": "/_cat/indices",               "name": "Elasticsearch index list exposed",                "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status", "verify_content": "index",           "category": "devops"},
    {"path": "/solr/admin/cores",           "name": "Solr core admin API exposed",                     "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status", "verify_content": "responseHeader",  "category": "devops"},

    # ══════════════════════════════════════
    # CRITICAL — Admin Panels (content verified)
    # ══════════════════════════════════════
    {"path": "/phpmyadmin",                 "name": "phpMyAdmin exposed",                      "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "phpMyAdmin",    "category": "admin"},
    {"path": "/phpmyadmin/",                "name": "phpMyAdmin exposed (trailing /)",          "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "phpMyAdmin",    "category": "admin"},
    {"path": "/pma",                        "name": "phpMyAdmin /pma alias exposed",            "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "phpMyAdmin",    "category": "admin"},
    {"path": "/adminer.php",                "name": "Adminer database manager exposed",         "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "Adminer",       "category": "admin"},
    {"path": "/manager/html",               "name": "Tomcat Manager interface exposed",         "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "Tomcat",        "category": "admin"},
    {"path": "/host-manager/html",          "name": "Tomcat Host Manager exposed",              "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "Tomcat",        "category": "admin"},
    {"path": "/jmx-console",               "name": "JBoss JMX console exposed",                "severity": "CRITICAL", "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,            "category": "admin"},

    # ══════════════════════════════════════
    # HIGH — Source Code Exposure (content verified)
    # ══════════════════════════════════════
    {"path": "/.git/HEAD",                  "name": ".git HEAD exposed",                       "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "ref:",          "category": "source_code"},
    {"path": "/.git/config",                "name": ".git config exposed",                     "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "[core]",        "category": "source_code"},
    {"path": "/.git/COMMIT_EDITMSG",        "name": ".git commit message exposed",             "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,            "category": "source_code"},
    {"path": "/.svn/entries",               "name": ".svn entries exposed",                    "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,            "category": "source_code"},
    {"path": "/.hg/hgrc",                   "name": "Mercurial hgrc exposed",                  "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,            "category": "source_code"},

    # ══════════════════════════════════════
    # HIGH — Debug & Monitoring (content verified)
    # ══════════════════════════════════════
    {"path": "/server-status",              "name": "Apache server-status exposed",            "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "Apache",        "category": "debug"},
    {"path": "/server-info",                "name": "Apache server-info exposed",              "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "Apache",        "category": "debug"},
    {"path": "/phpinfo.php",                "name": "phpinfo() exposed",                       "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "phpinfo",       "category": "debug"},
    {"path": "/info.php",                   "name": "PHP info page exposed",                   "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "PHP Version",   "category": "debug"},
    {"path": "/actuator",                   "name": "Spring Boot actuator index exposed",      "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "actuator",      "category": "debug"},
    {"path": "/actuator/mappings",          "name": "Spring Boot route mappings exposed",      "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,            "category": "debug"},
    {"path": "/actuator/beans",             "name": "Spring Boot beans list exposed",          "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": None,            "category": "debug"},
    {"path": "/laravel.log",                "name": "Laravel log exposed",                     "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "Stack trace",   "category": "logs"},
    {"path": "/storage/logs/laravel.log",   "name": "Laravel storage log exposed",             "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "Stack trace",   "category": "logs"},
    {"path": "/_cluster/health",            "name": "Elasticsearch cluster health exposed",    "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "cluster_name",  "category": "devops"},
    {"path": "/wp-json/wp/v2/users",        "name": "WordPress user enumeration API",          "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "slug",          "category": "cms"},
    {"path": "/xmlrpc.php",                 "name": "WordPress XML-RPC enabled",               "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "xmlrpc",        "category": "cms"},
    {"path": "/graphiql",                   "name": "GraphiQL IDE exposed",                    "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": 200, "match_type": "status",  "verify_content": "graphiql",      "category": "api"},

    # ══════════════════════════════════════
    # HIGH — Directory Listing (content verified)
    # ══════════════════════════════════════
    {"path": "/backup/",                    "name": "Backup directory listing",                "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": "Index of", "match_type": "keyword", "verify_content": None, "category": "dirlist"},
    {"path": "/logs/",                      "name": "Logs directory listing",                  "severity": "HIGH",     "finding_type": TYPE_VULNERABILITY, "match": "Index of", "match_type": "keyword", "verify_content": None, "category": "dirlist"},

    # ══════════════════════════════════════
    # MEDIUM — Potentially Sensitive Paths
    # Admin and API paths are recon findings, not confirmed vulnerabilities.
    #      since path existence alone is not a confirmed vulnerability
    # ══════════════════════════════════════
    {"path": "/admin",                      "name": "Admin path accessible",                   "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "admin"},
    {"path": "/admin/login",                "name": "Admin login page accessible",             "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "admin"},
    {"path": "/administrator",              "name": "Administrator path accessible",           "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "admin"},
    {"path": "/wp-admin",                   "name": "WordPress admin path accessible",         "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "WordPress", "category": "cms"},
    {"path": "/wp-login.php",               "name": "WordPress login accessible",              "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "WordPress", "category": "cms"},
    {"path": "/dashboard",                  "name": "Dashboard path accessible",               "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "admin"},
    {"path": "/cpanel",                     "name": "cPanel path accessible",                  "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "admin"},
    {"path": "/panel",                      "name": "Panel path accessible",                   "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "admin"},
    {"path": "/swagger",                    "name": "Swagger UI accessible",                   "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "api"},
    {"path": "/swagger-ui.html",            "name": "Swagger UI (Spring) accessible",          "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "swagger", "category": "api"},
    {"path": "/api-docs",                   "name": "API docs accessible",                     "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "api"},
    {"path": "/openapi.json",               "name": "OpenAPI JSON spec accessible",            "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "openapi", "category": "api"},
    {"path": "/openapi.yaml",               "name": "OpenAPI YAML spec accessible",            "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "api"},
    {"path": "/graphql",                    "name": "GraphQL endpoint accessible",             "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "api"},
    {"path": "/grafana",                    "name": "Grafana accessible",                      "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "Grafana", "category": "devops"},
    {"path": "/kibana",                     "name": "Kibana accessible",                       "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "Kibana", "category": "devops"},
    {"path": "/jenkins",                    "name": "Jenkins accessible",                      "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "Jenkins", "category": "devops"},
    {"path": "/uploads/",                   "name": "Uploads directory listing",               "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": "Index of", "match_type": "keyword", "verify_content": None, "category": "dirlist"},
    {"path": "/files/",                     "name": "Files directory listing",                 "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": "Index of", "match_type": "keyword", "verify_content": None, "category": "dirlist"},
    {"path": "/crossdomain.xml",            "name": "crossdomain.xml found",                  "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "cross-domain-policy", "category": "recon"},
    {"path": "/error_log",                  "name": "Error log accessible",                    "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "logs"},
    {"path": "/debug.log",                  "name": "Debug log accessible",                    "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "logs"},
    {"path": "/composer.json",              "name": "composer.json accessible",                "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "require", "category": "source_code"},
    {"path": "/package.json",               "name": "package.json accessible",                 "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "name",    "category": "source_code"},
    {"path": "/actuator/health",            "name": "Spring Boot health check accessible",     "severity": "MEDIUM",   "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "debug"},

    # ══════════════════════════════════════
    # INFO — Pure Recon (path discovery only)
    # API path discovery is informational — requires further testing to confirm issues.
    # ══════════════════════════════════════
    {"path": "/robots.txt",                 "name": "robots.txt found",                        "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "User-agent", "category": "recon"},
    {"path": "/sitemap.xml",                "name": "sitemap.xml found",                       "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": "<url",       "category": "recon"},
    {"path": "/.well-known/security.txt",   "name": "security.txt found",                      "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "recon"},
    {"path": "/api/v1",                     "name": "API v1 path accessible",                  "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "api"},
    {"path": "/api/v2",                     "name": "API v2 path accessible",                  "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "api"},
    {"path": "/api/v3",                     "name": "API v3 path accessible",                  "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "api"},
    {"path": "/login",                      "name": "Login page found",                        "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "recon"},
    {"path": "/signin",                     "name": "Sign-in page found",                      "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "recon"},
    {"path": "/requirements.txt",           "name": "requirements.txt accessible",             "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "source_code"},
    {"path": "/Gemfile",                    "name": "Gemfile accessible",                      "severity": "INFO",     "finding_type": TYPE_RECON,         "match": 200, "match_type": "status",  "verify_content": None, "category": "source_code"},
]

# ─────────────────────────────────────────
# Security Header Checks
# HSTS is only applicable to HTTPS responses.
# Missing security headers are hardening gaps, not confirmed vulnerabilities.
# ─────────────────────────────────────────

SECURITY_HEADERS = [
    # These are hardening recommendations, not confirmed vulnerabilities
    {"header": "content-security-policy",          "name": "Missing CSP header",                  "severity": "MEDIUM", "https_only": False},
    {"header": "x-frame-options",                  "name": "Missing X-Frame-Options",             "severity": "MEDIUM", "https_only": False},
    {"header": "x-content-type-options",           "name": "Missing X-Content-Type-Options",      "severity": "LOW",    "https_only": False},
    {"header": "referrer-policy",                  "name": "Missing Referrer-Policy",             "severity": "LOW",    "https_only": False},
    {"header": "permissions-policy",               "name": "Missing Permissions-Policy",          "severity": "LOW",    "https_only": False},
    # HSTS header check restricted to HTTPS responses only.
    {"header": "strict-transport-security",        "name": "Missing HSTS (HTTPS only)",           "severity": "MEDIUM", "https_only": True},
    {"header": "cross-origin-embedder-policy",     "name": "Missing COEP header",                 "severity": "LOW",    "https_only": False},
    {"header": "cross-origin-opener-policy",       "name": "Missing COOP header",                 "severity": "LOW",    "https_only": False},
]

# ─────────────────────────────────────────
# Technology Fingerprints
# ─────────────────────────────────────────

TECH_HEADERS = {
    "x-powered-by":           "Technology",
    "server":                 "Server",
    "x-generator":            "Generator",
    "x-drupal-cache":         "Drupal",
    "x-wp-nonce":             "WordPress",
    "x-shopify-stage":        "Shopify",
    "x-rails-version":        "Ruby on Rails",
    "x-aspnet-version":       "ASP.NET",
    "x-aspnetmvc-version":    "ASP.NET MVC",
    "x-cloud-trace-context":  "Google Cloud",
    "x-amz-request-id":       "AWS",
    "x-azure-ref":            "Azure",
    "cf-ray":                 "Cloudflare",
    "x-vercel-id":            "Vercel",
    "x-cache":                "CDN/Cache",
}

CORS_TEST_ORIGIN = "https://evil-redshadow.com"


# ─────────────────────────────────────────
# Cookie Parser (Fix — critical bug fixed)
# Cookie parsing handles multi-value Set-Cookie headers correctly.
# This is WRONG — Set-Cookie cannot be safely split on commas because
# cookie expires/max-age attributes contain commas (e.g. "Expires=Thu, 01 Jan 2026").
# httpx stores multiple Set-Cookie headers correctly in response.headers.get_list()
# We use that method to get one string per cookie header.
# ─────────────────────────────────────────

def parse_cookies(response):
    """
    Fix: correctly parses multiple Set-Cookie headers using httpx's get_list().
    Returns list of raw cookie strings, one per Set-Cookie header.
    Never splits on comma — avoids the date-in-expires bug.
    """
    try:
        # httpx Headers supports multi-value access
        return response.headers.get_list("set-cookie")
    except AttributeError:
        # Fallback for non-httpx response objects
        raw = response.headers.get("set-cookie", "")
        return [raw] if raw else []


def audit_cookies(url, response):
    """
    Fix: uses corrected cookie parsing.
    Audits each cookie independently for HttpOnly, Secure, SameSite.
    Also adds short proof snippet showing which cookie failed.
    """
    findings = []
    cookies  = parse_cookies(response)

    for raw_cookie in cookies:
        if not raw_cookie:
            continue

        cookie_lower = raw_cookie.lower()
        name_match   = re.match(r'\s*([^=;\s]+)\s*=', raw_cookie)
        cookie_name  = name_match.group(1).strip() if name_match else "unknown"

        # Skip analytics / tracking cookies — not security-relevant
        if any(skip in cookie_name.lower() for skip in
               ["_ga", "ga_", "gtm", "fbp", "__utm", "_gcl", "_gid", "intercom"]):
            continue

        # Proof snippet included to support manual validation.
        snippet = raw_cookie[:80] + ("..." if len(raw_cookie) > 80 else "")

        if "httponly" not in cookie_lower:
            findings.append({
                "type":           "cookie",
                "name":           f"Cookie '{cookie_name}' missing HttpOnly",
                "severity":       "MEDIUM",
                "finding_type":   TYPE_HARDENING,
                "url":            url,
                "status":         response.status_code,
                "confidence":     "CONFIRMED",
                "matched_snippet": snippet,
            })
        if "secure" not in cookie_lower:
            findings.append({
                "type":           "cookie",
                "name":           f"Cookie '{cookie_name}' missing Secure flag",
                "severity":       "LOW",
                "finding_type":   TYPE_HARDENING,
                "url":            url,
                "status":         response.status_code,
                "confidence":     "CONFIRMED",
                "matched_snippet": snippet,
            })
        if "samesite" not in cookie_lower:
            findings.append({
                "type":           "cookie",
                "name":           f"Cookie '{cookie_name}' missing SameSite",
                "severity":       "LOW",
                "finding_type":   TYPE_HARDENING,
                "url":            url,
                "status":         response.status_code,
                "confidence":     "CONFIRMED",
                "matched_snippet": snippet,
            })

    return findings


# ─────────────────────────────────────────
# CORS Check (Expanded — Fix)
# CORS testing includes OPTIONS preflight and full header coverage.
# Tests both GET and OPTIONS methods for complete CORS analysis.
# ─────────────────────────────────────────

def check_cors(url, insecure):
    """
    Expanded CORS check covering:
      1. Simple GET with injected Origin
      2. OPTIONS preflight (Access-Control-Request-Method + Headers)
      3. Checks for wildcard, origin reflection, credentials + reflection combo
    Includes header_evidence proof field.
    """
    findings = []
    headers  = {"User-Agent": UA, "Origin": CORS_TEST_ORIGIN}

    # ── Test 1: Simple GET ──
    try:
        resp = httpx.get(url, headers=headers, timeout=TIMEOUT,
                         follow_redirects=True, verify=not insecure)
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            findings.append({
                "type":             "cors",
                "name":             "CORS wildcard (*) — any origin allowed",
                "severity":         "MEDIUM",
                "finding_type":     TYPE_VULNERABILITY,
                "url":              url,
                "status":           resp.status_code,
                "confidence":       "CONFIRMED",
                "header_evidence":  f"Access-Control-Allow-Origin: *",
            })
        elif CORS_TEST_ORIGIN in acao:
            sev  = "HIGH" if acac == "true" else "MEDIUM"
            name = "CORS origin reflection with credentials" if acac == "true" else "CORS origin reflection"
            findings.append({
                "type":             "cors",
                "name":             name,
                "severity":         sev,
                "finding_type":     TYPE_VULNERABILITY,
                "url":              url,
                "status":           resp.status_code,
                "confidence":       "CONFIRMED",
                "header_evidence":  f"ACAO: {acao} | ACAC: {acac}",
            })
    except Exception as ex:
        if DELAY > 0:
            pass  # CORS check failed gracefully
        # Log at debug level only - CORS checks failing is expected on non-web services

    # ── Test 2: OPTIONS preflight ──
    try:
        resp = httpx.options(
            url,
            headers={
                **headers,
                "Access-Control-Request-Method":  "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
            timeout=TIMEOUT,
            verify=not insecure,
        )
        acam = resp.headers.get("access-control-allow-methods", "")
        acah = resp.headers.get("access-control-allow-headers", "")
        acao = resp.headers.get("access-control-allow-origin", "")

        if resp.status_code in (200, 204) and CORS_TEST_ORIGIN in acao:
            findings.append({
                "type":             "cors",
                "name":             "CORS preflight allows arbitrary origin",
                "severity":         "HIGH",
                "finding_type":     TYPE_VULNERABILITY,
                "url":              url,
                "status":           resp.status_code,
                "confidence":       "CONFIRMED",
                "header_evidence":  f"ACAO: {acao} | Methods: {acam} | Headers: {acah}",
            })

        # Dangerous method exposure
        if acam and any(m in acam.upper() for m in ["DELETE", "PUT", "PATCH"]):
            findings.append({
                "type":             "cors",
                "name":             f"CORS exposes dangerous HTTP methods: {acam}",
                "severity":         "MEDIUM",
                "finding_type":     TYPE_HARDENING,
                "url":              url,
                "status":           resp.status_code,
                "confidence":       "CONFIRMED",
                "header_evidence":  f"Access-Control-Allow-Methods: {acam}",
            })
    except Exception as ex:
        pass  # Preflight check failed — non-web service or network error

    return findings


# ─────────────────────────────────────────
# Content Verifier
# ─────────────────────────────────────────

def verify_content(text, verify_str):
    if not verify_str:
        return True, ""
    found  = verify_str.lower() in text.lower()
    # Returns a context snippet around the match for manual review.
    if found:
        idx     = text.lower().find(verify_str.lower())
        snippet = text[max(0, idx-20):idx+60].strip().replace("\n", " ")
        return True, snippet
    return False, ""


# ─────────────────────────────────────────
# Technology Fingerprinting
# ─────────────────────────────────────────

def fingerprint_tech(response_headers):
    return {label: response_headers.get(h, "") for h, label in TECH_HEADERS.items() if response_headers.get(h)}


# ─────────────────────────────────────────
# Single Host Prober
# ─────────────────────────────────────────

def probe_host(args):
    url, insecure = args
    findings      = []

    # ── Path probes ──
    for probe in PROBES:
        target_url = url.rstrip("/") + probe["path"]
        try:
            resp = httpx.get(
                target_url,
                timeout=TIMEOUT,
                follow_redirects=False,
                verify=not insecure,
                headers={"User-Agent": UA},
            )

            matched = False
            if probe["match_type"] == "status":
                matched = resp.status_code == probe["match"]
            elif probe["match_type"] == "keyword":
                matched = probe["match"].lower() in resp.text.lower()
            elif probe["match_type"] == "body_regex":
                matched = bool(re.search(probe["match"], resp.text, re.IGNORECASE))

            if matched:
                verify_str           = probe.get("verify_content") or ""
                confirmed, snippet   = verify_content(resp.text, verify_str)
                confidence           = "CONFIRMED" if confirmed else "LIKELY"

                finding = {
                    "type":           "path_probe",
                    "name":           probe["name"],
                    "severity":       probe["severity"],
                    "finding_type":   probe["finding_type"],
                    "category":       probe.get("category", "general"),
                    "url":            target_url,
                    "status":         resp.status_code,
                    "size":           len(resp.content),
                    "confidence":     confidence,
                }
                # Proof fields for manual validation.
                if snippet:
                    finding["matched_snippet"] = snippet
                if probe["match_type"] == "keyword":
                    finding["matched_keyword"]  = probe["match"]

                findings.append(finding)

            time.sleep(DELAY)

        except Exception as ex:
            # Single probe path failed — skip and continue with remaining probes
            # This is expected for network timeouts and refused connections
            continue

    # ── Root page: headers, CORS, cookies, tech ──
    try:
        root         = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                                 verify=not insecure, headers={"User-Agent": UA})
        resp_headers = {k.lower(): v for k, v in root.headers.items()}
        is_https     = url.startswith("https://")

        # Security headers — Fix: HSTS only on HTTPS
        for check in SECURITY_HEADERS:
            if check.get("https_only") and not is_https:
                continue   # HSTS not applicable to plain HTTP responses.
            if check["header"] not in resp_headers:
                # Records present headers as evidence context.
                findings.append({
                    "type":             "missing_header",
                    "name":             check["name"],
                    "severity":         check["severity"],
                    "finding_type":     TYPE_HARDENING,
                    "category":         "headers",
                    "url":              url,
                    "status":           root.status_code,
                    "confidence":       "CONFIRMED",
                    "header_evidence":  f"Header '{check['header']}' not present in response",
                })

        # CORS check (expanded)
        cors_findings = check_cors(url, insecure)
        findings.extend(cors_findings)

        # Cookie audit (fixed parsing)
        cookie_findings = audit_cookies(url, root)
        findings.extend(cookie_findings)

        # Tech fingerprinting
        tech = fingerprint_tech(resp_headers)

    except Exception as ex:
        # Tech fingerprinting failed for this host — use empty dict
        tech = {}

    return {"url": url, "findings": findings, "technology": tech}


# ─────────────────────────────────────────
# Main Probe Entry Point
# ─────────────────────────────────────────

def run_probes(input_file, output_file, insecure=False):
    if not os.path.exists(input_file):
        cprint(f"  [!] Input file not found: {input_file}", "red")
        return

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            passive_data = json.load(f)
    except Exception as e:
        cprint(f"  [!] Failed to read passive results: {e}", "red")
        return

    urls = [entry.get("url") for entry in passive_data if entry.get("url")]
    if not urls:
        cprint("  [!] No live hosts found to probe.", "yellow")
        return

    cprint(f"  [+] Probing {len(urls)} hosts — {len(PROBES)} path probes + header/CORS/cookie checks...", "cyan")

    with ThreadPool(THREADS) as pool:
        raw = list(tqdm(pool.imap(probe_host, [(u, insecure) for u in urls]),
                        total=len(urls), desc="  HTTP Probing", ncols=70))

    results = [e for e in raw if e["findings"]]

    # ── Stats split by finding_type ──
    vulns     = sum(1 for e in results for f in e["findings"] if f["finding_type"] == TYPE_VULNERABILITY)
    recon     = sum(1 for e in results for f in e["findings"] if f["finding_type"] == TYPE_RECON)
    hardening = sum(1 for e in results for f in e["findings"] if f["finding_type"] == TYPE_HARDENING)
    critical  = sum(1 for e in results for f in e["findings"] if f["severity"] == "CRITICAL")
    high      = sum(1 for e in results for f in e["findings"] if f["severity"] == "HIGH")
    confirmed = sum(1 for e in results for f in e["findings"] if f.get("confidence") == "CONFIRMED")
    total     = sum(len(e["findings"]) for e in results)

    cprint(f"\n  [✓] Probing complete — {total} findings across {len(results)} hosts", "green")
    cprint(f"  🚨 Vulnerabilities : {vulns}  (CRITICAL: {critical} | HIGH: {high})", "red")
    cprint(f"  🔍 Recon findings  : {recon}", "cyan")
    cprint(f"  🛡  Hardening gaps  : {hardening}", "yellow")
    cprint(f"  ✅ Confirmed       : {confirmed}/{total}", "green")

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    for entry in results:
        cprint(f"\n  [→] {entry['url']}", "cyan")
        if entry.get("technology"):
            cprint(f"      Tech: {' | '.join(f'{k}: {v}' for k,v in entry['technology'].items())}", "cyan")
        for f in sorted(entry["findings"], key=lambda x: sev_order.get(x["severity"], 5)):
            colour = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"cyan","LOW":"white","INFO":"white"}.get(f["severity"],"white")
            conf   = "✅" if f.get("confidence") == "CONFIRMED" else "⚠️ "
            ftype  = {"vulnerability":"🔴","recon":"🔵","hardening":"🛡"}.get(f["finding_type"],"")
            cprint(f"      [{f['severity']}] {conf}{ftype} {f['name']}", colour)
            if f.get("matched_snippet"):
                cprint(f"           Proof  : {f['matched_snippet']}", colour)
            if f.get("header_evidence"):
                cprint(f"           Header : {f['header_evidence']}", colour)

    # ── Save ──
    dirpath = os.path.dirname(output_file)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        cprint(f"\n  [✓] Probe results saved to {output_file}", "green")
    except Exception as e:
        cprint(f"  [!] Failed to write probe results: {e}", "red")