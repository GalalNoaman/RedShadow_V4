# 🛡️ RedShadow V4 — Red Team Reconnaissance Framework

**RedShadow V4** is a professional-grade red team automation framework for passive and active reconnaissance, secret discovery, CVE analysis, and report generation. Built for bug bounty hunters and penetration testers, it runs a full 14-stage recon pipeline from a single command — or each stage individually.

> ⚠️ For educational and lawful use only. Always obtain explicit written authorisation before scanning any target. See `LICENSE.txt` for full terms.

---

## 🚀 What's New in V4

Every module has been rewritten from scratch with major capability upgrades:

| Area | What changed |
|---|---|
| **DNS Bruteforce** | Deep wildcard detection, IPv6 fallback, thread-local resolvers, real retry logic, rich JSON output with CNAME targets |
| **Probe** | 100+ probes across 9 categories, content verification, CORS preflight testing, cookie security audit, confidence scoring, proof fields |
| **Secret Scanner** | Shannon entropy checking, 30+ patterns, word-boundary false positive filtering, per-finding confidence |
| **S3 Scanner** | GCP + Azure bucket support, regional S3 endpoints, opt-in write test |
| **JS Extractor** | Source map scanning, inline script scanning, GraphQL introspection detection, subdomain leakage, parameter extraction |
| **CVE Analysis** | Version-aware filtering, EPSS enrichment, attack surface tagging (RCE/SQLi/SSRF etc.), risk scoring per target |
| **NVD Lookup** | Multi-strategy search (CPE → keyword+version → keyword), 40+ CPE mappings, version-aware cache, richer output |
| **GitHub Scanner** | 30 queries, retry on rate limit, GCP/Azure patterns, progress counter |
| **Wayback** | 5-source URL collection, IDOR detection, tech fingerprinting, secret scanning in responses |
| **Takeover** | 40 services, multi-fingerprint per service, NXDOMAIN detection, CONFIRMED/LIKELY/POTENTIAL confidence |
| **Pipeline** | Resume support (checksum-validated), parallel stages, per-stage weighted ETA, findings-aware summary |
| **Report** | HTML injection fix, EPSS column, attack surface badges, CORS/GraphQL/leaked subdomain sections, risk-sorted CVE table |

---

## 📦 Full Feature List

**Reconnaissance**
- Subdomain enumeration via `crt.sh` (certificate transparency)
- DNS bruteforce with deep wildcard detection and company-name permutations
- Passive HTTP recon — headers, title, tech stack, IP resolution
- Wayback Machine scanning — 5 sources, secret detection in responses, IDOR tagging

**Vulnerability Detection**
- 100+ active HTTP probes — exposed files, admin panels, Spring Boot actuators, debug endpoints
- CORS misconfiguration detection (GET + OPTIONS preflight)
- Cookie security audit (HttpOnly, Secure, SameSite)
- Open redirect detection — header-based and meta refresh
- Subdomain takeover detection — 40 services, content-verified
- S3/GCS/Azure bucket discovery and misconfiguration detection
- GraphQL introspection detection
- Source map and inline script endpoint extraction

**Secret Discovery**
- JavaScript and HTML secret scanning — AWS keys, GitHub tokens, Stripe, database URLs, JWTs, and 30+ more
- GitHub public repository secret scanning — 30 targeted queries
- Shannon entropy validation — filters placeholder values, keeps real secrets

**CVE & Risk Analysis**
- Nmap port scanning with service/version detection
- NVD API v2 lookup with CPE-based precision search
- EPSS exploitation probability enrichment
- Attack surface tagging — RCE, Auth Bypass, SQLi, SSRF, XXE, Path Traversal, and more
- Version-aware CVE filtering — only CVEs affecting the detected version
- Composite risk scoring per target (CVSS × EPSS weighted)

**Reporting**
- Dark-themed HTML report with 16 summary stat boxes
- Risk-sorted CVE table with EPSS column, attack surface badges, CWE IDs
- Separate probe sections for vulnerabilities, recon findings, and hardening gaps
- Confidence badges on every finding (CONFIRMED / LIKELY / POTENTIAL)

---

## 🛠️ Requirements

```bash
sudo apt update
sudo apt install nmap python3-venv -y
```

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Or use the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

**Optional API keys** (add to `.env` for best results):

```env
NVD_API_KEY=your_key_here       # https://nvd.nist.gov/developers/request-an-api-key
GITHUB_TOKEN=your_token_here    # https://github.com/settings/tokens (no scopes needed)
```

---

## 🚀 Usage

### ⚡ Auto Mode — Full 14-Stage Pipeline

```bash
sudo venv/bin/python3 main.py auto --target hackerone.com
```

**All flags:**

```bash
--output-dir  custom_folder          # Output directory (default: outputs/)
--wordlist    /path/to/wordlist.txt  # Custom DNS wordlist
--no-bruteforce                      # Skip DNS bruteforce
--insecure                           # Disable TLS verification
--verbose                            # Show detailed error output
--resume                             # Resume from last completed stage
```

> `sudo` is required for Nmap SYN scanning (`-sS`). Without sudo, set `nmap_args: "-sT"` in `config.yaml`.

**Resume a crashed scan:**
```bash
sudo venv/bin/python3 main.py auto --target hackerone.com --resume
```

---

### 🔧 Manual Mode — Run Any Stage Individually

```bash
# Subdomain enumeration
python3 main.py domain --target hackerone.com

# DNS bruteforce
python3 main.py bruteforce --target hackerone.com --wordlist /path/to/list.txt

# Passive recon
python3 main.py passive --input outputs/subdomains.txt

# HTTP probing (100+ checks)
python3 main.py probe --input outputs/passive_results.json

# Subdomain takeover (40 services)
python3 main.py takeover --input outputs/subdomains.txt

# Secret scanner
python3 main.py secret --input outputs/passive_results.json

# S3/GCS/Azure bucket scanner
python3 main.py s3 --target hackerone.com

# JavaScript endpoint extractor
python3 main.py js --input outputs/passive_results.json

# Wayback Machine scanner
python3 main.py wayback --target hackerone.com

# GitHub secret scanner
python3 main.py github --target hackerone.com

# Open redirect detection
python3 main.py redirect --input outputs/passive_results.json

# Port scan (Nmap)
sudo venv/bin/python3 main.py scan --input outputs/subdomains.txt

# CVE analysis with EPSS enrichment
python3 main.py analyse --input outputs/scan_results.json

# Generate full report
python3 main.py report --input outputs/analysis_results.json --html outputs/report.html

# NVD cache management
python3 main.py cache --stats
python3 main.py cache --clear
python3 main.py cache --purge
```

---

## 🗺️ Pipeline Stages

| # | Stage | Depends On | Parallel |
|---|---|---|---|
| 1 | Subdomain Enumeration (crt.sh) | — | — |
| 2 | DNS Bruteforce | — | — |
| 3 | Subdomain Takeover Check | subdomains.txt | — |
| 4 | Passive Recon | subdomains.txt | — |
| 5 | HTTP Probing | passive_results.json | ✅ with 6/7/9 |
| 6 | Open Redirect Detection | passive_results.json | ✅ with 5/7/9 |
| 7 | Secret Scanner | passive_results.json | ✅ with 5/6/9 |
| 8 | S3 Bucket Scanner | target only | ✅ with 10/11 |
| 9 | JS Endpoint Extractor | passive_results.json | ✅ with 5/6/7 |
| 10 | Wayback Machine Scanner | target only | ✅ with 8/11 |
| 11 | GitHub Secret Scanner | target only | ✅ with 8/10 |
| 12 | Port Scan (Nmap) | subdomains.txt | — |
| 13 | CVE Analysis | scan_results.json | — |
| 14 | Report Generation | all outputs | — |

Stages marked ✅ run in parallel threads, saving significant scan time.

---

## 📁 Project Structure

```
RedShadow_V4/
├── .gitignore
├── LICENSE.txt
├── README.md
├── SECURITY.md
├── config.yaml
├── main.py
├── requirements.txt
├── setup.sh
├── data/
│   ├── cve_map.json          ← local CVE fallback map
│   └── nvd_cache/            ← auto-generated NVD response cache
├── modules/
│   ├── __init__.py
│   ├── analyse.py            ← CVE analysis + EPSS + risk scoring
│   ├── bruteforce.py         ← DNS bruteforce with wildcard detection
│   ├── domain.py             ← crt.sh subdomain enumeration
│   ├── githubscan.py         ← GitHub secret scanner
│   ├── jsextractor.py        ← JS endpoint + source map extractor
│   ├── nvd.py                ← NVD API v2 with CPE-based lookup
│   ├── passive.py            ← Passive HTTP recon
│   ├── pipeline.py           ← 14-stage orchestrator with resume
│   ├── probe.py              ← 100+ active HTTP probes
│   ├── redirect.py           ← Open redirect detection
│   ├── report.py             ← HTML + Markdown report generator
│   ├── s3scanner.py          ← S3/GCS/Azure bucket scanner
│   ├── scan.py               ← Nmap port scanner
│   ├── secret.py             ← Secret + credential scanner
│   ├── takeover.py           ← Subdomain takeover detection
│   ├── utils.py              ← Thread-safe config loader
│   └── wayback.py            ← Wayback Machine scanner
└── outputs/                  ← all scan results written here
```

---

## ⚙️ Configuration

All settings live in `config.yaml`. Key options:

```yaml
s3scanner:
  enable_write_check: false   # set true ONLY in a lab — writes a test file to verify bucket write access

githubscan:
  token: ""                   # GitHub token for higher rate limits (10 → 50 req/min)

pipeline:
  resume: false               # set true to always resume interrupted scans
  skip_bruteforce: false
```

Add API keys to `.env`:
```env
NVD_API_KEY=...
GITHUB_TOKEN=...
```

---

## 📋 Output Files

| File | Contents |
|---|---|
| `subdomains.txt` | Discovered subdomains (one per line) |
| `subdomains_dns.json` | Rich DNS data — IP, record type, CNAME targets |
| `passive_results.json` | HTTP status, title, tech stack per subdomain |
| `probe_results.json` | Active probe findings with confidence and proof |
| `takeover_results.json` | Takeover candidates with CONFIRMED/LIKELY/POTENTIAL |
| `secret_results.json` | Exposed credentials with entropy scores |
| `s3_results.json` | Public/private cloud buckets (AWS/GCP/Azure) |
| `js_results.json` | Endpoints, GraphQL introspection, leaked subdomains |
| `wayback_results.json` | Live archived URLs, secrets found in responses |
| `github_results.json` | Leaked credentials in public repositories |
| `redirect_results.json` | Confirmed open redirects |
| `scan_results.json` | Nmap port scan results with service versions |
| `analysis_results.json` | CVEs with EPSS, attack surface, risk scores |
| `redshadow_report.md` | Markdown report |
| `redshadow_report.html` | Dark-themed HTML report — open in any browser |

---

## 📌 License

Copyright © 2026 Galal Noaman. All rights reserved.

For educational and non-commercial use only. Not permitted for commercial use, redistribution, or use against systems without explicit authorisation. See `LICENSE.txt` for full terms.

Contact: Jalalnoaman@gmail.com | GitHub: github.com/GalalNoaman/RedShadow_V4