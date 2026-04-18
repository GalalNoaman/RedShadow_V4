# 🛡️ RedShadow V4 — Red Team Reconnaissance Framework

**RedShadow V4** is a professional red team reconnaissance framework built in Python. It runs a full multi-stage recon pipeline from a single command — covering port scanning, passive HTTP recon, secret detection, cloud storage analysis, CVE correlation, and automated report generation.

> ⚠️ For educational and lawful use only. Always obtain explicit written authorisation before scanning any target. See `LICENSE.txt` for full terms.

---

## 🚀 Key Features

**Two pipeline modes:**
- **Domain mode** — 15-stage pipeline from subdomain enumeration through to CVE analysis and report
- **IP mode** — 10-stage pipeline for raw IPs and CIDR ranges with no domain dependency

**Reconnaissance**
- Subdomain enumeration via certificate transparency (crt.sh)
- DNS bruteforce with deep wildcard detection and permutation generation
- Passive HTTP recon — headers, title, tech stack, IP resolution
- Wayback Machine scanning with secret detection in archived responses

**Vulnerability Detection**
- 100+ active HTTP probes — exposed files, admin panels, debug endpoints, actuators
- CORS misconfiguration detection (GET + OPTIONS preflight)
- Cookie security audit (HttpOnly, Secure, SameSite)
- Open redirect detection
- Subdomain takeover detection across 40 services
- S3, GCS, and Azure blob container discovery and misconfiguration detection
- GraphQL introspection detection

**Secret Discovery**
- JavaScript and HTML secret scanning — AWS keys, GitHub tokens, Stripe, JWTs, database URLs, and 30+ patterns
- Shannon entropy validation to filter placeholder values
- GitHub public repository secret scanning with 30 targeted queries

**CVE and Risk Analysis**
- Nmap port scanning with service and version detection
- NVD API v2 lookup with CPE-based precision search and multi-strategy fallback
- EPSS exploitation probability enrichment per CVE
- HTTP fingerprint enrichment — Server headers and response bodies feed version detection
- Version-aware CVE filtering with CONFIRMED / POSSIBLY AFFECTED / UNLIKELY classification
- Context flags for agent-forwarding-only CVEs and non-default component requirements
- Backport risk warnings for Ubuntu/Debian/RHEL packages
- Composite risk scoring per target

**Correlation Engine**
- 13 detection rules across 4 tiers — from confirmed secrets to recon leads
- 5 chain patterns for multi-stage attack path detection
- Type-specific narratives explaining how signals connect
- Ranked leads with confidence levels (HIGH / MEDIUM / LOW)

**Reporting**
- Dark-themed HTML report with executive summary and ranked priority actions
- Version-matched CVE table with EPSS, version relevance badges, and context flags
- Correlated leads with narratives and collapsible validation checklists
- Hardening gaps in collapsed section — vulnerabilities surface first
- Markdown report generated alongside HTML

**Engineering**
- 58 unit tests across 4 test files
- Deep JSON schema validation for all stage outputs
- Structured per-run logging to `outputs/logs/`
- Run quality score (0-100) across 5 dimensions
- Resume support with checksum validation
- Parallel stage execution with weighted ETA

---

## 🛠️ Installation

```bash
sudo apt update && sudo apt install nmap -y
pip install -r requirements.txt --break-system-packages
```

Or use the setup script:

```bash
chmod +x setup.sh && ./setup.sh
```

**API keys** — add to `.env` in the project root:

```env
NVD_API_KEY=your_key_here       # https://nvd.nist.gov/developers/request-an-api-key
GITHUB_TOKEN=your_token_here    # https://github.com/settings/tokens
```

Without an NVD key: 5 requests per 30 seconds. With one: 50 requests per 30 seconds.

---

## 🚀 Usage

### IP Mode

```bash
# Triage scan — skips redirect and S3 (~70% faster, recommended first pass)
sudo python3 main.py scan-ips --ips 192.168.1.1 --triage

# Deep scan — all stages
sudo python3 main.py scan-ips --ips 192.168.1.1 --deep

# Multiple IPs
sudo python3 main.py scan-ips --ips 10.0.0.1,10.0.0.2,10.0.0.3 --triage

# Specific ports only (stay within authorised scope)
sudo python3 main.py scan-ips --ips 10.0.0.1 --deep --ports 443,8080,8443

# CIDR range
sudo python3 main.py scan-ips --ips 10.0.0.0/24 --triage

# From a targets file
sudo python3 main.py scan-ips --targets targets.txt --deep

# Custom output directory
sudo python3 main.py scan-ips --ips 10.0.0.1 --triage --output-dir outputs/my_scan
```

### Domain Mode

```bash
# Full 15-stage pipeline
sudo python3 main.py auto --target example.com

# Resume an interrupted scan
sudo python3 main.py auto --target example.com --resume

# Skip DNS bruteforce
sudo python3 main.py auto --target example.com --no-bruteforce
```

### IP Mode Flags

| Flag | Description |
|---|---|
| `--triage` / `--fast` | Skip redirect and S3 scanning (~70% faster) |
| `--deep` | Run all stages including redirect and S3 |
| `--ports` | Comma-separated port list — overrides config.yaml |
| `--output-dir` | Custom output directory |
| `--debug` | Enable verbose debug logging |
| `--quiet` | Suppress non-essential output |
| `--resume` | Resume from last completed stage |
| `--format` | Output format: `all`, `html`, `md`, `json` |
| `--threads` | Override thread count for scanning stages |
| `--timeout` | Override HTTP timeout in seconds |

### Run Tests

```bash
python3 -m pytest tests/ -v
```

---

## 🗺️ Pipeline Stages

### IP Mode (10 stages)

| # | Stage | Notes |
|---|---|---|
| 1 | Port Scan (Nmap) | Scans specified ports with service detection |
| 2 | Passive HTTP Recon | Probes all open ports for HTTP/HTTPS services |
| 3 | HTTP Probing | 100+ path probes, CORS, cookie audit |
| 4 | Secret Scanner | Scans HTTP responses for credentials |
| 5 | JS Extractor | Endpoint and subdomain extraction from JS |
| 6 | Open Redirect | Skipped in `--triage` mode |
| 7 | S3 Bucket Scanner | Skipped in `--triage` mode |
| 8 | CVE Analysis | NVD lookup with HTTP fingerprint enrichment |
| 9 | Correlation Engine | 13 rules, 5 chain patterns, ranked leads |
| 10 | Report Generation | HTML + Markdown with executive summary |

### Domain Mode (15 stages)

| # | Stage |
|---|---|
| 1 | Subdomain Enumeration (crt.sh) |
| 2 | DNS Bruteforce |
| 3 | Subdomain Takeover Check |
| 4 | Passive HTTP Recon |
| 5–9 | HTTP Probing, Redirect, Secrets, S3, JS (parallel) |
| 10 | Wayback Machine Scanner |
| 11 | GitHub Secret Scanner |
| 12 | Port Scan (Nmap) |
| 13 | CVE Analysis |
| 14 | Correlation Engine |
| 15 | Report Generation |

---

## 📁 Project Structure

```
RedShadow_V4/
├── main.py                   ← Entry point and CLI
├── config.yaml               ← All settings
├── .env                      ← API keys (never committed)
├── requirements.txt
├── setup.sh
├── data/
│   ├── cve_map.json          ← Local CVE fallback map (64 products, 113 CVEs)
│   └── nvd_cache/            ← Auto-generated NVD response cache
├── modules/
│   ├── analyse.py            ← CVE analysis, EPSS enrichment, risk scoring
│   ├── bruteforce.py         ← DNS bruteforce with wildcard detection
│   ├── correlate.py          ← Correlation engine — 13 rules, 5 chain patterns
│   ├── domain.py             ← crt.sh subdomain enumeration
│   ├── githubscan.py         ← GitHub secret scanner
│   ├── jsextractor.py        ← JS endpoint and source map extractor
│   ├── logger.py             ← Structured per-run logging
│   ├── matchers.py           ← Product normalisation and CVE precision helpers
│   ├── nvd.py                ← NVD API v2 with CPE-based lookup
│   ├── passive.py            ← Passive HTTP recon
│   ├── pipeline.py           ← Domain mode 15-stage orchestrator
│   ├── pipeline_ip.py        ← IP mode 10-stage orchestrator
│   ├── probe.py              ← 100+ active HTTP probes
│   ├── redirect.py           ← Open redirect detection
│   ├── report.py             ← HTML and Markdown report generator
│   ├── s3scanner.py          ← S3, GCS, and Azure bucket scanner
│   ├── scan.py               ← Nmap port scanner
│   ├── schemas.py            ← JSON schema validation for stage outputs
│   ├── secret.py             ← Secret and credential scanner
│   ├── takeover.py           ← Subdomain takeover detection
│   ├── utils.py              ← Thread-safe config loader
│   └── wayback.py            ← Wayback Machine scanner
├── tests/
│   ├── test_matchers.py      ← Normalisation and CVE precision tests
│   ├── test_pipeline_ip_parsers.py
│   ├── test_schemas.py       ← Schema validation tests
│   └── test_validators.py    ← IP/CIDR/domain validation tests
└── outputs/                  ← All scan results written here (git-ignored)
```

---

## 📋 Output Files

| File | Contents |
|---|---|
| `scan_results.json` | Nmap port scan results with service versions |
| `passive_results.json` | HTTP status, title, tech stack per host |
| `probe_results.json` | Active probe findings with confidence and proof |
| `secret_results.json` | Exposed credentials with entropy scores |
| `js_results.json` | Endpoints, GraphQL, leaked subdomains |
| `s3_results.json` | Public/private cloud buckets (AWS/GCP/Azure) |
| `analysis_results.json` | CVEs with EPSS, version relevance, risk scores |
| `attack_paths.json` | Correlated leads ranked by confidence and score |
| `redshadow_report.html` | Dark-themed HTML report — open in any browser |
| `redshadow_report.md` | Markdown report |
| `logs/run_<timestamp>.log` | Structured JSON-lines run log |

---

## ⚙️ Configuration

All settings live in `config.yaml`. Key options:

```yaml
scan:
  nmap_ports: "443,8080,8443,..."   # Default port list (overridden by --ports flag)

cve_quality:
  max_per_service: 15               # Cap CVEs shown per service
  min_cvss: 4.0                     # Minimum CVSS score

ip_mode:
  triage_by_default: true           # Recommend --triage for IP scans

s3scanner:
  enable_write_check: false         # Set true ONLY in a lab environment

correlation:
  min_confidence: LOW               # Minimum confidence level for leads
```

---

## 📌 Legal

Copyright © 2026 Galal Noaman. All rights reserved.

For educational and non-commercial use only. Not permitted for commercial use, redistribution, or use against systems without explicit written authorisation. See `LICENSE.txt` for full terms.

Contact: Jalalnoaman@gmail.com | GitHub: github.com/GalalNoaman/RedShadow_V4