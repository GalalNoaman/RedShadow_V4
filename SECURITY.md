# 🔒 Security Policy — RedShadow V4

## ✅ Intended Use

RedShadow V4 is a reconnaissance and analysis framework built for **lawful, educational, and professional security research**. It performs passive and active recon, secret discovery, and CVE analysis. It is **not** an exploitation framework.

**Allowed use cases:**

- Reconnaissance on assets you **own** or have **explicit written permission** to test
- Bug bounty testing on platforms where external recon is within the defined scope
- Authorised penetration testing engagements with a signed scope agreement
- Academic or lab-based cybersecurity research in controlled, isolated environments
- Personal skill development against intentionally vulnerable targets (HackTheBox, TryHackMe, DVWA, etc.)

---

## 🚫 Prohibited Use

You **must not** use RedShadow V4 to:

- Scan or probe systems without explicit written authorisation from the owner
- Exploit, damage, or disrupt any live system or service
- Collect or exfiltrate data from systems you do not own
- Conduct commercial assessments without a written licence from the author
- Sell, rebrand, resell, or redistribute this tool or any of its modules
- Remove author credit or project branding from any part of the codebase
- Violate any local, national, or international law — including but not limited to:
  - UK Computer Misuse Act 1990
  - US Computer Fraud and Abuse Act (CFAA)
  - EU Directive on Attacks Against Information Systems
  - Equivalent legislation in your jurisdiction

---

## ⚠️ Active Capabilities Notice

RedShadow V4 performs **active network operations** that generate real traffic toward the target. Before running any scan, you must understand what the tool does:

| Stage | Active Operations |
|---|---|
| DNS Bruteforce | Sends thousands of DNS queries to resolve subdomains |
| Passive Recon | Makes HTTP/S requests to each discovered subdomain |
| HTTP Probing | Sends 100+ targeted HTTP requests per host |
| Open Redirect | Sends crafted GET/OPTIONS requests with injected Origin headers |
| Secret Scanner | Fetches HTML and JavaScript files from live hosts |
| S3 Scanner | Makes HTTP requests to hundreds of guessed bucket names |
| JS Extractor | Fetches JavaScript files and source maps from live hosts |
| GitHub Scanner | Queries GitHub's code search API using target-related terms |
| Wayback Scanner | Queries public archive APIs and probes live URLs |
| Port Scan | Runs Nmap SYN/service scans against resolved IP addresses |

Running this tool without authorisation on any of the above operations may constitute unauthorised computer access under applicable law.

---

## 🛠️ Reporting Security Issues in This Tool

If you discover a **security vulnerability in RedShadow V4 itself** (e.g. path traversal, arbitrary code execution, unsafe defaults), please report it **privately and responsibly**:

📧 **Jalalnoaman@gmail.com**

Please include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- The potential impact and affected version
- Your suggested fix if you have one

**Response commitment:** I will acknowledge your report within 72 hours and aim to release a fix within 14 days for critical issues.

**Do not** open public GitHub issues for security vulnerabilities before they have been fixed. Coordinated disclosure protects all users.

---

## 🔐 Intentional Limitations

RedShadow V4 does **not** include — and will not include — the following:

- Exploit code or proof-of-concept attack payloads
- Shell generation or reverse shell capability
- Command and control (C2) infrastructure
- Post-exploitation modules
- Automated vulnerability chaining or attack automation
- Credential stuffing or brute force login modules

The pipeline identifies and reports vulnerabilities. It does **not** exploit them. CVE analysis produces a report — it does not attempt to trigger the vulnerability.

These limitations are intentional and permanent. Feature requests for offensive exploitation capabilities will not be accepted.

---

## ✅ Responsible Disclosure

If you use RedShadow V4 to discover real vulnerabilities in a third-party system:

- Follow the affected vendor's published responsible disclosure or bug bounty policy
- Do not access, copy, modify, or delete data beyond what is needed to confirm the issue
- Do not publicly disclose the vulnerability until the vendor has had reasonable time to patch — typically 90 days
- Submit reports through the vendor's official channel (HackerOne, Bugcrowd, security@vendor.com, etc.)
- Do not use the vulnerability to harm users, disrupt services, or gain unauthorised access

Responsible disclosure protects users, builds your reputation, and may qualify you for a bug bounty reward.

---

## 🏛️ Legal Notice

Use of this tool is entirely at your own risk. The author accepts no liability for:

- Any illegal, unauthorised, or unethical use of this software
- Damage, data loss, or service disruption caused by running this tool
- Legal consequences arising from misuse
- Actions taken by third parties using this codebase

By using RedShadow V4 you confirm that you understand its capabilities, hold the necessary authorisation for your target, and accept full legal and ethical responsibility for your actions.

---

© 2026 **Galal Noaman** — All rights reserved.
Contact: Jalalnoaman@gmail.com | GitHub: github.com/GalalNoaman/RedShadow_V4