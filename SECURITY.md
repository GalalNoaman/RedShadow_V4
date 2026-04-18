# Security Policy — RedShadow V4

## Authorised Use Only

RedShadow V4 is designed for use by security professionals on systems they own or have explicit written authorisation to test. Unauthorised scanning of systems you do not own or have permission to test is illegal in most jurisdictions and is strictly prohibited.

Before running any scan:
- Obtain explicit written authorisation from the system owner
- Confirm the scope of authorised targets with the client
- Keep a copy of your authorisation documentation

## Responsible Disclosure

If you discover a security vulnerability in RedShadow V4 itself, please report it responsibly:

- **Do not** open a public GitHub issue for security vulnerabilities
- Email: Jalalnoaman@gmail.com with the subject line `RedShadow Security Report`
- Include a clear description of the vulnerability and steps to reproduce
- Allow reasonable time for a fix before any public disclosure

## Sensitive Data

RedShadow writes all scan output to the `outputs/` directory. This directory is git-ignored and should never be committed to version control. It may contain:

- Discovered credentials and secrets
- CVE analysis results
- Target IP addresses and open ports
- Cloud storage bucket contents

Treat all output files as sensitive. Delete or securely store them after use.

## API Keys

API keys for NVD and GitHub are stored in `.env` which is git-ignored. Never commit this file. If you believe your keys have been exposed, rotate them immediately:

- NVD: https://nvd.nist.gov/developers/request-an-api-key
- GitHub: https://github.com/settings/tokens

## Scope of This Tool

RedShadow is a reconnaissance and analysis tool. It does not perform exploitation. Findings produced by this tool require manual validation before being treated as confirmed vulnerabilities.