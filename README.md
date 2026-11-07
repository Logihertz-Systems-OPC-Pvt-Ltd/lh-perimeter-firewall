# lh-perimeter-firewall

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-perimeter-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-perimeter-firewall/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise waf, owasp crs & edge firewall auditor developed by **Logihertz Systems (OPC) Private Limited**.

Audits AWS WAF/Cloudflare/ModSecurity rule manifests, OWASP Core Rule Set (CRS) paranoia configurations, and iptables/nftables perimeter policies for shadow allow rules, detection-only bypasses, and missing egress filters.

---

## Key Features

- **Multi-Source Policy Ingestion**: Ingests ModSecurity configs, Cloudflare edge firewall rules, AWS WAF manifests, and IP blocklists.
- **Enforcement Mode Verification**: Flags WAF policies set to `DetectionOnly`, `simulate`, or disabled mode in production environments.
- **OWASP Core Rule Set (CRS) Auditing**: Verifies that SQLi, XSS, RCE, LFI, and SSRF rule groups are actively enabled and enforced.
- **Permissive Whitelist & Bypass Analysis**: Detects bypass rules matching `0.0.0.0/0`, wildcard paths, or spoofable HTTP request headers.
- **Traffic Log Correlation**: Correlates visitor traffic logs against blocklists to identify active malicious scanner IPs that remain unblocked.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-WAF-001` | `CRITICAL` | WAF Engine Disabled or in Detection-Only Mode — SecRuleEngine Off/DetectionOnly in production |
| `LH-WAF-002` | `CRITICAL` | Missing Core OWASP CRS Injection & RCE Rule Groups — SQLi, XSS, RCE, or LFI rule sets disabled |
| `LH-WAF-003` | `CRITICAL` | Overly Broad WAF Bypass or Spoofable Whitelist Rule — allow rules matching 0.0.0.0/0 or wildcard paths |
| `LH-WAF-004` | `HIGH` | Active Malicious Probing IPs Missing from Perimeter Blocklist — scanner IPs in logs not denied in WAF |
| `LH-WAF-005` | `HIGH` | Request Body Inspection Disabled or Partial-Process Bypass — SecRequestBodyAccess Off |
| `LH-WAF-006` | `HIGH` | Missing High-Risk ASN, Datacenter Scraper, or Tor Exit-Node Deny Rules — missing known scraper ASN blocks |
| `LH-WAF-007` | `HIGH` | Weak Anomaly Scoring Threshold or Low Paranoia Level — anomaly threshold set too permissive (> 10) |
| `LH-WAF-008` | `MEDIUM` | Missing Edge Drop Rules for Sensitive Dotfiles & Backups — missing blocks for /.git, /.env, and backup files |
| `LH-WAF-009` | `MEDIUM` | Unrestricted HTTP Methods or Legacy Protocol Versions — dangerous methods (TRACE, TRACK, CONNECT) allowed |
| `LH-WAF-010` | `LOW` | Missing WAF Rule Hit Audit Logging or Stale Threat Intelligence Feed — logging disabled or feeds > 30 days old |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-perimeter-firewall.git
cd lh-perimeter-firewall

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-firewall` (also accessible via `lh-firewall`, `lh-waf`, `lh-perimeter-firewall`).

```bash
# Scan a ModSecurity configuration file
lh-firewall scan /etc/modsecurity/modsecurity.conf

# Audit a WAF policy YAML against visitor traffic logs
lh-firewall scan waf-policy.yaml --logs access.log

# Export findings to OASIS SARIF v2.1.0
lh-firewall scan ./waf-rules/ --format sarif --output waf-report.sarif

# List all WAF detection rules
lh-firewall rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
