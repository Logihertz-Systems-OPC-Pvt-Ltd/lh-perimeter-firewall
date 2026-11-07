# Security Rules Reference: lh-perimeter-firewall

An enterprise web application firewall & perimeter defense auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-perimeter-firewall`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-WAF-001` | `CRITICAL` | Engine Mode | WAF Engine Disabled or in Detection-Only Mode |
| `LH-WAF-002` | `CRITICAL` | Rule Coverage | Missing Core OWASP CRS Injection & RCE Rule Groups |
| `LH-WAF-003` | `CRITICAL` | Bypass Rules | Overly Broad WAF Bypass or Spoofable Whitelist Rule |
| `LH-WAF-004` | `HIGH` | Threat Intelligence | Active Malicious Probing IPs Missing from Perimeter Blocklist |
| `LH-WAF-005` | `HIGH` | Inspection Depth | Request Body Inspection Disabled or Partial-Process Bypass |
| `LH-WAF-006` | `HIGH` | Reputation | Missing High-Risk ASN, Datacenter Scraper, or Tor Exit-Node Deny Rules |
| `LH-WAF-007` | `HIGH` | Anomaly Scoring | Weak Anomaly Scoring Threshold or Low Paranoia Level |
| `LH-WAF-008` | `MEDIUM` | Perimeter Defense | Missing Edge Drop Rules for Sensitive Dotfiles & Backups |
| `LH-WAF-009` | `MEDIUM` | Protocol Hygiene | Unrestricted HTTP Methods or Legacy Protocol Versions |
| `LH-WAF-010` | `LOW` | Logging & Telemetry | Missing WAF Rule Hit Audit Logging or Stale Threat Intelligence |

---

## Granular Rule Specifications

### `LH-WAF-001`: WAF Engine Disabled or in Detection-Only Mode

- **Severity**: `CRITICAL`
- **Category**: `Engine Mode`
- **Description**: SecRuleEngine set to Off or DetectionOnly in production environment.
- **Remediation**: Set SecRuleEngine On to actively block matching malicious requests.

---

### `LH-WAF-002`: Missing Core OWASP CRS Injection & RCE Rule Groups

- **Severity**: `CRITICAL`
- **Category**: `Rule Coverage`
- **Description**: Core Rule Set SQLi, XSS, RCE, or LFI protection rule groups are disabled.
- **Remediation**: Enable OWASP Core Rule Set rule groups 930 (LFI), 932 (RCE), 941 (XSS), and 942 (SQLi).

---

### `LH-WAF-003`: Overly Broad WAF Bypass or Spoofable Whitelist Rule

- **Severity**: `CRITICAL`
- **Category**: `Bypass Rules`
- **Description**: WAF bypass rule matches 0.0.0.0/0, wildcard paths, or spoofable User-Agent/Referer headers.
- **Remediation**: Restrict WAF bypasses strictly to verified client IP ranges and authenticated tokens.

---

### `LH-WAF-004`: Active Malicious Probing IPs Missing from Perimeter Blocklist

- **Severity**: `HIGH`
- **Category**: `Threat Intelligence`
- **Description**: Scanner IPs probing sensitive paths in access logs are not denied in WAF rules.
- **Remediation**: Add aggressive scanner IPs to edge drop rules or perimeter IP blocklists.

---

### `LH-WAF-005`: Request Body Inspection Disabled or Partial-Process Bypass

- **Severity**: `HIGH`
- **Category**: `Inspection Depth`
- **Description**: SecRequestBodyAccess set to Off, preventing inspection of POST/PUT request bodies.
- **Remediation**: Enable SecRequestBodyAccess On and set SecRequestBodyLimit to at least 12.5MB.

---

### `LH-WAF-006`: Missing High-Risk ASN, Datacenter Scraper, or Tor Exit-Node Deny Rules

- **Severity**: `HIGH`
- **Category**: `Reputation`
- **Description**: WAF policy does not restrict traffic originating from known malicious scraper ASNs.
- **Remediation**: Configure ASN reputation filtering to block or challenge commercial proxy/VPN traffic.

---

### `LH-WAF-007`: Weak Anomaly Scoring Threshold or Low Paranoia Level

- **Severity**: `HIGH`
- **Category**: `Anomaly Scoring`
- **Description**: CRS anomaly threshold set too permissive (> 10) or paranoia level set to 1.
- **Remediation**: Set inbound anomaly threshold to 5 and increase paranoia level to 2 for public APIs.

---

### `LH-WAF-008`: Missing Edge Drop Rules for Sensitive Dotfiles & Backups

- **Severity**: `MEDIUM`
- **Category**: `Perimeter Defense`
- **Description**: WAF lacks edge drop rules for /.git, /.env, and database backup files.
- **Remediation**: Add explicit edge block rules denying access to dotfiles and configuration extensions.

---

### `LH-WAF-009`: Unrestricted HTTP Methods or Legacy Protocol Versions

- **Severity**: `MEDIUM`
- **Category**: `Protocol Hygiene`
- **Description**: Dangerous HTTP methods (TRACE, TRACK, CONNECT) or legacy HTTP/1.0 allowed.
- **Remediation**: Restrict allowed HTTP methods strictly to GET, POST, PUT, DELETE, and HEAD.

---

### `LH-WAF-010`: Missing WAF Rule Hit Audit Logging or Stale Threat Intelligence

- **Severity**: `LOW`
- **Category**: `Logging & Telemetry`
- **Description**: SecAuditEngine set to Off or IP reputation feed older than 30 days.
- **Remediation**: Enable SecAuditEngine RelevantOnly and configure automated daily threat feed updates.

---
