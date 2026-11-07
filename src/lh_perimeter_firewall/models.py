# ==============================================================================
# Product:       lh-perimeter-firewall (lh-firewall)
# Module:        src.lh_perimeter_firewall.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-perimeter-firewall."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for perimeter firewall and WAF security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


@dataclass
class WafBypassRule:
    """WAF whitelist or bypass rule definition."""

    rule_id: str = ""
    description: str = ""
    source_ip: str = ""
    path_pattern: str = ""
    match_header: str = ""
    action: str = "allow"


@dataclass
class WafPolicy:
    """Parsed Web Application Firewall or perimeter security policy manifest."""

    policy_id: str = ""
    name: str = ""
    target_domain: str = ""
    waf_mode: str = ""  # active, block, detection_only, simulate, disabled, off
    sec_rule_engine: str = ""  # On, Off, DetectionOnly
    crs_sqli_enabled: bool | None = None
    crs_xss_enabled: bool | None = None
    crs_rce_enabled: bool | None = None
    crs_lfi_enabled: bool | None = None
    crs_ssrf_enabled: bool | None = None
    enabled_rule_groups: list[str] = field(default_factory=list)
    bypass_rules: list[WafBypassRule] = field(default_factory=list)
    blocked_ips: list[str] = field(default_factory=list)
    blocked_asns: list[str] = field(default_factory=list)
    inspect_request_body: bool | None = None
    sec_request_body_access: str = ""  # On, Off
    sec_request_body_limit_action: str = ""  # Reject, ProcessPartial
    block_bad_asn: bool | None = None
    block_tor_exit_nodes: bool | None = None
    anomaly_score_threshold: int | None = None
    paranoia_level: int | None = None
    drop_sensitive_dotfiles: bool | None = None
    blocked_path_patterns: list[str] = field(default_factory=list)
    allowed_http_methods: list[str] = field(default_factory=list)
    audit_logging: bool | None = None
    sec_audit_engine: str = ""  # On, Off, RelevantOnly
    threat_feed_age_days: int | None = None
    source_file: str = ""
    line_number: int = 0


@dataclass
class TrafficEvent:
    """Captured web visitor traffic record from server logs."""

    event_id: str = ""
    timestamp: str = ""
    client_ip: str = ""
    asn: str = ""
    request_uri: str = ""
    http_method: str = "GET"
    status_code: int = 200
    waf_action: str = "allow"
    source_file: str = ""
    line_number: int = 0


@dataclass
class AuditFinding:
    """Security finding or vulnerability detected in WAF or perimeter policies."""

    rule_id: str
    severity: FindingSeverity
    category: str
    target_resource: str
    title: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AuditReport:
    """Consolidated perimeter firewall audit report."""

    target: str
    files_scanned: int = 0
    policies_analyzed: int = 0
    traffic_events_analyzed: int = 0
    findings_count: int = 0
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0


@dataclass(frozen=True)
class AuditRuleDefinition:
    """Static metadata for perimeter firewall audit rules."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, AuditRuleDefinition] = {
    "LH-WAF-001": AuditRuleDefinition(
        rule_id="LH-WAF-001",
        title="WAF Engine Disabled or in Detection-Only / Simulate Mode",
        severity=FindingSeverity.CRITICAL,
        category="Engine State",
        description=(
            "WAF is turned off (SecRuleEngine Off), running in detection/simulate mode, or set "
            "to log-only without actively blocking malicious requests."
        ),
        remediation=(
            "Enable active blocking mode (SecRuleEngine On or waf_mode: block) on production "
            "edge firewalls."
        ),
    ),
    "LH-WAF-002": AuditRuleDefinition(
        rule_id="LH-WAF-002",
        title="Missing Core OWASP CRS Injection & RCE Rule Groups",
        severity=FindingSeverity.CRITICAL,
        category="Core Protections",
        description=(
            "WAF configuration omits or disables essential OWASP CRS rule groups: SQL Injection "
            "(SQLi), Cross-Site Scripting (XSS), RCE, LFI, or SSRF."
        ),
        remediation=(
            "Enable complete OWASP CRS core protection rule groups including SQLi, XSS, RCE, "
            "LFI, and SSRF modules."
        ),
    ),
    "LH-WAF-003": AuditRuleDefinition(
        rule_id="LH-WAF-003",
        title="Overly Broad WAF Bypass or Spoofable Whitelist Rule",
        severity=FindingSeverity.CRITICAL,
        category="Bypass Integrity",
        description=(
            "Firewall contains overly broad bypass rules allowing 0.0.0.0/0, wildcard paths "
            "(/*), or easily spoofed headers (User-Agent, X-Forwarded-For, Referer)."
        ),
        remediation=(
            "Scope bypass rules to specific verified internal IP addresses and cryptographically "
            "signed tokens rather than client-controlled headers."
        ),
    ),
    "LH-WAF-004": AuditRuleDefinition(
        rule_id="LH-WAF-004",
        title="Active Malicious Probing IPs Missing from Perimeter Blocklist",
        severity=FindingSeverity.HIGH,
        category="Threat Correlation",
        description=(
            "Traffic telemetry reveals malicious clients probing sensitive endpoints (/.git, "
            "/.env, wp-config.php) that remain unblocked in edge perimeter rules."
        ),
        remediation=(
            "Correlate scanner telemetry with automated edge blocking to drop hostile probing "
            "IPs at the perimeter."
        ),
    ),
    "LH-WAF-005": AuditRuleDefinition(
        rule_id="LH-WAF-005",
        title="Request Body Inspection Disabled or Partial-Process Bypass",
        severity=FindingSeverity.HIGH,
        category="Inspection Depth",
        description=(
            "Request body inspection is disabled (SecRequestBodyAccess Off) or configured with "
            "ProcessPartial, allowing attackers to bypass inspection via body padding."
        ),
        remediation=(
            "Enable full request body inspection (SecRequestBodyAccess On) and enforce "
            "SecRequestBodyLimitAction Reject."
        ),
    ),
    "LH-WAF-006": AuditRuleDefinition(
        rule_id="LH-WAF-006",
        title="Missing High-Risk ASN, Datacenter, or Tor Exit-Node Filtering",
        severity=FindingSeverity.HIGH,
        category="Threat Intelligence",
        description=(
            "Perimeter policy lacks reputation filtering for known bulletproof hosters, scraper "
            "datacenters, or Tor exit nodes."
        ),
        remediation=(
            "Subscribe to high-risk ASN intelligence feeds and block or challenge traffic "
            "originating from known hostile datacenters and Tor exit nodes."
        ),
    ),
    "LH-WAF-007": AuditRuleDefinition(
        rule_id="LH-WAF-007",
        title="Weak Anomaly Scoring Threshold or Low Paranoia Level",
        severity=FindingSeverity.HIGH,
        category="Anomaly Scoring",
        description=(
            "OWASP CRS inbound anomaly score threshold is set too high (> 10) or paranoia level "
            "is below recommended production baseline (paranoia_level < 2)."
        ),
        remediation=(
            "Lower inbound anomaly score threshold to <= 5 (or max 10) and increase paranoia "
            "level to at least 2."
        ),
    ),
    "LH-WAF-008": AuditRuleDefinition(
        rule_id="LH-WAF-008",
        title="Missing Edge Drop Rules for Sensitive Dotfiles & Backup Artifacts",
        severity=FindingSeverity.MEDIUM,
        category="Surface Hardening",
        description=(
            "Firewall policy lacks explicit perimeter drop rules for /.git, /.env, /.aws, *.bak, "
            "*.sql, and database administration interfaces."
        ),
        remediation=(
            "Configure edge deny rules that immediately drop requests for hidden files, version "
            "control directories, and backup archives."
        ),
    ),
    "LH-WAF-009": AuditRuleDefinition(
        rule_id="LH-WAF-009",
        title="Unrestricted HTTP Methods or Missing Method Allowlist",
        severity=FindingSeverity.MEDIUM,
        category="Protocol Hygiene",
        description=(
            "WAF permits dangerous or legacy HTTP methods (TRACE, TRACK, CONNECT, DEBUG) or lacks "
            "an explicit HTTP method allowlist."
        ),
        remediation=(
            "Enforce a strict HTTP method allowlist (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS) "
            "and reject TRACE, TRACK, and CONNECT."
        ),
    ),
    "LH-WAF-010": AuditRuleDefinition(
        rule_id="LH-WAF-010",
        title="Missing WAF Audit Logging or Stale Threat Intelligence Feed",
        severity=FindingSeverity.LOW,
        category="Audit & Freshness",
        description=(
            "WAF security rule hit logging is disabled (SecAuditEngine Off), or perimeter threat "
            "intelligence feeds exceed 30 days without updates."
        ),
        remediation=(
            "Enable comprehensive WAF audit logging for all triggered rules and update threat "
            "intelligence feeds on a daily or weekly schedule."
        ),
    ),
}
