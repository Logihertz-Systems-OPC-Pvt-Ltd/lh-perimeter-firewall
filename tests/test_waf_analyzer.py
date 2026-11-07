# ==============================================================================
# Product:       lh-perimeter-firewall (lh-firewall)
# Module:        tests.test_waf_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for waf_analyzer module and detection rules (LH-WAF-001 through LH-WAF-010)."""

from __future__ import annotations

from pathlib import Path

from lh_perimeter_firewall.models import (
    AuditFinding,
    FindingSeverity,
    TrafficEvent,
    WafBypassRule,
    WafPolicy,
)
from lh_perimeter_firewall.waf_analyzer import (
    WafAnalyzer,
    audit_firewall_target,
    calculate_risk_score,
)

ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"


def test_clean_target_produces_no_findings(sample_clean_yaml: Path) -> None:
    """Test that a strictly configured WAF policy produces 0 findings."""
    report = audit_firewall_target(sample_clean_yaml)
    assert report.findings_count == 0
    assert len(report.findings) == 0
    assert report.risk_score == 0
    assert report.policies_analyzed == 1
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-001: WAF Engine Disabled or in Detection-Only Mode (CRITICAL) ---
    # Evaluates security posture against waf engine disabled or in detection-only
    # mode.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_001_engine_disabled() -> None:
    """Test LH-WAF-001: WAF disabled or detection only mode."""
    pol1 = WafPolicy(policy_id="p-01", waf_mode="detection_only")
    pol2 = WafPolicy(policy_id="p-02", sec_rule_engine="Off")
    analyzer = WafAnalyzer([pol1, pol2], [])
    findings = analyzer._check_lh_waf_001()
    assert len(findings) == 2
    assert all(f.rule_id == "LH-WAF-001" for f in findings)
    assert all(f.severity == FindingSeverity.CRITICAL for f in findings)
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-002 (CRITICAL):
    #     Missing Core OWASP CRS Injection & RCE Rule Groups
    # ---
    # Evaluates security posture against missing core owasp crs injection & rce rule
    # groups.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_002_missing_core_injection_groups() -> None:
    """Test LH-WAF-002: Missing core OWASP CRS injection & RCE groups."""
    pol = WafPolicy(
        policy_id="p-02",
        waf_mode="block",
        crs_sqli_enabled=False,
        crs_rce_enabled=False,
        crs_ssrf_enabled=False,
    )
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_002()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-002"
    assert findings[0].severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-003 (CRITICAL):
    #     Overly Broad WAF Bypass or Spoofable Whitelist Rule
    # ---
    # Evaluates security posture against overly broad waf bypass or spoofable
    # whitelist rule.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_003_broad_bypass_rules() -> None:
    """Test LH-WAF-003: Overly broad bypass (0.0.0.0/0, /*, X-Forwarded-For)."""
    bypass = WafBypassRule(
        rule_id="b-1",
        source_ip=ANY_IPV4_CIDR,
        path_pattern="/*",
        match_header="X-Forwarded-For",
        action="allow",
    )
    pol = WafPolicy(policy_id="p-03", waf_mode="block", bypass_rules=[bypass])
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_003()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-003"
    assert findings[0].severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-004 (HIGH):
    #     Active Malicious Probing IPs Missing from Perimeter Blocklist
    # ---
    # Evaluates security posture against active malicious probing ips missing from
    # perimeter blocklist.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_004_malicious_probing_ips() -> None:
    """Test LH-WAF-004: Hostile scanner IP probing /.git/config not in blocklist."""
    pol = WafPolicy(policy_id="p-04", blocked_ips=["192.0.2.1"])
    ev1 = TrafficEvent(
        event_id="ev-1",
        client_ip="203.0.113.55",
        request_uri="/.git/config",
        waf_action="allow",
    )
    ev2 = TrafficEvent(
        event_id="ev-2",
        client_ip="192.0.2.1",  # already blocked
        request_uri="/.env",
        waf_action="block",
    )
    analyzer = WafAnalyzer([pol], [ev1, ev2])
    findings = analyzer._check_lh_waf_004()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-004"
    assert findings[0].severity == FindingSeverity.HIGH
    assert "203.0.113.55" in findings[0].target_resource
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-005 (HIGH):
    #     Request Body Inspection Disabled or Partial-Process Bypass
    # ---
    # Evaluates security posture against request body inspection disabled or
    # partial-process bypass.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_005_body_inspection_disabled() -> None:
    """Test LH-WAF-005: inspect_request_body=False or ProcessPartial."""
    pol = WafPolicy(
        policy_id="p-05",
        waf_mode="block",
        inspect_request_body=False,
        sec_request_body_limit_action="ProcessPartial",
    )
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_005()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-005"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-006 (HIGH):
    #     Missing High-Risk ASN, Datacenter Scraper, or Tor Exit-Node Deny Rules
    # ---
    # Evaluates security posture against missing high-risk asn, datacenter scraper,
    # or tor exit-node deny rules.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_006_missing_asn_and_tor() -> None:
    """Test LH-WAF-006: Missing ASN reputation and Tor exit node filtering."""
    pol = WafPolicy(
        policy_id="p-06",
        waf_mode="block",
        block_bad_asn=False,
        block_tor_exit_nodes=False,
        blocked_asns=[],
    )
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_006()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-006"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-007 (HIGH):
    #     Weak Anomaly Scoring Threshold or Low Paranoia Level
    # ---
    # Evaluates security posture against weak anomaly scoring threshold or low
    # paranoia level.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_007_weak_anomaly_threshold() -> None:
    """Test LH-WAF-007: Anomaly score > 10 or paranoia level < 2."""
    pol = WafPolicy(
        policy_id="p-07",
        waf_mode="block",
        anomaly_score_threshold=25,
        paranoia_level=1,
    )
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_007()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-007"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-008 (MEDIUM):
    #     Missing Edge Drop Rules for Sensitive Dotfiles & Backups
    # ---
    # Evaluates security posture against missing edge drop rules for sensitive
    # dotfiles & backups.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_008_missing_dotfile_drop() -> None:
    """Test LH-WAF-008: Missing edge drop rules for dotfiles."""
    pol = WafPolicy(
        policy_id="p-08",
        waf_mode="block",
        drop_sensitive_dotfiles=False,
        blocked_path_patterns=[],
    )
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_008()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-008"
    assert findings[0].severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-009 (MEDIUM):
    #     Unrestricted HTTP Methods or Legacy Protocol Versions
    # ---
    # Evaluates security posture against unrestricted http methods or legacy
    # protocol versions.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_009_dangerous_http_methods() -> None:
    """Test LH-WAF-009: Allowed TRACE/TRACK or missing method whitelist."""
    pol = WafPolicy(
        policy_id="p-09",
        waf_mode="block",
        allowed_http_methods=["GET", "POST", "TRACE", "TRACK"],
    )
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_009()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-009"
    assert findings[0].severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-010 (LOW):
    #     Missing WAF Rule Hit Audit Logging or Stale Threat Intelligence
    # ---
    # Evaluates security posture against missing waf rule hit audit logging or stale
    # threat intelligence.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_waf_010_missing_audit_and_stale_feed() -> None:
    """Test LH-WAF-010: audit_logging=False or threat_feed_age_days > 30."""
    pol = WafPolicy(
        policy_id="p-10",
        waf_mode="block",
        audit_logging=False,
        threat_feed_age_days=50,
    )
    analyzer = WafAnalyzer([pol], [])
    findings = analyzer._check_lh_waf_010()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-WAF-010"
    assert findings[0].severity == FindingSeverity.LOW


def test_malicious_yaml_triggers_complete_rule_catalog(sample_malicious_yaml: Path) -> None:
    """Test sample_malicious_yaml triggers expected rules."""
    report = audit_firewall_target(sample_malicious_yaml)
    detected_rules = {f.rule_id for f in report.findings}
    expected = {
        "LH-WAF-001",
        "LH-WAF-002",
        "LH-WAF-003",
        "LH-WAF-005",
        "LH-WAF-006",
        "LH-WAF-007",
        "LH-WAF-008",
        "LH-WAF-009",
        "LH-WAF-010",
    }
    assert expected.issubset(detected_rules)
    assert report.risk_score > 60


def test_calculate_risk_score() -> None:
    """Test calculate_risk_score with various combinations and 100 cap."""
    assert calculate_risk_score([]) == 0

    findings = [
        AuditFinding(
            rule_id="LH-WAF-001",
            severity=FindingSeverity.CRITICAL,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-WAF-004",
            severity=FindingSeverity.HIGH,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-WAF-008",
            severity=FindingSeverity.MEDIUM,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-WAF-010",
            severity=FindingSeverity.LOW,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
    ]
    # 25 + 15 + 5 + 2 = 47
    assert calculate_risk_score(findings) == 47

    # Cap at 100
    many_crits = [findings[0]] * 10
    assert calculate_risk_score(many_crits) == 100
