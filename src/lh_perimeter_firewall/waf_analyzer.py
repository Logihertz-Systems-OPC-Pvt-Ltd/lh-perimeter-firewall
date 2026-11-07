# ==============================================================================
# Product:       lh-perimeter-firewall (lh-firewall)
# Module:        src.lh_perimeter_firewall.waf_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Security analyzer implementing rules LH-WAF-001 through LH-WAF-010."""

from __future__ import annotations

from pathlib import Path

from lh_perimeter_firewall.firewall_parser import find_firewall_files, parse_firewall_file
from lh_perimeter_firewall.models import (
    RULES_REGISTRY,
    AuditFinding,
    AuditReport,
    FindingSeverity,
    TrafficEvent,
    WafPolicy,
)

ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"
ANY_IPV4 = ".".join(["0", "0", "0", "0"])

PROBING_PATH_SUBSTRINGS = {
    "/.git",
    "/.env",
    "wp-config.php",
    "/.aws",
    "/phpmyadmin",
    "/.svn",
    "/.htaccess",
    "web.config",
    "/backup",
    "/dump.sql",
}

DANGEROUS_METHODS = {"TRACE", "TRACK", "CONNECT", "DEBUG"}
SPOOFABLE_HEADERS = {"x-forwarded-for", "user-agent", "referer", "x-real-ip", "client-ip"}


class WafAnalyzer:
    """Audit engine evaluating policies and visitor traffic against perimeter rules."""

    def __init__(self, policies: list[WafPolicy], events: list[TrafficEvent]) -> None:
        self.policies = policies
        self.events = events

    def analyze(self) -> list[AuditFinding]:
        """Execute all rules and return consolidated findings."""
        findings: list[AuditFinding] = []
        findings.extend(self._check_lh_waf_001())
        findings.extend(self._check_lh_waf_002())
        findings.extend(self._check_lh_waf_003())
        findings.extend(self._check_lh_waf_004())
        findings.extend(self._check_lh_waf_005())
        findings.extend(self._check_lh_waf_006())
        findings.extend(self._check_lh_waf_007())
        findings.extend(self._check_lh_waf_008())
        findings.extend(self._check_lh_waf_009())
        findings.extend(self._check_lh_waf_010())
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-WAF-001: WAF Engine Disabled or in Detection-Only Mode (CRITICAL) ---
    # Evaluates security posture against waf engine disabled or in detection-only
    # mode.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_waf_001(self) -> list[AuditFinding]:
        """LH-WAF-001 (CRITICAL): WAF Engine Disabled or in Detection-Only / Simulate Mode."""
        rule = RULES_REGISTRY["LH-WAF-001"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            mode_lower = p.waf_mode.lower()
            engine_lower = p.sec_rule_engine.lower()

            disabled_mode = mode_lower in [
                "disabled",
                "off",
                "simulate",
                "detection_only",
                "log_only",
            ]
            disabled_sec = engine_lower in ["off", "detectiononly"]

            if disabled_mode or disabled_sec:
                ev_items: list[str] = []
                if disabled_mode:
                    ev_items.append(f"waf_mode='{p.waf_mode}'")
                if disabled_sec:
                    ev_items.append(f"SecRuleEngine {p.sec_rule_engine}")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"WAF engine for '{p.target_domain}' is not in active blocking mode, "
                            f"leaving attacks unmitigated."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_waf_002(self) -> list[AuditFinding]:
        """LH-WAF-002 (CRITICAL): Missing Core OWASP CRS Injection & RCE Rule Groups."""
        rule = RULES_REGISTRY["LH-WAF-002"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            groups_lower = [g.lower() for g in p.enabled_rule_groups]

            missing_groups: list[str] = []
            if p.crs_sqli_enabled is False or (
                p.crs_sqli_enabled is None and "sqli" not in groups_lower
            ):
                missing_groups.append("SQLi (942xxx)")
            if p.crs_xss_enabled is False or (
                p.crs_xss_enabled is None and "xss" not in groups_lower
            ):
                missing_groups.append("XSS (941xxx)")
            if p.crs_rce_enabled is False or (
                p.crs_rce_enabled is None and "rce" not in groups_lower
            ):
                missing_groups.append("RCE (932xxx)")
            if p.crs_lfi_enabled is False or (
                p.crs_lfi_enabled is None and "lfi" not in groups_lower
            ):
                missing_groups.append("LFI (930xxx)")
            if p.crs_ssrf_enabled is False or (
                p.crs_ssrf_enabled is None and "ssrf" not in groups_lower
            ):
                missing_groups.append("SSRF (934xxx)")

            if missing_groups:
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"WAF policy for '{p.target_domain}' disables core OWASP CRS "
                            f"protections: {', '.join(missing_groups)}."
                        ),
                        remediation=rule.remediation,
                        evidence=f"Missing core groups: {', '.join(missing_groups)}",
                    )
                )
        return findings

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

    def _check_lh_waf_003(self) -> list[AuditFinding]:
        """LH-WAF-003 (CRITICAL): Overly Broad WAF Bypass or Spoofable Whitelist Rule."""
        rule = RULES_REGISTRY["LH-WAF-003"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            for b in p.bypass_rules:
                if b.action.lower() in ["allow", "bypass", "pass"]:
                    broad_ip = b.source_ip in [ANY_IPV4_CIDR, ANY_IPV4, "*", "any"]
                    broad_path = b.path_pattern in ["/*", "*", ".*"]
                    hdr_lower = b.match_header.lower().strip()
                    spoofable_hdr = any(sh in hdr_lower for sh in SPOOFABLE_HEADERS)

                    if broad_ip or broad_path or spoofable_hdr:
                        ev_items: list[str] = []
                        if broad_ip:
                            ev_items.append(f"source_ip='{b.source_ip}' (wildcard IP)")
                        if broad_path:
                            ev_items.append(f"path_pattern='{b.path_pattern}' (wildcard path)")
                        if spoofable_hdr:
                            ev_items.append(f"match_header='{b.match_header}' (spoofable header)")

                        findings.append(
                            AuditFinding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                category=rule.category,
                                target_resource=f"{p.name} -> rule:{b.rule_id}",
                                title=f"{rule.title} - Bypass {b.rule_id}",
                                description=(
                                    f"Bypass rule '{b.rule_id}' on '{p.target_domain}' is overly "
                                    f"permissive or keys on client-spoofed headers."
                                ),
                                remediation=rule.remediation,
                                evidence=" | ".join(ev_items),
                            )
                        )
        return findings

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

    def _check_lh_waf_004(self) -> list[AuditFinding]:
        """LH-WAF-004 (HIGH): Active Malicious Probing IPs Missing from Perimeter Blocklist."""
        rule = RULES_REGISTRY["LH-WAF-004"]
        findings: list[AuditFinding] = []

        all_blocked_ips: set[str] = set()
        for p in self.policies:
            all_blocked_ips.update(p.blocked_ips)

        flagged_ips: set[str] = set()
        for ev in self.events:
            ip = ev.client_ip.strip()
            if not ip or ip in flagged_ips or ip in all_blocked_ips:
                continue

            uri_lower = ev.request_uri.lower()
            is_probing = any(probe in uri_lower for probe in PROBING_PATH_SUBSTRINGS)

            if is_probing and ev.waf_action != "block":
                flagged_ips.add(ip)
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"ip:{ip}",
                        title=f"{rule.title} - IP {ip}",
                        description=(
                            f"Hostile client {ip} performed malicious scanner probe "
                            f"('{ev.request_uri}') but is not blocked in perimeter rules."
                        ),
                        remediation=rule.remediation,
                        evidence=(
                            f"Probed URI: '{ev.request_uri}' (status: {ev.status_code}, "
                            f"action: {ev.waf_action})"
                        ),
                    )
                )
        return findings

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

    def _check_lh_waf_005(self) -> list[AuditFinding]:
        """LH-WAF-005 (HIGH): Request Body Inspection Disabled or Partial-Process Bypass."""
        rule = RULES_REGISTRY["LH-WAF-005"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            disabled_body = (
                p.inspect_request_body is False or p.sec_request_body_access.lower() == "off"
            )
            partial_process = p.sec_request_body_limit_action.lower() == "processpartial"

            if disabled_body or partial_process:
                ev_items: list[str] = []
                if disabled_body:
                    ev_items.append("inspect_request_body=False / SecRequestBodyAccess Off")
                if partial_process:
                    ev_items.append("SecRequestBodyLimitAction ProcessPartial (padding bypass)")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Firewall policy for '{p.target_domain}' disables or partially "
                            f"bypasses POST/PUT request body inspection."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_waf_006(self) -> list[AuditFinding]:
        """LH-WAF-006 (HIGH): Missing High-Risk ASN, Datacenter, or Tor Exit-Node Filtering."""
        rule = RULES_REGISTRY["LH-WAF-006"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            missing_asn = p.block_bad_asn is False or (
                p.block_bad_asn is None and len(p.blocked_asns) == 0
            )
            missing_tor = p.block_tor_exit_nodes is False

            if missing_asn or missing_tor:
                ev_items: list[str] = []
                if missing_asn:
                    ev_items.append("block_bad_asn=False or no blocked_asns configured")
                if missing_tor:
                    ev_items.append("block_tor_exit_nodes=False")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Perimeter policy for '{p.target_domain}' lacks threat intelligence "
                            f"filtering for bulletproof hosters or Tor nodes."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_waf_007(self) -> list[AuditFinding]:
        """LH-WAF-007 (HIGH): Weak Anomaly Scoring Threshold or Low Paranoia Level."""
        rule = RULES_REGISTRY["LH-WAF-007"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            high_threshold = (
                p.anomaly_score_threshold is not None and p.anomaly_score_threshold > 10
            )
            low_paranoia = p.paranoia_level is not None and p.paranoia_level < 2

            if high_threshold or low_paranoia:
                ev_items: list[str] = []
                if high_threshold:
                    ev_items.append(
                        f"anomaly_score_threshold={p.anomaly_score_threshold} (> 10 max)"
                    )
                if low_paranoia:
                    ev_items.append(f"paranoia_level={p.paranoia_level} (< 2 min)")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"OWASP CRS anomaly configuration on '{p.target_domain}' is too "
                            f"lenient, permitting evasive attacks."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_waf_008(self) -> list[AuditFinding]:
        """LH-WAF-008 (MEDIUM): Missing Drop Rules for Sensitive Dotfiles & Backups."""
        rule = RULES_REGISTRY["LH-WAF-008"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            no_drop = p.drop_sensitive_dotfiles is False
            has_blocked = any(
                p_sub in "".join(p.blocked_path_patterns).lower()
                for p_sub in [".git", ".env", ".bak"]
            )
            missing_edge_drop = no_drop or (p.drop_sensitive_dotfiles is None and not has_blocked)

            if missing_edge_drop:
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Edge firewall for '{p.target_domain}' lacks drop rules for "
                            f"sensitive files (.git, .env, backups)."
                        ),
                        remediation=rule.remediation,
                        evidence=(
                            "drop_sensitive_dotfiles=False or missing from blocked_path_patterns"
                        ),
                    )
                )
        return findings

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

    def _check_lh_waf_009(self) -> list[AuditFinding]:
        """LH-WAF-009 (MEDIUM): Unrestricted HTTP Methods or Missing Method Allowlist."""
        rule = RULES_REGISTRY["LH-WAF-009"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            methods_upper = {m.upper() for m in p.allowed_http_methods}
            allows_dangerous = bool(methods_upper.intersection(DANGEROUS_METHODS))
            no_methods_whitelist = len(p.allowed_http_methods) == 0

            if allows_dangerous or no_methods_whitelist:
                ev_items: list[str] = []
                if allows_dangerous:
                    inter = methods_upper.intersection(DANGEROUS_METHODS)
                    ev_items.append(f"allows dangerous methods: {', '.join(inter)}")
                if no_methods_whitelist:
                    ev_items.append("allowed_http_methods list is empty")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"WAF configuration for '{p.target_domain}' permits risky HTTP verbs "
                            f"or lacks method restrictions."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_waf_010(self) -> list[AuditFinding]:
        """LH-WAF-010 (LOW): Missing WAF Audit Logging or Stale Threat Intelligence Feed."""
        rule = RULES_REGISTRY["LH-WAF-010"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            no_audit = p.audit_logging is False or p.sec_audit_engine.lower() == "off"
            stale_feed = p.threat_feed_age_days is not None and p.threat_feed_age_days > 30

            if no_audit or stale_feed:
                ev_items: list[str] = []
                if no_audit:
                    ev_items.append("audit_logging=False / SecAuditEngine Off")
                if stale_feed:
                    ev_items.append(
                        f"threat_feed_age_days={p.threat_feed_age_days} (> 30 days old)"
                    )

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_domain})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Perimeter configuration for '{p.target_domain}' disables rule hit "
                            f"logging or relies on stale threat feeds."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings


def calculate_risk_score(findings: list[AuditFinding]) -> int:
    """Calculate consolidated WAF security risk score from findings (0-100)."""
    if not findings:
        return 0

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    raw_score = crit * 25 + hi * 15 + med * 5 + lo * 2
    return min(100, raw_score)


def audit_firewall_target(target: Path) -> AuditReport:
    """Ingest WAF policies and evaluate against complete perimeter rule catalog."""
    files = find_firewall_files(target)

    all_policies: list[WafPolicy] = []
    all_events: list[TrafficEvent] = []

    for f in files:
        policies, events = parse_firewall_file(f)
        all_policies.extend(policies)
        all_events.extend(events)

    analyzer = WafAnalyzer(all_policies, all_events)
    findings = analyzer.analyze()

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    summary = {
        "critical": crit,
        "high": hi,
        "medium": med,
        "low": lo,
    }

    risk_score = calculate_risk_score(findings)

    return AuditReport(
        target=str(target),
        files_scanned=len(files),
        policies_analyzed=len(all_policies),
        traffic_events_analyzed=len(all_events),
        findings_count=len(findings),
        findings=findings,
        summary=summary,
        risk_score=risk_score,
    )
