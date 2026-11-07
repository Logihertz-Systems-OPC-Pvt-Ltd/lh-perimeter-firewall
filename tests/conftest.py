# ==============================================================================
# Product:       lh-perimeter-firewall (lh-firewall)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-perimeter-firewall test suite."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
import yaml

ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"


@pytest.fixture
def sample_clean_yaml(tmp_path: Path) -> Path:
    """Fixture providing compliant WAF policy in YAML format."""
    file_path = tmp_path / "compliant_waf.yaml"
    data = {
        "policies": [
            {
                "policy_id": "pol-clean-01",
                "name": "Production Hardened WAF",
                "target_domain": "api.logihertz.com",
                "waf_mode": "block",
                "sec_rule_engine": "On",
                "crs_sqli_enabled": True,
                "crs_xss_enabled": True,
                "crs_rce_enabled": True,
                "crs_lfi_enabled": True,
                "crs_ssrf_enabled": True,
                "enabled_rule_groups": ["sqli", "xss", "rce", "lfi", "ssrf"],
                "bypass_rules": [
                    {
                        "rule_id": "b-clean-1",
                        "source_ip": "198.51.100.10/32",
                        "path_pattern": "/internal/health",
                        "action": "allow",
                    }
                ],
                "blocked_ips": ["192.0.2.66"],
                "blocked_asns": ["AS12345"],
                "inspect_request_body": True,
                "sec_request_body_access": "On",
                "sec_request_body_limit_action": "Reject",
                "block_bad_asn": True,
                "block_tor_exit_nodes": True,
                "anomaly_score_threshold": 5,
                "paranoia_level": 2,
                "drop_sensitive_dotfiles": True,
                "blocked_path_patterns": ["/.git", "/.env", "/.aws", "*.bak"],
                "allowed_http_methods": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                "audit_logging": True,
                "sec_audit_engine": "On",
                "threat_feed_age_days": 3,
            }
        ]
    }
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_malicious_yaml(tmp_path: Path) -> Path:
    """Fixture providing policies triggering rules LH-WAF-001 through LH-WAF-010."""
    file_path = tmp_path / "insecure_waf.yaml"
    data = {
        "policies": [
            # LH-WAF-001: Detection-only mode
            {
                "policy_id": "pol-01",
                "name": "Passive Detection Policy",
                "target_domain": "portal.example.com",
                "waf_mode": "detection_only",
                "sec_rule_engine": "DetectionOnly",
            },
            # LH-WAF-002: Missing core injection groups (SQLi, RCE, SSRF)
            {
                "policy_id": "pol-02",
                "name": "Missing CRS Injection Policy",
                "target_domain": "legacy.example.com",
                "waf_mode": "block",
                "crs_sqli_enabled": False,
                "crs_rce_enabled": False,
                "crs_ssrf_enabled": False,
            },
            # LH-WAF-003: Overly broad bypass rule (0.0.0.0/0 & X-Forwarded-For)
            {
                "policy_id": "pol-03",
                "name": "Broad Whitelist Policy",
                "target_domain": "api.example.com",
                "waf_mode": "block",
                "bypass_rules": [
                    {
                        "rule_id": "bypass-wildcard-ip",
                        "source_ip": ANY_IPV4_CIDR,
                        "path_pattern": "/*",
                        "match_header": "X-Forwarded-For",
                        "action": "allow",
                    }
                ],
            },
            # LH-WAF-005: Disabled request body inspection & ProcessPartial
            {
                "policy_id": "pol-05",
                "name": "Partial Body Inspection",
                "target_domain": "upload.example.com",
                "waf_mode": "block",
                "inspect_request_body": False,
                "sec_request_body_access": "Off",
                "sec_request_body_limit_action": "ProcessPartial",
            },
            # LH-WAF-006: Missing ASN and Tor filtering
            {
                "policy_id": "pol-06",
                "name": "No ASN Filter Policy",
                "target_domain": "edge.example.com",
                "waf_mode": "block",
                "block_bad_asn": False,
                "block_tor_exit_nodes": False,
                "blocked_asns": [],
            },
            # LH-WAF-007: Weak anomaly threshold and low paranoia
            {
                "policy_id": "pol-07",
                "name": "Permissive Anomaly Policy",
                "target_domain": "app.example.com",
                "waf_mode": "block",
                "anomaly_score_threshold": 25,
                "paranoia_level": 1,
            },
            # LH-WAF-008: Missing edge drop rules for dotfiles
            {
                "policy_id": "pol-08",
                "name": "No Dotfile Drop Policy",
                "target_domain": "static.example.com",
                "waf_mode": "block",
                "drop_sensitive_dotfiles": False,
                "blocked_path_patterns": [],
            },
            # LH-WAF-009: Dangerous HTTP methods (TRACE, TRACK, CONNECT)
            {
                "policy_id": "pol-09",
                "name": "Dangerous Verbs Policy",
                "target_domain": "services.example.com",
                "waf_mode": "block",
                "allowed_http_methods": ["GET", "POST", "TRACE", "TRACK", "CONNECT"],
            },
            # LH-WAF-010: Missing audit logging & stale threat feed
            {
                "policy_id": "pol-10",
                "name": "No Audit Log Stale Feed",
                "target_domain": "data.example.com",
                "waf_mode": "block",
                "audit_logging": False,
                "sec_audit_engine": "Off",
                "threat_feed_age_days": 45,
            },
        ]
    }
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_traffic_json(tmp_path: Path) -> Path:
    """Fixture providing visitor traffic events with unblocked scanner IPs."""
    file_path = tmp_path / "traffic.json"
    records = [
        # Unblocked IP probing /.env
        {
            "event_id": "ev-001",
            "timestamp": "2026-11-01T10:00:00Z",
            "client_ip": "203.0.113.88",
            "asn": "AS4444",
            "request_uri": "/.env",
            "http_method": "GET",
            "status_code": 200,
            "waf_action": "allow",
        },
        # Unblocked IP probing /.git/config
        {
            "event_id": "ev-002",
            "timestamp": "2026-11-01T10:05:00Z",
            "client_ip": "198.51.100.42",
            "asn": "AS5555",
            "request_uri": "/.git/config",
            "http_method": "GET",
            "status_code": 404,
            "waf_action": "allow",
        },
        # Already blocked IP
        {
            "event_id": "ev-003",
            "timestamp": "2026-11-01T10:10:00Z",
            "client_ip": "192.0.2.66",
            "asn": "AS12345",
            "request_uri": "/.git/HEAD",
            "http_method": "GET",
            "status_code": 403,
            "waf_action": "block",
        },
    ]
    file_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_modsecurity_conf(tmp_path: Path) -> Path:
    """Fixture providing ModSecurity configuration file."""
    conf_file = tmp_path / "modsec.conf"
    content = (
        "SecRuleEngine On\n"
        "SecRequestBodyAccess On\n"
        "SecRequestBodyLimitAction Reject\n"
        "SecAuditEngine On\n"
        'SecAction "id:900000,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5"\n'
        'SecAction "id:900001,phase:1,nolog,pass,setvar:tx.paranoia_level=2"\n'
        'SecRule REQUEST_URI "@rx \\/\\.(?:git|env|aws)" "id:1001,deny,status:403"\n'
        'SecRule REQUEST_METHOD "!^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)$" "id:1002,deny"\n'
        'SecRule ARGS "@rx union.*select" "id:942100,deny"\n'
        'SecRule ARGS "@rx <script>" "id:941100,deny"\n'
        'SecRule ARGS "@rx ;cat.*passwd" "id:932100,deny"\n'
        'SecRule ARGS "@rx \\.\\./" "id:930100,deny"\n'
        'SecRule ARGS "@rx http://169\\.254\\.169\\.254" "id:934100,deny"\n'
    )
    conf_file.write_text(content, encoding="utf-8")
    return conf_file


@pytest.fixture
def sample_traffic_csv(tmp_path: Path) -> Path:
    """Fixture providing CSV visitor traffic log."""
    csv_file = tmp_path / "traffic.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "event_id",
                "timestamp",
                "client_ip",
                "asn",
                "request_uri",
                "http_method",
                "status_code",
                "waf_action",
            ]
        )
        writer.writerow(
            [
                "csv-01",
                "2026-11-01T12:00:00Z",
                "198.51.100.99",
                "AS9999",
                "/wp-config.php",
                "GET",
                "200",
                "allow",
            ]
        )
    return csv_file
