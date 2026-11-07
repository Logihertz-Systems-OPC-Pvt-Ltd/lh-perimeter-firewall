# ==============================================================================
# Product:       lh-perimeter-firewall (lh-firewall)
# Module:        tests.test_firewall_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for firewall_parser module."""

from __future__ import annotations

from pathlib import Path

from lh_perimeter_firewall.firewall_parser import (
    find_firewall_files,
    parse_conf_file,
    parse_csv_file,
    parse_firewall_file,
    parse_json_file,
    parse_yaml_file,
)


def test_parse_yaml_clean(sample_clean_yaml: Path) -> None:
    """Test parsing compliant YAML WAF policy."""
    policies, events = parse_yaml_file(sample_clean_yaml)
    assert len(policies) == 1
    assert len(events) == 0
    p = policies[0]
    assert p.target_domain == "api.logihertz.com"
    assert p.waf_mode == "block"
    assert p.sec_rule_engine == "On"
    assert p.crs_sqli_enabled is True
    assert p.anomaly_score_threshold == 5
    assert p.paranoia_level == 2
    assert p.inspect_request_body is True
    assert p.sec_request_body_access == "On"
    assert p.sec_request_body_limit_action == "Reject"
    assert "192.0.2.66" in p.blocked_ips
    assert len(p.bypass_rules) == 1


def test_parse_yaml_malicious(sample_malicious_yaml: Path) -> None:
    """Test parsing insecure YAML policies."""
    policies, events = parse_yaml_file(sample_malicious_yaml)
    assert len(policies) == 9
    assert len(events) == 0


def test_parse_json_traffic(sample_traffic_json: Path) -> None:
    """Test parsing JSON visitor traffic events."""
    policies, events = parse_json_file(sample_traffic_json)
    assert len(policies) == 0
    assert len(events) == 3
    assert events[0].client_ip == "203.0.113.88"
    assert events[0].request_uri == "/.env"


def test_parse_ndjson(tmp_path: Path) -> None:
    """Test parsing newline-delimited JSON (NDJSON)."""
    ndjson_file = tmp_path / "traffic.jsonl"
    lines = [
        '{"event_id": "nd-1", "client_ip": "10.0.0.1", "request_uri": "/home", "status_code": 200}',
        '{"event_id": "nd-2", "client_ip": "10.0.0.2", "request_uri": "/.env", "status_code": 403}',
    ]
    ndjson_file.write_text("\n".join(lines), encoding="utf-8")
    policies, events = parse_json_file(ndjson_file)
    assert len(policies) == 0
    assert len(events) == 2
    assert events[1].request_uri == "/.env"


def test_parse_conf_file(sample_modsecurity_conf: Path) -> None:
    """Test parsing ModSecurity configuration file."""
    policies, events = parse_conf_file(sample_modsecurity_conf)
    assert len(policies) == 1
    assert len(events) == 0
    p = policies[0]
    assert p.sec_rule_engine == "On"
    assert p.waf_mode == "block"
    assert p.crs_sqli_enabled is True
    assert p.crs_xss_enabled is True
    assert p.crs_rce_enabled is True
    assert p.crs_lfi_enabled is True
    assert p.crs_ssrf_enabled is True
    assert p.anomaly_score_threshold == 5
    assert p.paranoia_level == 2
    assert p.drop_sensitive_dotfiles is True


def test_parse_csv_traffic(sample_traffic_csv: Path) -> None:
    """Test parsing CSV visitor traffic log."""
    policies, events = parse_csv_file(sample_traffic_csv)
    assert len(policies) == 0
    assert len(events) == 1
    assert events[0].client_ip == "198.51.100.99"
    assert events[0].request_uri == "/wp-config.php"


def test_find_firewall_files(tmp_path: Path) -> None:
    """Test finding supported firewall and traffic files in directory."""
    (tmp_path / "waf.yaml").write_text("name: w", encoding="utf-8")
    (tmp_path / "traffic.json").write_text("[]", encoding="utf-8")
    (tmp_path / "modsec.conf").write_text("SecRuleEngine On", encoding="utf-8")
    (tmp_path / "log.csv").write_text("client_ip,request_uri", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("notes", encoding="utf-8")

    files = find_firewall_files(tmp_path)
    file_names = [f.name for f in files]
    assert "waf.yaml" in file_names
    assert "traffic.json" in file_names
    assert "modsec.conf" in file_names
    assert "log.csv" in file_names
    assert "ignored.txt" not in file_names


def test_parse_firewall_file_dispatcher(sample_clean_yaml: Path) -> None:
    """Test parse_firewall_file dispatcher."""
    policies, events = parse_firewall_file(sample_clean_yaml)
    assert len(policies) == 1
    assert len(events) == 0
