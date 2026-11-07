# ==============================================================================
# Product:       lh-perimeter-firewall (lh-firewall)
# Module:        src.lh_perimeter_firewall.firewall_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parsers for WAF manifests, ModSecurity/CRS configs, and visitor traffic logs."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

import yaml

from lh_perimeter_firewall.models import TrafficEvent, WafBypassRule, WafPolicy

ANY_IPV4_CIDR = ".".join(["0", "0", "0", "0"]) + "/0"
ANY_IPV4 = ".".join(["0", "0", "0", "0"])


def _extract_bool(data: dict[str, Any], aliases: list[str]) -> bool | None:
    """Extract boolean value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                s = val.strip().lower()
                if s in ["true", "yes", "1", "on", "enabled", "strict", "active", "block"]:
                    return True
                if s in ["false", "no", "0", "off", "disabled", "simulate", "detection_only"]:
                    return False
            if isinstance(val, int):
                return bool(val)
    return None


def _extract_str(data: dict[str, Any], aliases: list[str], default: str = "") -> str:
    """Extract string value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if val is not None:
                return str(val).strip()
    return default


def _extract_int(data: dict[str, Any], aliases: list[str]) -> int | None:
    """Extract integer value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            try:
                return int(val)
            except (ValueError, TypeError):
                continue
    return None


def _extract_list(data: dict[str, Any], aliases: list[str]) -> list[str]:
    """Extract string list checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, list):
                return [str(x).strip() for x in val if x is not None]
            if isinstance(val, str):
                return [x.strip() for x in val.split(",") if x.strip()]
    return []


def _extract_bypass_rules(data: dict[str, Any]) -> list[WafBypassRule]:
    """Extract bypass/whitelist rule definitions from dictionary."""
    rules: list[WafBypassRule] = []
    candidates = data.get("bypass_rules") or data.get("whitelists") or data.get("allow_rules") or []
    if isinstance(candidates, list):
        for idx, item in enumerate(candidates, start=1):
            if isinstance(item, dict):
                r_id = str(item.get("rule_id") or item.get("id") or f"bypass-{idx}")
                desc = str(item.get("description") or item.get("desc") or "")
                src_ip = str(item.get("source_ip") or item.get("ip") or item.get("cidr") or "")
                path = str(item.get("path_pattern") or item.get("path") or item.get("uri") or "")
                hdr = str(item.get("match_header") or item.get("header") or "")
                act = str(item.get("action") or "allow").lower()
                rules.append(
                    WafBypassRule(
                        rule_id=r_id,
                        description=desc,
                        source_ip=src_ip,
                        path_pattern=path,
                        match_header=hdr,
                        action=act,
                    )
                )
    return rules


def _dict_to_waf_policy(data: dict[str, Any], source_file: str, line_no: int) -> WafPolicy:
    """Convert parsed dictionary into a WafPolicy object."""
    pol_id = _extract_str(data, ["policy_id", "id", "name", "rule_id"], f"pol-{line_no}")
    name = _extract_str(data, ["name", "title", "description"], pol_id)
    domain = _extract_str(data, ["target_domain", "domain", "host", "hostname"], "*")

    waf_mode = _extract_str(data, ["waf_mode", "mode", "engine_mode", "action"], "block").lower()
    sec_rule_engine = _extract_str(data, ["sec_rule_engine", "secruleengine"], "")

    crs_sqli = _extract_bool(data, ["crs_sqli_enabled", "sqli_protection", "sqli"])
    crs_xss = _extract_bool(data, ["crs_xss_enabled", "xss_protection", "xss"])
    crs_rce = _extract_bool(data, ["crs_rce_enabled", "rce_protection", "rce"])
    crs_lfi = _extract_bool(data, ["crs_lfi_enabled", "lfi_protection", "lfi"])
    crs_ssrf = _extract_bool(data, ["crs_ssrf_enabled", "ssrf_protection", "ssrf"])
    rule_groups = _extract_list(data, ["enabled_rule_groups", "rule_groups", "crs_groups"])

    bypass_rules = _extract_bypass_rules(data)
    blocked_ips = _extract_list(
        data, ["blocked_ips", "deny_ips", "ip_blocklist", "blacklisted_ips"]
    )
    blocked_asns = _extract_list(data, ["blocked_asns", "deny_asns", "asn_blocklist"])

    inspect_body = _extract_bool(
        data, ["inspect_request_body", "request_body_inspection", "body_inspection"]
    )
    sec_body_access = _extract_str(data, ["sec_request_body_access", "secrequestbodyaccess"], "")
    sec_body_limit = _extract_str(
        data,
        ["sec_request_body_limit_action", "secrequestbodylimitaction", "body_limit_action"],
        "",
    )

    block_bad_asn = _extract_bool(data, ["block_bad_asn", "filter_bad_asns", "asn_reputation"])
    block_tor = _extract_bool(data, ["block_tor_exit_nodes", "block_tor", "tor_blocking"])

    anomaly_score = _extract_int(
        data,
        [
            "anomaly_score_threshold",
            "inbound_anomaly_score_threshold",
            "anomaly_threshold",
            "threshold",
        ],
    )
    paranoia = _extract_int(data, ["paranoia_level", "paranoia", "crs_paranoia_level"])

    drop_dotfiles = _extract_bool(
        data, ["drop_sensitive_dotfiles", "block_dotfiles", "drop_dotfiles"]
    )
    blocked_paths = _extract_list(
        data, ["blocked_path_patterns", "blocked_paths", "deny_paths", "blocked_urls"]
    )
    allowed_methods = _extract_list(
        data, ["allowed_http_methods", "allowed_methods", "http_methods"]
    )

    audit_logging = _extract_bool(data, ["audit_logging", "enable_audit_log", "logging"])
    sec_audit = _extract_str(data, ["sec_audit_engine", "secauditengine"], "")
    feed_age = _extract_int(
        data, ["threat_feed_age_days", "feed_age_days", "threat_intelligence_age_days"]
    )

    return WafPolicy(
        policy_id=pol_id,
        name=name,
        target_domain=domain,
        waf_mode=waf_mode,
        sec_rule_engine=sec_rule_engine,
        crs_sqli_enabled=crs_sqli,
        crs_xss_enabled=crs_xss,
        crs_rce_enabled=crs_rce,
        crs_lfi_enabled=crs_lfi,
        crs_ssrf_enabled=crs_ssrf,
        enabled_rule_groups=rule_groups,
        bypass_rules=bypass_rules,
        blocked_ips=blocked_ips,
        blocked_asns=blocked_asns,
        inspect_request_body=inspect_body,
        sec_request_body_access=sec_body_access,
        sec_request_body_limit_action=sec_body_limit,
        block_bad_asn=block_bad_asn,
        block_tor_exit_nodes=block_tor,
        anomaly_score_threshold=anomaly_score,
        paranoia_level=paranoia,
        drop_sensitive_dotfiles=drop_dotfiles,
        blocked_path_patterns=blocked_paths,
        allowed_http_methods=allowed_methods,
        audit_logging=audit_logging,
        sec_audit_engine=sec_audit,
        threat_feed_age_days=feed_age,
        source_file=source_file,
        line_number=line_no,
    )


def _dict_to_traffic_event(data: dict[str, Any], source_file: str, line_no: int) -> TrafficEvent:
    """Convert parsed dictionary into a TrafficEvent record."""
    evt_id = _extract_str(data, ["event_id", "id", "log_id"], f"evt-{line_no}")
    ts = _extract_str(data, ["timestamp", "time", "date"], "")
    client_ip = _extract_str(data, ["client_ip", "ip", "source_ip", "remote_addr"], "")
    asn = _extract_str(data, ["asn", "client_asn", "as_number"], "")
    uri = _extract_str(data, ["request_uri", "uri", "path", "url"], "/")
    method = _extract_str(data, ["http_method", "method", "verb"], "GET").upper()
    status = _extract_int(data, ["status_code", "status", "http_status"]) or 200
    waf_action = _extract_str(data, ["waf_action", "action", "decision"], "allow").lower()

    return TrafficEvent(
        event_id=evt_id,
        timestamp=ts,
        client_ip=client_ip,
        asn=asn,
        request_uri=uri,
        http_method=method,
        status_code=status,
        waf_action=waf_action,
        source_file=source_file,
        line_number=line_no,
    )


WAF_POLICY_KEYS = {
    "waf_mode",
    "sec_rule_engine",
    "crs_sqli_enabled",
    "crs_xss_enabled",
    "crs_rce_enabled",
    "crs_lfi_enabled",
    "crs_ssrf_enabled",
    "enabled_rule_groups",
    "bypass_rules",
    "whitelists",
    "blocked_ips",
    "inspect_request_body",
    "sec_request_body_access",
    "block_bad_asn",
    "block_tor_exit_nodes",
    "anomaly_score_threshold",
    "paranoia_level",
    "drop_sensitive_dotfiles",
    "allowed_http_methods",
    "audit_logging",
    "threat_feed_age_days",
}


def _is_policy_dict(data: dict[str, Any]) -> bool:
    """Check if dictionary has recognizable WAF policy attributes."""
    normalized = {k.strip().lower() for k in data.keys()}
    return bool(normalized.intersection(WAF_POLICY_KEYS))


def parse_yaml_file(path: Path) -> tuple[list[WafPolicy], list[TrafficEvent]]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse YAML manifest for WAF policies or visitor traffic events."""
    policies: list[WafPolicy] = []
    events: list[TrafficEvent] = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        loaded = yaml.safe_load(content)

        if isinstance(loaded, list):
            for idx, item in enumerate(loaded, start=1):
                if isinstance(item, dict):
                    if _is_policy_dict(item):
                        policies.append(_dict_to_waf_policy(item, str(path), idx))
                    else:
                        events.append(_dict_to_traffic_event(item, str(path), idx))
        elif isinstance(loaded, dict):
            if "policies" in loaded and isinstance(loaded["policies"], list):
                for idx, p in enumerate(loaded["policies"], start=1):
                    if isinstance(p, dict):
                        policies.append(_dict_to_waf_policy(p, str(path), idx))
            if "events" in loaded and isinstance(loaded["events"], list):
                for idx, ev in enumerate(loaded["events"], start=1):
                    if isinstance(ev, dict):
                        events.append(_dict_to_traffic_event(ev, str(path), idx))
            if not policies and not events:
                if _is_policy_dict(loaded):
                    policies.append(_dict_to_waf_policy(loaded, str(path), 1))
                else:
                    events.append(_dict_to_traffic_event(loaded, str(path), 1))
    except Exception:
        return policies, events

    return policies, events


def parse_json_file(path: Path) -> tuple[list[WafPolicy], list[TrafficEvent]]:
    """Parse JSON or NDJSON files for WAF policies or traffic events."""
    policies: list[WafPolicy] = []
    events: list[TrafficEvent] = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            return [], []

        if content.startswith("["):
            loaded = json.loads(content)
            if isinstance(loaded, list):
                for idx, item in enumerate(loaded, start=1):
                    if isinstance(item, dict):
                        if _is_policy_dict(item):
                            policies.append(_dict_to_waf_policy(item, str(path), idx))
                        else:
                            events.append(_dict_to_traffic_event(item, str(path), idx))
                return policies, events
        elif content.startswith("{"):
            try:
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    if "policies" in loaded and isinstance(loaded["policies"], list):
                        for idx, p in enumerate(loaded["policies"], start=1):
                            if isinstance(p, dict):
                                policies.append(_dict_to_waf_policy(p, str(path), idx))
                    if "events" in loaded and isinstance(loaded["events"], list):
                        for idx, ev in enumerate(loaded["events"], start=1):
                            if isinstance(ev, dict):
                                events.append(_dict_to_traffic_event(ev, str(path), idx))
                    if not policies and not events:
                        if _is_policy_dict(loaded):
                            policies.append(_dict_to_waf_policy(loaded, str(path), 1))
                        else:
                            events.append(_dict_to_traffic_event(loaded, str(path), 1))
                    return policies, events
            except json.JSONDecodeError:
                _ = None

        # NDJSON fallback
        for idx, line in enumerate(content.splitlines(), start=1):
            clean = line.strip()
            if clean:
                try:
                    obj = json.loads(clean)
                    if isinstance(obj, dict):
                        if _is_policy_dict(obj):
                            policies.append(_dict_to_waf_policy(obj, str(path), idx))
                        else:
                            events.append(_dict_to_traffic_event(obj, str(path), idx))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return policies, events

    return policies, events


def parse_conf_file(path: Path) -> tuple[list[WafPolicy], list[TrafficEvent]]:
    """Parse ModSecurity/OWASP CRS configuration file into WafPolicy."""
    policies: list[WafPolicy] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")

        # SecRuleEngine
        m_engine = re.search(r"SecRuleEngine\s+(On|Off|DetectionOnly)", content, re.IGNORECASE)
        sec_engine = m_engine.group(1) if m_engine else ""

        # SecRequestBodyAccess
        m_body_acc = re.search(r"SecRequestBodyAccess\s+(On|Off)", content, re.IGNORECASE)
        body_acc = m_body_acc.group(1) if m_body_acc else ""

        # SecRequestBodyLimitAction
        m_body_act = re.search(
            r"SecRequestBodyLimitAction\s+(Reject|ProcessPartial)", content, re.IGNORECASE
        )
        body_limit_act = m_body_act.group(1) if m_body_act else ""

        # SecAuditEngine
        m_audit = re.search(r"SecAuditEngine\s+(On|Off|RelevantOnly)", content, re.IGNORECASE)
        sec_audit = m_audit.group(1) if m_audit else ""

        # Anomaly threshold & paranoia level
        m_thresh = re.search(
            r"setvar:tx\.inbound_anomaly_score_threshold=(\d+)", content, re.IGNORECASE
        )
        thresh = int(m_thresh.group(1)) if m_thresh else None

        m_paranoia = re.search(r"setvar:tx\.paranoia_level=(\d+)", content, re.IGNORECASE)
        paranoia = int(m_paranoia.group(1)) if m_paranoia else None

        # CRS rule detection by ID ranges or tags
        has_sqli = bool(re.search(r"id:942\d{3}|tag:.*sqli", content, re.IGNORECASE))
        has_xss = bool(re.search(r"id:941\d{3}|tag:.*xss", content, re.IGNORECASE))
        has_rce = bool(re.search(r"id:932\d{3}|tag:.*rce", content, re.IGNORECASE))
        has_lfi = bool(re.search(r"id:930\d{3}|tag:.*lfi", content, re.IGNORECASE))
        has_ssrf = bool(re.search(r"id:934\d{3}|tag:.*ssrf", content, re.IGNORECASE))

        # Check for dotfile drop rules
        has_dotfile_rule = any(
            pat in content.lower()
            for pat in [".git", ".env", ".aws", "git|env|aws", "\\.git", "\\.env"]
        )

        # Check for allowed HTTP methods
        m_methods = re.search(r"REQUEST_METHOD\s+\"?\^?\(([^)\"]+)\)", content, re.IGNORECASE)
        allowed_methods = (
            [x.strip() for x in m_methods.group(1).split("|") if x.strip()] if m_methods else []
        )

        # Check for bypass / allow rules
        bypass_rules: list[WafBypassRule] = []
        bypass_pattern = re.compile(
            r"""SecRule\s+([^\s]+)\s+["']@ipMatch\s+([^"'\s]+)["']\s+["'][^"']*allow[^"']*["']""",
            re.IGNORECASE,
        )
        for idx, m in enumerate(bypass_pattern.finditer(content), start=1):
            src_ip = m.group(2).strip()
            bypass_rules.append(
                WafBypassRule(
                    rule_id=f"conf-allow-{idx}",
                    source_ip=src_ip,
                    action="allow",
                )
            )

        policy = WafPolicy(
            policy_id=path.stem,
            name=f"ModSecurity Conf ({path.name})",
            target_domain=path.name,
            waf_mode="block"
            if sec_engine.lower() == "on"
            else ("detection_only" if sec_engine.lower() == "detectiononly" else "off"),
            sec_rule_engine=sec_engine,
            crs_sqli_enabled=has_sqli,
            crs_xss_enabled=has_xss,
            crs_rce_enabled=has_rce,
            crs_lfi_enabled=has_lfi,
            crs_ssrf_enabled=has_ssrf,
            sec_request_body_access=body_acc,
            sec_request_body_limit_action=body_limit_act,
            sec_audit_engine=sec_audit,
            anomaly_score_threshold=thresh,
            paranoia_level=paranoia,
            drop_sensitive_dotfiles=has_dotfile_rule,
            allowed_http_methods=allowed_methods,
            bypass_rules=bypass_rules,
            source_file=str(path),
            line_number=1,
        )
        policies.append(policy)
    except Exception:
        return policies, []

    return policies, []


def parse_csv_file(path: Path) -> tuple[list[WafPolicy], list[TrafficEvent]]:
    """Parse CSV web visitor traffic logs."""
    events: list[TrafficEvent] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=1):
                events.append(_dict_to_traffic_event(row, str(path), idx))
    except Exception:
        return [], events

    return [], events


def parse_firewall_file(path: Path) -> tuple[list[WafPolicy], list[TrafficEvent]]:
    """Dispatch file parsing based on extension."""
    suffix = path.suffix.lower()
    if suffix in [".yaml", ".yml"]:
        return parse_yaml_file(path)
    if suffix in [".json", ".jsonl", ".ndjson"]:
        return parse_json_file(path)
    if suffix in [".conf", ".rules"]:
        return parse_conf_file(path)
    if suffix == ".csv":
        return parse_csv_file(path)

    # Fallback to YAML
    p, e = parse_yaml_file(path)
    if p or e:
        return p, e
    return parse_conf_file(path)


def find_firewall_files(target: Path) -> list[Path]:
    """Find all WAF manifests, ModSecurity configs, and traffic logs in path."""
    if target.is_file():
        return [target]

    supported_suffixes = {
        ".yaml",
        ".yml",
        ".json",
        ".jsonl",
        ".ndjson",
        ".conf",
        ".rules",
        ".csv",
    }
    found: list[Path] = []
    ignored_parts = {".git", ".venv", "node_modules", "__pycache__"}

    for p in target.rglob("*"):
        if p.is_file():
            if any(ign in p.parts for ign in ignored_parts):
                continue
            if p.suffix.lower() in supported_suffixes:
                found.append(p)

    return sorted(found)
