"""
SIGMA-style rule engine for Atomic Red Team / MITRE ATT&CK detection.
Rules operate on raw log dicts — no ML, no training, deterministic.
"""

import re
import logging
from datetime import datetime, timezone
from collections import defaultdict

logger = logging.getLogger("sigma")

# ---------------------------------------------------------------------------
# Rule schema: each rule is a dict with:
#   id, name, mitre, severity, description, match(log) -> bool
# ---------------------------------------------------------------------------

def _port(log, *ports):
    return int(log.get("dst_port", 0)) in ports

def _event(log, *types):
    return str(log.get("event_type", "")).lower() in types

def _proto(log, *protos):
    return str(log.get("protocol", "")).lower() in protos

def _cat(log, *cats):
    return str(log.get("threat_category", "")).lower() in cats

def _bytes_gt(log, n):
    return int(log.get("bytes", 0)) > n

def _conn_gt(log, n):
    return int(log.get("connection_count", 0)) > n

def _is_external_src(log):
    src = str(log.get("src_ip", ""))
    return not any(src.startswith(p) for p in ("10.", "192.168.", "172.16.", "172.17.",
                                                "172.18.", "172.19.", "172.20.", "172.21.",
                                                "172.22.", "172.23.", "172.24.", "172.25.",
                                                "172.26.", "172.27.", "172.28.", "172.29.",
                                                "172.30.", "172.31.", "127.", "::1", "fc", "fd"))

def _is_external_dst(log):
    dst = str(log.get("dst_ip", ""))
    return not any(dst.startswith(p) for p in ("10.", "192.168.", "172.16.", "172.17.",
                                                "172.18.", "172.19.", "172.20.", "172.21.",
                                                "172.22.", "172.23.", "172.24.", "172.25.",
                                                "172.26.", "172.27.", "172.28.", "172.29.",
                                                "172.30.", "172.31.", "127.", "::1", "fc", "fd"))


RULES = [
    # --- Reconnaissance / Scanning ---
    {
        "id": "SYN-001",
        "name": "Network Port Scan Detected",
        "mitre": "T1046",
        "tactic": "Discovery",
        "severity": "medium",
        "description": "Port scanning activity — rapid connections to multiple ports",
        "match": lambda log: _event(log, "port_scan", "recon") or
                             (_conn_gt(log, 20) and _proto(log, "tcp") and not _event(log, "http", "https")),
    },
    {
        "id": "SYN-002",
        "name": "ICMP Sweep / Host Discovery",
        "mitre": "T1018",
        "tactic": "Discovery",
        "severity": "low",
        "description": "ICMP-based host discovery scan",
        "match": lambda log: _proto(log, "icmp") and _conn_gt(log, 5),
    },

    # --- Brute Force ---
    {
        "id": "BRU-001",
        "name": "SSH Brute Force",
        "mitre": "T1110.001",
        "tactic": "Credential Access",
        "severity": "high",
        "description": "Multiple SSH login attempts — brute force",
        "match": lambda log: _port(log, 22) and (
            _event(log, "brute_force") or _conn_gt(log, 10)
        ),
    },
    {
        "id": "BRU-002",
        "name": "RDP Brute Force",
        "mitre": "T1110.001",
        "tactic": "Credential Access",
        "severity": "high",
        "description": "Multiple RDP login attempts",
        "match": lambda log: _port(log, 3389) and (
            _event(log, "brute_force") or _conn_gt(log, 5)
        ),
    },
    {
        "id": "BRU-003",
        "name": "SMB Brute Force / Password Spray",
        "mitre": "T1110.003",
        "tactic": "Credential Access",
        "severity": "high",
        "description": "SMB authentication brute force",
        "match": lambda log: _port(log, 445, 139) and (
            _event(log, "brute_force") or _conn_gt(log, 5)
        ),
    },
    {
        "id": "BRU-004",
        "name": "FTP Brute Force",
        "mitre": "T1110.001",
        "tactic": "Credential Access",
        "severity": "medium",
        "description": "FTP authentication brute force",
        "match": lambda log: _port(log, 21) and _conn_gt(log, 5),
    },

    # --- Lateral Movement ---
    {
        "id": "LAT-001",
        "name": "Lateral Movement via RDP",
        "mitre": "T1021.001",
        "tactic": "Lateral Movement",
        "severity": "high",
        "description": "RDP connection to internal host",
        "match": lambda log: _port(log, 3389) and not _is_external_dst(log) and
                             _event(log, "lateral_movement", "rdp"),
    },
    {
        "id": "LAT-002",
        "name": "Lateral Movement via SMB",
        "mitre": "T1021.002",
        "tactic": "Lateral Movement",
        "severity": "high",
        "description": "SMB lateral movement — admin share access",
        "match": lambda log: _port(log, 445, 139) and
                             _event(log, "lateral_movement", "smb"),
    },
    {
        "id": "LAT-003",
        "name": "SSH Lateral Movement",
        "mitre": "T1021.004",
        "tactic": "Lateral Movement",
        "severity": "high",
        "description": "SSH connection between internal hosts",
        "match": lambda log: _port(log, 22) and not _is_external_src(log) and
                             not _is_external_dst(log) and
                             _event(log, "lateral_movement", "ssh"),
    },
    {
        "id": "LAT-004",
        "name": "WMI / DCOM Remote Execution",
        "mitre": "T1021.003",
        "tactic": "Lateral Movement",
        "severity": "critical",
        "description": "WMI/DCOM port activity — possible remote code execution",
        "match": lambda log: _port(log, 135, 593) and not _is_external_dst(log),
    },

    # --- Command & Control ---
    {
        "id": "C2-001",
        "name": "C2 Beacon Pattern",
        "mitre": "T1071.001",
        "tactic": "Command and Control",
        "severity": "critical",
        "description": "Periodic C2 beaconing to external host",
        "match": lambda log: _event(log, "c2_beacon") or
                             _cat(log, "c2"),
    },
    {
        "id": "C2-002",
        "name": "DNS Tunneling / C2",
        "mitre": "T1071.004",
        "tactic": "Command and Control",
        "severity": "high",
        "description": "Anomalous DNS traffic — possible tunneling",
        "match": lambda log: _port(log, 53) and _bytes_gt(log, 4096),
    },
    {
        "id": "C2-003",
        "name": "Non-Standard Port C2",
        "mitre": "T1571",
        "tactic": "Command and Control",
        "severity": "high",
        "description": "Outbound connection to external host on uncommon port",
        "match": lambda log: _is_external_dst(log) and
                             int(log.get("dst_port", 0)) not in (
                                 80, 443, 53, 123, 25, 465, 587, 993, 995, 110, 143, 22, 21
                             ) and
                             _proto(log, "tcp") and
                             int(log.get("dst_port", 0)) > 1024,
    },

    # --- Exfiltration ---
    {
        "id": "EXF-001",
        "name": "Data Exfiltration — Large Upload",
        "mitre": "T1048",
        "tactic": "Exfiltration",
        "severity": "critical",
        "description": "Large data transfer to external host",
        "match": lambda log: _is_external_dst(log) and _bytes_gt(log, 1_000_000),
    },
    {
        "id": "EXF-002",
        "name": "Data Exfiltration via DNS",
        "mitre": "T1048.003",
        "tactic": "Exfiltration",
        "severity": "high",
        "description": "Unusual DNS query volume — DNS exfiltration",
        "match": lambda log: _event(log, "data_exfil") or _cat(log, "exfil", "exfiltration"),
    },
    {
        "id": "EXF-003",
        "name": "FTP Exfiltration",
        "mitre": "T1048.002",
        "tactic": "Exfiltration",
        "severity": "high",
        "description": "Large FTP upload to external host",
        "match": lambda log: _port(log, 21, 20) and _is_external_dst(log) and _bytes_gt(log, 100_000),
    },

    # --- Privilege Escalation ---
    {
        "id": "PRV-001",
        "name": "Privilege Escalation Activity",
        "mitre": "T1068",
        "tactic": "Privilege Escalation",
        "severity": "critical",
        "description": "Privilege escalation technique detected",
        "match": lambda log: _event(log, "privesc") or _cat(log, "privesc", "privilege_escalation"),
    },



    # --- DoS ---
    {
        "id": "DOS-001",
        "name": "Denial of Service — High Rate",
        "mitre": "T1498",
        "tactic": "Impact",
        "severity": "critical",
        "description": "High-volume traffic — possible DoS attack",
        "match": lambda log: _conn_gt(log, 100) and _proto(log, "udp", "icmp"),
    },
    {
        "id": "DOS-002",
        "name": "SYN Flood",
        "mitre": "T1498.001",
        "tactic": "Impact",
        "severity": "critical",
        "description": "SYN flood — TCP connection rate anomaly",
        "match": lambda log: _conn_gt(log, 50) and _proto(log, "tcp") and
                             int(log.get("bytes", 0)) < 200,
    },

    # --- Initial Access ---
    {
        "id": "INI-001",
        "name": "External SSH Access",
        "mitre": "T1190",
        "tactic": "Initial Access",
        "severity": "medium",
        "description": "SSH connection from external IP",
        "match": lambda log: _port(log, 22) and _is_external_src(log),
    },
    {
        "id": "INI-002",
        "name": "External RDP Exposure",
        "mitre": "T1190",
        "tactic": "Initial Access",
        "severity": "high",
        "description": "RDP exposed to external network",
        "match": lambda log: _port(log, 3389) and _is_external_src(log),
    },
]


class SigmaEngine:
    """Stateless SIGMA-style rule matcher. Returns alert dicts for matched logs."""

    def __init__(self):
        self.rules = RULES
        logger.info(f"SigmaEngine loaded {len(self.rules)} rules")

    def scan(self, logs: list[dict]) -> list[dict]:
        alerts = []
        for log in logs:
            matched = self._match_all(log)
            for rule, alert in matched:
                alerts.append(alert)
        return alerts

    def _match_all(self, log: dict) -> list[tuple]:
        matched = []
        for rule in self.rules:
            try:
                if rule["match"](log):
                    alert = self._build_alert(log, rule)
                    matched.append((rule, alert))
            except Exception as e:
                logger.debug(f"Rule {rule['id']} error: {e}")
        return matched

    def _build_alert(self, log: dict, rule: dict) -> dict:
        return {
            **log,
            "sigma_rule_id": rule["id"],
            "sigma_rule_name": rule["name"],
            "mitre_technique": rule["mitre"],
            "mitre_tactic": rule["tactic"],
            "ml_severity": rule["severity"],
            "ml_anomaly": True,
            "ml_rf_class": _mitre_to_class(rule["tactic"]),
            "ml_rf_confidence": 1.0,
            "ml_if_score": 0.0,
            "ml_explanation": f"[SIGMA {rule['id']}] {rule['description']}",
            "ml_detected_at": datetime.now(timezone.utc).isoformat(),
            "ml_score": 1.0,
            "detection_method": "sigma",
        }


def _mitre_to_class(tactic: str) -> str:
    mapping = {
        "Discovery": "probe",
        "Credential Access": "r2l",
        "Lateral Movement": "r2l",
        "Command and Control": "u2r",
        "Exfiltration": "u2r",
        "Privilege Escalation": "u2r",
        "Impact": "dos",
        "Execution": "u2r",
        "Initial Access": "probe",
    }
    return mapping.get(tactic, "unknown_anomaly")
