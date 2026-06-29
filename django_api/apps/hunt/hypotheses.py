BUILTIN_HYPOTHESES = [
    {
        "hypothesis_id": "HYP-001",
        "name": "Reconnaissance — Port Scanning Activity",
        "description": "Hunt for systematic port scanning that may indicate an "
                       "attacker mapping your network prior to exploitation. "
                       "Covers both TCP SYN scans and ICMP sweeps.",
        "tactic": "discovery",
        "mitre_technique": "T1046",
        "severity": "medium",
        "sigma_rule_ids": ["SYN-001", "SYN-002"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"terms": {"event_type.keyword": ["port_scan", "recon"]}},
                        {"term":  {"mitre_techniques.keyword": "T1046"}},
                        {"term":  {"mitre_techniques.keyword": "T1018"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 200
        },
        "hunt_steps": [
            "1. Run the query to identify scanning source IPs",
            "2. Check if the same src_ip appears in multiple agent logs",
            "3. Look for scanning followed by exploitation attempts (BRU/LAT rules)",
            "4. Check src_ip against ThreatActorProfile for known bad reputation",
            "5. If internal src_ip is scanning, suspect compromised host — escalate"
        ],
        "follow_up_queries": [
            "HYP-002",  # Check if scan led to brute force
            "HYP-005",  # Check for lateral movement after recon
        ]
    },
    {
        "hypothesis_id": "HYP-002",
        "name": "Credential Access — Brute Force Campaigns",
        "description": "Hunt for sustained brute force attacks across SSH, RDP, SMB, "
                       "and FTP. Look for patterns suggesting credential stuffing or "
                       "password spraying rather than single targeted attempts.",
        "tactic": "credential_access",
        "mitre_technique": "T1110",
        "severity": "high",
        "sigma_rule_ids": ["BRU-001", "BRU-002", "BRU-003", "BRU-004"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"mitre_techniques.keyword": "T1110.001"}},
                        {"term": {"mitre_techniques.keyword": "T1110.003"}},
                        {"terms": {"event_type.keyword": ["brute_force", "failed_login"]}},
                        {"term": {"ml_rf_class.keyword": "r2l"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 500
        },
        "hunt_steps": [
            "1. Group results by src_ip — high frequency from same IP = brute force",
            "2. Group results by agent_name — same agent hit by many IPs = password spray",
            "3. Check timestamps — attempts over long period = slow/low brute force (stealth)",
            "4. Look for any successful logins after failed attempts (ml_if_score drop)",
            "5. If success detected, immediately pivot to HYP-005 Lateral Movement",
            "6. Check if targeted ports (22, 3389, 445) are exposed externally"
        ],
        "follow_up_queries": ["HYP-005", "HYP-006"]
    },
    {
        "hypothesis_id": "HYP-003",
        "name": "Lateral Movement — Internal Propagation",
        "description": "Hunt for an attacker moving between systems after initial "
                       "compromise. Focus on internal IP-to-IP connections on "
                       "admin protocols: RDP, SMB, SSH, WMI/DCOM.",
        "tactic": "lateral_movement",
        "mitre_technique": "T1021",
        "severity": "high",
        "sigma_rule_ids": ["LAT-001", "LAT-002", "LAT-003", "LAT-004"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"mitre_techniques.keyword": "T1021.001"}},
                        {"term": {"mitre_techniques.keyword": "T1021.002"}},
                        {"term": {"mitre_techniques.keyword": "T1021.003"}},
                        {"term": {"mitre_techniques.keyword": "T1021.004"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 200
        },
        "hunt_steps": [
            "1. Map the src_ip → dst_ip connections to build a movement graph",
            "2. Identify the original entry point (earliest timestamp, external src_ip)",
            "3. Trace the propagation path through internal hosts",
            "4. Check if any agent_name appears as both src and dst (pivot host)",
            "5. Look for admin tool usage on non-admin hosts",
            "6. Check timestamps — rapid sequential movement = automated tool"
        ],
        "follow_up_queries": ["HYP-004", "HYP-007"]
    },
    {
        "hypothesis_id": "HYP-004",
        "name": "Command & Control — Beaconing Detection",
        "description": "Hunt for C2 beaconing: regular outbound connections at "
                       "fixed intervals to the same external IP. Covers HTTP/S "
                       "C2 channels and DNS tunneling.",
        "tactic": "command_and_control",
        "mitre_technique": "T1071",
        "severity": "critical",
        "sigma_rule_ids": ["C2-001", "C2-002", "C2-003"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"mitre_techniques.keyword": "T1071.001"}},
                        {"term": {"mitre_techniques.keyword": "T1071.004"}},
                        {"terms": {"event_type.keyword": ["c2_beacon", "dns_tunnel"]}},
                        {"term": {"ml_rf_class.keyword": "u2r"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 200
        },
        "hunt_steps": [
            "1. Group by src_ip + dst_ip pair — repeated pair = potential beacon",
            "2. Examine timestamps — regular intervals (e.g. every 30s/60s) = beacon",
            "3. Check dst_ip reputation in ThreatActorProfile",
            "4. Look for DNS queries with unusually long subdomains (DNS tunneling)",
            "5. Check if beaconing agent shows lateral movement or exfil activity",
            "6. Correlate with AgentBaseline — C2 often starts with off-hours activity"
        ],
        "follow_up_queries": ["HYP-006", "HYP-007"]
    },
    {
        "hypothesis_id": "HYP-005",
        "name": "Exfiltration — Data Theft Detection",
        "description": "Hunt for unusual outbound data transfers suggesting "
                       "data exfiltration. Covers large byte transfers, "
                       "DNS exfil, and FTP transfers to external hosts.",
        "tactic": "exfiltration",
        "mitre_technique": "T1048",
        "severity": "high",
        "sigma_rule_ids": ["EXF-001", "EXF-002", "EXF-003"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"mitre_techniques.keyword": "T1048"}},
                        {"term": {"mitre_techniques.keyword": "T1048.002"}},
                        {"term": {"mitre_techniques.keyword": "T1048.003"}},
                        {"terms": {"event_type.keyword": ["data_exfil", "exfil", "ftp_transfer"]}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 200
        },
        "hunt_steps": [
            "1. Identify large outbound byte counts to external IPs",
            "2. Check if transfer destination is in a high-risk country (RU/CN/KP)",
            "3. Look for exfil happening during off-hours (baseline deviation)",
            "4. Correlate with C2 activity — exfil often follows C2 establishment",
            "5. Check connector — Umbrella may have DNS exfil that Wazuh missed",
            "6. Flag the src agent for incident escalation"
        ],
        "follow_up_queries": ["HYP-004"]
    },
    {
        "hypothesis_id": "HYP-006",
        "name": "Privilege Escalation — Root/Admin Access Attempts",
        "description": "Hunt for privilege escalation activity suggesting an "
                       "attacker attempting to gain administrative control "
                       "of a compromised system.",
        "tactic": "privilege_escalation",
        "mitre_technique": "T1068",
        "severity": "critical",
        "sigma_rule_ids": ["PRV-001"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"mitre_techniques.keyword": "T1068"}},
                        {"terms": {"event_type.keyword": ["privesc", "sudo_attempt", "root_access"]}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 200
        },
        "hunt_steps": [
            "1. Identify the agent where escalation occurred",
            "2. Check for brute force activity on same agent in previous 24h",
            "3. Look for lateral movement originating FROM this agent after escalation",
            "4. Check if escalation succeeded (look for admin-level activity post-event)",
            "5. Immediately propose block on src_ip if external",
            "6. Escalate agent to incident — compromised host"
        ],
        "follow_up_queries": ["HYP-003", "HYP-004"]
    },
    {
        "hypothesis_id": "HYP-007",
        "name": "Initial Access — Exposed Services Exploitation",
        "description": "Hunt for exploitation of externally-facing services. "
                       "Focus on SSH and RDP directly exposed to the internet, "
                       "common initial access vectors in East African deployments.",
        "tactic": "initial_access",
        "mitre_technique": "T1190",
        "severity": "high",
        "sigma_rule_ids": ["INI-001", "INI-002"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"mitre_techniques.keyword": "T1190"}},
                        {"terms": {"event_type.keyword": ["external_ssh", "external_rdp"]}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 200
        },
        "hunt_steps": [
            "1. List all external src_IPs making SSH/RDP connections",
            "2. Verify each src_ip against ThreatActorProfile",
            "3. Check if any of these led to successful auth (look for post-login activity)",
            "4. Identify which agents have external-facing services — should be minimal",
            "5. Flag unexpectedly exposed services for remediation",
            "6. Correlate with WireGuard VPN logs — legitimate remote agents use VPN"
        ],
        "follow_up_queries": ["HYP-002", "HYP-003"]
    },
    {
        "hypothesis_id": "HYP-008",
        "name": "Impact — Denial of Service Activity",
        "description": "Hunt for DoS/DDoS activity targeting your monitored "
                       "infrastructure including high-rate traffic floods and "
                       "SYN flood patterns.",
        "tactic": "impact",
        "mitre_technique": "T1498",
        "severity": "critical",
        "sigma_rule_ids": ["DOS-001", "DOS-002"],
        "es_query": {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"mitre_techniques.keyword": "T1498"}},
                        {"term": {"mitre_techniques.keyword": "T1498.001"}},
                        {"term": {"ml_rf_class.keyword": "dos"}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"ml_detected_at": {"order": "desc"}}],
            "size": 200
        },
        "hunt_steps": [
            "1. Identify peak traffic volume and timing",
            "2. List all src_IPs — many IPs = DDoS, single IP = targeted DoS",
            "3. Check which agents/services are targeted",
            "4. Correlate with baseline deviation — volume spike should have fired",
            "5. If DDoS: engage upstream provider for null-routing",
            "6. If single-source DoS: block src_ip via HITL queue"
        ],
        "follow_up_queries": []
    },
]


def seed_hypotheses():
    """
    Seed the HuntHypothesis table with builtin hypotheses.
    Idempotent — skips existing entries. Call from apps.py ready().
    """
    from .models import HuntHypothesis
    for h in BUILTIN_HYPOTHESES:
        HuntHypothesis.objects.get_or_create(
            hypothesis_id=h["hypothesis_id"],
            defaults={
                "name":             h["name"],
                "description":      h["description"],
                "tactic":           h["tactic"],
                "mitre_technique":  h["mitre_technique"],
                "severity":         h["severity"],
                "sigma_rule_ids":   h["sigma_rule_ids"],
                "es_query":         h["es_query"],
                "hunt_steps":       h["hunt_steps"],
                "follow_up_queries": h.get("follow_up_queries", []),
                "is_builtin":       True,
            }
        )
